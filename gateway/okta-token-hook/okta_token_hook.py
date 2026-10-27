#!/usr/bin/env python3
"""Okta token inline hook: put Portkey AI Gateway "Mode A" claims (nested objects
included) into Okta access tokens, mapping Okta groups to gateway workspaces.

Python 3.8+, standard library only. Plain HTTP by default: run it behind a
TLS-terminating reverse proxy or tunnel (Okta only calls HTTPS endpoints), or pass
--tls-cert/--tls-key.

FAIL CLOSED by design: Okta fails OPEN (hook timeout or error -> the ORIGINAL token is
issued). So set ALL Mode A claims (portkey_oid, portkey_workspace, defaults, limits) only
from this hook, none from Okta claim expressions. A failed hook then yields a token with
no portkey_oid/portkey_workspace, which the gateway rejects. A user in no mapped group
gets no commands, with the same effect.

Request shape (Okta token inline hook; see README for what is confirmed):
  data.context.user.id / .profile.login   user (profile may be absent: UNCONFIRMED)
  data.access.claims                      the access token's current claims
  groups: Okta does not document groups in the hook request (UNCONFIRMED). Add a
  Groups-type claim named "groups" (filter: Starts with aigw-) to the access token; it
  shows up in data.access.claims.groups. data.context.user.groups is read as a fallback.
Response: {"commands":[{"type":"com.okta.access.patch","value":[{"op":"add",
  "path":"/claims/<name>","value":<any JSON>}]}]}

Secrets are never logged. Log lines carry a user-id hash, the matched rule, claim names.
"""
import argparse
import hashlib
import hmac
import json
import logging
import os
import signal
import ssl
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

VERSION = "0.1.1"
MAX_BODY = 256 * 1024
HANDLER_TIMEOUT = 10      # seconds a client may sit silent; Okta waits 3 s for the hook, so a real call is far inside it
PATCH_TYPE = "com.okta.access.patch"
# Claims the mapping may not set (JWT-standard or Okta identity): a typo must not
# overwrite iss/sub/aud/exp. Okta's own reserved list is UNCONFIRMED; this is conservative.
FORBIDDEN = {"iss", "sub", "aud", "exp", "iat", "nbf", "jti", "scp", "cid", "uid", "ver"}
log = logging.getLogger("okta_token_hook")


class Mapping:
    """Ordered group->claims rules, loaded from JSON; reloads when the mtime changes."""

    def __init__(self, path):
        self.path = path
        self.rules = []
        self.default = None
        self._mtime = None
        self._lock = threading.Lock()
        self.load()

    def load(self):
        with open(self.path, "r", encoding="utf-8") as f:
            doc = json.load(f)
        rules = doc.get("rules")
        if not isinstance(rules, list):
            raise ValueError("mapping: 'rules' must be a list")
        default = doc.get("default")
        for i, r in enumerate(rules + ([default] if default else [])):
            if not isinstance(r, dict) or not isinstance(r.get("claims"), dict):
                raise ValueError("mapping: rule %d needs a 'claims' object" % i)
            bad = FORBIDDEN & set(r["claims"])
            if bad:
                raise ValueError("mapping: rule %d sets forbidden claims %s" % (i, sorted(bad)))
        for i, r in enumerate(rules):
            if not isinstance(r.get("group"), str):
                raise ValueError("mapping: rule %d needs a 'group' string" % i)
        mtime = os.stat(self.path).st_mtime_ns
        with self._lock:
            self.rules, self.default, self._mtime = rules, default, mtime

    def refresh(self):
        """Reload on mtime change; keep the old mapping if the new file is bad."""
        try:
            if os.stat(self.path).st_mtime_ns != self._mtime:
                self.load()
                log.info("mapping reloaded (%d rules)", len(self.rules))
        except (OSError, ValueError) as e:
            log.error("mapping reload failed, keeping previous: %s", e)

    def match(self, groups):
        """First rule (file order) whose group the user has; else the default rule."""
        with self._lock:
            rules, default = self.rules, self.default
        gs = set(groups)
        for r in rules:
            if r["group"] in gs:
                return r["group"], r
        if default:
            return "(default)", default
        return None, None


def extract_groups(payload):
    data = payload.get("data") or {}
    claims = (data.get("access") or {}).get("claims") or {}
    user = (data.get("context") or {}).get("user") or {}
    out = []
    for src in (claims.get("groups"), user.get("groups")):
        if isinstance(src, list):
            out += [g for g in src if isinstance(g, str)]
        elif isinstance(src, str):
            out.append(src)
    return out


def extract_user(payload):
    """(user id, login) from data.context.user; login may be None."""
    data = payload.get("data") or {}
    user = (data.get("context") or {}).get("user") or {}
    claims = (data.get("access") or {}).get("claims") or {}
    uid = user.get("id") or claims.get("uid") or claims.get("sub") or ""
    login = (user.get("profile") or {}).get("login") or claims.get("sub")
    return str(uid), (login if isinstance(login, str) and "@" in login else None)


def build_commands(payload, mapping):
    """Return (response dict, log info). Never raises on odd shapes."""
    if not isinstance(payload, dict) or not isinstance(payload.get("data"), dict):
        return {}, {"user": "-", "rule": None, "claims": [], "note": "unexpected-shape"}
    uid, login = extract_user(payload)
    group, rule = mapping.match(extract_groups(payload))
    info = {"user": hashlib.sha256(uid.encode()).hexdigest()[:10], "rule": group, "claims": []}
    if rule is None:
        return {}, info
    claims = dict(rule["claims"])
    if rule.get("email_id_from_login") and login:
        claims["email_id"] = login
    info["claims"] = sorted(claims)
    ops = [{"op": "add", "path": "/claims/" + k, "value": v} for k, v in claims.items()]
    return {"commands": [{"type": PATCH_TYPE, "value": ops}]}, info


def make_handler(mapping, secret, header):
    secret_b = secret.encode()

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        server_version = "okta-token-hook"
        timeout = HANDLER_TIMEOUT      # without it a client that stops sending holds its thread forever

        def log_message(self, *a):  # replaced by our own one-line log
            pass

        def _send(self, code, obj=None):
            body = json.dumps(obj if obj is not None else {}).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            if self.path == "/healthz":
                return self._send(200, {"ok": True})
            self._send(404, {"error": "not found"})

        def do_POST(self):
            got = (self.headers.get(header) or "").encode()
            if not hmac.compare_digest(got, secret_b):
                log.warning("401 auth header %s missing or wrong", header)
                self.close_connection = True
                return self._send(401, {"error": "unauthorized"})
            try:
                n = int(self.headers.get("Content-Length") or "0")
            except ValueError:
                n = -1
            if n < 0 or n > MAX_BODY:
                log.warning("413 body size %s over cap %d", n, MAX_BODY)
                self.close_connection = True
                return self._send(413, {"error": "too large"})
            raw = self.rfile.read(n)
            mapping.refresh()
            try:
                payload = json.loads(raw.decode("utf-8"))
            except ValueError:
                log.warning("200 {} malformed JSON body (%d bytes)", n)
                return self._send(200, {})
            resp, info = build_commands(payload, mapping)
            log.info("200 user=%s rule=%s claims=%s%s", info["user"], info["rule"],
                     ",".join(info["claims"]) or "-",
                     " note=" + info["note"] if "note" in info else "")
            self._send(200, resp)

    return Handler


def read_secret(env, path):
    s = os.environ.get(env) if env else None
    if not s and path:
        with open(path, "r", encoding="utf-8") as f:
            s = f.read().strip()
    if not s:
        raise SystemExit("no secret: set the env var (--secret-env) or give --secret-file")
    return s


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--mapping", required=True, help="group->claims JSON file")
    ap.add_argument("--listen", default="127.0.0.1", help="default 127.0.0.1")
    ap.add_argument("--port", type=int, default=8080)
    ap.add_argument("--secret-env", default="OKTA_HOOK_SECRET",
                    help="env var holding the exact header value Okta sends (default %(default)s)")
    ap.add_argument("--secret-file", help="file holding the secret (used if the env var is unset)")
    ap.add_argument("--auth-header", default="Authorization", help="header name configured in Okta")
    ap.add_argument("--tls-cert")
    ap.add_argument("--tls-key")
    a = ap.parse_args(argv)
    logging.basicConfig(level=logging.INFO, stream=sys.stderr,
                        format="%(asctime)s %(levelname)s %(message)s")
    secret = read_secret(a.secret_env, a.secret_file)
    mapping = Mapping(a.mapping)
    srv = ThreadingHTTPServer((a.listen, a.port), make_handler(mapping, secret, a.auth_header))
    srv.daemon_threads = True
    if a.tls_cert:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(a.tls_cert, a.tls_key)
        srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    if hasattr(signal, "SIGHUP"):
        def hup(*_):
            try:
                mapping.load()
                log.info("mapping reloaded on SIGHUP (%d rules)", len(mapping.rules))
            except (OSError, ValueError) as e:
                log.error("SIGHUP reload failed, keeping previous: %s", e)
        signal.signal(signal.SIGHUP, hup)
    log.info("okta_token_hook %s listening on %s:%d, %d rules", VERSION, a.listen,
             srv.server_port, len(mapping.rules))
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
