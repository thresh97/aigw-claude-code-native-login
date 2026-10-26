#!/usr/bin/env python3
"""aigw-claude-auth: keep a gateway JWT in Claude Code's settings while Claude Code keeps its own Anthropic login.

Claude Code sends its native login (`claude login`) as `Authorization: Bearer ...`. The AI gateway authenticates the
caller with a JWT in a second header (`x-portkey-api-key` by default), which Claude Code sends from
`env.ANTHROPIC_CUSTOM_HEADERS` in its settings file and re-reads when that file changes. This tool gets that JWT and
keeps it fresh:

  login         sign in to the IdP (device code or PKCE in a browser) and store the refresh token
  sync          make sure the settings hold a JWT that is valid for more than `refresh_before` seconds
  daemon        run `sync` ahead of every expiry (the background refresher)
  hook precheck UserPromptSubmit hook: refresh if the JWT is (nearly) expired, wait for Claude Code to reload, or
                block the prompt when no JWT can be had. When signed out, it starts a device code sign-in in the
                background and puts the URL and code into the block message, so the user can sign in from the session
  hook stop-failure  StopFailure hook: after a gateway auth failure, force a refresh so the retry works, and notify
  token         print a valid JWT on stdout (for scripts and curl)
  status        show where the JWT comes from and when it expires (never the token itself)
  install       add ANTHROPIC_BASE_URL and the two hooks to the settings file (or print them for managed settings)
  logout        forget the refresh token and put the sentinel into the settings

Where the JWT comes from (config file, see README):
  * an OIDC IdP whose token the gateway accepts directly (Portkey "Mode B"), or
  * an OIDC IdP token exchanged at a token broker for a gateway-signed JWT (Portkey "Mode A"), or
  * any command that prints a JWT (`token_command`).

When no JWT can be had and the one in the settings is unusable, `sync` writes the sentinel value (`expired`) instead
of an empty header. A load balancer rule can answer that sentinel with a non-401 status, which Claude Code shows at
once; a 401 would send a native-login Claude Code into its OAuth refresh-and-retry loop for about four minutes.

Python 3.8+, standard library only. macOS, Linux and native Windows (fcntl or msvcrt for locking, ctypes for the
Windows process check, a PowerShell toast and a Task Scheduler task on Windows).
"""
import argparse
import base64
import hashlib
import http.server
import json
import os
import re
import secrets
import shlex
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import webbrowser
from xml.sax.saxutils import escape as xml_escape
from contextlib import contextmanager
from pathlib import Path

if sys.platform == "win32":
    import msvcrt
else:
    import fcntl

VERSION = "1.2.0"
MARKER = re.compile(r"aigw[-_]claude[-_]auth")   # identifies our hook entries in a settings file
HOOK_TIMEOUT = 30   # written into our hook entries; Claude Code's default is also 30 s (observed with 2.1.286)

DEFAULTS = {
    "issuer": "",                      # OIDC issuer; endpoints come from its discovery document
    "token_endpoint": "",              # or set the endpoints explicitly (they override discovery)
    "device_authorization_endpoint": "",
    "authorization_endpoint": "",
    "client_id": "",                   # a public client (no secret)
    "scope": "openid offline_access",  # offline_access is what gets a refresh token; add the gateway/broker scope
    "idp_token": "access_token",       # which IdP token to use: access_token or id_token
    "broker_url": "",                  # full exchange URL; empty = the IdP token is the gateway JWT
    "token_command": "",               # instead of an IdP: a command that prints a JWT
    "header": "x-portkey-api-key",     # the header the gateway reads the JWT from
    "sentinel": "expired",             # written when no usable JWT can be had (never an empty value)
    "refresh_before": 300,             # seconds: renew when less than this is left
    "hook_wait": 3,                    # seconds the precheck hook waits after a refresh (Claude Code reloads ~1 s later)
    "block_on_failure": True,          # precheck blocks the prompt when there is no usable JWT
    "hook_login": "device",            # when signed out, the precheck starts a device code sign-in: device | off
    "notify": "auto",                  # desktop notification (StopFailure renewal, hook sign-in result): auto | off | a command (gets the message as $1)
    "redirect_uri": "http://127.0.0.1:{port}/",  # PKCE loopback redirect; {port} is filled in
    "redirect_port": 0,                # 0 = any free port (fine for Entra and most IdPs); set if the IdP pins the port
    "http_timeout": 30,
    "hook_http_timeout": 5,            # per request inside a hook: Claude Code gives up on a hook after HOOK_TIMEOUT s and
                                       # then sends the prompt anyway, so discovery + refresh + broker + hook_wait must fit
}

GATEWAY_FAILURE = re.compile(r"Portkey Error:|API Error: 498|AI gateway token")


class AuthError(Exception):
    """A failure the user can act on; the message says how."""


# --------------------------------------------------------------------------------------------- paths and config

def is_windows():
    return sys.platform == "win32"      # read at call time so tests can mock it


def config_dir():
    if os.environ.get("AIGW_CLAUDE_AUTH_DIR"):
        return Path(os.environ["AIGW_CLAUDE_AUTH_DIR"])
    if is_windows():
        return Path(os.environ.get("APPDATA") or Path.home() / "AppData" / "Roaming") / "aigw-claude-auth"
    return Path.home() / ".config" / "aigw-claude-auth"


def log_dir():
    """Where the Task Scheduler daemon (which has no console) writes its log. Only used on Windows."""
    return Path(os.environ.get("LOCALAPPDATA") or Path.home() / "AppData" / "Local") / "aigw-claude-auth" / "logs"


def default_settings_path():
    if os.environ.get("AIGW_CLAUDE_SETTINGS"):
        return Path(os.environ["AIGW_CLAUDE_SETTINGS"])
    base = os.environ.get("CLAUDE_CONFIG_DIR") or Path.home() / ".claude"
    return Path(base) / "settings.json"


def load_config(path):
    cfg = dict(DEFAULTS)
    if path.exists():
        user = json.loads(path.read_text())
        unknown = set(user) - set(DEFAULTS)
        if unknown:
            raise AuthError(f"unknown keys in {path}: {', '.join(sorted(unknown))}")
        cfg.update(user)
    if not cfg["token_command"] and not cfg["client_id"]:
        raise AuthError(f"no token source configured: set client_id (and issuer) or token_command in {path}")
    if cfg["idp_token"] not in ("access_token", "id_token"):
        raise AuthError("idp_token must be access_token or id_token")
    if cfg["hook_login"] not in ("device", "off"):
        raise AuthError("hook_login must be device or off")
    if not cfg["sentinel"]:
        raise AuthError("sentinel must not be empty (an empty header can't be told apart from a missing one)")
    return cfg


# --------------------------------------------------------------------------------------------- small helpers

def jwt_claims(token):
    """Decoded payload of a JWT without verifying it, or {} if it isn't one. Only used to read `exp`."""
    try:
        seg = token.split(".")[1]
        return json.loads(base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4)))
    except (IndexError, ValueError, AttributeError):
        return {}


def seconds_left(token):
    exp = jwt_claims(token).get("exp")
    return int(exp - time.time()) if isinstance(exp, (int, float)) else -1


def fingerprint(token):
    """Safe to print: length, a short hash and the expiry."""
    if not token:
        return "none"
    left = seconds_left(token)
    when = f"expires in {left}s" if left >= 0 else "expired or not a JWT"
    return f"len {len(token)} sha256 {hashlib.sha256(token.encode()).hexdigest()[:10]} {when}"


def log(msg, quiet=False):
    if not quiet:
        print(f"aigw-claude-auth: {msg}", file=sys.stderr, flush=True)


def write_private(path, text):
    """Atomic write (temp file, fsync, rename) with mode 600. Keeps an existing file's mode if it is stricter."""
    # On Windows mode 700/600 do nothing; the profile directories (%APPDATA%) are user-only by default. No icacls for now.
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    mode = 0o600
    if path.exists():
        mode = path.stat().st_mode & 0o777 & 0o600 or 0o600
    fd, tmp = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as f:
            f.write(text)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, mode)
        replace_file(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise


def replace_file(src, dst, tries=40, pause=0.05):
    """os.replace; on Windows retry for about 2 s while another process holds the target open (PermissionError)."""
    for i in range(tries):
        try:
            return os.replace(src, dst)
        except PermissionError:
            if not is_windows() or i == tries - 1:
                raise
            time.sleep(pause)


def _kernel32():
    import ctypes
    k = ctypes.WinDLL("kernel32", use_last_error=True)
    k.OpenProcess.restype = ctypes.c_void_p
    k.OpenProcess.argtypes = [ctypes.c_uint32, ctypes.c_int, ctypes.c_uint32]
    k.GetExitCodeProcess.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint32)]
    k.CloseHandle.argtypes = [ctypes.c_void_p]
    return k


def _pid_alive_windows(pid):
    """os.kill(pid, 0) would terminate the process on Windows; ask for its exit code instead (STILL_ACTIVE = 259)."""
    import ctypes
    k = _kernel32()
    h = k.OpenProcess(0x1000, 0, pid)                       # PROCESS_QUERY_LIMITED_INFORMATION
    if not h:
        return ctypes.get_last_error() == 5                 # ERROR_ACCESS_DENIED: it exists, but is not ours
    try:
        code = ctypes.c_uint32()
        return bool(k.GetExitCodeProcess(h, ctypes.byref(code))) and code.value == 259
    finally:
        k.CloseHandle(h)


def pid_alive(pid):
    if not isinstance(pid, int) or pid <= 0:
        return False
    if is_windows():
        return _pid_alive_windows(pid)
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def http_json(url, data=None, headers=None, timeout=30):
    """POST form data (or GET when data is None); returns (status, parsed JSON or {})."""
    body = urllib.parse.urlencode(data).encode() if isinstance(data, dict) else data
    req = urllib.request.Request(url, data=body, headers=headers or {}, method="POST" if body is not None else "GET")
    if isinstance(data, dict):
        req.add_header("Content-Type", "application/x-www-form-urlencoded")
    req.add_header("Accept", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            status, raw = r.status, r.read()
    except urllib.error.HTTPError as e:
        status, raw = e.code, e.read()
    except (urllib.error.URLError, OSError) as e:
        raise AuthError(f"cannot reach {urllib.parse.urlsplit(url).netloc}: {getattr(e, 'reason', e)}")
    try:
        return status, json.loads(raw or b"{}")
    except ValueError:
        return status, {}


# --------------------------------------------------------------------------------------------- Claude settings

class Settings:
    """The one value we own in Claude Code's settings: our header's line in env.ANTHROPIC_CUSTOM_HEADERS.

    ANTHROPIC_CUSTOM_HEADERS holds `Name: value` lines separated by newlines; other lines and every other key in the
    file are left as they are.
    """

    def __init__(self, path, header):
        self.path = Path(path)
        self.header = header

    def load(self):
        if not self.path.exists():
            return {}
        text = self.path.read_text(encoding="utf-8-sig")
        return json.loads(text) if text.strip() else {}

    def _lines(self, data):
        raw = (data.get("env") or {}).get("ANTHROPIC_CUSTOM_HEADERS", "")
        return [l for l in raw.split("\n") if l.strip()]

    def get(self):
        for line in self._lines(self.load()):
            name, _, value = line.partition(":")
            if name.strip().lower() == self.header.lower():
                return value.strip()
        return ""

    def put(self, value):
        data = self.load()
        lines = [l for l in self._lines(data) if l.partition(":")[0].strip().lower() != self.header.lower()]
        lines.append(f"{self.header}: {value}")
        data.setdefault("env", {})["ANTHROPIC_CUSTOM_HEADERS"] = "\n".join(lines)
        write_private(self.path, json.dumps(data, indent=2) + "\n")

    def merge(self, base_url=None, hook_command=None):
        """Add ANTHROPIC_BASE_URL and our two hooks; replaces earlier entries of ours, keeps everything else."""
        data = self.load()
        if base_url:
            data.setdefault("env", {})["ANTHROPIC_BASE_URL"] = base_url
        if hook_command:
            hooks = data.setdefault("hooks", {})
            for event, sub in (("UserPromptSubmit", "precheck"), ("StopFailure", "stop-failure")):
                entries = [e for e in hooks.get(event, []) if not MARKER.search(json.dumps(e))]
                entries.append(hook_entry(hook_command, sub))
                hooks[event] = entries
        write_private(self.path, json.dumps(data, indent=2) + "\n")
        return data


# --------------------------------------------------------------------------------------------- state

class State:
    """state.json (mode 600) in the config dir: the IdP refresh token and discovered endpoints. Never the JWT.

    hook-login.json (mode 600) is there while a sign-in started by the precheck hook is pending: the user code, the
    verification URL, the expiry and the waiting process's pid. Never the device code.
    """

    def __init__(self, directory):
        self.dir = Path(directory)
        self.file = self.dir / "state.json"
        self.pending_file = self.dir / "hook-login.json"

    def pending(self):
        """The pending hook sign-in, or {} if there is none or it is over (expired, or its process is gone)."""
        try:
            p = json.loads(self.pending_file.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {}
        return p if p.get("expires_at", 0) > time.time() + 10 and pid_alive(p.get("pid")) else {}

    def load(self):
        return json.loads(self.file.read_text(encoding="utf-8")) if self.file.exists() else {}

    def save(self, data):
        write_private(self.file, json.dumps(data, indent=2) + "\n")

    @contextmanager
    def lock(self):
        """One writer at a time across the daemon, hooks and manual runs."""
        self.dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        if is_windows():
            with open(self.dir / "lock", "ab") as f:
                while True:                                 # LK_LOCK gives up after ~10 s; keep waiting like flock does
                    f.seek(0)
                    try:
                        msvcrt.locking(f.fileno(), msvcrt.LK_LOCK, 1)
                        break
                    except OSError:
                        continue
                try:
                    yield
                finally:
                    f.seek(0)
                    msvcrt.locking(f.fileno(), msvcrt.LK_UNLCK, 1)
            return
        with open(self.dir / "lock", "w") as f:
            fcntl.flock(f, fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(f, fcntl.LOCK_UN)


# --------------------------------------------------------------------------------------------- IdP and broker

class TokenSource:
    def __init__(self, cfg, state):
        self.cfg = cfg
        self.state = state
        self.got_refresh_token = False

    # -- endpoints
    def endpoints(self):
        cfg, st = self.cfg, self.state.load()
        found = dict(st.get("endpoints") or {})
        if cfg["issuer"] and not (found and found.get("issuer") == cfg["issuer"]):
            url = cfg["issuer"].rstrip("/") + "/.well-known/openid-configuration"
            status, doc = http_json(url, timeout=cfg["http_timeout"])
            if status != 200 or "token_endpoint" not in doc:
                raise AuthError(f"OIDC discovery failed at {url} (HTTP {status})")
            found = {k: doc.get(k, "") for k in ("token_endpoint", "device_authorization_endpoint", "authorization_endpoint")}
            found["issuer"] = cfg["issuer"]
            st["endpoints"] = found
            self.state.save(st)
        for k in ("token_endpoint", "device_authorization_endpoint", "authorization_endpoint"):
            if cfg[k]:
                found[k] = cfg[k]
        if not found.get("token_endpoint"):
            raise AuthError("no token endpoint: set issuer or token_endpoint in the config")
        return found

    # -- the token request every grant ends with
    def _token_request(self, form):
        form = dict(form, client_id=self.cfg["client_id"])
        status, body = http_json(self.endpoints()["token_endpoint"], form, timeout=self.cfg["http_timeout"])
        return status, body

    def _keep(self, body):
        """Store a (rotated) refresh token and return the IdP token we use."""
        st = self.state.load()
        self.got_refresh_token = bool(body.get("refresh_token"))
        if self.got_refresh_token:
            st["refresh_token"] = body["refresh_token"]
        st["signed_in_at"] = st.get("signed_in_at") or int(time.time())
        self.state.save(st)
        tok = body.get(self.cfg["idp_token"])
        if not tok:
            raise AuthError(f"the IdP response has no {self.cfg['idp_token']} (check scope and idp_token)")
        return tok

    def refresh(self):
        st = self.state.load()
        rt = st.get("refresh_token")
        if not rt:
            raise AuthError("not signed in to the gateway: run `aigw-claude-auth login`")
        status, body = self._token_request({"grant_type": "refresh_token", "refresh_token": rt, "scope": self.cfg["scope"]})
        if status == 200:
            return self._keep(body)
        if body.get("error") in ("invalid_grant", "interaction_required", "login_required"):
            st.pop("refresh_token", None)
            self.state.save(st)
            raise AuthError("gateway sign-in expired: run `aigw-claude-auth login`")
        raise AuthError(f"IdP refresh failed: HTTP {status} {body.get('error', '')} {body.get('error_description', '')[:120]}".strip())

    def exchange(self, idp_token):
        url = self.cfg["broker_url"]
        status, body = http_json(url, b"", headers={"Authorization": f"Bearer {idp_token}"}, timeout=self.cfg["http_timeout"])
        tok = body.get("token") or body.get("access_token")
        if status != 200 or not tok:
            detail = body.get("error") or body.get("message") or ""
            raise AuthError(f"token broker refused the exchange: HTTP {status} {detail}".strip())
        return tok

    def from_command(self):
        try:
            p = subprocess.run(self.cfg["token_command"], shell=True, capture_output=True, text=True, timeout=120)
        except subprocess.TimeoutExpired:
            raise AuthError("token_command timed out")
        tok = p.stdout.strip()
        if p.returncode != 0 or not tok:
            raise AuthError(f"token_command failed (exit {p.returncode}): {p.stderr.strip()[:200]}")
        return tok

    def gateway_jwt(self, idp=None):
        """A fresh gateway JWT from whichever source is configured. idp: an IdP token just obtained by a sign-in."""
        if self.cfg["token_command"]:
            return self.from_command()
        idp = idp or self.refresh()
        return self.exchange(idp) if self.cfg["broker_url"] else idp

    # -- interactive sign-in
    def device_start(self):
        """Ask the IdP for a device code. Adds `deadline` (epoch seconds) to the IdP's answer."""
        ep = self.endpoints().get("device_authorization_endpoint")
        if not ep:
            raise AuthError("the IdP has no device authorization endpoint; use --pkce")
        status, d = http_json(ep, {"client_id": self.cfg["client_id"], "scope": self.cfg["scope"]}, timeout=self.cfg["http_timeout"])
        if status != 200 or "device_code" not in d:
            raise AuthError(f"device authorization failed: HTTP {status} {d.get('error', '')} {d.get('error_description', '')[:160]}".strip())
        d["deadline"] = int(time.time()) + int(d.get("expires_in", 900))
        return d

    @staticmethod
    def device_prompt(d):
        """'open <url> and enter the code <code>' (or just the URL when the IdP gives one with the code in it)."""
        if d.get("verification_uri_complete"):
            return f"open {d['verification_uri_complete']}"
        return f"open {d.get('verification_uri') or d.get('verification_url')} and enter the code {d['user_code']}"

    def login_device(self, out=None):
        d = self.device_start()
        print(f"To sign in to the gateway, {self.device_prompt(d)}", file=out or sys.stderr, flush=True)
        return self.device_poll(d)

    def device_poll(self, d):
        """Wait for the user to finish the device sign-in; returns the IdP token."""
        interval, deadline = int(d.get("interval", 5)), d["deadline"]
        while time.time() < deadline:
            time.sleep(interval)
            status, body = self._token_request({"grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                                                "device_code": d["device_code"]})
            if status == 200:
                return self._keep(body)
            err = body.get("error")
            if err == "authorization_pending":
                continue
            if err == "slow_down":
                interval += 5
                continue
            raise AuthError(f"device sign-in failed: {err or status} {body.get('error_description', '')[:160]}".strip())
        raise AuthError("device sign-in timed out")

    def login_pkce(self, open_browser=True, out=None):
        out = out or sys.stderr
        ep = self.endpoints().get("authorization_endpoint")
        if not ep:
            raise AuthError("the IdP has no authorization endpoint; use --device")
        verifier = secrets.token_urlsafe(64)
        challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
        state = secrets.token_urlsafe(24)
        got = {}

        class Callback(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                q = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
                if "code" not in q and "error" not in q:          # favicon and the like
                    self.send_response(404)
                    self.end_headers()
                    return
                got.update({k: v[0] for k, v in q.items()})
                ok = "code" in q and q.get("state", [""])[0] == state
                page = b"Signed in to the gateway. You can close this tab." if ok else b"Gateway sign-in failed. Check the terminal."
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.send_header("Content-Length", str(len(page)))
                self.end_headers()
                self.wfile.write(page)

        srv = http.server.HTTPServer(("127.0.0.1", int(self.cfg["redirect_port"])), Callback)
        redirect = self.cfg["redirect_uri"].format(port=srv.server_address[1])
        url = ep + ("&" if "?" in ep else "?") + urllib.parse.urlencode({
            "response_type": "code", "client_id": self.cfg["client_id"], "redirect_uri": redirect,
            "scope": self.cfg["scope"], "state": state, "code_challenge": challenge, "code_challenge_method": "S256"})
        print(f"To sign in to the gateway, open {url}", file=out, flush=True)
        if open_browser:
            webbrowser.open(url)
        srv.timeout = 1
        deadline = time.time() + 300
        while not got and time.time() < deadline:
            srv.handle_request()
        srv.server_close()
        if not got:
            raise AuthError("browser sign-in timed out")
        if got.get("state") != state:
            raise AuthError("browser sign-in returned the wrong state; try again")
        if "code" not in got:
            raise AuthError(f"browser sign-in failed: {got.get('error')} {got.get('error_description', '')[:160]}")
        status, body = self._token_request({"grant_type": "authorization_code", "code": got["code"],
                                            "redirect_uri": redirect, "code_verifier": verifier})
        if status != 200:
            raise AuthError(f"code exchange failed: HTTP {status} {body.get('error', '')} {body.get('error_description', '')[:160]}".strip())
        return self._keep(body)


# --------------------------------------------------------------------------------------------- sync

class Result:
    def __init__(self, ok, changed, message, token=""):
        self.ok, self.changed, self.message, self.token = ok, changed, message, token


def sync(cfg, state, settings, force=False, idp=None):
    """Make sure the settings hold a JWT valid for more than refresh_before seconds.

    Returns ok=False when no fresh JWT could be had. The current value is replaced by the sentinel only if it is
    no longer usable (less than 30 s left), so a short IdP outage doesn't throw away a JWT that still works.
    idp: an IdP token from a sign-in that just happened, used instead of a refresh.
    """
    with state.lock():
        current = settings.get()
        if not force and seconds_left(current) > cfg["refresh_before"]:
            return Result(True, False, f"current JWT still valid ({fingerprint(current)})", current)
        try:
            new = TokenSource(cfg, state).gateway_jwt(idp)
        except AuthError as e:
            if seconds_left(current) < 30 and current != cfg["sentinel"]:
                settings.put(cfg["sentinel"])
                return Result(False, True, f"{e} (wrote the sentinel)", cfg["sentinel"])
            return Result(False, False, str(e), current)
        left = seconds_left(new)
        if left < 60:
            msg = "the new JWT has no exp claim" if left < 0 else f"the new JWT expires in {left}s"
            if seconds_left(current) < 30 and current != cfg["sentinel"]:
                settings.put(cfg["sentinel"])
            return Result(False, False, f"refusing to use it: {msg}", current)
        settings.put(new)
        return Result(True, True, f"wrote a new JWT ({fingerprint(new)})", new)


# --------------------------------------------------------------------------------------------- commands

def cmd_login(a, cfg, state, settings):
    if cfg["token_command"]:
        raise AuthError("token_command is configured; there is nothing to sign in to")
    src = TokenSource(cfg, state)
    method = "device" if a.device else "pkce" if a.pkce else ("pkce" if browser_available() else "device")
    # No lock while the user signs in (that can take minutes and would stall the hooks); the old refresh token stays
    # usable until the new sign-in succeeds.
    idp = src.login_device() if method == "device" else src.login_pkce(open_browser=not a.no_browser)
    r = finish_login(cfg, state, settings, src, idp)
    log(r.message)
    return 0 if r.ok else 1


def finish_login(cfg, state, settings, src, idp):
    """After a sign-in: drop a stale refresh token if the IdP sent none, then write a JWT from the new IdP token."""
    if not src.got_refresh_token:
        with state.lock():
            state.save({k: v for k, v in state.load().items() if k != "refresh_token"})
        log("warning: the IdP returned no refresh token (is offline_access in scope?); you will have to sign in again when the JWT expires")
    return sync(cfg, state, settings, force=True, idp=idp)


def browser_available():
    if os.environ.get("SSH_CONNECTION") or os.environ.get("SSH_TTY"):
        return False
    return sys.platform == "darwin" or bool(os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY"))


def cmd_logout(a, cfg, state, settings):
    with state.lock():
        state.save({k: v for k, v in state.load().items() if k != "refresh_token"})
        settings.put(cfg["sentinel"])
    log("signed out; the settings now hold the sentinel")
    return 0


def cmd_sync(a, cfg, state, settings):
    r = sync(cfg, state, settings, force=a.force)
    log(r.message, quiet=a.quiet and r.ok)
    return 0 if r.ok else 1


def cmd_token(a, cfg, state, settings):
    r = sync(cfg, state, settings, force=a.force)
    if not r.ok:
        log(r.message)
        return 1
    print(r.token)
    return 0


def cmd_status(a, cfg, state, settings):
    st = state.load()
    source = "token_command" if cfg["token_command"] else ("IdP + broker" if cfg["broker_url"] else "IdP token as the JWT")
    rows = [("version", VERSION), ("settings", str(settings.path)), ("header", cfg["header"]), ("source", source),
            ("signed in", "yes" if st.get("refresh_token") else ("n/a" if cfg["token_command"] else "no")),
            ("jwt", fingerprint(settings.get()) if settings.get() != cfg["sentinel"] else "sentinel (no usable JWT)")]
    claims = jwt_claims(settings.get())
    for k in ("iss", "sub", "portkey_workspace"):
        if k in claims:
            rows.append((f"jwt {k}", str(claims[k])))
    p = state.pending()
    if p:
        rows.append(("pending", f"hook sign-in: open {p['uri']} and enter {p['user_code']} (until {time.strftime('%H:%M', time.localtime(p['expires_at']))})"))
    for k, v in rows:
        print(f"{k:12} {v}")
    return 0


def cmd_daemon(a, cfg, state, settings):
    stop = threading.Event()
    if is_windows() and sys.stderr is None:                 # started by Task Scheduler through pythonw: no console
        log_dir().mkdir(parents=True, exist_ok=True)
        sys.stderr = open(log_dir() / "daemon.log", "a", encoding="utf-8", buffering=1)
    for name in ("SIGTERM", "SIGINT", "SIGBREAK"):          # SIGBREAK exists on Windows only
        if hasattr(signal, name):
            signal.signal(getattr(signal, name), lambda *_: stop.set())
    backoff = 30
    log(f"daemon started (settings {settings.path})")
    while not stop.is_set():
        r = sync(cfg, state, settings)
        if r.changed or not r.ok:
            log(r.message)
        if r.ok:
            backoff = 30
            wait = seconds_left(r.token) - cfg["refresh_before"]
        else:
            wait, backoff = backoff, min(backoff * 2, 300)
        # Short naps, so a laptop that slept through the expiry catches up within max_sleep of waking.
        stop.wait(max(5, min(wait, a.max_sleep)))
    log("daemon stopped")
    return 0


def default_hook_command():
    """macOS/Linux: a shell command string. Windows: an argv list for exec form (no shell, so no quoting; finding 17)."""
    script = str(Path(__file__).resolve())
    if is_windows():
        return [str(Path(sys.executable).resolve()), script]
    return f"{shlex.quote(sys.executable)} {shlex.quote(script)}"


def hook_entry(hook_command, sub):
    if isinstance(hook_command, (list, tuple)):
        h = {"type": "command", "command": hook_command[0], "args": [*hook_command[1:], "hook", sub], "timeout": HOOK_TIMEOUT}
    else:
        h = {"type": "command", "command": f"{hook_command} hook {sub}", "timeout": HOOK_TIMEOUT}
    return {"hooks": [h]}


def cmd_hook(a, cfg, state, settings):
    # Up to three requests (discovery, refresh, broker) plus hook_wait must finish inside HOOK_TIMEOUT, or Claude Code
    # drops our block decision and sends the prompt with whatever is in the settings.
    cfg = dict(cfg, http_timeout=min(cfg["http_timeout"], cfg["hook_http_timeout"]))
    try:
        payload = json.loads(sys.stdin.read() or "{}")
    except ValueError:
        payload = {}
    if a.event == "precheck":
        return hook_precheck(cfg, state, settings)
    return hook_stop_failure(cfg, state, settings, payload)


def hook_precheck(cfg, state, settings):
    """UserPromptSubmit. Silent and instant while the JWT is good; otherwise refresh and give Claude Code time to reload."""
    try:
        r = sync(cfg, state, settings)
    except Exception as e:                                  # a bug, or the settings file can't be written
        log(f"precheck error: {e}")
        try:
            dead = seconds_left(settings.get()) <= 0
        except Exception:
            dead = False                                    # can't tell: don't break the user's prompt
        if dead and cfg["block_on_failure"]:                # the request would only get a 401
            print(json.dumps({"decision": "block", "reason": f"AI gateway: cannot renew the JWT: {e}"}))
        return 0
    if r.ok:
        if r.changed:
            time.sleep(cfg["hook_wait"])
        return 0
    if seconds_left(settings.get()) > 0:                    # refresh failed, but what's there still works for now
        log(r.message)
        return 0
    if cfg["block_on_failure"]:
        reason = f"AI gateway: {r.message}"
        if cfg["hook_login"] == "device" and not cfg["token_command"] and not state.load().get("refresh_token"):
            try:
                reason = hook_login_reason(cfg, state, settings)
            except Exception as e:                          # fall back to the plain message
                log(f"could not start a sign-in from the hook: {e}")
        print(json.dumps({"decision": "block", "reason": reason}))
    else:
        log(r.message)
        if r.changed:          # we just wrote the sentinel: let the request carry it, so a load balancer rule answers 498
            time.sleep(cfg["hook_wait"])
    return 0


def hook_login_reason(cfg, state, settings):
    """Start a device sign-in in the background (or reuse the pending one) and return the block message for it.

    The waiting is done by a detached `hook-login-wait` process, so the hook returns at once. It gets the device code
    on stdin (never on the command line or on disk) and its output goes to hook-login.log, not to the hook's stdout,
    which Claude Code reads until it closes. Prompts sent before the sign-in is done get the same code again.
    """
    with state.lock():                                      # two sessions prompting at once start one sign-in
        p = state.pending()
        if not p:
            d = TokenSource(cfg, state).device_start()
            cmd = [sys.executable, str(Path(__file__).resolve()), "--config", cfg["_config_path"], "--state-dir", str(state.dir),
                   "--settings", str(settings.path), "hook-login-wait"]
            with open(state.dir / "hook-login.log", "a", encoding="utf-8") as logf:
                child = spawn_detached(cmd, logf)
            child.stdin.write(json.dumps(d).encode())
            child.stdin.close()
            p = {"prompt": TokenSource.device_prompt(d), "uri": d.get("verification_uri_complete") or d.get("verification_uri") or d.get("verification_url"),
                 "user_code": d.get("user_code", ""), "expires_at": d["deadline"], "pid": child.pid}
            write_private(state.pending_file, json.dumps(p) + "\n")
    minutes = max(1, int(p["expires_at"] - time.time()) // 60)
    return (f"AI gateway sign-in needed: {p['prompt']} (within {minutes} min), then send your prompt again. "
            f"Or run `aigw-claude-auth login` in a terminal.")


def spawn_detached(cmd, logf):
    """Start `cmd` detached from the hook: stdin a pipe, stdout and stderr to logf (never the hook's stdout)."""
    kw = dict(stdin=subprocess.PIPE, stdout=logf, stderr=subprocess.STDOUT)
    if not is_windows():
        return subprocess.Popen(cmd, start_new_session=True, **kw)
    # DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP. CREATE_NO_WINDOW would be ignored together with DETACHED_PROCESS.
    # CREATE_BREAKAWAY_FROM_JOB first, so a job that kills its children on close doesn't take the worker along;
    # a job that doesn't allow breakaway refuses it, and then we go without.
    flags = 0x00000008 | 0x00000200
    cmd = list(cmd)
    pyw = Path(cmd[0]).with_name("pythonw.exe")
    if pyw.exists():
        cmd[0] = str(pyw)
    try:
        return subprocess.Popen(cmd, creationflags=flags | 0x01000000, **kw)
    except OSError:
        return subprocess.Popen(cmd, creationflags=flags, **kw)


def cmd_hook_login_wait(a, cfg, state, settings):
    """The background half of the hook sign-in: wait for the user, write the JWT, notify, clean up."""
    d = json.loads(sys.stdin.read())
    log(f"waiting for the device sign-in (code {d.get('user_code', '?')})")
    try:
        src = TokenSource(cfg, state)
        r = finish_login(cfg, state, settings, src, src.device_poll(d))
        msg = "Signed in to the AI gateway; send your prompt again." if r.ok else f"AI gateway: {r.message}"
    except AuthError as e:
        msg = f"AI gateway sign-in: {e}"
    finally:
        with state.lock():                                  # remove the pending file only if it is still ours
            try:
                if json.loads(state.pending_file.read_text(encoding="utf-8")).get("pid") == os.getpid():
                    state.pending_file.unlink()
            except (OSError, ValueError):
                pass
    log(msg)
    notify(cfg, msg)
    return 0


def hook_stop_failure(cfg, state, settings, payload):
    """StopFailure. After a gateway auth failure, get a new JWT so the user's retry works, and tell them."""
    text = payload.get("last_assistant_message") or ""
    if not isinstance(text, str):
        text = json.dumps(text)
    if not GATEWAY_FAILURE.search(text):
        return 0
    try:
        r = sync(cfg, state, settings, force=True)
        msg = "AI gateway token renewed; retry your prompt." if r.ok else f"AI gateway: {r.message}"
    except Exception as e:
        msg = f"AI gateway: {e}"
    log(msg)
    notify(cfg, msg)
    return 0


TOAST_PS = r"""$ProgressPreference = 'SilentlyContinue'
$ErrorActionPreference = 'Stop'
[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null
[Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime] | Out-Null
$xml = New-Object Windows.Data.Xml.Dom.XmlDocument
$xml.LoadXml('<toast><visual><binding template="ToastGeneric"><text>Claude Code</text><text>@@TEXT@@</text></binding></visual></toast>')
$toast = New-Object Windows.UI.Notifications.ToastNotification $xml
[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier('{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\WindowsPowerShell\v1.0\powershell.exe').Show($toast)
"""


def toast_argv(msg):
    """Windows PowerShell 5.1 WinRT toast (S7: about 1 s). The text is XML- and PowerShell-quote-escaped; no tokens."""
    text = xml_escape(msg).replace("'", "''")
    enc = base64.b64encode(TOAST_PS.replace("@@TEXT@@", text).encode("utf-16-le")).decode()
    return ["powershell.exe", "-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden", "-EncodedCommand", enc]


def split_command(text, windows=False):
    """shlex.split; on Windows keep backslashes (non-POSIX mode) and drop the double quotes around a word."""
    if not windows:
        return shlex.split(text)
    return [w[1:-1] if len(w) > 1 and w[0] == w[-1] == '"' else w for w in shlex.split(text, posix=False)]


def notify(cfg, msg):
    how = cfg["notify"]
    if how == "off":
        return
    try:
        if how != "auto":
            subprocess.run(split_command(how, windows=is_windows()) + [msg], timeout=10, capture_output=True)
        elif is_windows():
            subprocess.run(toast_argv(msg), timeout=10, capture_output=True, stdin=subprocess.DEVNULL, creationflags=0x08000000)
        elif sys.platform == "darwin":
            subprocess.run(["osascript", "-e", f"display notification {json.dumps(msg)} with title \"Claude Code\""], timeout=10, capture_output=True)
        elif shutil.which("notify-send"):
            subprocess.run(["notify-send", "Claude Code", msg], timeout=10, capture_output=True)
    except (OSError, subprocess.TimeoutExpired):
        pass


def cmd_install(a, cfg, state, settings):
    hook = a.hook_command or default_hook_command()
    if not MARKER.search(hook if isinstance(hook, str) else json.dumps(hook)):
        raise AuthError("--hook-command must contain 'aigw-claude-auth' or 'aigw_claude_auth' so later installs can find and replace it")
    if a.print:
        snippet = {"hooks": {"UserPromptSubmit": [hook_entry(hook, "precheck")], "StopFailure": [hook_entry(hook, "stop-failure")]}}
        if a.base_url:
            snippet["env"] = {"ANTHROPIC_BASE_URL": a.base_url}
        print(json.dumps(snippet, indent=2))
        return 0
    settings.merge(base_url=a.base_url, hook_command=None if a.no_hooks else hook)
    log(f"updated {settings.path}")
    r = sync(cfg, state, settings)
    log(r.message)
    return 0 if r.ok else 1


TASK_NAME = "aigw-claude-auth"


def task_xml(user, python, script):
    """Task Scheduler definition: at log on of `user`, one instance, restart on failure, no time limit."""
    pyw = Path(python).with_name("pythonw.exe")
    exe = str(pyw if pyw.exists() else python)
    return f"""<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><Description>Keeps the gateway JWT in Claude Code's settings fresh (aigw-claude-auth daemon)</Description></RegistrationInfo>
  <Triggers><LogonTrigger><Enabled>true</Enabled><UserId>{xml_escape(user)}</UserId></LogonTrigger></Triggers>
  <Principals><Principal id="Author"><UserId>{xml_escape(user)}</UserId><LogonType>InteractiveToken</LogonType><RunLevel>LeastPrivilege</RunLevel></Principal></Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <StartWhenAvailable>true</StartWhenAvailable>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <RestartOnFailure><Interval>PT1M</Interval><Count>999</Count></RestartOnFailure>
  </Settings>
  <Actions Context="Author"><Exec><Command>{xml_escape(exe)}</Command><Arguments>{xml_escape(subprocess.list2cmdline([script, "daemon"]))}</Arguments></Exec></Actions>
</Task>
"""


def current_user():
    """DOMAIN\\user as Windows knows it (`whoami` is right where %USERDOMAIN% says WORKGROUP over ssh)."""
    if is_windows():
        try:
            who = subprocess.run(["whoami.exe"], capture_output=True, text=True, timeout=10).stdout.strip()
            if who:
                return who
        except (OSError, subprocess.TimeoutExpired):
            pass
    return (os.environ.get("USERDOMAIN", "") + "\\" + os.environ.get("USERNAME", "")).lstrip("\\")


def cmd_task(a, cfg, state, settings):
    """Windows background start: a Task Scheduler task that runs the daemon at log on (the launchd/systemd counterpart)."""
    user = current_user()
    xml = task_xml(user, str(Path(sys.executable).resolve()), str(Path(__file__).resolve()))
    if a.action == "print":
        print(xml)
        return 0
    if not is_windows():
        raise AuthError("the task command is for Windows; use the launchd agent or systemd unit elsewhere")
    if a.action == "remove":
        r = subprocess.run(["schtasks.exe", "/Delete", "/TN", a.name, "/F"], capture_output=True, text=True)
        log((r.stdout or r.stderr).strip())
        return r.returncode
    path = Path(tempfile.mkdtemp(prefix="aigw-task-")) / "task.xml"
    try:
        path.write_text(xml, encoding="utf-16")
        r = subprocess.run(["schtasks.exe", "/Create", "/TN", a.name, "/XML", str(path), "/F"], capture_output=True, text=True)
    finally:
        shutil.rmtree(path.parent, ignore_errors=True)
    log((r.stdout or r.stderr).strip())
    return r.returncode


def main(argv=None):
    ap = argparse.ArgumentParser(prog="aigw-claude-auth", description=__doc__.split("\n\n")[0])
    ap.add_argument("--config", type=Path, help="config file (default: <config dir>/config.json)")
    ap.add_argument("--state-dir", type=Path, help="where the refresh token lives (default: ~/.config/aigw-claude-auth, on Windows %%APPDATA%%\\aigw-claude-auth, or $AIGW_CLAUDE_AUTH_DIR)")
    ap.add_argument("--settings", type=Path, help="Claude Code settings file (default: $CLAUDE_CONFIG_DIR/settings.json or ~/.claude/settings.json)")
    ap.add_argument("--version", action="version", version=VERSION)
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("login", help="sign in to the IdP")
    g = p.add_mutually_exclusive_group()
    g.add_argument("--device", action="store_true", help="device code flow (any terminal, including ssh)")
    g.add_argument("--pkce", action="store_true", help="browser on this machine, loopback redirect")
    p.add_argument("--no-browser", action="store_true", help="with --pkce: print the URL instead of opening it")
    sub.add_parser("logout", help="forget the refresh token, write the sentinel")
    p = sub.add_parser("sync", help="renew the JWT in the settings if needed")
    p.add_argument("--force", action="store_true", help="renew even if the current JWT is still valid")
    p.add_argument("--quiet", action="store_true", help="say nothing on success")
    p = sub.add_parser("token", help="print a valid JWT")
    p.add_argument("--force", action="store_true")
    sub.add_parser("status", help="where the JWT comes from and when it expires")
    p = sub.add_parser("daemon", help="renew ahead of every expiry until stopped")
    p.add_argument("--max-sleep", type=int, default=60, help="longest nap in seconds (bounds the catch-up after sleep)")
    p = sub.add_parser("hook", help="for Claude Code hooks; reads the hook JSON on stdin")
    p.add_argument("event", choices=["precheck", "stop-failure"])
    sub.add_parser("hook-login-wait", help="internal: the precheck hook's background sign-in (device code JSON on stdin)")
    p = sub.add_parser("install", help="add ANTHROPIC_BASE_URL and the hooks to the settings file")
    p.add_argument("--base-url", help="the gateway URL for ANTHROPIC_BASE_URL")
    p.add_argument("--no-hooks", action="store_true", help="only the base URL (for example when IT ships the hooks)")
    p.add_argument("--hook-command", help="how hooks call this tool (default: this interpreter and file; must contain 'aigw-claude-auth')")
    p.add_argument("--print", action="store_true", help="print the snippet for managed settings instead of writing")
    p = sub.add_parser("task", help="Windows: install or remove the Task Scheduler task that runs the daemon at log on")
    p.add_argument("action", choices=["install", "remove", "print"], help="print shows the task definition (XML) and registers nothing")
    p.add_argument("--name", default=TASK_NAME, help="task name (default: %(default)s)")
    a = ap.parse_args(argv)

    cdir = a.state_dir or config_dir()
    try:
        if a.cmd == "task":                                     # needs no config
            return cmd_task(a, None, None, None)
        cfg = load_config(a.config or cdir / "config.json")
        cfg["_config_path"] = str((a.config or cdir / "config.json").resolve())   # for the hook's background sign-in
        state = State(cdir)
        settings = Settings(a.settings or default_settings_path(), cfg["header"])
        handler = {"login": cmd_login, "logout": cmd_logout, "sync": cmd_sync, "token": cmd_token, "status": cmd_status,
                   "daemon": cmd_daemon, "hook": cmd_hook, "hook-login-wait": cmd_hook_login_wait, "install": cmd_install, "task": cmd_task}[a.cmd]
        return handler(a, cfg, state, settings)
    except AuthError as e:
        if a.cmd == "hook":                                  # hooks must never fail Claude Code's turn
            log(str(e))
            return 0
        log(f"error: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
