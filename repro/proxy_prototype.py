#!/usr/bin/env python3
"""Prototype of the v2 "Mode 2" local injecting proxy (docs/design-v2.md), for spike S11. Not the final client code.

Claude Code points ANTHROPIC_BASE_URL at this proxy. For each request it:
  - removes any client-supplied gateway header, and adds its own from the token file (re-read on every request);
  - passes everything else (Authorization, anthropic-beta, ...) through untouched;
  - streams the response to Claude Code chunk by chunk (SSE, chunked encoding), without buffering;
  - turns a gateway refusal (401 whose body has "Portkey Error:") into 498, with the same body as the load balancer
    guard (GUARD_MESSAGES in mock_gateway.py). Anthropic's relayed 401 ("anthropic error:") passes through unchanged;
  - fails closed: no usable token (file missing, empty or the sentinel) -> 498 without contacting the upstream.

Listens on 127.0.0.1 only. Logs status, latency and a token fingerprint (length and short hash), never bodies or tokens.

    proxy_prototype.py --token-file PATH --upstream http://gateway:8787 [--port 0] [--header x-portkey-api-key]
"""
import argparse
import http.client
import json
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

from mock_gateway import GUARD_MESSAGES, fingerprint    # same 498 bodies as the load balancer rules

HOP_BY_HOP = {"connection", "keep-alive", "proxy-connection", "te", "trailer", "transfer-encoding", "upgrade", "host", "content-length"}
CHUNK = 64 * 1024


def make_handler(token_file, upstream, header, sentinel, log):
    up = urlsplit(upstream)
    connect = http.client.HTTPSConnection if up.scheme == "https" else http.client.HTTPConnection
    lock = threading.Lock()

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *a):
            pass

        def token(self):
            try:
                with open(token_file) as f:
                    value = f.read().strip()
            except OSError:
                return None, "missing"
            if not value:
                return None, "missing"
            if value == sentinel:
                return None, "expired"
            return value, None

        def reply(self, code, body, ctype="application/json", extra=None):
            data = body if isinstance(body, bytes) else json.dumps(body).encode()
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            for k, v in (extra or {}).items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(data)

        def refuse(self, what):    # the 498 the load balancer guard would send
            self.reply(498, {"type": "error", "error": {"type": "gateway_token_error", "message": GUARD_MESSAGES[what]}})
            return 498

        def forward(self):
            t0 = time.time()
            n = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(n) if n else None
            token, why = self.token()
            note = ""
            if token is None:
                status, note = self.refuse(why), f"no-token:{why}"
            else:
                try:
                    status, note = self.relay(body, token)
                except (OSError, http.client.HTTPException) as e:
                    status, note = 502, f"upstream-error:{type(e).__name__}"
                    self.reply(502, {"type": "error", "error": {"type": "proxy_error", "message": "could not reach the gateway"}})
            entry = {"t": round(t0, 3), "ms": round((time.time() - t0) * 1000), "method": self.command, "path": self.path.split("?")[0],
                     "status": status, "note": note, "token": fingerprint(token) if token else None}
            with lock:
                log.write(json.dumps(entry) + "\n")
                log.flush()

        def relay(self, body, token):
            fwd = {k: v for k, v in self.headers.items() if k.lower() not in HOP_BY_HOP and k.lower() != header}
            fwd[header] = token
            fwd["Host"] = up.netloc
            conn = connect(up.hostname, up.port, timeout=300)
            try:
                conn.request(self.command, self.path, body=body, headers=fwd)
                resp = conn.getresponse()
                ctype = resp.getheader("Content-Type", "application/json")
                if resp.status == 401:      # small and needed whole: is it the gateway's refusal or Anthropic's?
                    data = resp.read()
                    if b"Portkey Error:" in data:
                        return self.refuse("expired"), "gateway-401->498"
                    self.reply(401, data, ctype, {k: v for k, v in resp.getheaders() if k.lower() in ("request-id", "x-should-retry")})
                    return 401, "passthrough-401"
                self.stream(resp)
                return resp.status, ""
            finally:
                conn.close()

        def stream(self, resp):
            self.send_response(resp.status)
            length = resp.getheader("Content-Length")
            for k, v in resp.getheaders():
                if k.lower() not in HOP_BY_HOP:
                    self.send_header(k, v)
            chunked = length is None and self.command != "HEAD"
            if length is not None:
                self.send_header("Content-Length", length)
            elif chunked:
                self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()
            while True:
                data = resp.read1(CHUNK)      # whatever has arrived, not "wait for CHUNK bytes"
                if not data:
                    break
                self.wfile.write(f"{len(data):x}\r\n".encode() + data + b"\r\n" if chunked else data)
                self.wfile.flush()
            if chunked:
                self.wfile.write(b"0\r\n\r\n")
                self.wfile.flush()

        do_GET = do_POST = do_PUT = do_DELETE = do_HEAD = do_PATCH = forward

    return Handler


def serve(token_file, upstream, port=0, header="x-portkey-api-key", sentinel="expired", log=sys.stderr):
    """Start in a background thread; returns the server (server_address[1] is the port)."""
    srv = ThreadingHTTPServer(("127.0.0.1", port), make_handler(str(token_file), upstream, header.lower(), sentinel, log))
    srv.daemon_threads = True
    srv.handle_error = lambda *a: None      # Claude Code drops idle keep-alive connections
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--token-file", required=True, help="file holding the gateway JWT (re-read on every request)")
    ap.add_argument("--upstream", required=True, help="gateway base URL, e.g. http://127.0.0.1:8787")
    ap.add_argument("--port", type=int, default=0)
    ap.add_argument("--header", default="x-portkey-api-key")
    ap.add_argument("--sentinel", default="expired")
    ap.add_argument("--log", help="append JSONL here instead of stderr")
    a = ap.parse_args()
    s = serve(a.token_file, a.upstream, a.port, a.header, a.sentinel, open(a.log, "a") if a.log else sys.stderr)
    print(f"proxy on http://127.0.0.1:{s.server_address[1]} -> {a.upstream}", file=sys.stderr, flush=True)
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        pass
