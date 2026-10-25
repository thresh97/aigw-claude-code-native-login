#!/usr/bin/env python3
"""A stand-in for the AI gateway (and the optional load balancer guard in front of it), for the offline scenarios.

It answers the Anthropic Messages API the way the real gateway does in this layout:

  1. LB guard (only when the control file says "guard": true), the same rules as the ALB listener rules in the README:
       x-portkey-api-key == <sentinel>                      -> 498, gateway_token_error "expired"
       no x-portkey-api-key and an OAuth anthropic-beta     -> 498, gateway_token_error "missing"
  2. Gateway JWT check (Portkey's): x-portkey-api-key must be a JWT whose payload has exp in the future and
     kind == "gateway", and its fingerprint is not listed in "revoked". The signature isn't checked; the fake broker doesn't sign.
     Failure -> 401 with Portkey's body: {"status":"failure","message":"Portkey Error: ... Error Code: 03"}
  3. Anthropic (relayed by the gateway): Authorization must be "Bearer <oauth>" when "oauth" is set in the control
     file. Failure -> 401 with the relayed Anthropic body, request-id and x-should-retry: false.
  4. Otherwise a normal reply ("MOCK-OK"), streamed when asked.

"chunked_sse": N in the control file makes a streamed reply go out as chunked SSE, one event at a time, N seconds apart
(to see whether a proxy in between passes it on as it arrives).

"force": N in the control file skips all that and answers HTTP N with a gateway body (to see how Claude Code treats N).

With --upstream URL it is a logging relay in front of a real gateway instead (for the live scenarios: request counts
and statuses without a TLS proxy). Responses are buffered, which Claude Code doesn't mind.

The control file (JSON) is reread on every request, so a test can change behaviour mid-session. Every request is
appended to the log (JSONL) with credentials replaced by fingerprints.
"""
import argparse
import base64
import hashlib
import json
import sys
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

SECRET_HEADERS = {"authorization", "x-api-key", "x-portkey-api-key", "proxy-authorization", "cookie"}
RELAY_RESPONSE_HEADERS = ("content-type", "request-id", "x-should-retry", "retry-after")


def fingerprint(value):
    """Safe to log: length and a short hash, plus the scheme for Bearer values."""
    scheme = "Bearer " if value.startswith("Bearer ") else ""
    raw = value[len(scheme):]
    return f"{scheme}len{len(raw)}:{hashlib.sha256(raw.encode()).hexdigest()[:10]}"


def jwt_payload(token):
    try:
        seg = token.split(".")[1]
        return json.loads(base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4)))
    except (IndexError, ValueError):
        return None


def portkey_401(reason):
    return 401, {"status": "failure", "message": f"Portkey Error: {reason}. Error Code: 03"}, {}


def anthropic_401():
    body = {"error": {"message": "anthropic error: Invalid bearer token", "type": "authentication_error"}, "provider": "anthropic"}
    return 401, body, {"request-id": "req_mock" + str(int(time.time() * 1000)), "x-should-retry": "false"}


GUARD_MESSAGES = {   # the same bodies as the load balancer rules in the README
    "expired": "AI gateway token expired and could not be refreshed. Sign in to the gateway again, then retry.",
    "missing": "AI gateway token missing (no x-portkey-api-key). Sign in to the gateway, then retry.",
}


def guard_498(what):
    return 498, {"type": "error", "error": {"type": "gateway_token_error", "message": GUARD_MESSAGES[what]}}, {}


def decide(headers, ctl):
    """Status, JSON body and extra headers for one request, or None for a normal reply."""
    if ctl.get("force"):
        return int(ctl["force"]), {"type": "error", "error": {"type": "gateway_error", "message": f"mock gateway: forced {ctl['force']}"}}, {}
    key = headers.get("x-portkey-api-key")
    if ctl.get("guard"):
        if key is not None and key == ctl.get("sentinel", "expired"):
            return guard_498("expired")
        if not key and "oauth-2025-04-20" in (headers.get("anthropic-beta") or ""):
            return guard_498("missing")
    if not key:
        return portkey_401("missing x-portkey-api-key")
    claims = jwt_payload(key)
    if claims is None:
        return portkey_401("JWT verification failed: malformed token")
    if claims.get("kind") != "gateway" or fingerprint(key) in ctl.get("revoked", []):
        return portkey_401("JWT verification failed: signature verification failed")
    if claims.get("exp", 0) <= time.time():
        return portkey_401("JWT verification failed: token expired")
    want = ctl.get("oauth")
    if want and headers.get("authorization") != f"Bearer {want}":
        return anthropic_401()
    return None


def make_handler(log_path, control_path, upstream=None):
    lock = threading.Lock()

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *a):
            pass

        def control(self):
            try:
                with open(control_path) as f:
                    return json.load(f)
            except (OSError, ValueError):
                return {}

        def send(self, code, body, extra=None, ctype="application/json"):
            data = body if isinstance(body, bytes) else json.dumps(body).encode()
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            for k, v in (extra or {}).items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(data)
            return code

        def send_chunked(self, pieces, gap):
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()
            for i, piece in enumerate(pieces):
                if i:
                    time.sleep(float(gap))
                self.wfile.write(f"{len(piece):x}\r\n".encode() + piece + b"\r\n")
                self.wfile.flush()
            self.wfile.write(b"0\r\n\r\n")
            return 200

        def record(self, body, status, t0):
            hdrs = {k.lower(): (fingerprint(v) if k.lower() in SECRET_HEADERS else v) for k, v in self.headers.items()}
            entry = {"t": round(t0, 3), "ms": round((time.time() - t0) * 1000), "method": self.command, "path": self.path,
                     "status": status, "headers": hdrs}
            try:
                entry["stream"] = json.loads(body).get("stream") if body else None
            except ValueError:
                pass
            with lock, open(log_path, "a") as f:
                f.write(json.dumps(entry) + "\n")

        def relay(self, body):
            fwd = {k: v for k, v in self.headers.items() if k.lower() not in ("host", "content-length", "connection", "accept-encoding")}
            req = urllib.request.Request(upstream.rstrip("/") + self.path, data=body if self.command == "POST" else None,
                                         headers=fwd, method=self.command)
            try:
                resp = urllib.request.urlopen(req, timeout=300)
            except urllib.error.HTTPError as e:
                resp = e
            data = resp.read()
            extra = {k: v for k, v in resp.headers.items() if k.lower() in RELAY_RESPONSE_HEADERS and k.lower() != "content-type"}
            return self.send(resp.status if hasattr(resp, "status") else resp.code, data, extra,
                             ctype=resp.headers.get("Content-Type", "application/json"))

        def handle_any(self):
            t0 = time.time()
            n = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(n) if n else b""
            if upstream:
                status = self.relay(body)
            else:
                status = self.mock(body)
            self.record(body, status, t0)

        def mock(self, body):
            if not self.path.split("?")[0].endswith("/v1/messages"):
                return self.send(200, {})
            verdict = decide({k.lower(): v for k, v in self.headers.items()}, self.control())
            if verdict:
                code, payload, extra = verdict
                return self.send(code, payload, extra)
            try:
                req = json.loads(body or b"{}")
            except ValueError:
                req = {}
            model = req.get("model") or "claude-mock"
            cmd = self.control().get("bash_command")
            last = (req.get("messages") or [{}])[-1]
            if cmd and req.get("stream") and req.get("tools") and last.get("role") == "user" \
                    and "RUN-BASH" in json.dumps(last) and "tool_result" not in json.dumps(last):
                # a turn that asks for a Bash tool call (lets a scenario see the Bash tool's environment)
                events = [
                    ("message_start", {"type": "message_start", "message": {"id": "msg_mock", "type": "message", "role": "assistant", "model": model,
                                                                           "content": [], "stop_reason": None, "stop_sequence": None,
                                                                           "usage": {"input_tokens": 1, "output_tokens": 1}}}),
                    ("content_block_start", {"type": "content_block_start", "index": 0,
                                             "content_block": {"type": "tool_use", "id": "toolu_mock1", "name": "Bash", "input": {}}}),
                    ("content_block_delta", {"type": "content_block_delta", "index": 0,
                                             "delta": {"type": "input_json_delta", "partial_json": json.dumps({"command": cmd})}}),
                    ("content_block_stop", {"type": "content_block_stop", "index": 0}),
                    ("message_delta", {"type": "message_delta", "delta": {"stop_reason": "tool_use", "stop_sequence": None}, "usage": {"output_tokens": 2}}),
                    ("message_stop", {"type": "message_stop"}),
                ]
                return self.send(200, "".join(f"event: {e}\ndata: {json.dumps(d)}\n\n" for e, d in events).encode(), ctype="text/event-stream")
            if req.get("stream"):
                events = [
                    ("message_start", {"type": "message_start", "message": {"id": "msg_mock", "type": "message", "role": "assistant", "model": model,
                                                                           "content": [], "stop_reason": None, "stop_sequence": None,
                                                                           "usage": {"input_tokens": 1, "output_tokens": 1}}}),
                    ("content_block_start", {"type": "content_block_start", "index": 0, "content_block": {"type": "text", "text": ""}}),
                    ("content_block_delta", {"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": "MOCK-OK"}}),
                    ("content_block_stop", {"type": "content_block_stop", "index": 0}),
                    ("message_delta", {"type": "message_delta", "delta": {"stop_reason": "end_turn", "stop_sequence": None}, "usage": {"output_tokens": 2}}),
                    ("message_stop", {"type": "message_stop"}),
                ]
                gap = self.control().get("chunked_sse")
                if gap:
                    return self.send_chunked([f"event: {e}\ndata: {json.dumps(d)}\n\n".encode() for e, d in events], gap)
                sse = "".join(f"event: {e}\ndata: {json.dumps(d)}\n\n" for e, d in events).encode()
                return self.send(200, sse, ctype="text/event-stream")
            return self.send(200, {"id": "msg_mock", "type": "message", "role": "assistant", "model": model,
                                   "content": [{"type": "text", "text": "MOCK-OK"}], "stop_reason": "end_turn",
                                   "stop_sequence": None, "usage": {"input_tokens": 1, "output_tokens": 2}})

        do_GET = do_POST = do_HEAD = handle_any

    return Handler


def serve(log_path, control_path, upstream=None, port=0):
    """Start in a background thread; returns the server (server_address[1] is the port)."""
    srv = ThreadingHTTPServer(("127.0.0.1", port), make_handler(log_path, control_path, upstream))
    srv.handle_error = lambda *a: None      # Claude Code drops idle keep-alive connections; not worth a traceback
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--port", type=int, default=8787)
    ap.add_argument("--log", default="gateway.log.jsonl")
    ap.add_argument("--control", default="gateway.control.json")
    ap.add_argument("--upstream", help="relay to this gateway URL instead of mocking it")
    a = ap.parse_args()
    s = serve(a.log, a.control, a.upstream, a.port)
    print(f"mock gateway on http://127.0.0.1:{s.server_address[1]} (log {a.log}, control {a.control})", file=sys.stderr, flush=True)
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        pass
