#!/usr/bin/env python3
"""Offline tests for aigw_claude_auth.py: a fake OIDC IdP and a fake token broker on 127.0.0.1, no network, no Claude.

Run:  python3 -m unittest -v client/test_aigw_claude_auth.py      (from the repo root; about 10 s)
"""
import base64
import hashlib
import io
import json
import os
import stat
import sys
import tempfile
import threading
import time
import unittest
import urllib.parse
import urllib.request
from contextlib import redirect_stdout, redirect_stderr
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
import aigw_claude_auth as A  # noqa: E402


def jwt(exp, **claims):
    b = lambda o: base64.urlsafe_b64encode(json.dumps(o).encode()).decode().rstrip("=")
    return f"{b({'alg': 'RS256', 'kid': 'test'})}.{b(dict(claims, exp=int(exp)))}.c2ln"


class FakeIdP:
    """Discovery, device code, authorization code + PKCE (S256 checked), refresh with rotation, and a broker."""

    def __init__(self):
        self.calls = []
        self.refresh_tokens = set()
        self.codes = {}                  # code -> (challenge, redirect)
        self.device_polls = 0
        self.device_pending = 2          # authorization_pending this many times, then success
        self.device_slow_down = False
        self.refresh_error = None        # e.g. "invalid_grant"
        self.issue_refresh = True
        self.broker_status = 200
        self.idp_lifetime = 3600
        self.broker_lifetime = 3600
        idp = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _json(self, code, obj):
                data = json.dumps(obj).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_GET(self):
                u = urllib.parse.urlsplit(self.path)
                idp.calls.append(("GET", u.path))
                if u.path == "/.well-known/openid-configuration":
                    return self._json(200, {"issuer": idp.url, "token_endpoint": idp.url + "/token",
                                            "device_authorization_endpoint": idp.url + "/device",
                                            "authorization_endpoint": idp.url + "/authorize"})
                if u.path == "/authorize":   # the "browser": sign in at once and redirect to the loopback
                    q = {k: v[0] for k, v in urllib.parse.parse_qs(u.query).items()}
                    assert q["code_challenge_method"] == "S256"
                    code = "code-" + os.urandom(4).hex()
                    idp.codes[code] = (q["code_challenge"], q["redirect_uri"])
                    target = q["redirect_uri"] + "?" + urllib.parse.urlencode({"code": code, "state": q["state"]})
                    self.send_response(302)
                    self.send_header("Location", target)
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                self._json(404, {})

            def do_POST(self):
                n = int(self.headers.get("Content-Length") or 0)
                form = {k: v[0] for k, v in urllib.parse.parse_qs(self.rfile.read(n).decode()).items()}
                idp.calls.append(("POST", self.path, form.get("grant_type")))
                if self.path == "/device":
                    return self._json(200, {"device_code": "dev-1", "user_code": "ABCD-EFGH", "verification_uri": idp.url + "/activate",
                                            "expires_in": 60, "interval": 0})
                if self.path == "/token":
                    g = form.get("grant_type")
                    if form.get("client_id") != "cli":
                        return self._json(400, {"error": "invalid_client"})
                    if g == "urn:ietf:params:oauth:grant-type:device_code":
                        idp.device_polls += 1
                        if idp.device_slow_down and idp.device_polls == 1:
                            return self._json(400, {"error": "slow_down"})
                        if idp.device_polls <= idp.device_pending:
                            return self._json(400, {"error": "authorization_pending"})
                        return self._json(200, idp.tokens())
                    if g == "authorization_code":
                        challenge, redirect = idp.codes.pop(form.get("code"), (None, None))
                        ok = challenge and redirect == form.get("redirect_uri") and challenge == base64.urlsafe_b64encode(
                            hashlib.sha256(form.get("code_verifier", "").encode()).digest()).decode().rstrip("=")
                        return self._json(200, idp.tokens()) if ok else self._json(400, {"error": "invalid_grant"})
                    if g == "refresh_token":
                        if idp.refresh_error:
                            return self._json(400, {"error": idp.refresh_error, "error_description": "AADSTS700082: expired"})
                        if form.get("refresh_token") not in idp.refresh_tokens:
                            return self._json(400, {"error": "invalid_grant"})
                        idp.refresh_tokens.discard(form["refresh_token"])   # rotation: each refresh token works once
                        return self._json(200, idp.tokens())
                    return self._json(400, {"error": "unsupported_grant_type"})
                if self.path == "/exchange":
                    auth = self.headers.get("Authorization", "")
                    if idp.broker_status != 200:
                        return self._json(idp.broker_status, {"error": "no_matching_role"})
                    if not auth.startswith("Bearer ") or A.jwt_claims(auth[7:]).get("kind") != "idp":
                        return self._json(401, {"error": "invalid_token"})
                    return self._json(200, {"token": jwt(time.time() + idp.broker_lifetime, kind="gateway", portkey_workspace="ws-test", jti=os.urandom(4).hex())})
                self._json(404, {})

        self.srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.url = f"http://127.0.0.1:{self.srv.server_address[1]}"
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def tokens(self):
        out = {"access_token": jwt(time.time() + self.idp_lifetime, kind="idp", jti=os.urandom(4).hex()),
               "id_token": jwt(time.time() + 3600, kind="id", jti=os.urandom(4).hex()),
               "token_type": "Bearer", "expires_in": self.idp_lifetime}
        if self.issue_refresh:
            rt = "rt-" + os.urandom(6).hex()
            self.refresh_tokens.add(rt)
            out["refresh_token"] = rt
        return out

    def close(self):
        self.srv.shutdown()


class Base(unittest.TestCase):
    def setUp(self):
        self.idp = FakeIdP()
        self.tmp = Path(tempfile.mkdtemp(prefix="aigw-auth-test-"))
        self.state_dir = self.tmp / "state"
        self.settings_path = self.tmp / "claude" / "settings.json"
        self.config_path = self.tmp / "config.json"
        self.write_config()

    def tearDown(self):
        self.idp.close()

    def write_config(self, **over):
        cfg = {"issuer": self.idp.url, "client_id": "cli", "scope": "openid offline_access api://gw/access_as_user",
               "broker_url": self.idp.url + "/exchange", "hook_wait": 0, "notify": "off"}
        cfg.update(over)
        self.config_path.write_text(json.dumps(cfg))

    def run_cli(self, *args, stdin=""):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err), mock.patch("sys.stdin", io.StringIO(stdin)):
            code = A.main(["--config", str(self.config_path), "--state-dir", str(self.state_dir), "--settings", str(self.settings_path), *args])
        return code, out.getvalue(), err.getvalue()

    def header(self):
        return A.Settings(self.settings_path, "x-portkey-api-key").get()

    def put_header(self, value):
        A.Settings(self.settings_path, "x-portkey-api-key").put(value)

    def sign_in(self):
        """Pretend a device login happened: store a refresh token the fake IdP knows."""
        rt = self.idp.tokens()["refresh_token"]
        A.State(self.state_dir).save({"refresh_token": rt})
        return rt


class SettingsTests(Base):
    def test_put_keeps_other_headers_and_keys(self):
        self.settings_path.parent.mkdir(parents=True)
        self.settings_path.write_text(json.dumps({"model": "opus", "env": {"FOO": "1", "ANTHROPIC_CUSTOM_HEADERS": "x-team: blue\nX-Portkey-Api-Key: old"}}))
        os.chmod(self.settings_path, 0o644)
        self.put_header("new")
        d = json.loads(self.settings_path.read_text())
        self.assertEqual(d["model"], "opus")
        self.assertEqual(d["env"]["FOO"], "1")
        self.assertEqual(d["env"]["ANTHROPIC_CUSTOM_HEADERS"], "x-team: blue\nx-portkey-api-key: new")
        self.assertEqual(stat.S_IMODE(self.settings_path.stat().st_mode), 0o600)
        self.assertEqual(self.header(), "new")

    def test_put_creates_file_and_is_atomic(self):
        self.put_header("a")
        ino = self.settings_path.stat().st_ino
        self.put_header("b")
        self.assertNotEqual(self.settings_path.stat().st_ino, ino, "expected a rename, not an in-place write")
        self.assertEqual([p.name for p in self.settings_path.parent.iterdir()], ["settings.json"], "temp file left behind")

    def test_install_is_idempotent_and_keeps_foreign_hooks(self):
        self.settings_path.parent.mkdir(parents=True)
        self.settings_path.write_text(json.dumps({"hooks": {"UserPromptSubmit": [{"hooks": [{"type": "command", "command": "other"}]}]}}))
        self.sign_in()
        for _ in range(2):
            code, _, _ = self.run_cli("install", "--base-url", "https://gw.example.com")
            self.assertEqual(code, 0)
        d = json.loads(self.settings_path.read_text())
        self.assertEqual(d["env"]["ANTHROPIC_BASE_URL"], "https://gw.example.com")
        ups = [h["hooks"][0]["command"] for h in d["hooks"]["UserPromptSubmit"]]
        self.assertEqual(len(ups), 2)
        self.assertEqual(ups[0], "other")
        self.assertTrue(ups[1].endswith("hook precheck"))
        self.assertTrue(d["hooks"]["StopFailure"][0]["hooks"][0]["command"].endswith("hook stop-failure"))
        self.assertEqual(A.jwt_claims(self.header()).get("kind"), "gateway")

    def test_install_print_writes_nothing(self):
        code, out, _ = self.run_cli("install", "--print", "--base-url", "https://gw.example.com")
        self.assertEqual(code, 0)
        self.assertIn("hook precheck", out)
        self.assertFalse(self.settings_path.exists())


class SyncTests(Base):
    def test_noop_while_valid(self):
        good = jwt(time.time() + 3600)
        self.put_header(good)
        code, _, _ = self.run_cli("sync")
        self.assertEqual(code, 0)
        self.assertEqual(self.header(), good)
        self.assertFalse([c for c in self.idp.calls if c[0] == "POST"])

    def test_refresh_and_exchange_when_near_expiry(self):
        rt = self.sign_in()
        self.put_header(jwt(time.time() + 100))           # under refresh_before (300)
        code, _, _ = self.run_cli("sync")
        self.assertEqual(code, 0)
        claims = A.jwt_claims(self.header())
        self.assertEqual((claims["kind"], claims["portkey_workspace"]), ("gateway", "ws-test"))
        new_rt = A.State(self.state_dir).load()["refresh_token"]
        self.assertNotEqual(new_rt, rt, "rotated refresh token not stored")
        self.assertEqual(self.run_cli("sync", "--force")[0], 0, "the rotated refresh token should work")

    def test_mode_b_uses_idp_token_directly(self):
        self.write_config(broker_url="", idp_token="id_token")
        self.sign_in()
        self.assertEqual(self.run_cli("sync", "--force")[0], 0)
        self.assertEqual(A.jwt_claims(self.header())["kind"], "id")
        self.assertFalse([c for c in self.idp.calls if c[1] == "/exchange"])

    def test_token_command(self):
        tok = jwt(time.time() + 3600, kind="cmd")
        f = self.tmp / "tok"
        f.write_text(tok)
        self.write_config(client_id="", issuer="", broker_url="", token_command=f"cat {f}")
        code, out, _ = self.run_cli("token")
        self.assertEqual((code, out.strip()), (0, tok))
        self.assertEqual(self.header(), tok)

    def test_failure_with_expired_current_writes_sentinel(self):
        self.put_header(jwt(time.time() - 10))            # not signed in, current unusable
        code, _, err = self.run_cli("sync")
        self.assertEqual(code, 1)
        self.assertEqual(self.header(), "expired")
        self.assertIn("aigw-claude-auth login", err)

    def test_failure_with_usable_current_keeps_it(self):
        cur = jwt(time.time() + 200)                       # needs renewing, but still works for a while
        self.put_header(cur)
        self.assertEqual(self.run_cli("sync")[0], 1)
        self.assertEqual(self.header(), cur)

    def test_invalid_grant_clears_refresh_token(self):
        self.sign_in()
        self.idp.refresh_error = "invalid_grant"
        code, _, err = self.run_cli("sync", "--force")
        self.assertEqual(code, 1)
        self.assertIn("sign-in expired", err)
        self.assertNotIn("refresh_token", A.State(self.state_dir).load())

    def test_broker_refusal(self):
        self.sign_in()
        self.idp.broker_status = 403
        code, _, err = self.run_cli("sync", "--force")
        self.assertEqual(code, 1)
        self.assertIn("HTTP 403", err)

    def test_short_lived_token_is_refused(self):
        self.sign_in()
        self.idp.broker_lifetime = 30
        self.put_header(jwt(time.time() - 1))
        self.assertEqual(self.run_cli("sync")[0], 1)
        self.assertEqual(self.header(), "expired")

    def test_no_token_ever_printed_by_status(self):
        self.sign_in()
        self.run_cli("sync", "--force")
        code, out, _ = self.run_cli("status")
        self.assertEqual(code, 0)
        self.assertNotIn(self.header(), out)
        self.assertIn("ws-test", out)

    def test_logout(self):
        self.sign_in()
        self.run_cli("sync", "--force")
        self.assertEqual(self.run_cli("logout")[0], 0)
        self.assertEqual(self.header(), "expired")
        self.assertNotIn("refresh_token", A.State(self.state_dir).load())

    def test_config_rejects_empty_sentinel_and_unknown_keys(self):
        self.write_config(sentinel="")
        self.assertEqual(self.run_cli("sync")[0], 1)
        self.write_config(refresh_befor=10)
        self.assertIn("unknown keys", self.run_cli("sync")[2])


class LoginTests(Base):
    def test_device_flow_with_pending_and_slow_down(self):
        self.idp.device_slow_down = True
        with mock.patch("time.sleep"):
            code, _, err = self.run_cli("login", "--device")
        self.assertEqual(code, 0, err)
        self.assertIn("ABCD-EFGH", err)
        self.assertIn("refresh_token", A.State(self.state_dir).load())
        self.assertEqual(A.jwt_claims(self.header())["kind"], "gateway")

    def test_pkce_flow(self):
        def browser(url):     # follow the IdP's redirect to our loopback, like a browser would
            threading.Thread(target=lambda: urllib.request.urlopen(url, timeout=10).read(), daemon=True).start()
            return True
        with mock.patch("webbrowser.open", side_effect=browser):
            code, _, err = self.run_cli("login", "--pkce")
        self.assertEqual(code, 0, err)
        self.assertEqual(A.jwt_claims(self.header())["kind"], "gateway")

    def test_login_without_refresh_token_warns(self):
        self.idp.issue_refresh = False
        with mock.patch("time.sleep"):
            code, _, err = self.run_cli("login", "--device")
        self.assertEqual(code, 0)
        self.assertIn("no refresh token", err)


class HookTests(Base):
    def test_precheck_silent_when_valid(self):
        self.put_header(jwt(time.time() + 3600))
        t0 = time.time()
        code, out, _ = self.run_cli("hook", "precheck", stdin='{"hook_event_name":"UserPromptSubmit"}')
        self.assertEqual((code, out), (0, ""))
        self.assertLess(time.time() - t0, 1)

    def test_precheck_refreshes_and_waits(self):
        self.write_config(hook_wait=1)
        self.sign_in()
        self.put_header(jwt(time.time() - 10))
        t0 = time.time()
        code, out, _ = self.run_cli("hook", "precheck", stdin="{}")
        self.assertEqual((code, out), (0, ""))
        self.assertGreaterEqual(time.time() - t0, 1)
        self.assertEqual(A.jwt_claims(self.header())["kind"], "gateway")

    def test_precheck_blocks_when_no_token(self):
        self.write_config(hook_login="off")
        self.put_header(jwt(time.time() - 10))
        code, out, _ = self.run_cli("hook", "precheck", stdin="{}")
        self.assertEqual(code, 0)
        d = json.loads(out)
        self.assertEqual(d["decision"], "block")
        self.assertIn("aigw-claude-auth login", d["reason"])
        self.assertNotIn(("POST", "/device", None), self.idp.calls)

    def wait_for(self, cond, timeout=15):
        end = time.time() + timeout
        while not cond():
            self.assertLess(time.time(), end, "timed out")
            time.sleep(0.2)

    def test_precheck_starts_device_sign_in_when_signed_out(self):
        self.idp.device_pending = 10**6                    # the user hasn't signed in yet
        self.put_header("expired")
        t0 = time.time()
        code, out, _ = self.run_cli("hook", "precheck", stdin="{}")
        self.assertLess(time.time() - t0, 5, "the hook must not wait for the user")
        reason = json.loads(out)["reason"]
        self.assertIn("ABCD-EFGH", reason)
        self.assertIn("/activate", reason)
        self.assertNotIn("dev-1", reason + self.state_dir.joinpath("hook-login.json").read_text())   # device code stays secret
        _, out2, _ = self.run_cli("hook", "precheck", stdin="{}")      # sent again too early: same code, no second flow
        self.assertIn("ABCD-EFGH", json.loads(out2)["reason"])
        self.assertEqual(sum(1 for c in self.idp.calls if c[1] == "/device"), 1)
        self.assertIn("pending", self.run_cli("status")[1])
        self.idp.device_pending = 0                        # the user signs in
        self.wait_for(lambda: A.jwt_claims(self.header()).get("kind") == "gateway")
        self.wait_for(lambda: not self.state_dir.joinpath("hook-login.json").exists())
        self.assertTrue(A.State(self.state_dir).load().get("refresh_token"))
        self.assertEqual(self.run_cli("hook", "precheck", stdin="{}")[:2], (0, ""))   # the resent prompt goes through

    def test_hook_sign_in_failure_clears_pending(self):
        self.idp.device_pending = 10**6
        self.put_header("expired")
        self.run_cli("hook", "precheck", stdin="{}")
        pending = json.loads(self.state_dir.joinpath("hook-login.json").read_text())
        os.kill(pending["pid"], 15)                         # the waiting process dies
        os.waitpid(pending["pid"], 0)                       # reap it (the hook ran in this process, so it's our child)
        self.assertEqual(A.State(self.state_dir).pending(), {})
        self.idp.calls.clear()
        _, out, _ = self.run_cli("hook", "precheck", stdin="{}")        # a fresh sign-in is started
        self.assertIn("ABCD-EFGH", json.loads(out)["reason"])
        self.assertEqual(sum(1 for c in self.idp.calls if c[1] == "/device"), 1)
        os.kill(json.loads(self.state_dir.joinpath("hook-login.json").read_text())["pid"], 15)

    def test_precheck_blocks_in_time_when_idp_hangs(self):
        import socket
        hang = socket.socket()
        hang.bind(("127.0.0.1", 0))
        hang.listen(8)                                     # accepts connections, never answers
        self.addCleanup(hang.close)
        self.write_config(issuer=f"http://127.0.0.1:{hang.getsockname()[1]}", http_timeout=60)
        self.sign_in()
        self.put_header(jwt(time.time() - 10))
        t0 = time.time()
        code, out, _ = self.run_cli("hook", "precheck", stdin="{}")
        self.assertLess(time.time() - t0, A.HOOK_TIMEOUT - 10, "the hook must finish well inside Claude Code's hook timeout")
        self.assertEqual(json.loads(out)["decision"], "block")

    def test_install_sets_hook_timeout(self):
        self.run_cli("install", "--no-hooks")
        self.run_cli("install")
        d = json.loads(self.settings_path.read_text())
        self.assertEqual(d["hooks"]["UserPromptSubmit"][0]["hooks"][0]["timeout"], A.HOOK_TIMEOUT)

    def test_precheck_blocks_when_settings_unwritable(self):
        # macOS `chflags uchg` on settings.json: the rename fails with EPERM.
        self.sign_in()
        self.put_header(jwt(time.time() - 10))
        with mock.patch.object(A, "write_private", side_effect=PermissionError(1, "Operation not permitted")):
            code, out, _ = self.run_cli("hook", "precheck", stdin="{}")
            self.assertEqual(code, 0)
            d = json.loads(out)
            self.assertEqual(d["decision"], "block")
            self.assertIn("Operation not permitted", d["reason"])
        self.put_header(jwt(time.time() + 3600))            # a usable JWT in an unwritable file: let the prompt through
        with mock.patch.object(A, "write_private", side_effect=PermissionError(1, "Operation not permitted")):
            self.assertEqual(self.run_cli("hook", "precheck", stdin="{}")[:2], (0, ""))

    def test_precheck_no_block_when_disabled(self):
        self.write_config(block_on_failure=False)
        self.put_header(jwt(time.time() - 10))
        self.assertEqual(self.run_cli("hook", "precheck", stdin="{}")[:2], (0, ""))

    def test_hook_never_fails_on_bad_config(self):
        self.config_path.write_text("{}")
        self.assertEqual(self.run_cli("hook", "precheck", stdin="{}")[:2], (0, ""))

    def test_stop_failure_gateway_401_forces_refresh_and_notifies(self):
        note, script = self.tmp / "note", self.tmp / "notify.sh"
        script.write_text(f'#!/bin/sh\nprintf %s "$1" > "{note}"\n')
        script.chmod(0o755)
        self.write_config(notify=str(script))
        self.sign_in()
        good = jwt(time.time() + 3600)                     # looks valid, but the gateway said no (revoked, wrong key)
        self.put_header(good)
        payload = {"hook_event_name": "StopFailure", "error": "authentication_failed",
                   "last_assistant_message": "Failed to authenticate. API Error: 401 Portkey Error: JWT verification failed: signature verification failed. Error Code: 03"}
        self.assertEqual(self.run_cli("hook", "stop-failure", stdin=json.dumps(payload))[0], 0)
        self.assertNotEqual(self.header(), good)
        self.assertIn("retry", note.read_text())

    def test_stop_failure_498_counts_as_gateway(self):
        self.sign_in()
        self.put_header("expired")
        payload = {"last_assistant_message": "API Error: 498 AI gateway token expired and could not be refreshed."}
        self.run_cli("hook", "stop-failure", stdin=json.dumps(payload))
        self.assertEqual(A.jwt_claims(self.header())["kind"], "gateway")

    def test_stop_failure_ignores_anthropic_errors(self):
        self.sign_in()
        cur = jwt(time.time() + 3600)
        self.put_header(cur)
        payload = {"last_assistant_message": "Failed to authenticate. API Error: 401 anthropic error: OAuth access token is invalid."}
        self.run_cli("hook", "stop-failure", stdin=json.dumps(payload))
        self.assertEqual(self.header(), cur)


class DaemonTests(Base):
    def test_daemon_refreshes_then_stops_on_signal(self):
        self.sign_in()
        self.put_header(jwt(time.time() - 1))
        stop = threading.Timer(1.5, lambda: os.kill(os.getpid(), __import__("signal").SIGTERM))
        stop.start()
        code, _, err = self.run_cli("daemon", "--max-sleep", "5")
        self.assertEqual(code, 0)
        self.assertIn("wrote a new JWT", err)
        self.assertEqual(A.jwt_claims(self.header())["kind"], "gateway")


if __name__ == "__main__":
    unittest.main()
