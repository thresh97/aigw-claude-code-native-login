#!/usr/bin/env python3
"""Offline tests for aigw_claude_auth.py: a fake OIDC IdP and a fake token broker on 127.0.0.1, no network, no Claude.

Run:  python3 -m unittest -v client/test_aigw_claude_auth.py      (from the repo root; about 10 s)
"""
import base64
import contextlib
import hashlib
import io
import json
import os
import shutil
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
        self.device_desc = "AADSTS50105: blocked by policy"
        self.device_error = None         # e.g. "unauthorized_client": the device grant is refused (policy)
        self.advertise_device = True     # device_authorization_endpoint in discovery
        self.grants = None               # grant_types_supported in discovery
        self.code_error = None           # e.g. "redirect_uri_mismatch" at the code exchange
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
                    doc = {"issuer": idp.url, "token_endpoint": idp.url + "/token", "authorization_endpoint": idp.url + "/authorize"}
                    if idp.advertise_device:
                        doc["device_authorization_endpoint"] = idp.url + "/device"
                    if idp.grants:
                        doc["grant_types_supported"] = idp.grants
                    return self._json(200, doc)
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
                if self.path == "/device" and idp.device_error:
                    return self._json(400, {"error": idp.device_error, "error_description": idp.device_desc})
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
                    if g == "authorization_code" and idp.code_error:
                        return self._json(400, {"error": idp.code_error, "error_description": "AADSTS500113: no reply address"})
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


def hook_words(h):
    """A hook's command and args as one string, for both the shell form and the Windows exec form."""
    return " ".join([h["command"], *h.get("args", [])])


HEADLESS = {"platform": "linux", "ssh": False, "browser_env": False, "vscode": False, "container": False, "wsl": False,
            "wsl_opener": False, "desktop": False}


class Base(unittest.TestCase):
    def setUp(self):
        # the machine running the tests must not decide the sign-in method (or open a browser): headless, no overrides
        env = mock.patch.dict(os.environ)
        env.start()
        self.addCleanup(env.stop)
        for k in ("AIGW_LOGIN_METHOD", "AIGW_HOOK_LOGIN"):
            os.environ.pop(k, None)
        sig = mock.patch.object(A, "environment_signals", side_effect=lambda env=None: dict(HEADLESS))
        sig.start()
        self.addCleanup(sig.stop)
        self.idp = FakeIdP()
        self.tmp = Path(tempfile.mkdtemp(prefix="aigw-auth-test-"))
        self.state_dir = self.tmp / "state"
        self.settings_path = self.tmp / "claude" / "settings.json"
        self.config_path = self.tmp / "config.json"
        self.write_config()

    def tearDown(self):
        self.idp.close()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def write_config(self, **over):
        cfg = {"issuer": self.idp.url, "client_id": "cli", "scope": "openid offline_access api://gw/access_as_user",
               "broker_url": self.idp.url + "/exchange", "hook_wait": 0, "notify": "off",
               "secret_store": "file"}      # file: tests never touch the real OS store
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
        if sys.platform != "win32":
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
        self.assertTrue(hook_words(d["hooks"]["UserPromptSubmit"][1]["hooks"][0]).endswith("hook precheck"))
        self.assertTrue(hook_words(d["hooks"]["StopFailure"][0]["hooks"][0]).endswith("hook stop-failure"))
        self.assertEqual(A.jwt_claims(self.header()).get("kind"), "gateway")

    def test_install_print_writes_nothing(self):
        code, out, _ = self.run_cli("install", "--print", "--base-url", "https://gw.example.com")
        self.assertEqual(code, 0)
        self.assertIn("precheck", out)
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
        self.write_config(client_id="", issuer="", broker_url="", token_command=f"type {f}" if sys.platform == "win32" else f"cat {f}")
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
        if sys.platform == "win32":
            self.wait_for(lambda: not A.pid_alive(pending["pid"]))
        else:
            os.waitpid(pending["pid"], 0)                   # reap it (the hook ran in this process, so it's our child)
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
        if sys.platform == "win32":
            script = self.tmp / "notify.py"
            script.write_text(f'import sys\nopen(r"{note}", "w").write(sys.argv[1])\n')
            self.write_config(notify=f'"{sys.executable}" "{script}"')
        else:
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


SIG_KEYS = ("ssh", "browser_env", "vscode", "container", "wsl", "wsl_opener", "desktop")


def sig(platform="linux", **on):
    return dict(HEADLESS, platform=platform, **{k: True for k in on if on[k]})


SUPPORT = {"device": True, "pkce": True}
CFG = dict(A.DEFAULTS)


def choose(flag=None, env=None, cfg=None, st=None, support=SUPPORT, signals=None, hook=False, now=None):
    return A.choose_method(flag, env or {}, dict(CFG, **(cfg or {})), st or {}, support, signals or sig(), hook=hook, now=now)[0]


def free_port():
    import socket
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class MethodSelectionTests(unittest.TestCase):
    """Environment signals -> method, on every platform, with the probes mocked."""

    def test_detection_matrix(self):
        cases = [
            ("macOS with a GUI session", sig("darwin", desktop=True), "pkce"),
            ("macOS without a GUI session", sig("darwin"), "device"),
            ("macOS GUI, over ssh", sig("darwin", desktop=True, ssh=True), "device"),
            ("ssh with a forwarded BROWSER", sig(ssh=True, browser_env=True), "pkce"),
            ("ssh, Linux with DISPLAY", sig(ssh=True, desktop=True), "device"),
            ("Linux DISPLAY or WAYLAND_DISPLAY", sig(desktop=True), "pkce"),
            ("Linux, nothing", sig(), "device"),
            ("container", sig(container=True, desktop=True), "device"),
            ("container with BROWSER", sig(container=True, browser_env=True), "pkce"),
            ("VS Code dev container", sig(container=True, vscode=True), "pkce"),
            ("VS Code remote over ssh", sig(ssh=True, vscode=True, browser_env=True), "pkce"),
            ("WSL with a Windows opener", sig(wsl=True, wsl_opener=True), "pkce"),
            ("WSL without one", sig(wsl=True), "device"),
            ("Windows desktop session", sig("windows", desktop=True), "pkce"),
            ("Windows service or ssh session", sig("windows"), "device"),
        ]
        for name, s, want in cases:
            with self.subTest(name):
                self.assertEqual(choose(signals=s), want)

    def test_signals_from_environment_and_probes(self):
        with mock.patch.object(A, "platform_name", return_value="darwin"), mock.patch.object(A, "probe_macos_gui", return_value=True), \
                mock.patch.object(A, "probe_container", return_value=False):
            self.assertTrue(A.environment_signals({})["desktop"])
            s = A.environment_signals({"SSH_TTY": "/dev/ttys001"})
            self.assertTrue(s["ssh"])
            self.assertEqual(A.classify_environment(s), "headless")
        with mock.patch.object(A, "platform_name", return_value="linux"), mock.patch.object(A, "probe_container", return_value=False):
            self.assertTrue(A.environment_signals({"WAYLAND_DISPLAY": "wayland-0"})["desktop"])
            self.assertFalse(A.environment_signals({})["desktop"])
            self.assertTrue(A.environment_signals({"VSCODE_IPC_HOOK_CLI": "/x"})["vscode"])
            self.assertTrue(A.environment_signals({"BROWSER": "/home/u/.vscode-server/bin/helper/bin/helpers/browser.sh"})["vscode"])
            with mock.patch.object(A, "probe_wsl_opener", return_value=True):
                s = A.environment_signals({"WSL_DISTRO_NAME": "Ubuntu"})
                self.assertEqual((s["wsl"], s["wsl_opener"]), (True, True))
        with mock.patch.object(A, "platform_name", return_value="windows"), mock.patch.object(A, "probe_container", return_value=False):
            self.assertTrue(A.environment_signals({"SESSIONNAME": "Console"})["desktop"])
            self.assertTrue(A.environment_signals({"SESSIONNAME": "RDP-Tcp#1"})["desktop"])
            self.assertFalse(A.environment_signals({"SESSIONNAME": "Console", "SSH_CONNECTION": "a b c d"})["desktop"])
            self.assertFalse(A.environment_signals({"SESSIONNAME": "Services"})["desktop"])
            self.assertFalse(A.environment_signals({})["desktop"])

    def test_macos_probe_runs_launchctl_for_this_user(self):
        if sys.platform == "win32":
            self.skipTest("POSIX uid")
        with mock.patch("subprocess.run", return_value=mock.Mock(returncode=0)) as run:
            self.assertTrue(A.probe_macos_gui())
            self.assertEqual(run.call_args[0][0], ["launchctl", "print", f"gui/{os.getuid()}"])
        with mock.patch("subprocess.run", return_value=mock.Mock(returncode=113)):
            self.assertFalse(A.probe_macos_gui())
        with mock.patch("subprocess.run", side_effect=FileNotFoundError):
            self.assertFalse(A.probe_macos_gui())

    def test_precedence(self):
        gui = sig("darwin", desktop=True)
        st = {"last_login_method": "device"}
        self.assertEqual(choose(signals=gui), "pkce")
        self.assertEqual(choose(signals=gui, st=st), "device")                                           # remembered beats detection
        self.assertEqual(choose(signals=gui, st=st, cfg={"login_method": "pkce-print"}), "pkce-print")   # config beats remembered
        self.assertEqual(choose(signals=gui, st=st, cfg={"login_method": "pkce-print"}, env={"AIGW_LOGIN_METHOD": "pkce"}), "pkce")
        self.assertEqual(choose(flag="pkce-paste", signals=gui, st=st, cfg={"login_method": "pkce-print"}, env={"AIGW_LOGIN_METHOD": "pkce"}), "pkce-paste")
        self.assertEqual(choose(signals=gui, st=st, env={"AIGW_LOGIN_METHOD": "auto"}), "device")       # auto defers to the next rule
        self.assertEqual(choose(env={"AIGW_LOGIN_METHOD": "paste"}), "pkce-paste")
        with self.assertRaises(A.AuthError):
            choose(env={"AIGW_LOGIN_METHOD": "carrier-pigeon"})

    def test_remembered_method_must_be_viable_here(self):
        st = {"last_login_method": "pkce"}                      # signed in on the desktop; now over ssh
        self.assertEqual(choose(signals=sig(ssh=True), st=st), "device")
        self.assertEqual(choose(signals=sig(), st={"last_login_method": "pkce-print"}), "device")          # no fixed port to forward
        self.assertEqual(choose(signals=sig(), st={"last_login_method": "pkce-print"}, cfg={"redirect_port": 8765}), "pkce-print")
        self.assertEqual(choose(signals=sig(), st={"last_login_method": "pkce-paste"}), "pkce-paste")
        self.assertEqual(choose(signals=sig(), st={"last_login_method": "pkce-paste"}, hook=True), "device")   # a hook has no terminal

    def test_fallback_order_when_device_is_unavailable(self):
        no_dev = {"device": False, "pkce": True}
        self.assertEqual(choose(support=no_dev), "pkce-paste")                                  # headless, no port
        self.assertEqual(choose(support=no_dev, cfg={"redirect_port": 8765}), "pkce-print")     # headless, forwardable port
        self.assertIsNone(choose(support=no_dev, hook=True))                                    # hook: block with next steps
        self.assertEqual(choose(support=no_dev, hook=True, cfg={"redirect_port": 8765}), "pkce-print")
        self.assertEqual(choose(support=no_dev, signals=sig(desktop=True)), "pkce")
        self.assertIsNone(choose(support={"device": False, "pkce": False}))

    def test_flag_ignored_in_hook_but_env_and_config_apply(self):
        self.assertEqual(choose(flag="pkce", hook=True), "device")
        self.assertEqual(choose(hook=True, env={"AIGW_LOGIN_METHOD": "pkce"}), "pkce")
        self.assertIsNone(choose(hook=True, cfg={"login_method": "pkce-paste"}))

    def test_learned_refusal_expires(self):
        st = {"device_unavailable": {"until": 1000}}
        self.assertEqual(choose(st=st, now=999), "pkce-paste")
        self.assertEqual(choose(st=st, now=1001), "device")
        pk = {"pkce_unavailable": {"until": 1000}}
        self.assertEqual(choose(signals=sig(desktop=True), st=pk, now=999), "device")
        self.assertIsNone(choose(st=dict(st, **pk), now=999))

    def test_idp_support_from_discovery(self):
        class Src:
            def __init__(self, ep):
                self.ep = ep

            def endpoints(self):
                return self.ep
        full = {"device_authorization_endpoint": "x", "authorization_endpoint": "y"}
        self.assertEqual(A.idp_support(Src(full)), {"device": True, "pkce": True})
        self.assertEqual(A.idp_support(Src(dict(full, grant_types_supported=["authorization_code"]))), {"device": False, "pkce": True})
        self.assertEqual(A.idp_support(Src({"authorization_endpoint": "y"})), {"device": False, "pkce": True})
        self.assertEqual(A.idp_support(Src(dict(full, grant_types_supported=["urn:ietf:params:oauth:grant-type:device_code"]))), {"device": True, "pkce": False})

    def test_config_validation(self):
        d = Path(tempfile.mkdtemp(prefix="aigw-auth-test-"))
        self.addCleanup(shutil.rmtree, d, True)
        f = d / "c.json"
        for k, v in (("login_method", "pigeon"), ("hook_login", "pkce")):
            f.write_text(json.dumps({"client_id": "x", k: v}))
            with self.assertRaises(A.AuthError):
                A.load_config(f)
        f.write_text(json.dumps({"client_id": "x", "login_method": "pkce-paste", "hook_login": "auto"}))
        self.assertEqual(A.load_config(f)["login_method"], "pkce-paste")

    def test_hook_login_env_override(self):
        self.assertEqual(A.effective_hook_login({"hook_login": "auto"}, {"AIGW_HOOK_LOGIN": "off"}), "off")
        self.assertEqual(A.effective_hook_login({"hook_login": "off"}, {"AIGW_HOOK_LOGIN": "device"}), "device")
        self.assertEqual(A.effective_hook_login({"hook_login": "device"}, {}), "device")

    def test_parse_redirect(self):
        self.assertEqual(A.parse_redirect(" http://127.0.0.1:5/?code=a&state=b#x \n"), {"code": "a", "state": "b"})
        self.assertEqual(A.parse_redirect("code=a&state=b"), {"code": "a", "state": "b"})
        self.assertEqual(A.parse_redirect("http://127.0.0.1:5/"), {})


def no_redirect_opener():
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *a, **k):
            return None
    return urllib.request.build_opener(NoRedirect)


class PasteStdin:
    """A stdin that answers like the user would: read the URL we printed, 'sign in', hand back the redirect address."""

    def __init__(self, tamper=None, blank=False):
        self.tamper, self.blank = tamper, blank

    def readline(self):
        if self.blank:
            return "\n"
        url = [l.strip() for l in sys.stderr.getvalue().splitlines() if l.strip().startswith("http")][0]
        try:
            no_redirect_opener().open(url, timeout=10)
        except urllib.error.HTTPError as e:                      # the 302 to the loopback that nobody serves
            target = e.headers["Location"]
        return (self.tamper(target) if self.tamper else target) + "\n"


class SignInSelectionTests(Base):
    def run_cli_keep_stdin(self, *args):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = A.main(["--config", str(self.config_path), "--state-dir", str(self.state_dir), "--settings", str(self.settings_path), *args])
        return code, out.getvalue(), err.getvalue()

    def test_paste_flow_end_to_end_with_device_grant_disabled(self):
        self.idp.advertise_device = False
        self.idp.grants = ["authorization_code", "refresh_token"]
        with mock.patch("sys.stdin", PasteStdin()):
            code, _, err = self.run_cli_keep_stdin("login", "--paste")
        self.assertEqual(code, 0, err)
        self.assertEqual(A.jwt_claims(self.header())["kind"], "gateway")
        st = A.State(self.state_dir).load()
        self.assertEqual(st["last_login_method"], "pkce-paste")
        self.assertTrue(st["refresh_token"])
        self.assertNotIn(("POST", "/device", None), self.idp.calls)

    def test_paste_rejects_wrong_state_and_blank(self):
        for stdin, msg in ((PasteStdin(tamper=lambda u: u.replace("state=", "state=x")), "wrong state"), (PasteStdin(blank=True), "nothing pasted")):
            with mock.patch("sys.stdin", stdin):
                code, _, err = self.run_cli_keep_stdin("login", "--paste")
            self.assertEqual(code, 1)
            self.assertIn(msg, err)
        self.assertFalse(self.settings_path.exists())
        self.assertNotIn("refresh_token", A.State(self.state_dir).load())

    def test_pkce_print_flag(self):
        port = free_port()
        self.write_config(redirect_port=port)
        err = io.StringIO()

        def browser_user():
            end = time.time() + 10
            while time.time() < end:
                time.sleep(0.1)
                m = [l for l in err.getvalue().splitlines() if "open http" in l]
                if m:
                    return urllib.request.urlopen(m[0].split("open ", 1)[1].strip(), timeout=10).read()
        t = threading.Thread(target=browser_user, daemon=True)
        t.start()
        with redirect_stderr(err), mock.patch("webbrowser.open") as wb:
            code = A.main(["--config", str(self.config_path), "--state-dir", str(self.state_dir), "--settings", str(self.settings_path), "login", "--pkce-print"])
        t.join(10)
        self.assertEqual(code, 0, err.getvalue())
        wb.assert_not_called()
        self.assertIn(f"ssh -L {port}:127.0.0.1:{port}", err.getvalue())
        self.assertEqual(A.State(self.state_dir).load()["last_login_method"], "pkce-print")

    def test_remembered_method_is_reused_and_flag_overrides_it(self):
        self.write_config(redirect_port=free_port())
        st = A.State(self.state_dir)
        st.save({"last_login_method": "pkce-print"})
        # no flag: the remembered pkce-print (viable: fixed port) is chosen over device
        self.assertEqual(A.choose_method(None, {}, A.load_config(self.config_path), st.load(), SUPPORT, dict(HEADLESS))[0], "pkce-print")
        with mock.patch("time.sleep"):
            code, _, err = self.run_cli("login", "--device")                  # the flag wins
        self.assertEqual(code, 0, err)
        self.assertIn(("POST", "/device", None), self.idp.calls)
        self.assertEqual(st.load()["last_login_method"], "device")

    def test_login_learns_device_unavailable_and_falls_back(self):
        self.idp.device_error = "unauthorized_client"
        with mock.patch("sys.stdin", PasteStdin()):
            code, _, err = self.run_cli_keep_stdin("login")
        self.assertEqual(code, 0, err)
        self.assertIn("trying another method", err)
        st = A.State(self.state_dir).load()
        self.assertEqual(st["last_login_method"], "pkce-paste")
        d = st["device_unavailable"]
        self.assertIn("unauthorized_client", d["reason"])
        self.assertIn("AADSTS50105", d["reason"])
        self.assertAlmostEqual(d["until"] - time.time(), 86400, delta=60)
        self.assertEqual(sum(1 for c in self.idp.calls if c[1] == "/device"), 1)
        self.idp.calls.clear()                                                  # remembered: no second device attempt
        with mock.patch("sys.stdin", PasteStdin()):
            self.assertEqual(self.run_cli_keep_stdin("login")[0], 0)
        self.assertEqual(sum(1 for c in self.idp.calls if c[1] == "/device"), 0)

    def test_explicit_device_is_not_second_guessed(self):
        self.idp.device_error = "invalid_grant"
        code, _, err = self.run_cli("login", "--device")
        self.assertEqual(code, 1)
        self.assertIn("device_unavailable", A.State(self.state_dir).load())

    def test_unrelated_device_errors_are_not_learned(self):
        self.idp.device_error = "temporarily_unavailable"
        self.idp.device_desc = "try again later"
        self.run_cli("login", "--device")
        self.assertNotIn("device_unavailable", A.State(self.state_dir).load())

    def test_pkce_redirect_refusal_is_learned(self):
        self.idp.code_error = "redirect_uri_mismatch"
        with mock.patch("webbrowser.open", side_effect=lambda url: threading.Thread(target=lambda: urllib.request.urlopen(url, timeout=10).read(), daemon=True).start()):
            code, _, err = self.run_cli("login", "--pkce")
        self.assertEqual(code, 1)
        self.assertIn("pkce_unavailable", A.State(self.state_dir).load())

    # -- in the Claude Code session (precheck hook)
    def wait_for(self, cond, timeout=15):
        end = time.time() + timeout
        while not cond():
            self.assertLess(time.time(), end, "timed out")
            time.sleep(0.2)

    def pending(self):
        return json.loads(self.state_dir.joinpath("hook-login.json").read_text())

    @staticmethod
    def url_in(reason):
        return reason.split("open ", 1)[1].split(" ", 1)[0]

    def test_hook_blocks_with_next_steps_when_nothing_is_viable(self):
        self.idp.device_error = "unauthorized_client"
        self.put_header("expired")
        code, out, _ = self.run_cli("hook", "precheck", stdin="{}")
        reason = json.loads(out)["reason"]
        self.assertIn("login --paste", reason)
        self.assertIn("ssh -L", reason)
        self.assertIn("device_unavailable", A.State(self.state_dir).load())
        self.assertFalse(self.state_dir.joinpath("hook-login.json").exists())

    def test_hook_pkce_print_in_session_end_to_end(self):
        self.idp.device_error = "unauthorized_client"            # the device grant is off: PKCE is the way
        port = free_port()
        self.write_config(redirect_port=port)
        self.put_header("expired")
        t0 = time.time()
        code, out, _ = self.run_cli("hook", "precheck", stdin="{}")
        self.assertLess(time.time() - t0, 10, "the hook must not wait for the user")
        reason = json.loads(out)["reason"]
        self.assertIn(self.idp.url + "/authorize", reason)
        self.assertIn(f"ssh -L {port}:127.0.0.1:{port}", reason)
        _, out2, _ = self.run_cli("hook", "precheck", stdin="{}")      # the second prompt reuses the pending sign-in
        self.assertEqual(self.url_in(json.loads(out2)["reason"]), self.url_in(reason))
        urllib.request.urlopen(self.url_in(reason), timeout=10).read()  # the user signs in
        self.wait_for(lambda: self.settings_path.exists() and A.jwt_claims(self.header()).get("kind") == "gateway")
        self.wait_for(lambda: not self.state_dir.joinpath("hook-login.json").exists())
        self.assertEqual(sum(1 for c in self.idp.calls if c[1] == "/authorize"), 1)
        self.assertEqual(A.State(self.state_dir).load()["last_login_method"], "pkce-print")
        self.assertEqual(self.run_cli("hook", "precheck", stdin="{}")[:2], (0, ""))

    def test_hook_remembered_pkce_print_preferred_over_device(self):
        self.write_config(redirect_port=free_port())
        A.State(self.state_dir).save({"last_login_method": "pkce-print"})
        self.put_header("expired")
        reason = json.loads(self.run_cli("hook", "precheck", stdin="{}")[1])["reason"]
        self.assertIn("/authorize", reason)
        self.assertNotIn("ABCD-EFGH", reason)
        os.kill(self.pending()["pid"], 15)

    def test_hook_env_overrides_remembered(self):
        self.write_config(redirect_port=free_port())
        A.State(self.state_dir).save({"last_login_method": "pkce-print"})
        self.put_header("expired")
        os.environ["AIGW_LOGIN_METHOD"] = "device"
        self.idp.device_pending = 10**6
        reason = json.loads(self.run_cli("hook", "precheck", stdin="{}")[1])["reason"]
        self.assertIn("ABCD-EFGH", reason)
        os.kill(self.pending()["pid"], 15)

    def test_hook_login_off_by_env(self):
        os.environ["AIGW_HOOK_LOGIN"] = "off"
        self.put_header("expired")
        code, out, _ = self.run_cli("hook", "precheck", stdin="{}")
        d = json.loads(out)
        self.assertEqual(d["decision"], "block")
        self.assertNotIn("ABCD-EFGH", d["reason"])
        self.assertNotIn(("POST", "/device", None), self.idp.calls)
        self.assertFalse(self.state_dir.joinpath("hook-login.json").exists())

    def test_hook_pkce_worker_opens_browser(self):
        """`pkce` in the worker (run in-process here so the browser opener can be mocked)."""
        opened = []

        def browser(url):
            opened.append(url)
            threading.Thread(target=lambda: urllib.request.urlopen(url, timeout=10).read(), daemon=True).start()
            return True
        argv = ["--config", str(self.config_path), "--state-dir", str(self.state_dir), "--settings", str(self.settings_path), "hook-login-wait", "--method", "pkce"]
        with mock.patch("webbrowser.open", side_effect=browser), mock.patch.object(A, "notify"):
            self.assertEqual(A.main(argv), 0)
        self.assertEqual(len(opened), 1)
        self.assertEqual(A.jwt_claims(self.header())["kind"], "gateway")
        self.assertEqual(A.State(self.state_dir).load()["last_login_method"], "pkce")
        self.assertFalse(self.state_dir.joinpath("hook-login.json").exists())


class DaemonTests(Base):
    def test_daemon_refreshes_then_stops_on_signal(self):
        self.sign_in()
        self.put_header(jwt(time.time() - 1))
        stop = threading.Timer(1.5, lambda: __import__("signal").raise_signal(__import__("signal").SIGTERM))
        stop.start()
        code, _, err = self.run_cli("daemon", "--max-sleep", "5")
        self.assertEqual(code, 0)
        self.assertIn("wrote a new JWT", err)
        self.assertEqual(A.jwt_claims(self.header())["kind"], "gateway")


SCRIPT = str(Path(A.__file__).resolve())


class WindowsMockTests(Base):
    """The Windows pieces, run on any OS with sys.platform and the system calls mocked."""

    def win(self):
        """Pretend to be Windows; where msvcrt does not exist, a no-op stand-in so the lock path can run."""
        stack = contextlib.ExitStack()
        stack.enter_context(mock.patch("sys.platform", "win32"))
        if not hasattr(A, "msvcrt"):
            stack.enter_context(mock.patch.object(A, "msvcrt", mock.Mock(LK_LOCK=1, LK_UNLCK=0), create=True))
        return stack

    def test_hook_entry_exec_form_on_windows(self):
        with self.win():
            hook = A.default_hook_command()
        self.assertEqual(hook, [str(Path(sys.executable).resolve()), SCRIPT])
        self.assertEqual(A.hook_entry(hook, "precheck"), {"hooks": [{"type": "command", "command": hook[0], "args": [SCRIPT, "hook", "precheck"], "timeout": A.HOOK_TIMEOUT}]})

    def test_hook_entry_shell_form_elsewhere_is_unchanged(self):
        with mock.patch("sys.platform", "linux"):
            hook = A.default_hook_command()
        self.assertIsInstance(hook, str)
        import shlex
        self.assertEqual(hook, f"{shlex.quote(sys.executable)} {shlex.quote(SCRIPT)}")
        self.assertEqual(A.hook_entry(hook, "stop-failure"), {"hooks": [{"type": "command", "command": f"{hook} hook stop-failure", "timeout": A.HOOK_TIMEOUT}]})

    def test_install_and_print_agree_on_windows_and_reinstall_replaces(self):
        self.sign_in()
        with self.win():
            code, out, _ = self.run_cli("install", "--print")
            self.assertEqual(code, 0)
            printed = json.loads(out)["hooks"]
            for _ in range(2):
                self.assertEqual(self.run_cli("install")[0], 0)
        d = json.loads(self.settings_path.read_text())
        self.assertEqual(d["hooks"], printed)
        self.assertEqual(len(d["hooks"]["UserPromptSubmit"]), 1)
        self.assertEqual(d["hooks"]["UserPromptSubmit"][0]["hooks"][0]["args"][-2:], ["hook", "precheck"])

    def test_install_replaces_shell_form_entry_with_exec_form(self):
        self.settings_path.parent.mkdir(parents=True)
        self.settings_path.write_text(json.dumps({"hooks": {"UserPromptSubmit": [{"hooks": [{"type": "command", "command": "'/x/aigw-claude-auth' hook precheck"}]}]}}))
        self.sign_in()
        with self.win():
            self.run_cli("install")
        ups = json.loads(self.settings_path.read_text())["hooks"]["UserPromptSubmit"]
        self.assertEqual(len(ups), 1)
        self.assertIn("args", ups[0]["hooks"][0])

    def test_default_dirs_on_windows(self):
        env = {"APPDATA": r"C:\Users\u\AppData\Roaming", "LOCALAPPDATA": r"C:\Users\u\AppData\Local"}
        with self.win(), mock.patch.dict(os.environ, env):
            os.environ.pop("AIGW_CLAUDE_AUTH_DIR", None)
            self.assertEqual(A.config_dir(), Path(env["APPDATA"]) / "aigw-claude-auth")
            self.assertEqual(A.log_dir(), Path(env["LOCALAPPDATA"]) / "aigw-claude-auth" / "logs")
            os.environ["AIGW_CLAUDE_AUTH_DIR"] = "/override"
            self.assertEqual(A.config_dir(), Path("/override"))

    def test_pid_alive_windows_uses_exit_code_not_kill(self):
        import ctypes

        class K:
            code, handle = 259, 1234

            def OpenProcess(s, access, inherit, pid):
                return s.handle

            def GetExitCodeProcess(s, h, ref):
                ref._obj.value = s.code
                return 1

            def CloseHandle(s, h):
                pass

        k = K()
        with self.win(), mock.patch.object(A, "_kernel32", return_value=k), mock.patch("os.kill", side_effect=AssertionError("os.kill on Windows")):
            self.assertTrue(A.pid_alive(42))
            k.code = 1
            self.assertFalse(A.pid_alive(42))
            k.handle = None
            with mock.patch.object(ctypes, "get_last_error", return_value=5, create=True):
                self.assertTrue(A.pid_alive(42))             # access denied: it exists
            with mock.patch.object(ctypes, "get_last_error", return_value=87, create=True):
                self.assertFalse(A.pid_alive(42))            # invalid parameter: no such pid

    def test_spawn_detached_windows_argv_and_flags(self):
        import subprocess
        pyw = self.tmp / "pythonw.exe"
        pyw.write_text("")
        py = self.tmp / "python.exe"
        calls = []

        def popen(cmd, **kw):
            calls.append((cmd, kw))
            if kw["creationflags"] & 0x01000000:
                raise PermissionError(5, "Access is denied")
            return mock.Mock()

        with self.win(), mock.patch("subprocess.Popen", side_effect=popen), open(self.tmp / "log", "w") as logf:
            A.spawn_detached([str(py), "script", "hook-login-wait"], logf)
        self.assertEqual(len(calls), 2, "breakaway refused, then retried without it")
        cmd, kw = calls[1]
        self.assertEqual(cmd, [str(pyw), "script", "hook-login-wait"])
        self.assertEqual(kw["creationflags"], 0x08 | 0x200)
        self.assertNotIn("start_new_session", kw)
        self.assertIs(kw["stdout"], logf)                      # never the hook's stdout
        self.assertEqual(kw["stderr"], subprocess.STDOUT)

    def test_spawn_detached_posix_unchanged(self):
        with mock.patch("sys.platform", "linux"), mock.patch("subprocess.Popen") as popen:
            A.spawn_detached(["a"], None)
        self.assertTrue(popen.call_args.kwargs["start_new_session"])
        self.assertNotIn("creationflags", popen.call_args.kwargs)

    def test_replace_file_retries_on_permission_error_on_windows_only(self):
        n = []

        def flaky(src, dst):
            n.append(1)
            if len(n) < 4:
                raise PermissionError(13, "in use")
            return "ok"

        with self.win(), mock.patch("os.replace", side_effect=flaky), mock.patch("time.sleep"):
            self.assertEqual(A.replace_file("a", "b"), "ok")
        self.assertEqual(len(n), 4)
        with self.win(), mock.patch("os.replace", side_effect=PermissionError(13, "x")), mock.patch("time.sleep"):
            with self.assertRaises(PermissionError):
                A.replace_file("a", "b")
        with mock.patch("sys.platform", "linux"), mock.patch("os.replace", side_effect=PermissionError(1, "x")) as r:
            with self.assertRaises(PermissionError):
                A.replace_file("a", "b")
        self.assertEqual(r.call_count, 1)

    def test_toast_argv(self):
        argv = A.toast_argv("Signed in <ok> & it's fine")
        self.assertEqual(argv[:6], ["powershell.exe", "-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden", "-EncodedCommand"])
        ps = base64.b64decode(argv[6]).decode("utf-16-le")
        self.assertIn("$ProgressPreference = 'SilentlyContinue'", ps)
        self.assertIn("Signed in &lt;ok&gt; &amp; it''s fine", ps)
        self.assertNotIn("@@", ps)
        self.assertNotRegex(ps.lower(), r"invoke-expression|iex|gzip|downloadstring")
        self.assertLess(len(argv[6]), 5000)

    def test_custom_notify_command_on_windows_keeps_backslashes_and_drops_quotes(self):
        self.assertEqual(A.split_command(r'"C:\Program Files\Python\python.exe" C:\x\n.py -v', windows=True),
                         [r"C:\Program Files\Python\python.exe", r"C:\x\n.py", "-v"])
        self.assertEqual(A.split_command("'a b' c", windows=False), ["a b", "c"])

    def test_notify_on_windows_runs_toast(self):
        with self.win(), mock.patch("subprocess.run") as run:
            A.notify({"notify": "auto"}, "hello")
        self.assertEqual(run.call_args.args[0][0], "powershell.exe")
        self.assertEqual(run.call_args.kwargs["creationflags"], 0x08000000)

    def test_task_xml(self):
        import xml.etree.ElementTree as ET
        script = r"C:\Users\me\My Dir\aigw_claude_auth.py"
        xml = A.task_xml("DOM\\me&co", r"C:\Python\python.exe", script)
        root = ET.fromstring(xml.split("?>", 1)[1])
        ns = {"t": "http://schemas.microsoft.com/windows/2004/02/mit/task"}
        self.assertEqual(root.find("t:Triggers/t:LogonTrigger/t:UserId", ns).text, "DOM\\me&co")
        self.assertEqual(root.find("t:Settings/t:MultipleInstancesPolicy", ns).text, "IgnoreNew")
        self.assertEqual(root.find("t:Settings/t:RestartOnFailure/t:Count", ns).text, "999")
        self.assertEqual(root.find("t:Actions/t:Exec/t:Arguments", ns).text, f'"{script}" daemon')
        self.assertTrue(root.find("t:Actions/t:Exec/t:Command", ns).text.endswith("python.exe"))

    def test_task_print_registers_nothing_and_install_refuses_off_windows(self):
        with mock.patch.object(A, "current_user", return_value="HOST\\me"), mock.patch("subprocess.run") as run:
            code, out, _ = self.run_cli("task", "print")
            self.assertEqual(code, 0)
            self.assertIn("<LogonTrigger>", out)
            if sys.platform != "win32":
                self.assertEqual(self.run_cli("task", "install")[0], 1)
        run.assert_not_called()

    def test_task_needs_no_config(self):
        self.config_path.unlink()
        self.assertEqual(self.run_cli("task", "print")[0], 0)

    def test_task_install_argv_on_windows(self):
        with self.win(), mock.patch.object(A, "current_user", return_value="HOST\\me"), \
                mock.patch("subprocess.run", return_value=mock.Mock(returncode=0, stdout="SUCCESS", stderr="")) as run:
            self.assertEqual(self.run_cli("task", "install", "--name", "aigw-test-x")[0], 0)
            self.assertEqual(self.run_cli("task", "remove", "--name", "aigw-test-x")[0], 0)
        self.assertEqual(run.call_args_list[0].args[0][:4], ["schtasks.exe", "/Create", "/TN", "aigw-test-x"])
        self.assertEqual(run.call_args_list[1].args[0], ["schtasks.exe", "/Delete", "/TN", "aigw-test-x", "/F"])

    def test_lock_uses_msvcrt_on_windows(self):
        fake = mock.Mock(LK_LOCK=1, LK_UNLCK=0)
        fake.locking.side_effect = [OSError(36, "deadlock"), None, None]      # first try times out, second gets it
        with self.win(), mock.patch.object(A, "msvcrt", fake, create=True), A.State(self.state_dir).lock():
            self.assertEqual(fake.locking.call_count, 2)
        self.assertEqual(fake.locking.call_count, 3)
        self.assertEqual(fake.locking.call_args.args[1], 0)


@unittest.skipUnless(sys.platform == "win32", "Windows only")
class WindowsRealTests(Base):
    def test_lock_contention_between_processes(self):
        import subprocess
        self.state_dir.mkdir()
        code = ("import sys,time; sys.path.insert(0, %r); import aigw_claude_auth as A\n"
                "s=A.State(%r)\nwith s.lock():\n print('held', flush=True); time.sleep(2)\n") % (str(Path(A.__file__).parent), str(self.state_dir))
        p = subprocess.Popen([sys.executable, "-c", code], stdout=subprocess.PIPE, text=True)
        self.assertEqual(p.stdout.readline().strip(), "held")
        t0 = time.time()
        with A.State(self.state_dir).lock():
            waited = time.time() - t0
        p.wait()
        self.assertGreater(waited, 1.0, "second locker must block until the first releases")

    def test_pid_alive_live_and_dead(self):
        import subprocess
        p = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
        try:
            self.assertTrue(A.pid_alive(p.pid))
        finally:
            p.kill()
            p.wait()
        self.assertFalse(A.pid_alive(p.pid))
        self.assertTrue(A.pid_alive(os.getpid()))

    def test_detached_worker_survives_parent_exit(self):
        import subprocess
        out = self.tmp / "worker.out"
        worker = self.tmp / "worker.py"
        worker.write_text("import sys,time\nd=sys.stdin.read()\ntime.sleep(3)\nopen(sys.argv[1],'w').write('done '+d)\n")
        parent = self.tmp / "parent.py"
        parent.write_text("import sys\nsys.path.insert(0, %r)\nimport aigw_claude_auth as A\nlogf=open(sys.argv[2],'a')\n"
                          "c=A.spawn_detached([sys.executable, sys.argv[1], sys.argv[3]], logf)\nc.stdin.write(b'payload'); c.stdin.close()\nprint(c.pid)\n"
                          % str(Path(A.__file__).parent))
        r = subprocess.run([sys.executable, str(parent), str(worker), str(self.tmp / "w.log"), str(out)], capture_output=True, text=True, timeout=30)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue(r.stdout.strip().isdigit(), "worker must not write to the hook's stdout: " + r.stdout)
        deadline = time.time() + 15
        while time.time() < deadline and not out.exists():
            time.sleep(0.2)
        self.assertEqual(out.read_text(), "done payload")

    def test_replace_file_waits_for_a_reader(self):
        target = self.tmp / "t.txt"
        target.write_text("old")
        src = self.tmp / "s.txt"
        src.write_text("new")
        f = open(target, "rb")                                 # Python opens without FILE_SHARE_DELETE: replace is refused
        threading.Timer(0.5, f.close).start()
        t0 = time.time()
        A.replace_file(str(src), str(target))
        self.assertGreater(time.time() - t0, 0.3)
        self.assertEqual(target.read_text(), "new")

    def test_hook_entry_exec_form(self):
        d = A.hook_entry(A.default_hook_command(), "precheck")["hooks"][0]
        self.assertTrue(Path(d["command"]).is_absolute() and d["command"].lower().endswith(".exe"))
        self.assertEqual(d["args"], [SCRIPT, "hook", "precheck"])


class FakeStore:
    """An in-memory credential store; fail=True makes every call raise like a locked keychain would."""
    name = "fake store"

    def __init__(self):
        self.value, self.fail, self.sets, self.set_while_locked = "", False, 0, []

    def _check(self):
        if self.fail:
            raise A.SecretStoreError("store unavailable")

    def get(self):
        self._check()
        return self.value

    def set(self, v):
        self._check()
        self.sets += 1
        self.set_while_locked.append(LOCK_DEPTH[0] > 0)
        self.value = v

    def delete(self):
        self._check()
        self.value = ""


LOCK_DEPTH = [0]


class StoreBase(Base):
    """Base with secret_store=auto and a FakeStore in place of the OS store."""

    def setUp(self):
        super().setUp()
        A._warned.clear()
        self.write_config(secret_store="auto")
        self.store = FakeStore()
        orig = A.State.lock

        @contextlib.contextmanager
        def counting(state):
            with orig(state):
                LOCK_DEPTH[0] += 1
                try:
                    yield
                finally:
                    LOCK_DEPTH[0] -= 1
        for p in (mock.patch.object(A, "make_store", lambda cfg, d, platform=None: None if cfg["secret_store"] == "file" else self.store),
                  mock.patch.object(A.State, "lock", counting)):
            p.start()
            self.addCleanup(p.stop)

    def state_text(self):
        f = self.state_dir / "state.json"
        return f.read_text() if f.exists() else ""


class SecretStoreTests(StoreBase):
    def test_login_puts_the_refresh_token_in_the_store_not_the_file(self):
        with mock.patch("time.sleep"):
            code, out, err = self.run_cli("login", "--device")
        self.assertEqual(code, 0, err)
        self.assertTrue(self.store.value.startswith("rt-"))
        self.assertNotIn("refresh_token", self.state_text())
        self.assertNotIn(self.store.value, out + err)
        self.assertEqual(self.run_cli("sync", "--force")[0], 0, "the stored token must be usable")

    def test_migration_moves_the_file_token_into_the_store(self):
        rt = self.sign_in()                                    # writes state.json like 1.2.0 did
        self.assertIn(rt, self.state_text())
        code, _, err = self.run_cli("sync", "--force")
        self.assertEqual(code, 0, err)
        self.assertIn("moved the refresh token", err)
        self.assertNotEqual(self.store.value, rt, "then rotated: the store holds the new token")
        self.assertNotIn("refresh_token", self.state_text())
        self.assertNotIn(rt, self.state_text())

    def test_migration_alone_keeps_the_value(self):
        rt = self.sign_in()
        self.put_header(jwt(time.time() + 3600))
        self.assertEqual(self.run_cli("sync")[0], 0)           # no renewal needed, still migrates
        self.assertEqual(self.store.value, rt)
        self.assertNotIn("refresh_token", self.state_text())
        self.assertFalse([c for c in self.idp.calls if c[0] == "POST"])

    def test_rotation_writes_the_store_under_the_lock(self):
        self.sign_in()
        self.run_cli("sync", "--force")
        before = self.store.value
        self.store.set_while_locked.clear()
        self.assertEqual(self.run_cli("sync", "--force")[0], 0)
        self.assertNotEqual(self.store.value, before)
        self.assertEqual(self.store.set_while_locked, [True], "store write must happen under the state lock")

    def test_store_failure_falls_back_to_the_file(self):
        self.store.fail = True
        with mock.patch("time.sleep"):
            code, out, err = self.run_cli("login", "--device")
        self.assertEqual(code, 0, err)
        rt = A.State(self.state_dir).load()["refresh_token"]
        self.assertIn("keeping it in state.json", err)
        self.assertNotIn(rt, out + err, "the warning must not carry the secret")
        self.assertEqual(self.run_cli("sync", "--force")[0], 0, "reads fall back to the file too")

    def test_store_down_but_file_has_it(self):
        rt = self.sign_in()
        self.store.fail = True
        self.assertEqual(self.run_cli("sync", "--force")[0], 0)
        self.assertNotEqual(A.State(self.state_dir).load()["refresh_token"], rt)

    def test_logout_removes_it_from_the_store(self):
        self.sign_in()
        self.run_cli("sync", "--force")
        self.assertTrue(self.store.value)
        self.assertEqual(self.run_cli("logout")[0], 0)
        self.assertEqual(self.store.value, "")
        self.assertNotIn("refresh_token", self.state_text())
        self.assertEqual(self.header(), "expired")

    def test_invalid_grant_clears_the_store(self):
        self.sign_in()
        self.run_cli("sync", "--force")
        self.idp.refresh_error = "invalid_grant"
        self.assertEqual(self.run_cli("sync", "--force")[0], 1)
        self.assertEqual(self.store.value, "")

    def test_status_says_where_but_not_the_value(self):
        self.sign_in()
        self.run_cli("sync", "--force")
        _, out, err = self.run_cli("status")
        self.assertRegex(out, r"refresh token\s+fake store")
        self.assertNotIn(self.store.value, out + err)
        self.store.value = ""
        self.assertRegex(self.run_cli("status")[1], r"refresh token\s+none")

    def test_file_setting_ignores_the_store(self):
        self.write_config(secret_store="file")
        with mock.patch.object(A, "make_store", wraps=A.make_store):
            self.sign_in()
            self.assertEqual(self.run_cli("sync", "--force")[0], 0)
        self.assertIn("refresh_token", A.State(self.state_dir).load())

    def test_bad_secret_store_value(self):
        self.write_config(secret_store="vault")
        self.assertEqual(self.run_cli("status")[0], 1)


class StoreDriverTests(unittest.TestCase):
    """The OS drivers with the OS commands and the Windows API mocked (runs on every OS)."""
    SECRET = "rt-SECRET." + "x" * 1500 + '"quote\\back'

    def test_make_store_by_platform(self):
        cfg = {"secret_store": "auto"}
        with mock.patch("os.access", return_value=True):
            self.assertIsInstance(A.make_store(cfg, "/s", platform="darwin"), A.MacKeychain)
        self.assertIsNone(A.make_store({"secret_store": "file"}, "/s", platform="darwin"))
        with mock.patch("shutil.which", return_value=None):
            self.assertIsNone(A.make_store(cfg, "/s", platform="linux"))                 # no secret-tool
        with mock.patch("shutil.which", return_value="/usr/bin/secret-tool"), \
                mock.patch.dict(os.environ, {"DBUS_SESSION_BUS_ADDRESS": ""}), mock.patch("os.path.exists", return_value=False):
            self.assertIsNone(A.make_store(cfg, "/s", platform="linux"))                 # no session bus
        with mock.patch("shutil.which", return_value="/usr/bin/secret-tool"), \
                mock.patch.dict(os.environ, {"DBUS_SESSION_BUS_ADDRESS": "unix:path=/x"}):
            self.assertIsInstance(A.make_store(cfg, "/s", platform="linux"), A.LibSecret)

    def test_account_differs_per_state_dir(self):
        self.assertNotEqual(A.store_account("/a"), A.store_account("/b"))
        self.assertEqual(A.store_account("/a"), A.store_account("/a"))

    @staticmethod
    def fake_run(backend, calls):
        def run(argv, input=None, **kw):
            calls.append((argv, input))
            return backend(argv, input)
        return run

    def test_mac_keychain_secret_goes_on_stdin_not_argv(self):
        calls, saved = [], {}

        def backend(argv, stdin):
            if argv[1] == "-i":
                saved["cmd"] = stdin
                return mock.Mock(returncode=0, stdout="", stderr="")
            if argv[1] == "find-generic-password":
                enc = saved["cmd"].split('-w "')[1].split('"')[0] if "cmd" in saved else None
                return mock.Mock(returncode=0 if enc else 44, stdout=(enc or "") + "\n", stderr="")
            saved.clear()
            return mock.Mock(returncode=0, stdout="", stderr="")
        s = A.MacKeychain("acct", run=self.fake_run(backend, calls), keychain="/tmp/x.keychain-db")
        s.set(self.SECRET)
        self.assertEqual(s.get(), self.SECRET)
        s.delete()
        self.assertEqual(s.get(), "")
        for argv, stdin in calls:
            self.assertEqual(argv[0], "/usr/bin/security")
            self.assertNotIn("add-generic-password", " ".join(argv))
            self.assertNotIn("rt-SECRET", " ".join(argv))
            self.assertIn("/tmp/x.keychain-db", " ".join(argv) + (stdin or ""))
        self.assertIn("add-generic-password -U", calls[0][1])
        self.assertEqual(calls[0][1].count("\n"), 1, "one command line, so no value can inject another")

    def test_mac_errors_raise(self):
        s = A.MacKeychain("acct", run=lambda *a, **k: mock.Mock(returncode=36, stdout="", stderr=""))
        for f in (s.get, lambda: s.set("x"), s.delete):
            with self.assertRaises(A.SecretStoreError):
                f()

        def boom(*a, **k):
            raise OSError("no security")
        with self.assertRaises(A.SecretStoreError):
            A.MacKeychain("acct", run=boom).get()

    def test_libsecret_secret_goes_on_stdin(self):
        calls, box = [], {}

        def backend(argv, stdin):
            if argv[1] == "store":
                box["v"] = stdin
                return mock.Mock(returncode=0, stdout="", stderr="")
            if argv[1] == "lookup":
                return mock.Mock(returncode=0 if "v" in box else 1, stdout=box.get("v", ""), stderr="")
            box.clear()
            return mock.Mock(returncode=0, stdout="", stderr="")
        s = A.LibSecret("acct", run=self.fake_run(backend, calls))
        self.assertEqual(s.get(), "")
        s.set(self.SECRET)
        self.assertEqual(s.get(), self.SECRET)
        s.delete()
        self.assertEqual(s.get(), "")
        self.assertNotIn("rt-SECRET", " ".join(" ".join(c[0]) for c in calls))
        self.assertEqual([c[1] for c in calls if c[0][1] == "store"], [self.SECRET])

    def test_libsecret_error_raises(self):
        s = A.LibSecret("acct", run=lambda *a, **k: mock.Mock(returncode=1, stdout="", stderr="Cannot autolaunch D-Bus"))
        with self.assertRaises(A.SecretStoreError):
            s.get()

    def test_windows_credential_with_a_fake_api(self):
        class Api:
            def __init__(self):
                self.d = {}

            def write(self, target, user, blob):
                self.d[target] = blob

            def read(self, target):
                return self.d.get(target)

            def delete(self, target):
                self.d.pop(target, None)
        api = Api()
        s = A.WinCredential("acct", service="svc", api=api)
        self.assertEqual(s.get(), "")
        s.set(self.SECRET)
        self.assertEqual(s.get(), self.SECRET)
        self.assertEqual(list(api.d), ["svc/acct"])
        s.delete()
        self.assertEqual(s.get(), "")


@unittest.skipUnless(sys.platform == "darwin", "macOS only")
class MacKeychainRealTests(unittest.TestCase):
    """Real /usr/bin/security against a throwaway keychain file; the login keychain and the search list are never used."""

    def setUp(self):
        import subprocess
        self.tmp = Path(tempfile.mkdtemp(prefix="aigw-kc-test-"))
        self.kc = self.tmp / "test.keychain-db"
        pw = os.urandom(8).hex()
        subprocess.run(["/usr/bin/security", "create-keychain", "-p", pw, str(self.kc)], check=True, capture_output=True)
        subprocess.run(["/usr/bin/security", "unlock-keychain", "-p", pw, str(self.kc)], check=True, capture_output=True)
        self.addCleanup(lambda: shutil.rmtree(self.tmp, ignore_errors=True))
        self.addCleanup(lambda: subprocess.run(["/usr/bin/security", "delete-keychain", str(self.kc)], capture_output=True))

    def test_round_trip_update_delete(self):
        s = A.MacKeychain("acct-test", service="aigw-claude-auth-test", keychain=self.kc)
        self.assertEqual(s.get(), "")
        big = "rt-" + os.urandom(1500).hex() + ".-_/+="            # 3000 chars: a long Entra-style token
        s.set(big)
        self.assertEqual(s.get(), big)
        odd = "rt-\"'\\ $x `y` é;\nadd-generic-password"       # quoting and injection attempts go through base64
        s.set(odd)
        self.assertEqual(s.get(), odd)
        with self.assertRaises(A.SecretStoreError):
            s.set("x" * 4500)
        s.set("second")                                        # -U updates in place
        self.assertEqual(s.get(), "second")
        s.delete()
        self.assertEqual(s.get(), "")
        s.delete()                                             # deleting nothing is fine

    def test_client_end_to_end_with_the_keychain(self):
        idp = FakeIdP()
        self.addCleanup(idp.close)
        state_dir = self.tmp / "state"
        cfg = {"issuer": idp.url, "client_id": "cli", "broker_url": idp.url + "/exchange", "hook_wait": 0, "notify": "off"}
        (self.tmp / "config.json").write_text(json.dumps(cfg))
        rt = idp.tokens()["refresh_token"]
        state_dir.mkdir()
        (state_dir / "state.json").write_text(json.dumps({"refresh_token": rt}))
        store = A.MacKeychain(A.store_account(state_dir), service="aigw-claude-auth-test", keychain=self.kc)
        with mock.patch.object(A, "make_store", lambda c, d, platform=None: store), redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            code = A.main(["--config", str(self.tmp / "config.json"), "--state-dir", str(state_dir), "--settings", str(self.tmp / "s.json"), "sync", "--force"])
        self.assertEqual(code, 0)
        self.assertTrue(store.get().startswith("rt-"))
        self.assertNotEqual(store.get(), rt)
        self.assertNotIn("refresh_token", (state_dir / "state.json").read_text())


@unittest.skipUnless(sys.platform == "win32", "Windows only")
class WinCredentialRealTests(unittest.TestCase):
    """Real Credential Manager, with a target prefixed aigw-claude-auth-test- that is deleted afterwards."""

    def setUp(self):
        self.service = "aigw-claude-auth-test-" + os.urandom(4).hex()
        self.store = A.WinCredential("acct", service=self.service)
        try:
            self.store.get()
        except A.SecretStoreError as e:       # 1312: a network-logon session (ssh, a service) has no credential set
            self.skipTest(f"no usable Credential Manager in this session ({e}); the client falls back to state.json here")
        self.addCleanup(self.cleanup)

    def cleanup(self):
        import subprocess
        self.store.delete()
        out = subprocess.run(["cmdkey", "/list"], capture_output=True, text=True).stdout
        self.assertNotIn(self.service, out, "test credential left behind")

    def test_round_trip(self):
        import subprocess
        self.assertEqual(self.store.get(), "")
        big = "rt-" + os.urandom(1500).hex() + "\"'\\ é"
        self.store.set(big)
        self.assertEqual(self.store.get(), big)
        self.store.set("second")
        self.assertEqual(self.store.get(), "second")
        self.assertIn(self.service, subprocess.run(["cmdkey", "/list"], capture_output=True, text=True).stdout)
        self.store.delete()
        self.assertEqual(self.store.get(), "")
        self.store.delete()


@unittest.skipUnless(sys.platform == "win32", "Windows only")
class WinClientRealTests(Base):
    """The client with the real Credential Manager driver (test-prefixed target). Works in any session: where the
    store is unusable (ssh: error 1312) the token must end up in state.json with a warning, and sync must still work."""

    def test_sync_with_the_real_store_or_its_fallback(self):
        A._warned.clear()
        service = "aigw-claude-auth-test-" + os.urandom(4).hex()
        store = A.WinCredential(A.store_account(self.state_dir), service=service)

        def cleanup():
            try:
                store.delete()
            except A.SecretStoreError:
                pass
        self.addCleanup(cleanup)
        self.write_config(secret_store="auto")
        rt = self.sign_in()
        with mock.patch.object(A, "make_store", lambda c, d, platform=None: store):
            code, out, err = self.run_cli("sync", "--force")
        self.assertEqual(code, 0, err)
        in_file = "refresh_token" in A.State(self.state_dir).load()
        try:
            in_store = bool(store.get())
        except A.SecretStoreError:
            in_store = False
        self.assertTrue(in_store != in_file, f"the token must be in exactly one place (store {in_store}, file {in_file})")
        self.assertNotIn(rt, out + err)
        if in_file:
            self.assertIn("state.json", err)


class InspectTests(Base):
    def gw(self, exp=None, header=None, **claims):
        b = lambda o: base64.urlsafe_b64encode(json.dumps(o).encode()).decode().rstrip("=")
        c = dict(claims)
        if exp is not False:
            c["exp"] = int(exp or time.time() + 3600)
        return f"{b(header or {'alg': 'RS256', 'kid': 'k1', 'typ': 'JWT'})}.{b(c)}.SIGNATURE-PART"

    def inspect(self, token, *args, **cfg):
        if cfg:
            self.write_config(**cfg)
        self.put_header(token)
        return self.run_cli("inspect", *args)

    def test_mode_a_claims_and_header(self):
        tok = self.gw(portkey_oid="oid-1", portkey_workspace="ws-1", defaults={"config_slug": "pc-main", "config_id": "cid"},
                      iss="https://broker.example", iat=int(time.time()))
        code, out, err = self.inspect(tok)
        self.assertEqual(code, 0, out + err)
        for want in ("alg=RS256 kid=k1 typ=JWT", "oid-1", "ws-1", "defaults.config_slug", "pc-main", "defaults.config_id", "cid",
                     "broker", "not verified", "time left", "UTC", "no renewal needed"):
            self.assertIn(want, out)
        self.assertIn(A.fingerprint(tok), out)

    def test_never_prints_the_token_or_signature(self):
        tok = self.gw(sub="alice-sub")
        _, out, err = self.inspect(tok)
        self.assertNotIn(tok, out + err)
        self.assertNotIn("SIGNATURE-PART", out + err)
        self.assertNotIn(tok.split(".")[1], out + err)

    def test_redaction_and_show_claims(self):
        tok = self.gw(sub="alice-sub-123", email="alice@example.test", groups=["g-secret-1"], oid="oid-x", name="Alice A", scp="gw")
        _, out, _ = self.inspect(tok)
        for secret in ("alice-sub-123", "alice@example.test", "g-secret-1", "Alice A"):
            self.assertNotIn(secret, out)
        self.assertIn("redacted", out)
        self.assertIn("scp", out)                              # other claims: names only
        _, out, _ = self.run_cli("inspect", "--show-claims")
        for secret in ("alice-sub-123", "alice@example.test", "g-secret-1"):
            self.assertIn(secret, out)

    def test_alg_none_is_an_error(self):
        code, out, _ = self.inspect(self.gw(header={"alg": "none", "typ": "JWT"}))
        self.assertEqual(code, 1)
        self.assertIn("alg is none", out)

    def test_expired_and_not_yet_valid(self):
        code, out, _ = self.inspect(self.gw(exp=time.time() - 60))
        self.assertEqual(code, 1)
        self.assertIn("expired", out)
        code, out, _ = self.inspect(self.gw(nbf=int(time.time()) + 600))
        self.assertEqual(code, 1)
        self.assertIn("not valid yet", out)
        code, out, _ = self.inspect(self.gw(exp=False, iss="x"))
        self.assertIn("no exp claim", out)

    def test_issuer_verdict_mode_b(self):
        cfg = dict(broker_url="", issuer="https://idp.example/v2.0")
        code, out, _ = self.inspect(self.gw(iss="https://idp.example/v2.0/"), **cfg)
        self.assertEqual(code, 0, out)
        self.assertIn("IdP direct", out)
        self.assertIn("matches", out)
        code, out, _ = self.inspect(self.gw(iss="https://evil.example"), **cfg)
        self.assertEqual(code, 1)
        self.assertIn("DIFFERS", out)

    def test_audience_verdict_when_configured(self):
        cfg = dict(A.DEFAULTS, audience="api://gw", issuer="", broker_url="", sentinel="expired")
        rows, problems = A.inspect_token(self.gw(aud=["other"]), cfg)
        self.assertEqual(len(problems), 1)
        self.assertIn("aud does not contain", problems[0])
        rows, problems = A.inspect_token(self.gw(aud="api://gw"), cfg)
        self.assertEqual(problems, [])

    def test_opaque_idp_token(self):
        code, out, _ = self.inspect("opaque-token-value-123", broker_url="")
        self.assertEqual(code, 1)
        self.assertIn("opaque", out)
        self.assertNotIn("opaque-token-value-123", out)

    def test_sentinel_and_token_command_source(self):
        code, out, _ = self.inspect("expired")
        self.assertEqual(code, 1)
        self.assertIn("sentinel", out)
        code, out, _ = self.inspect(self.gw(), broker_url="", token_command="x", client_id="", issuer="")
        self.assertIn("token_command", out)

    def test_fresh_mints_without_writing(self):
        self.sign_in()
        self.put_header(jwt(time.time() + 3600, kind="old"))
        code, out, err = self.run_cli("inspect", "--fresh")
        self.assertEqual(code, 0, out + err)
        self.assertEqual(A.jwt_claims(self.header())["kind"], "old", "settings must not change")
        self.assertIn("ws-test", out)
        self.assertIn("not written", out)

    def test_debug_on_logs_at_renewal_and_expires(self):
        self.sign_in()
        code, out, _ = self.run_cli("inspect", "--debug", "on")
        until = A.State(self.state_dir).load()["debug_until"]
        self.assertAlmostEqual(until, time.time() + 24 * 3600, delta=120)
        self.assertIn("ON until", out)
        _, out, err = self.run_cli("sync", "--force")
        self.assertIn("debug (until", err)
        self.assertNotIn(self.header(), err)
        self.assertNotIn("sub=", err)
        st = A.State(self.state_dir)
        st.save(dict(st.load(), debug_until=int(time.time()) - 1))      # expired: quiet again
        _, out, err = self.run_cli("sync", "--force")
        self.assertNotIn("debug (until", err)
        self.assertNotIn("ON until", self.run_cli("inspect")[1])
        self.run_cli("inspect", "--debug", "on")
        self.assertEqual(self.run_cli("inspect", "--debug", "off")[1].strip(), "debug: off")
        self.assertNotIn("debug_until", A.State(self.state_dir).load())


if __name__ == "__main__":
    unittest.main()
