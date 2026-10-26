#!/usr/bin/env python3
"""Offline tests for aigw_claude_auth.py: a fake OIDC IdP and a fake token broker on 127.0.0.1, no network, no Claude.

Run:  python3 -m unittest -v client/test_aigw_claude_auth.py      (from the repo root; about 10 s)
"""
import base64
import contextlib
import hashlib
import io
import json
import plistlib
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
        for k in ("AIGW_LOGIN_METHOD", "AIGW_HOOK_LOGIN", "XDG_CONFIG_HOME"):
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
        # never read the real managed locations (/Library, /etc/claude-code, Program Files, the registry, the plist)
        self.managed = self.tmp / "managed"
        mock.patch.object(A, "managed_dir", return_value=self.managed).start()
        mock.patch.object(A, "plist_paths", return_value=[]).start()
        mock.patch.object(A, "read_registry_policy", return_value=(None, "", "")).start()
        mock.patch.object(A, "personal_entry", return_value=None).start()      # never this machine's own personal install
        mock.patch.object(A, "home_dir", side_effect=lambda: self.tmp / "home").start()   # never the real LaunchAgents or systemd dir
        mock.patch.object(A, "service_run", side_effect=lambda argv: (False, "") if argv[1:2] == ["print"] else (True, "")).start()   # never launchctl, systemctl or schtasks
        mock.patch.object(A, "service_python", return_value="/usr/bin/python3").start()   # the same interpreter whatever the machine has
        self.addCleanup(mock.patch.stopall)

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


REAL_REGISTRY_READER = A.read_registry_policy         # Base.setUp patches the module's; one test wants the real one


class FleetTakeoverTests(Base):
    """A fleet install (config key `fleet`) moves a personal install of the same user aside; doctor reports leftovers."""

    def personal(self):
        """A personal install: config and state in the state dir, our hooks plus someone else's in the user's settings,
        a background entry."""
        self.state_dir.mkdir(parents=True)
        (self.state_dir / "config.json").write_text(json.dumps({"issuer": "https://other-idp.example", "client_id": "p", "secret_store": "file"}))
        (self.state_dir / "state.json").write_text(json.dumps({"refresh_token": "personal-rt"}))
        self.settings_path.parent.mkdir(parents=True)
        theirs = {"hooks": [{"type": "command", "command": "other-tool"}]}
        self.settings_path.write_text(json.dumps({"env": {"ANTHROPIC_CUSTOM_HEADERS": "x-portkey-api-key: a.b.c"},
                                                  "hooks": {"UserPromptSubmit": [A.hook_entry("aigw-claude-auth", "precheck"), theirs],
                                                            "StopFailure": [A.hook_entry("aigw-claude-auth", "stop-failure")]}}))
        unit = self.tmp / "aigw-claude-auth.service"
        unit.write_text("[Unit]\n")
        A.personal_entry.return_value = ("systemd", unit)
        return unit, theirs

    def take_over(self):
        calls = []
        cfg = A.load_config(self.config_path)
        done = A.take_over_personal(cfg, A.State(self.state_dir), A.Settings(self.settings_path, cfg["header"]),
                                    run=lambda argv, **kw: calls.append(argv), platform="linux")
        return done, calls

    def test_fleet_moves_the_personal_install_aside(self):
        self.write_config(fleet=True)
        unit, theirs = self.personal()
        done, calls = self.take_over()
        self.assertEqual(calls, [["systemctl", "--user", "disable", "--now", "aigw-claude-auth.service"], ["systemctl", "--user", "daemon-reload"]])
        backup, = self.tmp.glob("state.personal-*")
        self.assertEqual(sorted(p.name for p in backup.iterdir()), ["aigw-claude-auth.service", "config.json", "state.json"])
        self.assertEqual(list(self.state_dir.iterdir()), [])                  # the fleet starts with an empty state dir
        s = json.loads(self.settings_path.read_text())
        self.assertEqual(s["hooks"], {"UserPromptSubmit": [theirs]})          # only our hooks go
        self.assertIn("x-portkey-api-key", s["env"]["ANTHROPIC_CUSTOM_HEADERS"])
        self.assertEqual(len(done), 3)
        A.personal_entry.return_value = None
        self.assertEqual(self.take_over(), ([], []))                          # the next login finds nothing to do

    def test_personal_config_alone_is_not_touched(self):
        self.personal()
        self.assertEqual(self.take_over(), ([], []))
        self.assertTrue((self.state_dir / "config.json").exists())

    def test_doctor_reports_a_personal_install_only_for_a_fleet(self):
        self.personal()
        code, report, ids = DoctorTests.doctor(self)
        self.assertNotIn("personal-install", ids)
        self.assertIn("personal-install", [n["id"] for n in report["not_applicable"]])
        self.write_config(fleet=True)
        code, report, ids = DoctorTests.doctor(self)
        self.assertEqual(ids["personal-install"], "Warning")
        msg = [f["message"] for f in report["findings"] if f["id"] == "personal-install"][0]
        for part in ("config.json", "systemd entry", "hooks"):
            self.assertIn(part, msg)


class DoctorTests(Base):
    """`doctor` and the preflight, against fake managed dirs (see Base.setUp: the real locations are never read)."""

    def managed_file(self, data, name="managed-settings.json", sub=None):
        d = self.managed / sub if sub else self.managed
        d.mkdir(parents=True, exist_ok=True)
        (d / name).write_text(data if isinstance(data, str) else json.dumps(data))

    def user_settings(self, data):
        self.settings_path.parent.mkdir(parents=True, exist_ok=True)
        self.settings_path.write_text(json.dumps(data))

    def ours(self, timeout=A.HOOK_TIMEOUT, cmd=None):
        cmd = cmd or f"{sys.executable} {SCRIPT}"
        h = lambda sub: [{"hooks": [dict({"type": "command", "command": f"{cmd} hook {sub}"}, **({"timeout": timeout} if timeout else {}))]}]
        return {"UserPromptSubmit": h("precheck"), "StopFailure": h("stop-failure")}

    def doctor(self, *args, env=None):
        with mock.patch.dict(os.environ, env or {}):
            code, out, _ = self.run_cli("doctor", "--json", *args)
        report = json.loads(out)
        return code, report, {f["id"]: f["severity"] for f in report["findings"]}

    def clean_user(self):
        self.user_settings({"env": {"ANTHROPIC_BASE_URL": "http://gw.example"}, "hooks": self.ours()})

    def test_clean_setup_has_no_error_or_warning(self):
        self.clean_user()
        code, report, ids = self.doctor(env={"CLAUDE_CONFIG_DIR": str(self.settings_path.parent)})
        self.assertEqual((code, {k: v for k, v in ids.items() if v != "Info"}), (0, {}))
        self.assertEqual(ids["server-managed"], "Info")
        self.assertIn("proxy-listen", [n["id"] for n in report["not_applicable"]])

    def test_managed_custom_headers_is_an_error(self):
        self.clean_user()
        self.managed_file({"env": {"ANTHROPIC_CUSTOM_HEADERS": "x: y"}})
        code, _, ids = self.doctor()
        self.assertEqual((code, ids["managed-custom-headers"]), (1, "Error"))

    def test_hooks_only_without_managed_hooks(self):
        self.clean_user()
        self.managed_file({"allowManagedHooksOnly": True})
        self.assertEqual(self.doctor()[2]["hooks-only-missing"], "Error")
        self.managed_file({"allowManagedHooksOnly": True, "hooks": self.ours()})
        ids = self.doctor()[2]
        self.assertNotIn("hooks-only-missing", ids)
        self.assertNotIn("hook-missing", ids)

    def test_dropins_count_and_merge_in_name_order(self):
        self.user_settings({})
        self.managed_file({"env": {"AIGW_ISSUER": "a"}, "allowManagedHooksOnly": True}, "managed-settings.json")
        self.managed_file({"hooks": {"UserPromptSubmit": self.ours()["UserPromptSubmit"]}}, "10-a.json", sub="managed-settings.d")
        self.managed_file({"hooks": {"StopFailure": self.ours()["StopFailure"]}}, "20-b.json", sub="managed-settings.d")
        self.managed_file({"hooks": {"StopFailure": []}}, ".hidden.json", sub="managed-settings.d")
        self.managed_file({"env": {"X": "1"}}, "30-c.txt", sub="managed-settings.d")
        self.assertNotIn("hooks-only-missing", self.doctor()[2])
        merged, files, errs = A.read_managed_files()
        self.assertEqual([Path(f).name for f in files], ["managed-settings.json", "10-a.json", "20-b.json"])
        self.assertEqual(merged["env"], {"AIGW_ISSUER": "a"})

    def test_hook_missing_no_timeout_and_missing_binary(self):
        self.user_settings({"hooks": {}})
        self.assertEqual(self.doctor()[2]["hook-missing"], "Warning")
        self.user_settings({"hooks": self.ours(timeout=None)})
        self.assertEqual(self.doctor()[2]["hook-no-timeout"], "Warning")
        self.user_settings({"hooks": self.ours(cmd="/nonexistent/aigw-claude-auth")})
        self.assertEqual(self.doctor()[2]["hook-binary-missing"], "Error")
        other = self.tmp / "aigw-claude-auth"
        other.write_text("#!/bin/sh\n")
        self.user_settings({"hooks": self.ours(cmd=str(other))})
        self.assertEqual(self.doctor()[2]["hook-other-binary"], "Warning")

    def test_guarded_managed_hooks_are_recognized(self):
        # the repro harness ships its managed hooks as `[ -n "$X" ] || exit 0; <python> <client> hook precheck`
        self.user_settings({})
        guarded = f'[ -n "$AIGW_REPRO_MANAGED" ] || exit 0; {sys.executable} {SCRIPT}'
        self.managed_file({"allowManagedHooksOnly": True, "hooks": self.ours(cmd=guarded)})
        self.assertEqual({k: v for k, v in self.doctor()[2].items() if v != "Info" and k != "settings-file-mismatch"}, {})

    def test_settings_not_replaceable(self):
        self.clean_user()
        with mock.patch.object(A, "settings_blocker", return_value="x has the immutable flag"):
            self.assertEqual(self.doctor()[2]["settings-not-writable"], "Error")
        self.assertNotIn("settings-not-writable", self.doctor()[2])
        if sys.platform != "win32" and os.geteuid() != 0:
            os.chmod(self.settings_path.parent, 0o500)
            try:
                self.assertEqual(self.doctor()[2]["settings-not-writable"], "Error")
            finally:
                os.chmod(self.settings_path.parent, 0o700)
            os.chmod(self.settings_path, 0o444)             # a read-only file is fine: the client renames over it
            self.assertNotIn("settings-not-writable", self.doctor()[2])

    @unittest.skipUnless(sys.platform == "darwin", "chflags")
    def test_real_immutable_flag_detected(self):
        self.clean_user()
        os.chflags(self.settings_path, stat.UF_IMMUTABLE)
        try:
            self.assertIn("immutable", A.settings_blocker(self.settings_path))
        finally:
            os.chflags(self.settings_path, 0)

    def test_base_url_mismatch(self):
        self.clean_user()
        self.managed_file({"env": {"ANTHROPIC_BASE_URL": "http://other.example"}})
        self.assertEqual(self.doctor()[2]["base-url-mismatch"], "Error")
        self.managed_file({"env": {"ANTHROPIC_BASE_URL": "http://gw.example/"}})
        self.assertNotIn("base-url-mismatch", self.doctor()[2])

    def test_proxy_listen_mismatch_when_mode_is_proxy(self):
        self.user_settings({"env": {"ANTHROPIC_BASE_URL": "http://127.0.0.1:9999"}})
        self.write_config(mode="proxy", gateway_url="http://gw.example", proxy_listen="127.0.0.1:8123")
        self.assertEqual(self.doctor()[2]["proxy-listen"], "Error")
        self.write_config(mode="proxy", gateway_url="http://gw.example", proxy_listen="127.0.0.1:9999")
        self.assertNotIn("proxy-listen", self.doctor()[2])

    def test_settings_file_mismatch(self):
        self.clean_user()
        code, report, ids = self.doctor(env={"CLAUDE_CONFIG_DIR": str(self.tmp / "elsewhere")})
        self.assertEqual((code, ids["settings-file-mismatch"]), (1, "Error"))
        self.assertNotIn("settings-file-mismatch", self.doctor(env={"CLAUDE_CONFIG_DIR": str(self.settings_path.parent)})[2])

    def test_block_on_failure_false_against_saas(self):
        self.write_config(block_on_failure=False)
        self.user_settings({"env": {"ANTHROPIC_BASE_URL": "https://api.portkey.ai"}})
        self.assertEqual(self.doctor()[2]["block-on-failure"], "Error")
        self.user_settings({"env": {"ANTHROPIC_BASE_URL": "https://gw.internal.example"}})
        self.assertNotIn("block-on-failure", self.doctor()[2])

    def test_sentinel_empty_and_custom(self):
        self.write_config(sentinel="")
        code, _, ids = self.doctor()
        self.assertEqual((code, ids["sentinel-empty"]), (1, "Error"))
        self.write_config(sentinel="my-sentinel")
        self.assertEqual(self.doctor()[2]["sentinel-custom"], "Info")

    def test_invalid_config_and_unparseable_documents(self):
        self.config_path.write_text('{"bogus": 1, "client_id": "x"}')
        self.assertEqual(self.doctor()[2]["config-invalid"], "Error")
        self.write_config()
        self.settings_path.parent.mkdir(parents=True)
        self.settings_path.write_text("{nope")
        self.assertEqual(self.doctor()[2]["user-settings-invalid"], "Error")
        self.managed_file("{nope")
        self.assertEqual(self.doctor()[2]["managed-unparseable"], "Error")

    def test_credential_override_and_allowed_providers(self):
        self.clean_user()
        self.managed_file({"apiKeyHelper": "echo k", "env": {"ANTHROPIC_AUTH_TOKEN": "t", "ANTHROPIC_BASE_URL": "http://gw.example"}})
        ids = self.doctor()[2]
        self.assertEqual((ids["credential-override"], ids["allowed-providers"]), ("Warning", "Info"))
        self.managed_file({"allowedProviders": ["customEndpoint"], "env": {"ANTHROPIC_BASE_URL": "http://gw.example"}})
        self.assertNotIn("allowed-providers", self.doctor()[2])

    def test_managed_aigw_env_conflicts_with_helper_config(self):
        self.write_config(issuer="https://idp.example/a", hook_wait=0)
        self.clean_user()
        self.managed_file({"env": {"AIGW_ISSUER": "https://idp.example/b", "AIGW_HOOK_WAIT": "9", "AIGW_TYPO": "1", "AIGW_HEADER": "x-portkey-api-key"}})
        report = self.doctor()[1]
        got = sorted((f["id"], f["severity"]) for f in report["findings"] if f["id"].startswith("managed-") and f["id"] != "managed-custom-headers")
        self.assertEqual(got, [("managed-config-conflict", "Error"), ("managed-config-conflict", "Warning"), ("managed-unknown-key", "Warning")])

    def test_jwt_issuer_mismatch_only_without_broker(self):
        self.write_config(broker_url="", issuer="https://idp.example/a")
        self.put_header(jwt(time.time() + 3600, iss="https://idp.example/other"))
        self.assertEqual(self.doctor()[2]["jwt-claims"], "Error")
        self.put_header(jwt(time.time() + 3600, iss="https://idp.example/a/"))
        self.assertNotIn("jwt-claims", self.doctor()[2])
        self.write_config(issuer="https://idp.example/a")                        # a broker is configured: its iss is the broker's
        self.put_header(jwt(time.time() + 3600, iss="https://broker"))
        self.assertNotIn("jwt-claims", self.doctor()[2])

    def test_secret_store_finding_when_a_store_exists(self):
        self.sign_in()
        self.assertIn("secret-store", [n["id"] for n in self.doctor()[1]["not_applicable"]])      # Base writes secret_store: file
        self.write_config(secret_store="auto")
        with mock.patch.object(A, "make_store", return_value=None):
            self.assertNotIn("secret-store", self.doctor()[2])
        with mock.patch.object(A, "make_store", return_value=object()):
            self.assertEqual(self.doctor()[2]["secret-store"], "Warning")

    def test_managed_sources_rank_plist_over_file_and_hkcu_last(self):
        self.managed_file({"env": {"FROM": "file"}})
        with mock.patch.object(A, "read_plist_policy", return_value=({"env": {"FROM": "plist"}}, "", "/p.plist")):
            info = A.managed_effective()
            self.assertEqual((info["source"], info["settings"]["env"]["FROM"]), ("plist", "plist"))
        merge = {"managedSourcesBehavior": "merge", "env": {"FROM": "plist", "A": "1"}}
        with mock.patch.object(A, "read_plist_policy", return_value=(merge, "", "/p.plist")):
            self.assertEqual(A.managed_effective()["settings"]["env"], {"FROM": "plist", "A": "1"})
        (self.managed / "managed-settings.json").unlink()
        with mock.patch.object(A, "read_registry_policy", side_effect=lambda h: ({"env": {"FROM": h}}, "", h)):
            self.assertEqual(A.managed_effective()["settings"]["env"]["FROM"], "HKLM")      # HKLM (admin) ranks above HKCU
        with mock.patch.object(A, "read_registry_policy", side_effect=lambda h: ({"env": {"FROM": h}}, "", h) if h == "HKCU" else (None, "", "")):
            self.assertEqual(A.managed_effective()["source"], "HKCU")

    def test_policy_control_keys_alone_are_not_a_policy(self):
        self.managed_file({"managedSourcesBehavior": "merge"})
        self.assertEqual(A.managed_effective()["source"], "")

    @unittest.skipUnless(sys.platform == "win32", "winreg")
    def test_registry_read_is_read_only_and_does_not_raise(self):
        for hive in ("HKLM", "HKCU"):
            data, err, where = REAL_REGISTRY_READER(hive)
            self.assertTrue(data is None or isinstance(data, dict))

    def test_report_never_contains_the_token(self):
        tok = jwt(time.time() + 3600, iss="https://idp.example/x", secretclaim="SECRETVALUE")
        self.put_header(tok)
        for args in (("--json",), ()):
            out = self.run_cli("doctor", *args)[1]
            self.assertNotIn(tok, out)
            self.assertNotIn(tok.split(".")[2], out)
            self.assertNotIn("SECRETVALUE", out)
        self.assertIn("sha256", self.run_cli("doctor")[1])

    def test_text_report_and_exit_code(self):
        self.managed_file({"env": {"ANTHROPIC_CUSTOM_HEADERS": "x: y"}})
        code, out, _ = self.run_cli("doctor")
        self.assertEqual(code, 1)
        self.assertIn("[Error] managed-custom-headers", out)
        self.assertIn("fix:", out)

    def test_precheck_blocks_on_a_preflight_error_and_writes_nothing(self):
        self.sign_in()
        old = jwt(time.time() - 10)
        self.put_header(old)
        self.managed_file({"env": {"ANTHROPIC_CUSTOM_HEADERS": "x: y"}})
        code, out, _ = self.run_cli("hook", "precheck", stdin="{}")
        d = json.loads(out)
        self.assertEqual((code, d["decision"]), (0, "block"))
        self.assertIn("ANTHROPIC_CUSTOM_HEADERS", d["reason"])
        self.assertIn("managed-custom-headers", d["reason"])
        self.assertEqual(self.header(), old, "the precheck wrote despite an Error")
        self.assertFalse([c for c in self.idp.calls if c[0] == "POST"], "the precheck went to the IdP despite an Error")
        with mock.patch.dict(os.environ, {"AIGW_CLAUDE_PREFLIGHT": "off"}):         # the bypass the repro harness uses
            self.run_cli("hook", "precheck", stdin="{}")
        self.assertNotEqual(self.header(), old)

    def test_precheck_recovers_when_the_error_clears(self):
        self.sign_in()
        self.put_header(jwt(time.time() - 10))
        self.managed_file({"env": {"ANTHROPIC_CUSTOM_HEADERS": "x: y"}})
        self.assertEqual(json.loads(self.run_cli("hook", "precheck", stdin="{}")[1])["decision"], "block")
        (self.managed / "managed-settings.json").unlink()
        self.assertEqual(self.run_cli("hook", "precheck", stdin="{}")[:2], (0, ""))
        self.assertEqual(A.jwt_claims(self.header())["kind"], "gateway")

    def test_notify_only_when_the_findings_hash_changes(self):
        note = self.tmp / "notes"
        script = self.tmp / ("notify.py" if sys.platform == "win32" else "notify.sh")
        if sys.platform == "win32":
            script.write_text(f'import sys\nopen(r"{note}", "a").write(sys.argv[1] + "\\n")\n')
            self.write_config(notify=f'"{sys.executable}" "{script}"')
        else:
            script.write_text(f'#!/bin/sh\nprintf "%s\\n" "$1" >> "{note}"\n')
            script.chmod(0o755)
            self.write_config(notify=str(script))
        self.sign_in()
        self.put_header(jwt(time.time() + 3600))
        self.managed_file({"env": {"ANTHROPIC_CUSTOM_HEADERS": "x: y"}})
        for _ in range(3):
            self.run_cli("hook", "precheck", stdin="{}")
        self.assertEqual(len(note.read_text().splitlines()), 1)
        self.managed_file({"env": {"ANTHROPIC_CUSTOM_HEADERS": "x: y"}, "apiKeyHelper": "echo k"})    # a new warning: a new hash
        self.run_cli("hook", "precheck", stdin="{}")
        self.assertEqual(len(note.read_text().splitlines()), 2)
        (self.managed / "managed-settings.json").unlink()                           # cleared: one "fixed" note
        self.run_cli("hook", "precheck", stdin="{}")
        self.run_cli("hook", "precheck", stdin="{}")
        lines = note.read_text().splitlines()
        self.assertEqual(len(lines), 3)
        self.assertIn("fixed", lines[-1])

    def test_daemon_skips_the_write_on_an_error(self):
        self.sign_in()
        old = jwt(time.time() - 1)
        self.put_header(old)
        self.managed_file({"env": {"ANTHROPIC_CUSTOM_HEADERS": "x: y"}})
        threading.Timer(1.0, lambda: __import__("signal").raise_signal(__import__("signal").SIGTERM)).start()
        code, _, err = self.run_cli("daemon", "--max-sleep", "5")
        self.assertEqual(code, 0)
        self.assertIn("not renewing", err)
        self.assertEqual(self.header(), old)
        self.assertFalse([c for c in self.idp.calls if c[0] == "POST"])


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

    def test_windows_credential_splits_long_values(self):
        class Api:                                   # enforces Credential Manager's per-credential blob limit
            def __init__(self):
                self.d = {}

            def write(self, target, user, blob):
                if len(blob) > 2560:
                    raise A.SecretStoreError("CredWriteW error 1783")
                self.d[target] = blob

            def read(self, target):
                return self.d.get(target)

            def delete(self, target):
                self.d.pop(target, None)
        api = Api()
        s = A.WinCredential("acct", service="svc", api=api)
        long = "rt-" + "x" * 6000 + "é"
        s.set(long)
        self.assertEqual(s.get(), long)
        self.assertEqual(sorted(api.d), ["svc/acct", "svc/acct#1", "svc/acct#2"])
        s.set("short")                              # stale parts go away
        self.assertEqual(s.get(), "short")
        self.assertEqual(list(api.d), ["svc/acct"])
        s.set(long)
        s.delete()
        self.assertEqual(api.d, {})


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

    def test_flat_dotted_defaults_claim_is_a_problem(self):
        # Okta emits a claim named "defaults.config_slug" as a flat key (finding 21)
        tok = self.gw(portkey_oid="oid-1", portkey_workspace="ws-1", **{"defaults.config_slug": "pc-main"},
                      iss="https://broker.example", iat=int(time.time()))
        code, out, err = self.inspect(tok)
        self.assertEqual(code, 1, out + err)
        self.assertIn("PROBLEM", out)
        self.assertIn("not a nested defaults object", out)

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


# --------------------------------------------------------------------------------------------- Mode 2: the local proxy

def free_port():
    import socket
    with socket.socket() as sk:
        sk.bind(("127.0.0.1", 0))
        return sk.getsockname()[1]


class FakeGateway:
    """The gateway as the proxy sees it: records requests; answers 200, a Portkey 401 for a refused JWT, Anthropic's 401,
    or a chunked SSE stream whose second half waits for the test (so 'the first chunk arrived early' is not a timing guess)."""

    def __init__(self):
        self.requests = []               # {"headers": {lower: value}, "path", "body"}
        self.lock = threading.Lock()
        self.refused = set()             # JWTs the gateway refuses (Portkey 401)
        self.refuse_all = False
        self.anthropic_401 = False
        self.release = threading.Event()  # the SSE reply sends its second chunk when this is set
        self.barrier = None               # a threading.Barrier: the SSE reply waits for all parties (concurrency)
        self.gzip_401 = False
        self.reply = None                 # (status, {headers}): answer every request that is not refused or streamed with this
        gw = self

        class H(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *a):
                pass

            def send(self, code, obj, extra=None):
                data = obj if isinstance(obj, bytes) else json.dumps(obj).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                for k, v in (extra or {}).items():
                    self.send_header(k, v)
                self.end_headers()
                self.wfile.write(data)

            def do_POST(self):
                n = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(n)
                hdrs = {k.lower(): v for k, v in self.headers.items()}
                with gw.lock:
                    gw.requests.append({"headers": hdrs, "path": self.path, "body": body})
                key = hdrs.get("x-portkey-api-key", "")
                if gw.anthropic_401:
                    return self.send(401, {"error": {"message": "anthropic error: Invalid bearer token", "type": "authentication_error"},
                                           "provider": "anthropic"}, {"request-id": "req_x", "x-should-retry": "false"})
                if gw.refuse_all or key in gw.refused or not key:
                    msg = json.dumps({"status": "failure", "message": "Portkey Error: JWT verification failed. Error Code: 03"}).encode()
                    if gw.gzip_401:
                        import gzip
                        return self.send(401, gzip.compress(msg), {"Content-Encoding": "gzip"})
                    return self.send(401, msg)
                if self.path.startswith("/stream"):
                    self.send_response(200)
                    self.send_header("Content-Type", "text/event-stream")
                    self.send_header("Transfer-Encoding", "chunked")
                    self.end_headers()
                    for i, piece in enumerate((b"event: one\ndata: 1\n\n", b"event: two\ndata: 2\n\n")):
                        if i:
                            if gw.barrier:
                                gw.barrier.wait(10)
                            gw.release.wait(10)
                        self.wfile.write(f"{len(piece):x}\r\n".encode() + piece + b"\r\n")
                        self.wfile.flush()
                    self.wfile.write(b"0\r\n\r\n")
                    return
                if gw.reply:
                    return self.send(gw.reply[0], {"ok": gw.reply[0] < 400}, gw.reply[1])
                self.send(200, {"ok": True, "echo": body.decode("utf-8", "replace")})

            def do_GET(self):
                with gw.lock:
                    gw.requests.append({"headers": {k.lower(): v for k, v in self.headers.items()}, "path": self.path, "body": b""})
                self.send(200, {"ok": True})

        self.srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.srv.daemon_threads = True
        self.srv.handle_error = lambda *a: None
        self.url = f"http://127.0.0.1:{self.srv.server_address[1]}"
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def close(self):
        self.release.set()
        self.srv.shutdown()
        self.srv.server_close()


class ProxyBase(Base):
    """A running proxy (in this process) in front of a FakeGateway, signed in to the FakeIdP."""

    signed_in = True

    def setUp(self):
        super().setUp()
        self.gw = FakeGateway()
        self.addCleanup(self.gw.close)
        self.settings_path.parent.mkdir(parents=True, exist_ok=True)
        self.configure()
        if self.signed_in:
            self.sign_in()
        self.start_proxy()

    def configure(self, **over):
        self.write_config(**dict(dict(mode="proxy", gateway_url=self.gw.url, proxy_listen="127.0.0.1:0"), **over))

    def load(self):
        cfg = A.load_config(self.config_path)
        cfg["_config_path"] = str(self.config_path)
        return cfg

    def start_proxy(self, **kw):
        self.cfg = self.load()
        self.state = A.State(self.state_dir)
        self.settings = A.Settings(self.settings_path, self.cfg["header"])
        self.ps = A.ProxyServer(self.cfg, self.state, self.settings, renew_cooldown=kw.pop("renew_cooldown", 0), **kw)
        self.port = self.ps.start()
        self.addCleanup(self.ps.stop)
        self.secret = A.proxy_secret(self.state)
        return self.ps

    def restart_proxy(self, **kw):
        self.ps.stop()
        return self.start_proxy(**kw)

    def call(self, method="POST", path="/v1/messages", body=b'{"model":"m","stream":false}', headers=None, secret=True, port=None):
        """One request through the proxy: (status, response headers, body bytes)."""
        import http.client
        h = {"Content-Type": "application/json", "Authorization": "Bearer sk-ant-oat01-user", "anthropic-beta": "oauth-2025-04-20"}
        if secret:
            h[A.LOCAL_HEADER] = self.secret if secret is True else secret
        h.update(headers or {})
        c = http.client.HTTPConnection("127.0.0.1", port or self.port, timeout=20)
        try:
            c.request(method, path, body=body if method == "POST" else None, headers=h)
            r = c.getresponse()
            return r.status, {k.lower(): v for k, v in r.getheaders()}, r.read()
        finally:
            c.close()

    def renew(self):
        self.assertTrue(self.ps.holder.renew(force=True)[0])
        return self.ps.holder.token

    def idp_posts(self):
        return len([c for c in self.idp.calls if c[0] == "POST"])


class ProxyForwardTests(ProxyBase):
    def test_injects_the_jwt_and_strips_client_values(self):
        tok = self.renew()
        status, _, body = self.call(headers={"x-portkey-api-key": "client-supplied", "X-Portkey-Api-Key": "again"})
        self.assertEqual(status, 200)
        seen = self.gw.requests[0]["headers"]
        self.assertEqual(seen["x-portkey-api-key"], tok)
        self.assertNotIn("client-supplied", json.dumps(seen))
        self.assertNotIn(A.LOCAL_HEADER, seen, "the local secret must not reach the gateway")
        self.assertEqual(seen["authorization"], "Bearer sk-ant-oat01-user")
        self.assertEqual(seen["anthropic-beta"], "oauth-2025-04-20")
        self.assertEqual(seen["host"], self.gw.url.split("//")[1])
        self.assertEqual(json.loads(body)["echo"], '{"model":"m","stream":false}')

    def test_the_gateway_path_prefix_is_kept(self):
        self.configure(gateway_url=self.gw.url + "/anthropic/")
        self.restart_proxy()
        self.renew()
        self.call(path="/v1/messages?beta=true")
        self.assertEqual(self.gw.requests[0]["path"], "/anthropic/v1/messages?beta=true")

    def test_the_first_request_renews_when_the_daemon_has_not_yet(self):
        self.assertEqual(self.ps.holder.token, "")
        self.assertEqual(self.call()[0], 200)
        self.assertEqual(A.jwt_claims(self.gw.requests[0]["headers"]["x-portkey-api-key"])["kind"], "gateway")

    def test_the_jwt_is_never_written_to_the_settings(self):
        tok = self.renew()
        self.call()
        self.assertFalse(self.settings_path.exists() and tok in self.settings_path.read_text())
        for f in self.state_dir.iterdir():
            self.assertNotIn(tok, f.read_text(errors="replace"), f.name)

    def test_get_is_forwarded(self):
        self.renew()
        self.assertEqual(self.call("GET", "/v1/models")[0], 200)
        self.assertEqual(self.gw.requests[0]["path"], "/v1/models")

    def test_an_upstream_connection_failure_is_a_502_without_details(self):
        self.renew()
        self.gw.close()
        status, _, body = self.call()
        self.assertEqual(status, 502)
        self.assertNotIn(self.gw.url.encode(), body)

    def test_no_af_unix_anywhere(self):                       # Windows Python has none
        self.assertNotIn("AF_UNIX", Path(A.__file__).read_text())

    def test_it_also_serves_with_windows_socket_options(self):
        with mock.patch.object(A, "is_windows", return_value=True):
            self.restart_proxy()
        self.assertEqual(self.call()[0], 200)


class ProxySecretTests(ProxyBase):
    def test_a_request_needs_the_secret(self):
        self.renew()
        for secret in (False, "wrong", self.secret[:-1], self.secret + "x", ""):
            status, _, body = self.call(secret=secret)
            self.assertEqual(status, 498, secret)
            err = json.loads(body)["error"]
            self.assertEqual(err["type"], "proxy_auth_error")
            for leak in (self.secret, self.ps.holder.token, self.gw.url, "portkey", "jwt"):
                self.assertNotIn(leak.lower(), body.decode().lower())
        self.assertEqual(self.gw.requests, [], "nothing may reach the gateway without the secret")
        self.assertEqual(self.call()[0], 200)

    def test_the_comparison_is_constant_time(self):
        with mock.patch("hmac.compare_digest", wraps=__import__("hmac").compare_digest) as cmp:
            self.call(secret="wrong")
        self.assertTrue(cmp.called)

    def test_the_secret_file_is_private_and_stable(self):
        f = self.state_dir / "proxy-secret"
        self.assertGreaterEqual(len(f.read_text().strip()), 32)
        if sys.platform != "win32":
            self.assertEqual(stat.S_IMODE(f.stat().st_mode), 0o600)
        self.assertEqual(A.proxy_secret(A.State(self.state_dir), create=True), self.secret)

    def test_a_secret_made_after_start_is_picked_up(self):
        (self.state_dir / "proxy-secret").write_text("n" * 40 + "\n")
        self.assertEqual(self.call(secret="n" * 40)[0], 200)

    def test_options_preflight_from_a_web_page_is_refused(self):
        status, _, _ = self.call("OPTIONS", secret=False, headers={"Origin": "http://evil.example", "Access-Control-Request-Headers": A.LOCAL_HEADER})
        self.assertEqual(status, 498)


class ProxyStreamTests(ProxyBase):
    def test_sse_reaches_the_client_before_the_upstream_finishes(self):
        import http.client
        self.renew()
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=15)
        c.request("POST", "/stream", body=b"{}", headers={A.LOCAL_HEADER: self.secret, "Content-Type": "application/json"})
        r = c.getresponse()
        self.assertEqual(r.getheader("Transfer-Encoding"), "chunked")
        first = r.read1(65536)                               # the upstream is still waiting for gw.release
        self.assertIn(b"event: one", first)
        self.assertFalse(self.gw.release.is_set())
        self.gw.release.set()
        rest = r.read()
        self.assertIn(b"event: two", first + rest)
        c.close()

    def test_several_simultaneous_streams(self):
        import http.client
        n = 8
        self.renew()
        self.gw.barrier = threading.Barrier(n)               # every upstream reply waits until all n are in flight at once
        results, firsts = [None] * n, [None] * n

        def one(i):
            c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=30)
            c.request("POST", "/stream", body=b"{}", headers={A.LOCAL_HEADER: self.secret})
            r = c.getresponse()
            firsts[i] = r.read1(65536)                       # first chunk, while the others are all still open
            results[i] = (r.status, firsts[i] + r.read())
            c.close()

        threads = [threading.Thread(target=one, args=(i,)) for i in range(n)]
        for t in threads:
            t.start()
        time.sleep(0.5)
        self.gw.release.set()
        for t in threads:
            t.join(30)
        for i in range(n):
            self.assertEqual(results[i][0], 200, i)
            self.assertIn(b"event: one", firsts[i])
            self.assertIn(b"event: two", results[i][1])
        self.assertEqual(len(self.gw.requests), n)

    def test_plain_json_with_content_length_is_not_rechunked(self):
        self.renew()
        status, headers, body = self.call()
        self.assertEqual((status, "transfer-encoding" in headers), (200, False))
        self.assertEqual(int(headers["content-length"]), len(body))


class ProxyRefusalTests(ProxyBase):
    def test_gateway_401_renews_and_retries_once(self):
        old = self.renew()
        self.gw.refused.add(old)
        posts = self.idp_posts()
        status, _, body = self.call()
        self.assertEqual(status, 200, body)
        self.assertEqual(len(self.gw.requests), 2)
        first, second = (r["headers"]["x-portkey-api-key"] for r in self.gw.requests)
        self.assertEqual(first, old)
        self.assertNotEqual(second, old)
        self.assertEqual(second, self.ps.holder.token)
        self.assertGreater(self.idp_posts(), posts)
        self.assertEqual(self.call()[0], 200, "the renewed JWT is kept for the next request")

    def test_still_refused_after_the_retry_is_a_498_like_the_lb_guard(self):
        self.renew()
        self.gw.refuse_all = True
        status, _, body = self.call()
        self.assertEqual(status, 498)
        self.assertEqual(json.loads(body), {"type": "error", "error": {"type": "gateway_token_error", "message": A.GUARD_MESSAGES["expired"]}})
        self.assertEqual(len(self.gw.requests), 2, "one try and one retry, no more")

    def test_nothing_new_to_try_is_not_a_retry(self):
        f = self.tmp / "same-jwt"
        f.write_text(jwt(time.time() + 3600, kind="gateway"))
        self.configure(client_id="", issuer="", broker_url="", token_command=f"type {f}" if sys.platform == "win32" else f"cat {f}")
        self.restart_proxy()
        self.renew()
        self.gw.refuse_all = True
        status, _, _ = self.call()
        self.assertEqual((status, len(self.gw.requests)), (498, 1), "the source returned the same refused JWT")

    def test_renewals_forced_by_refusals_are_rate_limited(self):
        self.restart_proxy(renew_cooldown=60)
        self.renew()
        self.gw.refuse_all = True
        self.call()
        n = self.idp_posts()
        self.assertEqual(self.call()[0], 498)
        self.assertEqual(self.idp_posts(), n, "no IdP traffic inside the cooldown")

    def test_anthropics_401_is_passed_through_unchanged(self):
        self.renew()
        self.gw.anthropic_401 = True
        posts = self.idp_posts()
        status, headers, body = self.call()
        self.assertEqual(status, 401)
        self.assertEqual(json.loads(body)["provider"], "anthropic")
        self.assertEqual(headers.get("request-id"), "req_x")
        self.assertEqual(headers.get("x-should-retry"), "false")
        self.assertEqual(len(self.gw.requests), 1, "no retry")
        self.assertEqual(self.idp_posts(), posts, "no renewal")

    def test_a_gzipped_gateway_401_is_still_recognised(self):
        self.renew()
        self.gw.refuse_all = self.gw.gzip_401 = True
        self.assertEqual(self.call()[0], 498)

    def test_classify_401(self):
        self.assertEqual(A.classify_401(b'{"status":"failure","message":"Portkey Error: x"}'), "gateway")
        self.assertEqual(A.classify_401(b'{"error":{"message":"anthropic error: bad"},"provider":"anthropic"}'), "other")
        self.assertEqual(A.classify_401(b'{"error":{"message":"Portkey Error: x"},"provider": "anthropic"}'), "other")
        self.assertEqual(A.classify_401(b"unauthorized"), "other")

    def test_the_498_text_matches_the_lb_guard_everywhere(self):
        root = Path(A.__file__).resolve().parent.parent
        for f in ("repro/mock_gateway.py", "gateway/alb-guard-ingress.yaml"):
            p = root / f
            if p.exists():
                text = p.read_text()
                for msg in A.GUARD_MESSAGES.values():
                    self.assertIn(msg, text, f)


class ProxyFailClosedTests(ProxyBase):
    signed_in = False

    def test_no_jwt_answers_498_without_contacting_the_gateway_and_starts_a_sign_in(self):
        self.idp.device_pending = 10**6                       # the user doesn't finish
        status, _, body = self.call()
        self.assertEqual(status, 498)
        msg = json.loads(body)["error"]["message"]
        self.assertTrue(msg.startswith(A.GUARD_MESSAGES["expired"]))
        self.assertIn("ABCD-EFGH", msg)
        self.assertEqual(self.gw.requests, [])
        pending = json.loads(self.state_dir.joinpath("hook-login.json").read_text())
        self.addCleanup(lambda: os.kill(pending["pid"], 15))
        self.assertNotIn("dev-1", msg)                         # the device code stays secret
        n = len([c for c in self.idp.calls if c[1] == "/device"])
        self.call()
        self.assertEqual(len([c for c in self.idp.calls if c[1] == "/device"]), n, "the pending sign-in is reused")

    def test_finishing_the_sign_in_makes_the_proxy_work(self):
        self.idp.device_pending = 2
        self.assertEqual(self.call()[0], 498)
        end = time.time() + 25
        while time.time() < end:
            if self.call()[0] == 200:
                break
            time.sleep(0.3)
        else:
            log = self.state_dir / "hook-login.log"
            self.fail("the proxy never got a JWT after the sign-in; " + (log.read_text() if log.exists() else "no log"))
        self.assertTrue(self.gw.requests)

    def test_hook_login_off_gives_a_plain_498(self):
        self.configure(hook_login="off")
        self.restart_proxy()
        status, _, body = self.call()
        self.assertEqual((status, json.loads(body)["error"]["message"]), (498, A.GUARD_MESSAGES["expired"]))
        self.assertFalse(self.state_dir.joinpath("hook-login.json").exists())

    def test_an_idp_outage_with_a_refresh_token_is_498_not_a_hang(self):
        self.sign_in()
        self.idp.refresh_error = "temporarily_unavailable"
        t0 = time.time()
        for _ in range(3):
            self.assertEqual(self.call()[0], 498)
        self.assertLess(time.time() - t0, 5)
        self.assertEqual(len([c for c in self.idp.calls if c[0] == "POST" and c[2] == "refresh_token"]), 1, "retried at most once per backoff")

    def test_a_config_error_blocks_with_its_message(self):
        self.ps.blocked = {"id": "hook-binary-missing", "message": "the hook is gone", "fix": "re-run install", "severity": "Error"}
        self.ps.blocked_checked = time.time() + 3600
        status, _, body = self.call()
        self.assertEqual(status, 498)
        self.assertIn("the hook is gone", body.decode())
        self.assertEqual(self.gw.requests, [])


class ProxyControlTests(ProxyBase):
    def ask(self, method, path, secret=True):
        status, _, body = self.call(method, path, body=b"", secret=secret)
        return status, body

    def test_status_and_inspect_never_hold_the_token(self):
        tok = self.renew()
        for path in ("/_aigw/status", "/_aigw/inspect", "/_aigw/inspect?claims=1"):
            status, body = self.ask("GET", path)
            self.assertEqual(status, 200)
            self.assertNotIn(tok, body.decode())
            self.assertNotIn(tok.split(".")[2], body.decode())
        st = json.loads(self.ask("GET", "/_aigw/status")[1])
        self.assertEqual((st["mode"], st["usable"]), ("proxy", True))
        self.assertIn(A.fingerprint(tok).split(" expires")[0], st["jwt"])

    def test_the_control_channel_needs_the_secret(self):
        self.renew()
        for method, path in (("GET", "/_aigw/status"), ("GET", "/_aigw/inspect"), ("POST", "/_aigw/renew"), ("POST", "/_aigw/forget")):
            self.assertEqual(self.ask(method, path, secret=False)[0], 498, path)
            self.assertEqual(self.ask(method, path, secret="nope")[0], 498, path)
        self.assertTrue(self.ps.holder.usable())

    def test_unknown_control_path(self):
        self.assertEqual(self.ask("GET", "/_aigw/nothing")[0], 404)

    def test_renew_and_forget(self):
        old = self.renew()
        st, body = self.ask("POST", "/_aigw/renew")
        self.assertEqual((st, json.loads(body)["changed"]), (200, False), "still valid: not renewed")
        st, body = self.ask("POST", "/_aigw/renew?force=1")
        self.assertEqual(json.loads(body)["changed"], True)
        self.assertNotEqual(self.ps.holder.token, old)
        self.ask("POST", "/_aigw/forget")
        self.assertEqual(self.ps.holder.token, "")

    def test_inspect_live_from_the_cli(self):
        tok = self.renew()
        code, out, err = self.run_cli("inspect", "--live")
        self.assertEqual(code, 0, err)
        self.assertIn("asked the running proxy", out)
        self.assertIn("pid", out)
        self.assertNotIn(tok, out + err)
        # without --live, proxy mode asks the proxy as well
        self.assertIn("asked the running proxy", self.run_cli("inspect")[1])

    def test_inspect_live_without_a_proxy(self):
        self.ps.stop()
        code, out, err = self.run_cli("inspect", "--live")
        self.assertEqual(code, 1)
        self.assertIn("not running", err)

    def test_status_shows_the_proxy(self):
        self.renew()
        code, out, _ = self.run_cli("status")
        self.assertEqual(code, 0)
        self.assertIn("running on 127.0.0.1:", out)
        self.assertIn("in the proxy's memory", out)
        self.assertNotIn(self.ps.holder.token, out)

    def test_sync_asks_the_proxy_and_writes_nothing(self):
        code, _, err = self.run_cli("sync", "--force")
        self.assertEqual(code, 0, err)
        self.assertTrue(self.ps.holder.usable())
        self.assertFalse(self.settings_path.exists())

    def test_token_mints_without_writing(self):
        code, out, _ = self.run_cli("token")
        self.assertEqual((code, A.jwt_claims(out.strip()).get("kind")), (0, "gateway"))
        self.assertFalse(self.settings_path.exists())

    def test_logout_makes_the_proxy_forget(self):
        self.renew()
        code, _, _ = self.run_cli("logout")
        self.assertEqual(code, 0)
        self.assertEqual(self.ps.holder.token, "")
        self.assertFalse(self.settings_path.exists())
        self.assertNotIn("refresh_token", A.State(self.state_dir).load())


class MaskingTests(unittest.TestCase):
    def test_mask_secret_shows_at_most_eight_characters_and_the_length(self):
        m = A.mask_secret("Bearer sk-ant-oat01-abcdefghijklmnop")
        self.assertTrue(m.startswith("Bearer sk-a...mnop (len "), m)
        self.assertNotIn("abcdefgh", m)
        self.assertEqual(A.mask_secret("short-secret"), "... (len 12)")          # too short to show any of it
        tok = jwt(time.time() + 60, sub="x")
        self.assertEqual(A.mask_secret(tok), f"{tok[:4]}...{tok[-4:]} (len {len(tok)})")

    def test_log_headers_keeps_the_listed_ones_and_never_the_proxy_secret(self):
        h = {"Authorization": "Bearer sk-ant-oat01-abcdefghijklmnop", "x-portkey-api-key": "p" * 40, A.LOCAL_HEADER: "local-secret-value",
             "anthropic-beta": "oauth-2025-04-20", "Cookie": "session=abc", "User-Agent": "claude-cli/2"}
        out = A.log_headers(h, "x-portkey-api-key")
        self.assertEqual(set(out), {"authorization", "x-portkey-api-key", "anthropic-beta", "user-agent"})
        self.assertEqual(out["anthropic-beta"], "oauth-2025-04-20")
        self.assertNotIn("local-secret-value", json.dumps(out))
        self.assertNotIn("p" * 20, out["x-portkey-api-key"])

    def test_status_claims_includes_the_email_and_flattens_defaults(self):
        c = A.status_claims({"sub": "u1", "email_id": "dev@example.com", "portkey_oid": "o1", "portkey_workspace": "ws1",
                             "defaults": {"config_slug": "pc-main", "config_id": "cid"}, "scope": "a b", "groups": ["g"]})
        self.assertEqual(c, {"sub": "u1", "email": "dev@example.com", "portkey_oid": "o1", "portkey_workspace": "ws1",
                             "config_slug": "pc-main", "scope": "a b"})
        self.assertEqual(A.status_claims({"email": "other@example.com"}), {"email": "other@example.com"})
        self.assertEqual(A.status_claims({}), {})

    def test_proxy_log_requests_must_be_a_whole_number(self):
        base = Base("run")
        for bad in (-1, 10001, "5", True, 1.5):
            with self.subTest(bad=bad):
                p = Path(tempfile.mkdtemp(prefix="aigw-cfg-")) / "c.json"
                self.addCleanup(shutil.rmtree, p.parent, ignore_errors=True)
                p.write_text(json.dumps({"client_id": "c", "proxy_log_requests": bad}))
                with self.assertRaises(A.AuthError):
                    A.load_config(p)


class JwksTests(unittest.TestCase):
    CFG = dict(A.DEFAULTS, issuer="https://idp.example/v2.0", broker_url="https://broker.example/token/exchange", http_timeout=5)

    def rows(self, cfg, kid, reply):
        with mock.patch.object(A, "http_json", side_effect=reply if isinstance(reply, Exception) else None, return_value=None if isinstance(reply, Exception) else reply) as hj:
            return dict(A.jwks_rows(cfg, kid)), hj

    def test_a_broker_publishes_its_keys_at_its_own_origin(self):
        rows, hj = self.rows(self.CFG, "k1", (200, {"keys": [{"kid": "k0"}, {"kid": "k1"}]}))
        self.assertEqual(rows["jwks"], "https://broker.example/.well-known/jwks.json")
        self.assertIn("kid k1 is published there", rows["jwks check"])
        self.assertIn("does not verify the signature", rows["jwks check"])

    def test_a_kid_missing_from_the_jwks_is_called_out(self):
        rows, _ = self.rows(self.CFG, "k9", (200, {"keys": [{"kid": "k1"}]}))
        self.assertIn("kid k9 is NOT in that JWKS", rows["jwks check"])

    def test_an_unreachable_jwks_is_reported_not_raised(self):
        rows, _ = self.rows(self.CFG, "k1", A.AuthError("cannot reach broker.example: timed out"))
        self.assertIn("not reachable", rows["jwks check"])

    def test_without_a_broker_the_idps_discovery_document_names_the_jwks(self):
        cfg = dict(self.CFG, broker_url="")
        answers = iter([(200, {"jwks_uri": "https://idp.example/keys"}), (200, {"keys": [{"kid": "k1"}]})])
        with mock.patch.object(A, "http_json", side_effect=lambda url, **kw: next(answers)):
            rows = dict(A.jwks_rows(cfg, "k1"))
        self.assertEqual(rows["jwks"], "https://idp.example/keys")
        self.assertIn("is published there", rows["jwks check"])

    def test_a_token_command_has_no_known_jwks_and_makes_no_request(self):
        with mock.patch.object(A, "http_json") as hj:
            rows = dict(A.jwks_rows(dict(self.CFG, token_command="echo x"), "k1"))
        hj.assert_not_called()
        self.assertIn("unknown", rows["jwks"])


class SettlesRecords:
    """The proxy records a request after it has sent the reply, so a test that reads the request log right after call()
    returns can find it empty (a fast machine wins that race, a slow one loses it). Wait until the record is there."""

    def recorded(self):
        with self.ps.stats_lock:
            return sum(self.ps.stats.values())

    def call(self, *a, **kw):
        before = self.recorded()
        out = super().call(*a, **kw)
        if not (kw.get("path") or (a[1] if len(a) > 1 else "/v1/messages")).startswith("/_aigw/"):
            deadline = time.time() + 3
            while self.recorded() <= before and time.time() < deadline:
                time.sleep(0.01)
        return out


class ProxyRequestLogTests(SettlesRecords, ProxyBase):
    def entries(self, n=50):
        return self.ps.recent_requests(n)

    def test_each_request_is_kept_with_masked_credentials(self):
        tok = self.renew()
        self.assertEqual(self.call(headers={"Authorization": "Bearer sk-ant-oat01-abcdefghijklmnop"})[0], 200)
        e = self.entries()[-1]
        self.assertEqual((e["method"], e["path"], e["status"]), ("POST", "/v1/messages", 200))
        self.assertTrue(e["in"]["authorization"].startswith("Bearer sk-a..."), e["in"])
        self.assertEqual(e["in"]["anthropic-beta"], "oauth-2025-04-20")
        self.assertEqual(e["out"], {"x-portkey-api-key": A.mask_secret(tok)})
        dump = json.dumps(self.entries())
        for secret in (tok, tok.split(".")[2] if len(tok.split(".")[2]) > 8 else tok, "sk-ant-oat01-abcdefghijklmnop", self.secret):
            self.assertNotIn(secret, dump)
        self.assertNotIn(A.LOCAL_HEADER, dump)

    def test_a_refused_request_is_kept_without_the_wrong_secret(self):
        self.renew()
        self.assertEqual(self.call(secret="not-the-secret-value")[0], 498)
        e = self.entries()[-1]
        self.assertEqual(e["note"], "local-secret")
        self.assertNotIn("not-the-secret-value", json.dumps(self.entries()))

    def test_only_the_last_n_are_kept(self):
        self.configure(proxy_log_requests=3)
        self.restart_proxy()
        self.renew()
        for i in range(5):
            self.call(path=f"/v1/messages?i={i}")
        self.assertEqual(len(self.entries()), 3)
        self.assertEqual(len(self.entries(2)), 2)
        self.assertEqual(self.entries(0), [])

    def test_the_upstream_request_id_and_retry_after_are_kept(self):
        self.renew()
        self.gw.reply = (429, {"retry-after": "7", "request-id": "req_test123", "set-cookie": "never=kept"})
        self.assertEqual(self.call()[0], 429)
        e = self.entries()[-1]
        self.assertEqual((e["status"], e["up"]), (429, {"request-id": "req_test123", "retry-after": "7"}))
        self.gw.reply = None
        self.assertEqual(self.call()[0], 200)
        self.assertEqual(self.entries()[-1]["up"], {})                  # nothing carried over from the previous request
        self.assertNotIn("never=kept", json.dumps(self.entries()))

    def test_a_passed_through_401_keeps_the_request_id(self):
        self.renew()
        self.gw.anthropic_401 = True
        self.assertEqual(self.call()[0], 401)
        self.assertEqual(self.entries()[-1]["up"], {"request-id": "req_x"})

    def test_a_refusal_made_by_the_proxy_has_no_upstream_headers(self):
        self.assertEqual(self.call(secret="nope")[0], 498)
        self.assertEqual(self.entries()[-1]["up"], {})

    def test_zero_keeps_nothing(self):
        self.configure(proxy_log_requests=0)
        self.restart_proxy()
        self.renew()
        self.call()
        self.assertIsNone(self.ps.recent)
        status, _, body = self.call("GET", "/_aigw/requests", body=b"")
        self.assertEqual((status, json.loads(body)), (200, {"limit": 0, "requests": []}))

    def test_the_control_endpoint_takes_a_count_and_needs_the_secret(self):
        self.renew()
        for _ in range(4):
            self.call()
        status, _, body = self.call("GET", "/_aigw/requests?n=2", body=b"")
        self.assertEqual(status, 200)
        self.assertEqual(len(json.loads(body)["requests"]), 2)
        self.assertEqual(self.call("GET", "/_aigw/requests", body=b"", secret=False)[0], 498)


class ProxyStatusCliTests(SettlesRecords, ProxyBase):
    def setUp(self):
        self.port_wanted = free_port()
        super().setUp()

    def configure(self, **over):
        self.write_config(**dict(dict(mode="proxy", gateway_url=self.gw.url, proxy_listen=f"127.0.0.1:{self.port_wanted}"), **over))

    def hold(self, **claims):
        self.ps.holder.token = jwt(time.time() + 3600, **claims)

    def test_status_shows_who_the_jwt_is_for_including_the_email(self):
        self.hold(sub="user-1", email_id="dev@example.com", portkey_workspace="ws-1", defaults={"config_slug": "pc-main"})
        code, out, err = self.run_cli("status", "--offline")
        self.assertEqual(code, 0, err)
        self.assertRegex(out, r"jwt email\s+dev@example.com")
        self.assertRegex(out, r"jwt config_slug\s+pc-main")
        self.assertNotIn("jwks", out)                          # --offline: no network call

    def test_status_names_the_jwks_and_whether_it_publishes_the_kid(self):
        self.hold(sub="user-1")
        with mock.patch.object(A, "http_json", return_value=(200, {"keys": [{"kid": "test"}]})):
            code, out, _ = self.run_cli("status")
        self.assertEqual(code, 0)
        self.assertIn("/.well-known/jwks.json", out)
        self.assertIn("kid test is published there", out)

    def test_requests_prints_the_recent_requests_with_masked_headers(self):
        self.renew()
        self.call(headers={"Authorization": "Bearer sk-ant-oat01-abcdefghijklmnop"})
        code, out, err = self.run_cli("requests", "-n", "5")
        self.assertEqual(code, 0, err)
        self.assertIn("POST /v1/messages -> 200", out)
        self.assertIn("in  authorization: Bearer sk-a...mnop", out)
        self.assertIn("out x-portkey-api-key:", out)
        self.assertNotIn("sk-ant-oat01-abcdefghijklmnop", out)
        code, out, _ = self.run_cli("requests", "--json")
        self.assertEqual(json.loads(out)[-1]["status"], 200)

    def test_requests_prints_the_upstream_headers(self):
        self.renew()
        self.gw.reply = (429, {"retry-after": "7", "request-id": "req_test123"})
        self.call()
        code, out, err = self.run_cli("requests", "-n", "1")
        self.assertEqual(code, 0, err)
        self.assertIn("-> 429", out)
        self.assertRegex(out, r"up  request-id: req_test123")
        self.assertRegex(out, r"up  retry-after: 7")

    def test_requests_in_file_mode_says_why_there_is_no_log(self):
        self.write_config(mode="file")
        code, _, err = self.run_cli("requests")
        self.assertEqual(code, 1)
        self.assertIn("mode is file", err)


class ProxyConfigTests(Base):
    def test_only_loopback_addresses_are_accepted(self):
        for bad in ("0.0.0.0:8000", "192.168.1.5:8000", "[::]:8000", "example.com:8000", "8000", "127.0.0.1", "127.0.0.1:99999", "10.0.0.1:1", ":80"):
            with self.assertRaises(A.AuthError, msg=bad):
                A.parse_listen(bad)
            self.write_config(proxy_listen=bad)
            with self.assertRaises(A.AuthError, msg=bad):
                A.load_config(self.config_path)
        self.assertEqual(A.parse_listen("127.0.0.1:18787"), ("127.0.0.1", 18787))
        self.assertEqual(A.parse_listen("localhost:5"), ("127.0.0.1", 5))
        self.assertEqual(A.parse_listen("[::1]:5"), ("::1", 5))
        self.assertEqual(A.parse_listen("127.0.0.1:0"), ("127.0.0.1", 0))

    def test_the_proxy_command_refuses_a_non_loopback_address(self):
        self.write_config(mode="proxy", gateway_url="http://gw.example", proxy_listen="0.0.0.0:18787")
        code, _, err = self.run_cli("proxy")
        self.assertEqual(code, 1)
        self.assertIn("loopback", err)

    def test_defaults(self):
        self.assertEqual((A.DEFAULTS["mode"], A.DEFAULTS["proxy_listen"], A.DEFAULTS["gateway_url"]), ("file", "127.0.0.1:18787", ""))
        self.write_config(mode="bogus")
        with self.assertRaises(A.AuthError):
            A.load_config(self.config_path)

    def test_proxy_needs_a_gateway_url(self):
        self.write_config(mode="proxy")
        code, _, err = self.run_cli("install")
        self.assertEqual(code, 1)
        self.assertIn("gateway_url", err)

    def test_the_example_config_only_has_known_keys(self):
        ex = json.loads((Path(A.__file__).resolve().parent / "config.example.json").read_text())
        self.assertFalse(set(ex) - set(A.DEFAULTS))


class ProxyUpstreamTests(unittest.TestCase):
    """TLS verification and HTTPS_PROXY / NO_PROXY for the connection to the gateway (no network: only how it is set up)."""

    def conn(self, url, **env):
        with mock.patch.dict(os.environ, env):
            for k in ("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "NO_PROXY", "no_proxy", "ALL_PROXY", "all_proxy"):
                if k.upper() not in env:            # Windows environment names are case-insensitive
                    os.environ.pop(k, None)             # an empty lowercase variable would override the uppercase one
            return A.Upstream(url).connect()

    def test_https_verifies_certificates_against_the_system_store(self):
        import ssl
        up = A.Upstream("https://gw.example.com/base")
        self.assertEqual((up.ctx.verify_mode, up.ctx.check_hostname), (ssl.CERT_REQUIRED, True))
        c, target = self.conn("https://gw.example.com/base")
        self.assertEqual((c.host, c.port, target("/v1/messages")), ("gw.example.com", 443, "/base/v1/messages"))

    def test_https_proxy_is_honored_with_a_tunnel(self):
        c, target = self.conn("https://gw.example.com", HTTPS_PROXY="http://user:pw@proxy.local:3128")
        self.assertEqual((c.host, c.port, c._tunnel_host, c._tunnel_port), ("proxy.local", 3128, "gw.example.com", 443))
        self.assertIn("Proxy-Authorization", c._tunnel_headers)
        self.assertEqual(target("/v1/messages"), "/v1/messages")

    def test_no_proxy_and_loopback_bypass_it(self):
        c, _ = self.conn("https://gw.example.com", HTTPS_PROXY="http://proxy.local:3128", NO_PROXY="example.com")
        self.assertEqual(c.host, "gw.example.com")
        c, _ = self.conn("http://127.0.0.1:8787", HTTP_PROXY="http://proxy.local:3128")
        self.assertEqual((c.host, c.port), ("127.0.0.1", 8787))

    def test_http_upstream_through_a_proxy_uses_the_absolute_uri(self):
        c, target = self.conn("http://gw.example.com:8080/x", HTTP_PROXY="http://proxy.local:3128")
        self.assertEqual((c.host, c.port, target("/v1/messages")), ("proxy.local", 3128, "http://gw.example.com:8080/x/v1/messages"))


class SignedOutInstallTests(Base):
    def test_install_succeeds_signed_out_and_writes_the_settings(self):
        self.settings_path.parent.mkdir(parents=True, exist_ok=True)
        code, _, err = self.run_cli("install", "--base-url", "https://gw.example.com")
        self.assertEqual(code, 0, err)
        d = json.loads(self.settings_path.read_text())
        self.assertEqual(d["env"]["ANTHROPIC_BASE_URL"], "https://gw.example.com")
        self.assertIn("mode file:", err)
        self.assertIn("not signed in yet", err)

    def test_install_signed_out_in_proxy_mode_succeeds(self):
        self.settings_path.parent.mkdir(parents=True, exist_ok=True)
        port = free_port()
        self.write_config(mode="proxy", gateway_url="https://gw.example.com", proxy_listen=f"127.0.0.1:{port}")
        code, _, err = self.run_cli("install")
        self.assertEqual(code, 0, err)
        self.assertIn("mode proxy: the proxy is not running yet", err)


REAL_SERVICE_PYTHON = A.service_python       # the base class stubs A.service_python; these tests need the real one


FAKE_EXE = "/opt/not-a-real-machine/bin/python3"      # sys.executable is /usr/bin/python3 on Linux, which is in the search list


class ServicePythonTests(unittest.TestCase):
    def pick(self, versions, venv=False, usable=None):
        """service_python() with python_version() answering from `versions` (a path -> version map)."""
        with mock.patch.object(A, "python_version", side_effect=lambda p: versions.get(p)), \
             mock.patch.object(A.os, "access", side_effect=lambda p, mode: usable is None or p in usable), \
             mock.patch.object(A.sys, "executable", FAKE_EXE), \
             mock.patch.object(A.sys, "prefix", "/venv" if venv else sys.base_prefix):
            return REAL_SERVICE_PYTHON()

    def test_the_newest_wins_over_the_system_python(self):
        self.assertEqual(self.pick({"/opt/homebrew/bin/python3": (3, 13), "/usr/bin/python3": (3, 9)}), "/opt/homebrew/bin/python3")
        self.assertEqual(self.pick({"/opt/homebrew/bin/python3": (3, 9), "/usr/bin/python3": (3, 14)}), "/usr/bin/python3")

    def test_homebrew_wins_a_tie(self):
        v = {"/opt/homebrew/bin/python3": (3, 13), "/Library/Frameworks/Python.framework/Versions/Current/bin/python3": (3, 13)}
        self.assertEqual(self.pick(v), "/opt/homebrew/bin/python3")

    def test_too_old_and_missing_interpreters_are_skipped(self):
        self.assertEqual(self.pick({"/opt/homebrew/bin/python3": (3, 7), "/usr/bin/python3": (3, 9)}), "/usr/bin/python3")
        self.assertIsNone(self.pick({"/usr/bin/python3": (2, 7)}))
        self.assertIsNone(self.pick({}))

    def test_sys_executable_is_used_only_outside_a_virtualenv(self):
        v = {FAKE_EXE: (3, 14)}
        self.assertEqual(self.pick(v, venv=False, usable=[FAKE_EXE]), FAKE_EXE)
        self.assertIsNone(self.pick(v, venv=True, usable=[FAKE_EXE]))


class ProxyLingerDoctorTests(unittest.TestCase):
    """The proxy-linger finding: proxy mode, Linux, a systemd user unit, lingering off, and a session that can outlive the login."""

    def check(self, mode="proxy", platform="linux", unit=True, linger="no", ssh=False, desktop=False):
        tmp = Path(tempfile.mkdtemp(prefix="aigw-linger-"))
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        path = tmp / "aigw-claude-auth.service"
        if unit:
            path.write_text("[Service]\n")
        sig = dict(HEADLESS, ssh=ssh, desktop=desktop)
        ctx = {"cfg": {"mode": mode}, "na": {}}
        with mock.patch.object(A.sys, "platform", platform), mock.patch.object(A, "systemd_unit_path", return_value=path), \
             mock.patch.object(A, "linger_state", return_value=linger), mock.patch.object(A, "environment_signals", return_value=sig):
            return A.chk_proxy_linger(ctx), ctx["na"].get("proxy-linger", "")

    def test_ssh_or_headless_with_lingering_off_gets_a_warning_with_the_fix(self):
        for kw in ({"ssh": True, "desktop": True}, {"ssh": False, "desktop": False}):
            with self.subTest(**kw):
                found, _ = self.check(**kw)
                self.assertEqual([f["severity"] for f in found], ["Warning"])
                self.assertEqual(found[0]["id"], "proxy-linger")
                self.assertIn("install --linger", found[0]["fix"])
                self.assertIn("enable-linger", found[0]["fix"])

    def test_a_desktop_session_is_told_it_is_fine(self):
        found, na = self.check(desktop=True)
        self.assertFalse(found)
        self.assertIn("fine in a desktop session", na)

    def test_lingering_on_or_unreadable_says_nothing(self):
        for linger in ("yes", None):
            with self.subTest(linger=linger):
                self.assertEqual(self.check(linger=linger, ssh=True), (None, ""))

    def test_not_applicable_says_why(self):
        self.assertEqual(self.check(mode="file", ssh=True), (None, "mode is file"))
        self.assertEqual(self.check(platform="darwin", ssh=True), (None, "not Linux"))
        self.assertEqual(self.check(unit=False, ssh=True), (None, "no systemd user unit from install"))


class ServiceInstallTests(Base):
    def setUp(self):
        super().setUp()
        mock.patch.object(A.time, "sleep").start()          # the launchd wait and retry must not slow the tests
        self.addCleanup(mock.patch.stopall)

    def test_darwin_writes_a_launch_agent_and_bootstraps_it(self):
        calls = []
        ok, msg = A.service_install({}, platform="darwin", run=lambda argv: calls.append(argv) or (argv[1] != "print", ""))
        self.assertTrue(ok, msg)
        d = plistlib.loads((self.tmp / "home" / "Library" / "LaunchAgents" / "aigw-claude-auth.plist").read_bytes())
        self.assertEqual(d["ProgramArguments"][-1], "daemon")
        self.assertTrue(d["RunAtLoad"])
        self.assertEqual(calls[-1][:2], ["launchctl", "bootstrap"])

    def test_darwin_bootstrap_failure_is_reported_and_the_agent_file_stays(self):
        run = lambda argv: (False, "Bootstrap failed: 5") if argv[1] == "bootstrap" else (False, "")
        ok, msg = A.service_install({}, platform="darwin", run=run)
        self.assertFalse(ok)
        self.assertIn("Bootstrap failed", msg)
        self.assertIn("next desktop login", msg)
        self.assertTrue((self.tmp / "home" / "Library" / "LaunchAgents" / "aigw-claude-auth.plist").exists())

    def test_darwin_retries_a_bootstrap_that_races_the_old_agent(self):
        calls, tries = [], []
        def run(argv):
            calls.append(argv[1])
            if argv[1] == "bootstrap":
                tries.append(argv)
                return (len(tries) > 1, "Bootstrap failed: 5")     # first attempt races the old agent, the retry works
            return (False, "")                                       # print: the label is gone
        ok, msg = A.service_install({}, platform="darwin", run=run)
        self.assertTrue(ok, msg)
        self.assertEqual(len(tries), 2)

    def test_darwin_waits_until_launchd_forgets_the_old_agent(self):
        printed = iter([True, True, False])
        run = lambda argv: (next(printed), "") if argv[1] == "print" else (argv[1] == "bootout" or argv[1] == "bootstrap", "")
        ok, msg = A.service_install({}, platform="darwin", run=run)
        self.assertTrue(ok, msg)

    def test_linux_writes_a_user_unit_and_enables_it(self):
        calls = []
        ok, msg = A.service_install({}, platform="linux", run=lambda argv: calls.append(argv) or (True, ""))
        self.assertTrue(ok, msg)
        unit = (self.tmp / "home" / ".config" / "systemd" / "user" / "aigw-claude-auth.service").read_text()
        self.assertIn(" daemon\n", unit)
        self.assertIn("Restart=on-failure", unit)
        self.assertIn(["systemctl", "--user", "enable", "--now", "aigw-claude-auth.service"], calls)
        self.assertIn("--linger", msg)

    def linux(self, linger=False, show="no", enable=(True, ""), reload=(True, "")):
        calls = []

        def run(argv):
            calls.append(argv)
            if argv[:2] == ["systemctl", "--user"] and argv[2] == "daemon-reload":
                return reload
            if argv[:2] == ["loginctl", "show-user"]:
                return True, show
            if argv[:2] == ["loginctl", "enable-linger"]:
                return enable
            return True, ""
        ok, msg = A.service_install({}, platform="linux", run=run, linger=linger)
        return ok, msg, calls

    def test_linux_does_not_enable_lingering_by_default_and_says_when_to_use_it(self):
        ok, msg, calls = self.linux()
        self.assertTrue(ok, msg)
        self.assertFalse([c for c in calls if c[0] == "loginctl"], calls)
        for hint in ("--linger", "SSH-only or headless", "tmux"):
            self.assertIn(hint, msg)

    def test_linger_enables_lingering(self):
        ok, msg, calls = self.linux(linger=True)
        self.assertTrue(ok, msg)
        self.assertIn(["loginctl", "enable-linger"], calls)
        self.assertIn("lingering is on", msg)
        self.assertIn("disable-linger", msg)

    def test_linger_leaves_lingering_that_is_already_on_alone(self):
        ok, msg, calls = self.linux(linger=True, show="yes\n")
        self.assertTrue(ok, msg)
        self.assertNotIn(["loginctl", "enable-linger"], calls)
        self.assertIn("already on", msg)

    def test_a_refused_linger_is_a_warning_and_the_service_still_counts(self):
        ok, msg, _ = self.linux(linger=True, enable=(False, "Access denied"))
        self.assertTrue(ok, msg)
        self.assertIn("warning: could not enable lingering (Access denied)", msg)
        self.assertIn("sudo loginctl enable-linger", msg)

    def test_linger_is_not_attempted_when_the_service_did_not_start(self):
        ok, msg, calls = self.linux(linger=True, reload=(False, "no bus"))
        self.assertFalse(ok)
        self.assertFalse([c for c in calls if c[0] == "loginctl"], calls)

    def test_install_passes_linger_on_and_ignores_it_without_a_service(self):
        self.settings_path.parent.mkdir(parents=True, exist_ok=True)
        self.write_config(mode="proxy", gateway_url="https://gw.example.com", proxy_listen=f"127.0.0.1:{free_port()}")
        with mock.patch.object(A, "service_install", return_value=(True, "x")) as si:
            code, _, err = self.run_cli("install", "--linger")
        self.assertEqual(code, 0, err)
        self.assertEqual(si.call_args.kwargs, {"linger": True})
        with mock.patch.object(A, "service_install") as si:
            code, _, err = self.run_cli("install", "--linger", "--no-service")
        self.assertEqual(code, 0, err)
        si.assert_not_called()
        self.assertIn("--linger ignored", err)

    def test_linger_is_for_linux_only(self):
        self.settings_path.parent.mkdir(parents=True, exist_ok=True)
        self.write_config(mode="proxy", gateway_url="https://gw.example.com", proxy_listen=f"127.0.0.1:{free_port()}")
        with mock.patch.object(A, "service_install", return_value=(True, "x")), mock.patch.object(A.sys, "platform", "darwin"):
            code, _, err = self.run_cli("install", "--linger")
        self.assertEqual(code, 0, err)
        self.assertIn("--linger is for Linux", err)

    def test_the_help_says_when_to_use_linger(self):
        out = io.StringIO()
        with redirect_stdout(out), self.assertRaises(SystemExit) as cm:
            A.main(["install", "--help"])
        self.assertEqual(cm.exception.code, 0)
        text = " ".join(out.getvalue().split())
        for hint in ("--linger", "SSH-only or headless", "tmux or screen", "A desktop does not need it", "Off by default"):
            self.assertIn(hint, text)

    def test_linux_without_a_user_session_says_why(self):
        run = lambda argv: (False, "Failed to connect to bus") if "daemon-reload" in argv else (True, "")
        ok, msg = A.service_install({}, platform="linux", run=run)
        self.assertFalse(ok)
        self.assertIn("no systemd user session answered", msg)

    def test_unsupported_platform_says_so(self):
        ok, msg = A.service_install({}, platform="freebsd", run=lambda argv: (True, ""))
        self.assertFalse(ok)
        self.assertIn("no service manager for freebsd", msg)

    def test_install_no_service_skips_the_service(self):
        self.settings_path.parent.mkdir(parents=True, exist_ok=True)
        self.write_config(mode="proxy", gateway_url="https://gw.example.com", proxy_listen=f"127.0.0.1:{free_port()}")
        with mock.patch.object(A, "service_install") as si:
            code, _, err = self.run_cli("install", "--no-service")
        self.assertEqual(code, 0, err)
        si.assert_not_called()
        self.assertIn("--no-service", err)


class ProxyInstallTests(Base):
    def setUp(self):
        super().setUp()
        self.port = free_port()
        self.settings_path.parent.mkdir(parents=True, exist_ok=True)
        self.sign_in()

    def settings_data(self):
        return json.loads(self.settings_path.read_text())

    def headers(self):
        return (self.settings_data().get("env") or {}).get("ANTHROPIC_CUSTOM_HEADERS", "")

    def test_install_in_proxy_mode_writes_the_base_url_the_secret_and_no_jwt(self):
        self.settings_path.write_text(json.dumps({"model": "opus", "env": {"ANTHROPIC_CUSTOM_HEADERS": "x-team: blue\nx-portkey-api-key: " + jwt(time.time() + 3600)}}))
        self.write_config(mode="proxy", gateway_url="https://gw.example.com", proxy_listen=f"127.0.0.1:{self.port}")
        code, _, err = self.run_cli("install")
        self.assertEqual(code, 0, err)
        d = self.settings_data()
        self.assertEqual(d["env"]["ANTHROPIC_BASE_URL"], f"http://127.0.0.1:{self.port}")
        self.assertEqual(d["model"], "opus")
        lines = d["env"]["ANTHROPIC_CUSTOM_HEADERS"].split("\n")
        self.assertIn("x-team: blue", lines)
        self.assertIn(f"{A.LOCAL_HEADER}: {A.proxy_secret(A.State(self.state_dir))}", lines)
        self.assertFalse([l for l in lines if l.lower().startswith("x-portkey-api-key")], "the JWT must be gone")
        self.assertTrue(hook_words(d["hooks"]["UserPromptSubmit"][0]["hooks"][0]).endswith("hook precheck"))
        self.assertEqual(self.run_cli("install")[0], 0)           # idempotent, same secret
        self.assertEqual(self.settings_data(), d)

    def test_install_in_proxy_mode_refuses_base_url_and_port_zero(self):
        self.write_config(mode="proxy", gateway_url="https://gw.example.com", proxy_listen=f"127.0.0.1:{self.port}")
        self.assertIn("gateway_url", self.run_cli("install", "--base-url", "https://x.example")[2])
        self.write_config(mode="proxy", gateway_url="https://gw.example.com", proxy_listen="127.0.0.1:0")
        code, _, err = self.run_cli("install")
        self.assertEqual(code, 1)
        self.assertIn("fixed port", err)

    def test_install_print_has_no_secret(self):
        self.write_config(mode="proxy", gateway_url="https://gw.example.com", proxy_listen=f"127.0.0.1:{self.port}")
        code, out, err = self.run_cli("install", "--print")
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out)["env"], {"ANTHROPIC_BASE_URL": f"http://127.0.0.1:{self.port}"})
        self.assertFalse(self.state_dir.joinpath("proxy-secret").exists())

    def test_switching_modes_cleans_up_the_other_modes_entries(self):
        self.write_config(mode="file", proxy_listen=f"127.0.0.1:{self.port}", gateway_url="")
        self.assertEqual(self.run_cli("install", "--base-url", "https://gw.example.com")[0], 0)
        self.assertEqual(A.jwt_claims(self.header())["kind"], "gateway")
        # file -> proxy
        self.write_config(mode="proxy", gateway_url="https://gw.example.com", proxy_listen=f"127.0.0.1:{self.port}")
        self.assertEqual(self.run_cli("install")[0], 0)
        self.assertEqual(self.header(), "", "the JWT is gone from the settings")
        self.assertIn(A.LOCAL_HEADER, self.headers())
        self.assertEqual(self.settings_data()["env"]["ANTHROPIC_BASE_URL"], f"http://127.0.0.1:{self.port}")
        # proxy -> file
        self.write_config(mode="file", proxy_listen=f"127.0.0.1:{self.port}", gateway_url="https://gw.example.com")
        self.assertEqual(self.run_cli("install", "--base-url", "https://gw.example.com")[0], 0)
        self.assertNotIn(A.LOCAL_HEADER, self.headers())
        self.assertEqual(self.settings_data()["env"]["ANTHROPIC_BASE_URL"], "https://gw.example.com")
        self.assertEqual(A.jwt_claims(self.header())["kind"], "gateway")

    def test_back_to_file_without_a_base_url_removes_the_proxy_address(self):
        self.settings_path.write_text(json.dumps({"env": {"ANTHROPIC_BASE_URL": f"http://127.0.0.1:{self.port}", "ANTHROPIC_CUSTOM_HEADERS": f"{A.LOCAL_HEADER}: abc"}}))
        self.write_config(mode="file", proxy_listen=f"127.0.0.1:{self.port}")
        code, _, err = self.run_cli("install")
        self.assertEqual(code, 0, err)
        self.assertNotIn("ANTHROPIC_BASE_URL", self.settings_data()["env"])
        self.assertIn("--base-url", err)

    def test_file_mode_install_is_unchanged(self):
        self.assertEqual(self.run_cli("install", "--base-url", "https://gw.example.com")[0], 0)
        self.assertEqual(self.settings_data()["env"]["ANTHROPIC_BASE_URL"], "https://gw.example.com")
        self.assertFalse(self.state_dir.joinpath("proxy-secret").exists())
        self.assertNotIn(A.LOCAL_HEADER, self.headers())


class ProxyDoctorTests(ProxyBase):
    """Doctor against a proxy-mode configuration. The proxy in setUp listens on a free port; settings come from install."""

    def setUp(self):
        self.port_wanted = free_port()
        super().setUp()

    def configure(self, **over):
        self.write_config(**dict(dict(mode="proxy", gateway_url=self.gw.url, proxy_listen=f"127.0.0.1:{self.port_wanted}"), **over))

    def installed(self):
        self.assertEqual(self.run_cli("install")[0], 0)

    def doctor(self):
        code, out, _ = self.run_cli("doctor", "--json")
        return {f["id"]: f for f in json.loads(out)["findings"]}

    def test_a_clean_proxy_setup(self):
        self.installed()
        with mock.patch.dict(os.environ, {"CLAUDE_CONFIG_DIR": str(self.settings_path.parent)}):
            ids = self.doctor()
        self.assertEqual({k: v["severity"] for k, v in ids.items() if v["severity"] != "Info"}, {})

    def test_base_url_that_is_not_the_proxy(self):
        self.installed()
        d = json.loads(self.settings_path.read_text())
        d["env"]["ANTHROPIC_BASE_URL"] = "http://127.0.0.1:9"
        self.settings_path.write_text(json.dumps(d))
        self.assertEqual(self.doctor()["proxy-listen"]["severity"], "Error")
        d["env"].pop("ANTHROPIC_BASE_URL")
        self.settings_path.write_text(json.dumps(d))
        self.assertIn("not set", self.doctor()["proxy-listen"]["message"])
        self.managed.mkdir(parents=True, exist_ok=True)
        (self.managed / "managed-settings.json").write_text(json.dumps({"env": {"ANTHROPIC_BASE_URL": "http://gw.example"}}))
        self.assertEqual(self.doctor()["proxy-listen"]["severity"], "Error")
        (self.managed / "managed-settings.json").write_text(json.dumps({"env": {"ANTHROPIC_BASE_URL": f"http://127.0.0.1:{self.port_wanted}"}}))
        self.assertNotIn("proxy-listen", self.doctor())

    def test_proxy_not_running_and_port_taken(self):
        self.installed()
        self.assertNotIn("proxy-not-running", self.doctor())
        self.assertNotIn("proxy-port-taken", self.doctor())
        self.ps.stop()
        self.assertEqual(self.doctor()["proxy-not-running"]["severity"], "Error")
        import socket
        sk = socket.socket()
        self.addCleanup(sk.close)
        sk.bind(("127.0.0.1", self.port_wanted))
        sk.listen(5)
        ids = self.doctor()
        self.assertNotIn("proxy-not-running", ids)
        self.assertEqual(ids["proxy-port-taken"]["severity"], "Error")

    def test_a_jwt_left_in_the_settings_is_a_warning(self):
        self.installed()
        self.put_header(jwt(time.time() + 3600))
        self.assertEqual(self.doctor()["proxy-jwt-in-settings"]["severity"], "Warning")
        self.run_cli("install")
        self.assertNotIn("proxy-jwt-in-settings", self.doctor())

    def test_missing_or_wrong_local_secret(self):
        self.installed()
        d = json.loads(self.settings_path.read_text())
        d["env"]["ANTHROPIC_CUSTOM_HEADERS"] = f"{A.LOCAL_HEADER}: wrong"
        self.settings_path.write_text(json.dumps(d))
        self.assertEqual(self.doctor()["proxy-secret"]["severity"], "Error")
        d["env"].pop("ANTHROPIC_CUSTOM_HEADERS")
        self.settings_path.write_text(json.dumps(d))
        self.assertIn("no x-aigw-local", self.doctor()["proxy-secret"]["message"])

    def test_managed_custom_headers_hide_the_secret(self):
        self.installed()
        self.managed.mkdir(parents=True, exist_ok=True)
        (self.managed / "managed-settings.json").write_text(json.dumps({"env": {"ANTHROPIC_CUSTOM_HEADERS": "x: y"}}))
        ids = self.doctor()
        self.assertEqual(ids["managed-custom-headers"]["severity"], "Error")
        self.assertIn(A.LOCAL_HEADER, ids["managed-custom-headers"]["message"])

    def test_gateway_url_missing(self):
        self.write_config(mode="proxy", gateway_url="", proxy_listen=f"127.0.0.1:{self.port_wanted}")
        self.assertEqual(self.doctor()["proxy-gateway-url"]["severity"], "Error")


class ProxyHookTests(ProxyDoctorTests):
    """The hooks in proxy mode (the settings come from install, so the doctor gate is clean)."""

    def setUp(self):
        super().setUp()
        self.installed()
        env = mock.patch.dict(os.environ, {"CLAUDE_CONFIG_DIR": str(self.settings_path.parent)})
        env.start()
        self.addCleanup(env.stop)

    def test_precheck_is_silent_when_the_proxy_has_a_jwt(self):
        self.renew()
        t0 = time.time()
        code, out, _ = self.run_cli("hook", "precheck", stdin="{}")
        self.assertEqual((code, out), (0, ""))
        self.assertLess(time.time() - t0, 2, "no settings reload to wait for")

    def test_precheck_makes_the_proxy_renew(self):
        self.ps.holder.forget()
        code, out, _ = self.run_cli("hook", "precheck", stdin="{}")
        self.assertEqual((code, out), (0, ""))
        self.assertTrue(self.ps.holder.usable())
        self.assertFalse(self.header(), "nothing is written to the settings")

    def test_precheck_blocks_when_the_proxy_is_down(self):
        self.ps.stop()
        code, out, _ = self.run_cli("hook", "precheck", stdin="{}")
        d = json.loads(out)
        self.assertEqual(d["decision"], "block")
        self.assertIn("proxy", d["reason"])

    def test_precheck_blocks_with_the_sign_in_when_signed_out(self):
        self.state_dir.joinpath("state.json").write_text("{}")
        self.ps.holder.forget()
        self.idp.device_pending = 10**6
        code, out, err = self.run_cli("hook", "precheck", stdin="{}")
        self.assertTrue(out, err)
        d = json.loads(out)
        self.assertEqual(d["decision"], "block")
        self.assertIn("ABCD-EFGH", d["reason"])
        pending = json.loads(self.state_dir.joinpath("hook-login.json").read_text())
        self.addCleanup(lambda: os.kill(pending["pid"], 15))

    def test_stop_failure_forces_a_renewal_in_the_proxy(self):
        old = self.renew()
        payload = json.dumps({"last_assistant_message": "API Error: 498 AI gateway token expired"})
        code, _, err = self.run_cli("hook", "stop-failure", stdin=payload)
        self.assertEqual(code, 0)
        self.assertNotEqual(self.ps.holder.token, old)
        self.assertFalse(self.header())


class ProxyDaemonTests(Base):
    def test_the_daemon_serves_renews_and_stops_on_signal(self):
        gw = FakeGateway()
        self.addCleanup(gw.close)
        self.sign_in()
        self.settings_path.parent.mkdir(parents=True, exist_ok=True)
        self.write_config(mode="proxy", gateway_url=gw.url, proxy_listen=f"127.0.0.1:{free_port()}")
        self.assertEqual(self.run_cli("install")[0], 0)       # the settings the doctor gate wants: base URL and local secret
        installed = self.settings_path.read_text()
        seen = {}

        def client():
            import http.client
            end = time.time() + 15
            while time.time() < end:
                try:
                    info = json.loads(self.state_dir.joinpath("proxy.json").read_text())
                    secret = A.proxy_secret(A.State(self.state_dir))
                    if not secret:
                        raise OSError
                    c = http.client.HTTPConnection("127.0.0.1", info["port"], timeout=5)
                    c.request("POST", "/v1/messages", body=b"{}", headers={A.LOCAL_HEADER: secret})
                    r = c.getresponse()
                    seen["status"], seen["pid"] = r.status, info["pid"]
                    r.read()
                    c.close()
                    if r.status == 200:
                        break
                except (OSError, ValueError):
                    pass
                time.sleep(0.2)
            __import__("signal").raise_signal(__import__("signal").SIGTERM)

        threading.Thread(target=client, daemon=True).start()
        code, _, err = self.run_cli("daemon", "--max-sleep", "5")
        self.assertEqual(code, 0, err)
        self.assertEqual(seen.get("status"), 200, err)
        self.assertEqual(seen["pid"], os.getpid())
        self.assertIn("proxy listening", err)
        self.assertIn("proxy stopped", err)
        self.assertFalse(self.state_dir.joinpath("proxy.json").exists(), "the endpoint file is removed on exit")
        self.assertEqual(self.settings_path.read_text(), installed, "the daemon never writes the settings in proxy mode")

    def test_a_second_instance_exits_quietly(self):
        gw = FakeGateway()
        self.addCleanup(gw.close)
        port = free_port()
        self.write_config(mode="proxy", gateway_url=gw.url, proxy_listen=f"127.0.0.1:{port}")
        cfg = A.load_config(self.config_path)
        first = A.ProxyServer(cfg, A.State(self.state_dir), A.Settings(self.settings_path, cfg["header"]))
        first.start()
        self.addCleanup(first.stop)
        code, _, err = self.run_cli("daemon", "--max-sleep", "5")
        self.assertEqual(code, 0)
        self.assertIn("already running", err)

    def test_a_blocked_proxy_looks_again_and_a_fix_clears_it(self):
        gw = FakeGateway()
        self.addCleanup(gw.close)
        self.sign_in()
        self.settings_path.parent.mkdir(parents=True, exist_ok=True)
        self.write_config(mode="proxy", gateway_url=gw.url, proxy_listen="127.0.0.1:0")
        cfg = A.load_config(self.config_path)
        cfg["_config_path"] = str(self.config_path)
        ps = A.ProxyServer(cfg, A.State(self.state_dir), A.Settings(self.settings_path, cfg["header"]))
        ps.start()
        self.addCleanup(ps.stop)
        ps.blocked = {"id": "x", "message": "boom", "fix": "f", "severity": "Error"}
        ps.blocked_checked = 0                                # due for a re-check: the doctor has no Error now
        import http.client
        c = http.client.HTTPConnection("127.0.0.1", ps.port, timeout=10)
        with mock.patch.object(A, "preflight_errors", return_value=[]):
            c.request("POST", "/v1/messages", body=b"{}", headers={A.LOCAL_HEADER: ps.secret})
            self.assertEqual(c.getresponse().status, 200)
        self.assertIsNone(ps.blocked)


if __name__ == "__main__":
    unittest.main()
