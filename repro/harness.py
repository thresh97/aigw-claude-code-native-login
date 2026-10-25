#!/usr/bin/env python3
"""Runs Claude Code against the mock (or relayed real) gateway and prints observations; run.sh / run.py judge them.

Usage:  harness.py <scenario> --out DIR          (run.sh calls this; see `run.sh list`)

Output on stdout: one `key=value` line per observation, nothing else. Details (request logs with credential
fingerprints, Claude Code's stream output, hook payloads) go to DIR. No token or secret is ever printed or written:
the mock and the relay log fingerprints, and stored-login state is reduced to hashes.

Every Claude Code run gets a throwaway HOME, cwd and (except the stored-login scenarios) CLAUDE_CONFIG_DIR, and an
environment with no Anthropic, Vertex or Bedrock variables from the caller, so nothing of the user's setup is used
or touched. The client (client/aigw_claude_auth.py) runs as the hooks, exactly as `install` sets them up, against a
fake IdP and token broker (from the client's tests).
"""
import argparse
import hashlib
import http.client
import json
import os
import queue
import re
import shlex
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path[:0] = [str(HERE), str(ROOT / "client")]
import mock_gateway  # noqa: E402
import proxy_prototype  # noqa: E402
from test_aigw_claude_auth import FakeIdP, jwt  # noqa: E402

CLIENT = ROOT / "client" / "aigw_claude_auth.py"
CLAUDE = os.environ.get("CLAUDE_BIN") or shutil.which("claude") or "claude"
MODEL = os.environ.get("MODEL") or "claude-haiku-4-5"
OAUTH = "sk-ant-oat01-mock"     # a dummy; what the mock gateway expects as the Anthropic login in Authorization
PK = "x-portkey-api-key"
SENTINEL = os.environ.get("SENTINEL") or "expired"
IS_WIN = sys.platform == "win32"


def observe(key, value):
    print(f"{key}={value}", flush=True)


def wait_until(cond, timeout=20, step=0.5):
    """Poll cond() until it's true or timeout seconds pass. Hooks run after the turn's result is out, and how long
    after varies (seconds on a busy or slower machine), so fixed sleeps make the checks flaky."""
    end = time.monotonic() + timeout
    while not cond():
        if time.monotonic() > end:
            return False
        time.sleep(step)
    return True


def try_chmod(path, mode):
    """Best effort: on Windows chmod only sets the read-only flag, and a failure must not end a run."""
    try:
        os.chmod(path, mode)
    except OSError:
        pass


def kill_tree(proc):
    """Stop proc and its children. Windows has no process groups to signal: taskkill /T walks the tree, so files the
    children hold open are released before the throwaway dirs are removed."""
    if IS_WIN:
        subprocess.run(["taskkill", "/T", "/F", "/PID", str(proc.pid)], capture_output=True)
    try:
        proc.kill()
    except OSError:
        pass


def rmtree(path):
    """shutil.rmtree that retries on Windows, where a file a just-killed process held can stay locked for a moment."""
    tries = 10 if IS_WIN else 1
    for _ in range(tries):
        shutil.rmtree(path, ignore_errors=True)
        if not Path(path).exists():
            return
        time.sleep(0.5)


def command_hook(argv, **extra):
    """A hook entry for the command argv. Windows: exec form (command + args), which runs with no shell under both Git
    Bash and PowerShell and passes the arguments verbatim (README finding 17). Elsewhere: one POSIX-quoted string."""
    if IS_WIN:
        return {"type": "command", "command": argv[0], "args": list(argv[1:]), **extra}
    return {"type": "command", "command": " ".join(shlex.quote(a) for a in argv), **extra}


def secs(t0):
    return round(time.time() - t0, 1)


# --------------------------------------------------------------------------------------------- the pieces

class Gateway:
    """mock_gateway in this process: control file, request log, helpers to read it."""

    def __init__(self, out, upstream=None, **control):
        self.log = out / "gateway.log.jsonl"
        self.control_file = out / "gateway.control.json"
        self.log.touch()
        self.control = {"sentinel": SENTINEL, "oauth": OAUTH, "guard": False, "revoked": []}
        self.set(**control)
        self.srv = mock_gateway.serve(str(self.log), str(self.control_file), upstream)
        self.url = f"http://127.0.0.1:{self.srv.server_address[1]}"

    def set(self, **kw):
        self.control.update(kw)
        self.control_file.write_text(json.dumps(self.control), encoding="utf-8")

    def messages(self, since=0):
        rows = [json.loads(line) for line in self.log.read_text(encoding="utf-8").splitlines()]
        return [r for r in rows if r["path"].split("?")[0].endswith("/v1/messages")][since:]

    def mark(self):
        return len(self.messages())

    def close(self):
        self.srv.shutdown()


class Client:
    """The client's config and state in a throwaway dir, pointed at a fake IdP and broker."""

    def __init__(self, base, idp, **cfg):
        self.dir = base / "aigw-claude-auth"
        self.dir.mkdir(parents=True)
        self.idp = idp
        self.cfg = {"issuer": idp.url, "client_id": "cli", "scope": "openid offline_access", "broker_url": idp.url + "/exchange",
                    "notify": "off", "hook_wait": 3}
        self.configure(**cfg)

    def configure(self, **kw):
        self.cfg.update(kw)
        (self.dir / "config.json").write_text(json.dumps(self.cfg), encoding="utf-8")

    def sign_in(self):
        """What a finished `aigw-claude-auth login` leaves behind: a refresh token the IdP knows."""
        (self.dir / "state.json").write_text(json.dumps({"refresh_token": self.idp.tokens()["refresh_token"]}), encoding="utf-8")
        try_chmod(self.dir / "state.json", 0o600)

    def sign_out(self):
        (self.dir / "state.json").write_text("{}", encoding="utf-8")

    def run(self, *args, settings):
        env = dict(os.environ, AIGW_CLAUDE_AUTH_DIR=str(self.dir), AIGW_CLAUDE_SETTINGS=str(settings))
        return subprocess.run([sys.executable, str(CLIENT), *args], env=env, capture_output=True, encoding="utf-8", errors="replace", timeout=60)


class Claude:
    """Claude Code in a throwaway HOME/cwd. persistent(): one session fed turns over stream-json; oneshot(): `claude -p`."""

    CLEAN = ("PATH", "LANG", "LC_ALL", "TZ", "SSL_CERT_FILE", "NODE_EXTRA_CA_CERTS", "HTTPS_PROXY", "https_proxy", "NO_PROXY", "no_proxy")
    # Windows: what a process needs to start and to find programs and temp files. The profile locations (USERPROFILE,
    # APPDATA, LOCALAPPDATA) are throwaway, like HOME.
    CLEAN_WIN = ("SystemRoot", "SystemDrive", "windir", "ComSpec", "PATHEXT", "TEMP", "TMP", "ProgramFiles", "ProgramFiles(x86)",
                 "ProgramW6432", "ProgramData", "CommonProgramFiles", "PROCESSOR_ARCHITECTURE", "NUMBER_OF_PROCESSORS", "OS")

    def __init__(self, out, base_url, config_dir=None, env=None):
        self.out = out
        self.tmp = Path(tempfile.mkdtemp(prefix="aigw-repro-"))
        self.config_dir = Path(config_dir) if config_dir else self.tmp / "claude"
        self.config_dir.mkdir(exist_ok=True)
        (self.tmp / "cwd").mkdir()
        self.settings_file = self.config_dir / "settings.json"
        self.env = {k: os.environ[k] for k in self.CLEAN + (self.CLEAN_WIN if IS_WIN else ()) if k in os.environ}
        self.env.update(HOME=str(self.tmp), CLAUDE_CONFIG_DIR=str(self.config_dir), TERM="dumb", ANTHROPIC_MODEL=MODEL,
                        ANTHROPIC_BASE_URL=base_url, CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC="1", DISABLE_AUTOUPDATER="1",
                        DISABLE_TELEMETRY="1")
        if IS_WIN:
            appdata, local = self.tmp / "AppData" / "Roaming", self.tmp / "AppData" / "Local"
            appdata.mkdir(parents=True)
            local.mkdir(parents=True)
            self.env.update(USERPROFILE=str(self.tmp), APPDATA=str(appdata), LOCALAPPDATA=str(local))
        if config_dir and sys.platform == "darwin":
            # a stored login on macOS is in the login Keychain, which is found through the real HOME
            self.env.update({k: os.environ[k] for k in ("HOME", "USER") if k in os.environ})
        self.env.update(env or {})
        self.proc = None
        self.lines = queue.Queue()
        self.args = []          # extra command-line arguments for start()

    def settings(self):
        return json.loads(self.settings_file.read_text(encoding="utf-8")) if self.settings_file.exists() else {}

    def write_settings(self, d):
        self.settings_file.write_text(json.dumps(d, indent=2), encoding="utf-8")

    def oneshot(self, prompt, timeout=420):
        t0 = time.time()
        try:
            p = subprocess.run([CLAUDE, "-p", prompt, "--output-format", "json"], cwd=self.tmp / "cwd", env=self.env,
                               stdin=subprocess.DEVNULL, capture_output=True, encoding="utf-8", errors="replace", timeout=timeout)
            with open(self.out / "claude.oneshot.jsonl", "a", encoding="utf-8") as f:
                f.write(p.stdout.strip() + "\n")
            j = json.loads(p.stdout or "{}")
        except (subprocess.TimeoutExpired, ValueError) as e:
            j = {"is_error": True, "result": type(e).__name__}
        return {"seconds": secs(t0), "is_error": bool(j.get("is_error")), "text": str(j.get("result") or "")}

    def start(self):
        cmd = [CLAUDE, "-p", "--input-format", "stream-json", "--output-format", "stream-json", "--verbose", *self.args]
        self.proc = subprocess.Popen(cmd, cwd=self.tmp / "cwd", env=self.env, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                     stderr=open(self.out / "claude.stderr.txt", "a", encoding="utf-8"), encoding="utf-8", errors="replace")
        threading.Thread(target=lambda: [self.lines.put(line) for line in self.proc.stdout] and self.lines.put(None), daemon=True).start()

    def turn(self, prompt, timeout=420):
        """Send one user message, wait for its result. Returns seconds, is_error and the result text."""
        t0 = time.time()
        self.proc.stdin.write(json.dumps({"type": "user", "message": {"role": "user", "content": prompt}}) + "\n")
        self.proc.stdin.flush()
        result = None
        with open(self.out / "claude.stream.jsonl", "a", encoding="utf-8") as f:
            while time.time() - t0 < timeout:
                try:
                    line = self.lines.get(timeout=1)
                except queue.Empty:
                    continue
                if line is None:
                    result = {"is_error": True, "result": "claude exited"}
                    break
                f.write(line)
                try:
                    j = json.loads(line)
                except ValueError:
                    continue
                if j.get("type") == "result":
                    result = j
                    break
        result = result or {"is_error": True, "result": "TIMEOUT"}
        time.sleep(0.5)          # let the gateway log the last request
        return {"seconds": secs(t0), "is_error": bool(result.get("is_error")), "text": str(result.get("result") or "")}

    def stop(self):
        if self.proc:
            try:
                self.proc.stdin.close()
                self.proc.wait(timeout=20)
            except Exception:
                kill_tree(self.proc)

    def cleanup(self):
        self.stop()
        rmtree(self.tmp)


def fresh_jwt(lifetime=3600, **claims):
    return jwt(time.time() + lifetime, kind="gateway", **claims)


def header_of(settings_dict):
    """Our header's value from a settings dict ('' if absent)."""
    for line in (settings_dict.get("env", {}).get("ANTHROPIC_CUSTOM_HEADERS") or "").splitlines():
        k, _, v = line.partition(":")
        if k.strip().lower() == PK:
            return v.strip()
    return ""


def fp(value):
    return hashlib.sha256(value.encode()).hexdigest()[:10] if value else "none"


def classify(text):
    """Which side a failure message names: portkey, anthropic, gateway-token (LB guard), other or ok."""
    if "Portkey Error" in text:
        return "portkey"
    if "anthropic error" in text:
        return "anthropic"
    if "AI gateway token" in text:
        return "gateway-token"
    return "ok" if "MOCK-OK" in text or "LIVE-OK" in text else "other"


def capture_hook(out, label):
    """A hook command that appends its stdin (the hook payload) to out/hook.<label>.jsonl."""
    script = out / "capture_hook.py"
    script.write_text("import sys\nwith open(sys.argv[1], 'a', encoding='utf-8') as f:\n    f.write(sys.stdin.read().strip() + '\\n')\n", encoding="utf-8")
    return {"hooks": [command_hook([sys.executable, str(script), str(out / f"hook.{label}.jsonl")])]}


def notify_command(out, note):
    """The client's `notify` setting: a command that gets the message as its last argument and appends it to `note`.
    POSIX: a #!/bin/sh script. Windows: a Python script, run as `python script note` with forward slashes so the
    client's shlex.split of the setting keeps the paths whole."""
    if IS_WIN:
        script = out / "notify.py"
        script.write_text("import sys\nwith open(sys.argv[1], 'a', encoding='utf-8') as f:\n    f.write(sys.argv[2] + '\\n')\n", encoding="utf-8")
        return " ".join(f'"{Path(x).as_posix()}"' for x in (sys.executable, script, note))
    script = out / "notify.sh"
    script.write_text(f'#!/bin/sh\nprintf "%s\\n" "$1" >> {shlex.quote(str(note))}\n', encoding="utf-8")
    script.chmod(0o755)
    return str(script)


def payloads(out, label):
    f = out / f"hook.{label}.jsonl"
    return [json.loads(line) for line in f.read_text(encoding="utf-8").splitlines() if line.strip()] if f.exists() else []


def borrow_settings(settings_file):
    """Before a scenario replaces the settings.json of the user's LOGIN_CONFIG_DIR: keep a copy on disk
    (settings.json.repro-backup), so a killed run can still be undone. A backup left by a killed run is the original."""
    backup = settings_file.with_name(settings_file.name + ".repro-backup")
    if not backup.exists():
        data = {"existed": settings_file.exists(), "text": settings_file.read_text(encoding="utf-8") if settings_file.exists() else ""}
        with os.fdopen(os.open(backup, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w", encoding="utf-8") as f:   # may hold a JWT
            json.dump(data, f)
    return backup


def return_settings(settings_file, backup):
    saved = json.loads(backup.read_text(encoding="utf-8"))
    if saved["existed"]:
        settings_file.write_text(saved["text"], encoding="utf-8")
    else:
        settings_file.unlink(missing_ok=True)
    backup.unlink()


def cred_state(config_dir):
    """A stored `claude login`, reduced to hashes and the expiry (never the tokens)."""
    f = Path(config_dir) / ".credentials.json"
    if f.exists():
        o = json.loads(f.read_text(encoding="utf-8")).get("claudeAiOauth", {})
    elif sys.platform == "darwin":
        # macOS keeps it in the login Keychain; with CLAUDE_CONFIG_DIR the item's service name ends in the first 8 hex
        # of sha256(the config dir path)
        service = "Claude Code-credentials-" + hashlib.sha256(str(config_dir).encode()).hexdigest()[:8]
        r = subprocess.run(["security", "find-generic-password", "-s", service, "-w"], capture_output=True, encoding="utf-8", errors="replace", timeout=10)
        if r.returncode != 0 or not r.stdout.strip():
            return {"exists": False}
        o = json.loads(r.stdout).get("claudeAiOauth", {})
    else:
        return {"exists": False}
    return {"exists": True, "expiresAt": o.get("expiresAt"), "access": fp(o.get("accessToken", "")), "refresh": fp(o.get("refreshToken", ""))}


def login_valid(state):
    return state.get("exists") and (state.get("expiresAt") or 0) / 1000 > time.time()


# --------------------------------------------------------------------------------------------- scenarios

def scenario_headers(out):
    """`install` writes the gateway URL, the JWT header and the hooks; a running session picks up a JWT the client
    renews (atomic rename of settings.json) without a restart; the Anthropic login travels untouched in Authorization."""
    gw, idp = Gateway(out), FakeIdP()
    claude = Claude(out, gw.url, env={"CLAUDE_CODE_OAUTH_TOKEN": OAUTH})
    client = Client(claude.tmp, idp)
    claude.env["AIGW_CLAUDE_AUTH_DIR"] = str(client.dir)
    try:
        client.sign_in()
        r = client.run("install", "--base-url", gw.url, settings=claude.settings_file)
        observe("install_exit", r.returncode)
        s = claude.settings()
        observe("settings_base_url", "gateway" if s.get("env", {}).get("ANTHROPIC_BASE_URL") == gw.url else "other")
        observe("settings_hooks", ",".join(sorted(s.get("hooks", {}))))
        jwt1 = header_of(s)
        claude.start()
        mark = gw.mark()
        t = claude.turn("turn 1")
        reqs = gw.messages(mark)
        observe("turn1", classify(t["text"]))
        observe("turn1_authorization", "oauth" if reqs and reqs[0]["headers"].get("authorization") == mock_gateway.fingerprint(f"Bearer {OAUTH}") else "other")
        observe("turn1_gateway_header", "jwt1" if reqs and reqs[0]["headers"].get(PK) == mock_gateway.fingerprint(jwt1) else "other")
        ino = claude.settings_file.stat().st_ino
        r = client.run("sync", "--force", settings=claude.settings_file)
        jwt2 = header_of(claude.settings())
        observe("renewed_by_rename", "yes" if r.returncode == 0 and claude.settings_file.stat().st_ino != ino and jwt2 != jwt1 else "no")
        time.sleep(3)
        mark = gw.mark()
        t = claude.turn("turn 2, after the client renewed the JWT")
        reqs = gw.messages(mark)
        observe("turn2", classify(t["text"]))
        observe("turn2_gateway_header", {mock_gateway.fingerprint(jwt2): "jwt2", mock_gateway.fingerprint(jwt1): "jwt1"}.get(
            reqs[0]["headers"].get(PK) if reqs else "", "other"))
        observe("turn2_hook_refreshed", "no" if header_of(claude.settings()) == jwt2 else "yes")
    finally:
        claude.cleanup(), gw.close(), idp.close()


def scenario_errors(out):
    """How Claude Code (logged in with CLAUDE_CODE_OAUTH_TOKEN) handles each gateway failure: attempts, time, message,
    and the StopFailure `error` value."""
    gw = Gateway(out)
    claude = Claude(out, gw.url, env={"CLAUDE_CODE_OAUTH_TOKEN": OAUTH})
    good = fresh_jwt()
    claude.write_settings({"env": {"ANTHROPIC_CUSTOM_HEADERS": f"{PK}: {good}"}, "hooks": {"StopFailure": [capture_hook(out, "stopfailure")]}})
    cases = [
        ("portkey401", dict(revoked=[mock_gateway.fingerprint(good)])),
        ("anthropic401", dict(oauth="some-other-login")),
        ("403", dict(force=403)),
        ("407", dict(force=407)),
        ("498", dict(force=498)),
    ]
    try:
        claude.start()
        for name, ctl in cases:
            gw.set(revoked=[], oauth=OAUTH, force=None)
            gw.set(**ctl)
            seen = len(payloads(out, "stopfailure"))
            mark = gw.mark()
            t = claude.turn(f"case {name}")
            time.sleep(1)
            observe(f"{name}_attempts", len(gw.messages(mark)))
            observe(f"{name}_fast", "yes" if t["seconds"] < 15 else f"no ({t['seconds']}s)")
            observe(f"{name}_message", classify(t["text"]) if name.endswith("401") else ("status-shown" if name in t["text"] else "other"))
            wait_until(lambda: len(payloads(out, "stopfailure")) > seen)
            p = payloads(out, "stopfailure")[seen:]
            observe(f"{name}_stopfailure_error", p[0].get("error") if p else "none")
        gw.set(revoked=[], oauth=OAUTH, force=None)
        observe("recovery", classify(claude.turn("recovery")["text"]))
    finally:
        claude.cleanup(), gw.close()


def precheck_session(out, idp_up=True, signed_in=True, hook_wait=3, initial="expired", block=True, guard=False, hook_login="off"):
    """One persistent session with the client installed as the hooks; returns the observations of two turns.
    hook_login="device": the hook starts a device sign-in on turn 1; the "user" finishes it before turn 2."""
    gw, idp = Gateway(out, guard=guard), FakeIdP()
    idp.device_pending = 10**6 if hook_login == "device" else idp.device_pending   # nobody has signed in yet
    claude = Claude(out, gw.url, env={"CLAUDE_CODE_OAUTH_TOKEN": OAUTH})
    client = Client(claude.tmp, idp, hook_wait=hook_wait, block_on_failure=block, hook_login=hook_login)
    claude.env["AIGW_CLAUDE_AUTH_DIR"] = str(client.dir)
    obs = {}
    try:
        client.sign_in() if signed_in else client.sign_out()
        client.run("install", "--base-url", gw.url, settings=claude.settings_file)
        start_jwt = {"expired": jwt(time.time() - 60, kind="gateway"), "valid": fresh_jwt()}[initial]
        s = claude.settings()
        s["env"]["ANTHROPIC_CUSTOM_HEADERS"] = f"{PK}: {start_jwt}"
        claude.write_settings(s)
        if not idp_up:
            idp.close()           # stops answering, but the socket stays bound: connections hang like a dead IdP's
        claude.start()
        for i in (1, 2):
            mark = gw.mark()
            t = claude.turn(f"precheck turn {i}")
            reqs = gw.messages(mark)
            sent = reqs[0]["headers"].get(PK) if reqs else ""
            obs[f"turn{i}"] = classify(t["text"]) if reqs else ("blocked" if "AI gateway" in t["text"] or t["is_error"] else "no-request")
            obs[f"turn{i}_requests"] = len(reqs)
            obs[f"turn{i}_jwt"] = ("none" if not reqs else "initial" if sent == mock_gateway.fingerprint(start_jwt)
                                   else "sentinel" if sent == mock_gateway.fingerprint(SENTINEL) else "renewed")
            obs[f"turn{i}_seconds"] = t["seconds"]
            if hook_login == "device" and i == 1:
                stream = (out / "claude.stream.jsonl").read_text(encoding="utf-8") if (out / "claude.stream.jsonl").exists() else ""
                obs["code_in_message"] = "yes" if "ABCD-EFGH" in stream and "/activate" in stream else "no"
                obs["device_flows"] = sum(1 for c in idp.calls if c[1] == "/device")
                idp.device_pending = 0                     # the user enters the code; the background process finishes
                done = wait_until(lambda: header_of(claude.settings()) not in (SENTINEL, start_jwt, ""))
                obs["signed_in_in_background"] = "yes" if done else "no"
                time.sleep(2)                              # Claude Code reloads the settings about 1 s after the write
        obs["settings_value"] = "sentinel" if header_of(claude.settings()) == SENTINEL else "jwt"
        stream = (out / "claude.stream.jsonl").read_text(encoding="utf-8") if (out / "claude.stream.jsonl").exists() else ""
        obs["block_message"] = "yes" if "blocked by hook" in stream and "AI gateway" in stream else "no"
    finally:
        claude.cleanup(), gw.close()
        if idp_up:
            idp.close()
    return obs


def scenario_precheck(out):
    """The UserPromptSubmit hook renews an expired JWT before the request (and waits for the reload), does nothing
    while the JWT is valid, and blocks the prompt with a sign-in message when no JWT can be had. hooklogin: signed out,
    the block message carries a device code from a sign-in the hook started; once the user finishes it, the next
    prompt goes through."""
    cases = {"expired": dict(), "valid": dict(initial="valid"), "nowait": dict(hook_wait=0),
             "idphang": dict(idp_up=False), "signedout": dict(signed_in=False),
             "hooklogin": dict(signed_in=False, hook_login="device"),
             "lbguard": dict(signed_in=False, block=False, guard=True)}
    for name, kw in cases.items():
        sub = out / name
        sub.mkdir()
        for k, v in precheck_session(sub, **kw).items():
            if k.endswith("_seconds"):
                k, v = k.replace("_seconds", "_fast"), "yes" if v < {"expired": 8, "nowait": 8, "idphang": 20, "lbguard": 8}.get(name, 4) else f"no ({v}s)"
            observe(f"{name}_{k}", v)


def scenario_stopfailure(out):
    """After the gateway refuses a JWT that still looks valid (revoked, key rotated), the StopFailure hook renews it
    and notifies, so the user's retry works. An Anthropic-side failure is left alone."""
    gw, idp = Gateway(out), FakeIdP()
    claude = Claude(out, gw.url, env={"CLAUDE_CODE_OAUTH_TOKEN": OAUTH})
    note = out / "notifications.txt"
    client = Client(claude.tmp, idp, notify=notify_command(out, note))
    claude.env["AIGW_CLAUDE_AUTH_DIR"] = str(client.dir)
    try:
        client.sign_in()
        client.run("install", "--base-url", gw.url, settings=claude.settings_file)
        claude.start()
        observe("baseline", classify(claude.turn("baseline")["text"]))
        bad = header_of(claude.settings())
        gw.set(revoked=[mock_gateway.fingerprint(bad)])
        t = claude.turn("the gateway now refuses this JWT")
        observe("refused_turn", classify(t["text"]))
        wait_until(lambda: header_of(claude.settings()) not in (bad, "") and note.exists() and "renewed" in note.read_text(encoding="utf-8"))
        observe("jwt_replaced", "yes" if header_of(claude.settings()) not in (bad, "") else "no")
        observe("notified", "renewed" if note.exists() and "renewed" in note.read_text(encoding="utf-8") else "no")
        time.sleep(2)
        observe("retry_turn", classify(claude.turn("retry")["text"]))
        cur = header_of(claude.settings())
        gw.set(oauth="some-other-login")
        observe("anthropic_turn", classify(claude.turn("Anthropic refuses the login")["text"]))
        time.sleep(2)
        observe("anthropic_jwt_kept", "yes" if header_of(claude.settings()) == cur else "no")
    finally:
        claude.cleanup(), gw.close(), idp.close()


def scenario_stored_login(out):
    """A stored `claude login` (LOGIN_CONFIG_DIR) against the mock: a gateway 401 sends Claude Code into its OAuth
    refresh-and-retry loop (rotating the real login at Anthropic); 498 is shown at once and leaves the login alone."""
    cfg = Path(os.environ["LOGIN_CONFIG_DIR"]).expanduser()
    gw = Gateway(out, oauth=None)          # the mock can't check a real login; Authorization is only logged
    claude = Claude(out, gw.url, config_dir=cfg)
    backup = borrow_settings(claude.settings_file)
    good = fresh_jwt()
    try:
        before = cred_state(cfg)
        observe("login_present", "yes" if before.get("exists") else "no")
        claude.write_settings({"env": {"ANTHROPIC_CUSTOM_HEADERS": f"{PK}: {good}"}})
        claude.start()
        observe("baseline", classify(claude.turn("baseline")["text"]))
        for name, ctl in (("498", dict(force=498)), ("portkey401", dict(revoked=[mock_gateway.fingerprint(good)]))):
            gw.set(force=None, revoked=[])
            gw.set(**ctl)
            b = cred_state(cfg)
            mark = gw.mark()
            t = claude.turn(f"case {name}")
            time.sleep(2)
            a = cred_state(cfg)
            observe(f"{name}_attempts", "1" if len(gw.messages(mark)) == 1 else "many" if len(gw.messages(mark)) > 5 else len(gw.messages(mark)))
            observe(f"{name}_long", "yes" if t["seconds"] > 60 else "no")
            observe(f"{name}_login_rotated", "yes" if a.get("refresh") != b.get("refresh") else "no")
            observe(f"{name}_login_still_valid", "yes" if login_valid(a) else "no")
        gw.set(force=None, revoked=[])
        observe("recovery", classify(claude.turn("recovery")["text"]))
    finally:
        claude.stop()
        return_settings(claude.settings_file, backup)
        rmtree(claude.tmp)
        gw.close()


class Proxy:
    """repro/proxy_prototype.py in this process, in front of a gateway, with its token in a file (as the client would keep it)."""

    def __init__(self, out, upstream):
        self.log = out / "proxy.log.jsonl"
        self.log.touch()
        self.dir = Path(tempfile.mkdtemp(prefix="aigw-proxy-"))     # the token file stays out of the results dir
        self.token_file = self.dir / "gateway.token"
        self.srv = proxy_prototype.serve(self.token_file, upstream, log=open(self.log, "a", encoding="utf-8"))
        self.url = f"http://127.0.0.1:{self.srv.server_address[1]}"

    def set_token(self, value):
        """value None: the file is gone."""
        if value is None:
            self.token_file.unlink(missing_ok=True)
        else:
            self.token_file.write_text(value, encoding="utf-8")

    def rows(self, since=0):
        rows = [json.loads(line) for line in self.log.read_text(encoding="utf-8").splitlines()]
        return [r for r in rows if r["path"].endswith("/v1/messages")][since:]

    def mark(self):
        return len(self.rows())

    def close(self):
        self.srv.shutdown()
        rmtree(self.dir)


class UnixGateway:
    """The mock gateway listening on a Unix socket instead of TCP (for the socket base URL tries)."""

    class Server(ThreadingHTTPServer):
        address_family = getattr(socket, "AF_UNIX", None)  # absent on Windows Python; keeps the import working

        def server_bind(self):
            self.socket.bind(self.server_address)
            self.server_name, self.server_port = "unix", 0

        def get_request(self):
            conn, _ = self.socket.accept()
            return conn, ("unix", 0)

    def __init__(self, out):
        self.dir = Path(tempfile.mkdtemp(prefix="aigw-sock-"))
        self.path = str(self.dir / "gw.sock")
        self.log = out / "gateway.unix.log.jsonl"
        self.log.touch()
        ctl = out / "gateway.unix.control.json"
        ctl.write_text(json.dumps({"oauth": OAUTH}), encoding="utf-8")
        self.srv = self.Server(self.path, mock_gateway.make_handler(str(self.log), str(ctl)))
        self.srv.handle_error = lambda *a: None
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def messages(self):
        rows = [json.loads(line) for line in self.log.read_text(encoding="utf-8").splitlines()]
        return [r for r in rows if r["path"].split("?")[0].endswith("/v1/messages")]

    def close(self):
        self.srv.shutdown()
        rmtree(self.dir)


def socket_try(out, name, good, base_url, env=None, settings_env=None, timeout=15):
    """One `claude -p` against a Unix socket listener. base_url, env and settings_env are functions of the socket path.
    A try that never reaches the listener is cut off after `timeout` s: Claude Code retries a connection error with
    backoff for minutes. Returns the observation text and the requests the listener saw."""
    sub = out / name
    sub.mkdir()
    uds = UnixGateway(sub)
    claude = Claude(sub, base_url(uds.path), env={"CLAUDE_CODE_OAUTH_TOKEN": OAUTH, **(env(uds.path) if env else {})})
    claude.write_settings({"env": {"ANTHROPIC_CUSTOM_HEADERS": f"{PK}: {good}", **(settings_env(uds.path) if settings_env else {})}})
    try:
        r = claude.oneshot("socket try", timeout=timeout)
        time.sleep(0.5)
        reqs = uds.messages()
        if reqs:
            return f"reached-listener, reply {classify(r['text'])}", reqs
        return f"no-request ({'still retrying after %ss' % timeout if r['text'] == 'TimeoutExpired' else 'other: ' + r['text'][:80]})", reqs
    finally:
        claude.cleanup()
        uds.close()


def scenario_proxy(out):
    """Claude Code (CLAUDE_CODE_OAUTH_TOKEN login) through the prototype local proxy (repro/proxy_prototype.py), in front
    of the mock gateway: header injection, streaming, gateway 401 -> 498, Anthropic 401 passed through, fail closed;
    then whether Claude Code can reach a Unix socket (S11)."""
    gw = Gateway(out)
    claude = Claude(out, "http://unset", env={"CLAUDE_CODE_OAUTH_TOKEN": OAUTH})
    good, clients = fresh_jwt(), fresh_jwt(sub="client-supplied")
    proxy = Proxy(out, gw.url)
    proxy.set_token(good)
    claude.env["ANTHROPIC_BASE_URL"] = proxy.url
    # the settings still carry a (different, valid-looking) JWT of their own: the proxy must replace it
    claude.write_settings({"env": {"ANTHROPIC_CUSTOM_HEADERS": f"{PK}: {clients}"}, "hooks": {"StopFailure": [capture_hook(out, "stopfailure")]}})
    try:
        try:
            claude.start()
            # --- normal turn: injected header, stripped client value, untouched Authorization, streamed reply
            mark, pmark = gw.mark(), proxy.mark()
            t = claude.turn("normal")
            reqs, prow = gw.messages(mark), proxy.rows(pmark)
            h = reqs[0]["headers"] if reqs else {}
            observe("normal_result", classify(t["text"]))
            observe("normal_header_injected", "yes" if h.get(PK) == mock_gateway.fingerprint(good) else "no")
            observe("normal_client_header_stripped", "yes" if h.get(PK) != mock_gateway.fingerprint(clients) else "no")
            observe("normal_authorization", "oauth" if h.get("authorization") == mock_gateway.fingerprint(f"Bearer {OAUTH}") else "other")
            observe("normal_beta_passed", "yes" if "oauth-2025-04-20" in (h.get("anthropic-beta") or "") else "no")
            observe("normal_streamed", "yes" if reqs and reqs[0].get("stream") is True else "no")
            observe("normal_proxy_logged_fingerprint", "yes" if prow and prow[0]["token"] == mock_gateway.fingerprint(good) else "no")
            # --- token rotated in the file: the next request carries it, no restart
            renewed = fresh_jwt(sub="renewed")
            proxy.set_token(renewed)
            mark = gw.mark()
            t = claude.turn("after the token file changed")
            reqs = gw.messages(mark)
            observe("renewed_result", classify(t["text"]))
            observe("renewed_header_injected", "yes" if reqs and reqs[0]["headers"].get(PK) == mock_gateway.fingerprint(renewed) else "no")
            # --- the gateway refuses the JWT (Portkey 401), Anthropic refuses the login (relayed 401), no usable token
            cases = [
                ("portkey401", dict(revoked=[mock_gateway.fingerprint(good)]), good),
                ("anthropic401", dict(oauth="some-other-login"), good),
                ("notoken_missing", {}, None),
                ("notoken_empty", {}, ""),
                ("notoken_sentinel", {}, SENTINEL),
            ]
            for name, ctl, token in cases:
                gw.set(revoked=[], oauth=OAUTH, force=None)
                gw.set(**ctl)
                proxy.set_token(token)
                seen = len(payloads(out, "stopfailure"))
                mark, pmark = gw.mark(), proxy.mark()
                t = claude.turn(f"case {name}")
                time.sleep(1)
                rows = proxy.rows(pmark)
                observe(f"{name}_attempts", len(rows))
                observe(f"{name}_upstream_requests", len(gw.messages(mark)))
                observe(f"{name}_proxy_status", ",".join(sorted({str(r["status"]) for r in rows})) or "none")
                observe(f"{name}_proxy_note", ",".join(sorted({r["note"] or "-" for r in rows})) or "none")
                observe(f"{name}_fast", "yes" if t["seconds"] < 15 else f"no ({t['seconds']}s)")
                observe(f"{name}_message", classify(t["text"]))
                observe(f"{name}_498_shown", "yes" if "498" in t["text"] else "no")
                wait_until(lambda: len(payloads(out, "stopfailure")) > seen)
                p = payloads(out, "stopfailure")[seen:]
                observe(f"{name}_stopfailure_error", p[0].get("error") if p else "none")
            gw.set(revoked=[], oauth=OAUTH, force=None)
            proxy.set_token(good)
            observe("recovery", classify(claude.turn("recovery")["text"]))
        finally:
            claude.cleanup()
        # --- SSE passes through as it arrives: the mock sends chunked SSE 0.6 s apart; read it through the proxy
        gw.set(chunked_sse=0.6)
        conn = http.client.HTTPConnection("127.0.0.1", proxy.srv.server_address[1], timeout=30)
        body = json.dumps({"model": MODEL, "stream": True, "max_tokens": 8, "messages": [{"role": "user", "content": "x"}]})
        t0 = time.time()
        conn.request("POST", "/v1/messages", body, {"content-type": "application/json", "authorization": f"Bearer {OAUTH}",
                                                    "anthropic-beta": "oauth-2025-04-20"})
        resp = conn.getresponse()
        observe("sse_status", resp.status)
        observe("sse_chunked", "yes" if resp.getheader("Transfer-Encoding") == "chunked" else "no")
        first = resp.read1(65536)
        t_first = time.time() - t0
        rest = resp.read()
        t_all = time.time() - t0
        observe("sse_first_event_early", "yes" if first.startswith(b"event: message_start") and t_first < 0.5 else f"no ({t_first:.1f}s)")
        observe("sse_spread_over_time", "yes" if t_all > 2.5 else f"no ({t_all:.1f}s)")
        observe("sse_complete", "yes" if b"event: message_stop" in first + rest else "no")
        conn.close()
    finally:
        proxy.close()
        gw.close()
    if IS_WIN:
        return        # S11 needs AF_UNIX, which Windows Python lacks; run.py reports the socket_* expectations as SKIP (windows)
    # --- S11: can Claude Code reach a Unix socket? A plain-HTTP listener on a socket stands in for the gateway.
    good = fresh_jwt()
    tries = [
        ("socket_unix_url", lambda s: f"unix://{s}", None, None),
        ("socket_http_plus_unix", lambda s: "http+unix://" + s.replace("/", "%2F"), None, None),
        ("socket_http_unix_colon", lambda s: f"http://unix:{s}:/", None, None),
        ("socket_env_var", lambda s: "http://localhost", lambda s: {"ANTHROPIC_UNIX_SOCKET": s}, None),
        ("socket_env_var_in_settings", lambda s: "http://localhost", None, lambda s: {"ANTHROPIC_UNIX_SOCKET": s}),
    ]
    for name, base, env, settings_env in tries:
        result, reqs = socket_try(out, name, good, base, env, settings_env)
        observe(name, result)
        if reqs:
            h = reqs[0]["headers"]
            observe(f"{name}_gateway_header", "yes" if h.get(PK) == mock_gateway.fingerprint(good) else "no")
            observe(f"{name}_authorization", "oauth" if h.get("authorization") == mock_gateway.fingerprint(f"Bearer {OAUTH}") else "other")


def scenario_stored_login_proxy(out):
    """A stored `claude login` (LOGIN_CONFIG_DIR) through the prototype proxy and the mock gateway: a gateway 401 becomes
    498 at the proxy, so Claude Code makes one attempt and leaves the login alone (compare stored_login: 13 attempts
    and a rotated login without the proxy); no usable token fails the same way without reaching the gateway.
    Rotates the real login at Anthropic if the proxy does not work, so only run it on purpose."""
    cfg = Path(os.environ["LOGIN_CONFIG_DIR"]).expanduser()
    gw = Gateway(out, oauth=None)          # the mock can't check a real login; Authorization is only logged
    claude = Claude(out, "http://unset", config_dir=cfg)
    backup = borrow_settings(claude.settings_file)
    good = fresh_jwt()
    proxy = Proxy(out, gw.url)
    proxy.set_token(good)
    claude.env["ANTHROPIC_BASE_URL"] = proxy.url
    try:
        before = cred_state(cfg)
        observe("login_present", "yes" if before.get("exists") else "no")
        claude.write_settings({})          # no JWT in the settings: the proxy supplies it
        claude.start()
        observe("baseline", classify(claude.turn("baseline")["text"]))
        for name, ctl, token in (("portkey401", dict(revoked=[mock_gateway.fingerprint(good)]), good), ("notoken", {}, SENTINEL)):
            gw.set(force=None, revoked=[])
            gw.set(**ctl)
            proxy.set_token(token)
            b = cred_state(cfg)
            mark, pmark = gw.mark(), proxy.mark()
            t = claude.turn(f"case {name}")
            time.sleep(2)
            a = cred_state(cfg)
            n = len(proxy.rows(pmark))
            observe(f"{name}_attempts", "1" if n == 1 else "many" if n > 5 else n)
            observe(f"{name}_upstream_requests", len(gw.messages(mark)))
            observe(f"{name}_message", classify(t["text"]))
            observe(f"{name}_long", "yes" if t["seconds"] > 60 else "no")
            observe(f"{name}_login_rotated", "yes" if a.get("refresh") != b.get("refresh") else "no")
            observe(f"{name}_login_still_valid", "yes" if login_valid(a) else "no")
        gw.set(force=None, revoked=[])
        proxy.set_token(good)
        observe("recovery", classify(claude.turn("recovery")["text"]))
    finally:
        claude.stop()
        return_settings(claude.settings_file, backup)
        rmtree(claude.tmp)
        proxy.close()
        gw.close()


def tamper(token):
    """Flip a character in the middle of the signature (the last base64url character of an RS256 signature carries
    only 2 bits, so changing it may leave the signature valid)."""
    i = len(token) - 20
    return token[:i] + ("B" if token[i] != "B" else "C") + token[i + 1:]


def live_token():
    """A valid gateway JWT from TOKEN_COMMAND (default: the client's `token`)."""
    # shell=True: /bin/sh on POSIX, cmd.exe on Windows (double quotes and %VAR%; single quotes do not quote there)
    argv = [sys.executable, str(CLIENT), "token"]
    cmd = os.environ.get("TOKEN_COMMAND") or (subprocess.list2cmdline(argv) if IS_WIN else " ".join(shlex.quote(a) for a in argv))
    p = subprocess.run(cmd, shell=True, capture_output=True, encoding="utf-8", errors="replace", timeout=120)
    if p.returncode != 0 or p.stdout.count(".") != 2:
        sys.exit(f"TOKEN_COMMAND failed (exit {p.returncode}): {p.stderr.strip()[:200]}")
    return p.stdout.strip()


def gateway_request(token, oauth=None, extra=None):
    """One Messages call to GATEWAY_URL; returns (status, body text, headers)."""
    h = {"content-type": "application/json", "anthropic-version": "2023-06-01"}
    if token is not None:
        h[PK] = token
    if oauth:
        h["authorization"] = f"Bearer {oauth}"
        h["anthropic-beta"] = "oauth-2025-04-20"
    h.update(extra or {})
    body = json.dumps({"model": MODEL, "max_tokens": 8, "messages": [{"role": "user", "content": "Reply with exactly: LIVE-OK"}]}).encode()
    req = urllib.request.Request(os.environ["GATEWAY_URL"].rstrip("/") + "/v1/messages", data=body, headers=h, method="POST")
    try:
        r = urllib.request.urlopen(req, timeout=90)
        return r.status, r.read().decode(errors="replace"), r.headers
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode(errors="replace"), e.headers


def stored_access_token():
    o = json.loads((Path(os.environ["LOGIN_CONFIG_DIR"]).expanduser() / ".credentials.json").read_text(encoding="utf-8")).get("claudeAiOauth", {})
    return o.get("accessToken", "")


def scenario_gateway(out):
    """The real gateway with curl-like requests: which failures are the gateway's (Portkey 401 / LB 498) and which
    are Anthropic's (relayed 401), and that a valid JWT plus the user's own login gets a reply (passthrough)."""
    tok = live_token()
    guard = os.environ.get("LB_GUARD", "off") == "on"
    oauth = stored_access_token() if os.environ.get("LOGIN_CONFIG_DIR") else ""
    cases = [("missing", None, "x"), ("garbage", "not-a-jwt", "x"), ("tampered", tamper(tok), "x"),
             ("bearer_prefixed", f"Bearer {tok}", "x"), ("sentinel", SENTINEL, "x"),
             ("valid_bad_login", tok, "sk-ant-oat01-invalid"), ("valid_no_login", tok, None)]
    if oauth:
        cases.append(("valid_real_login", tok, oauth))
    for name, t, o in cases:
        status, body, hdrs = gateway_request(t, o if o != "x" else "sk-ant-oat01-invalid")
        (out / f"gateway.{name}.txt").write_text(f"{status}\n{body[:600]}\n", encoding="utf-8")
        who = classify(body)
        if status == 200:
            who = "reply"
        elif '"provider":"anthropic"' in body.replace(" ", "") or "anthropic error" in body:
            who = "anthropic"
        observe(f"{name}", f"{status} {who}")
    observe("lb_guard", "on" if guard else "off")


def scenario_live_login(out):
    """The real gateway with a stored `claude login` (LOGIN_CONFIG_DIR), through the logging relay: a refused JWT
    costs the OAuth retry loop (about 4 min); with the LB guard, the sentinel and a missing header fail at once."""
    cfg = Path(os.environ["LOGIN_CONFIG_DIR"]).expanduser()
    tok = live_token()
    gw = Gateway(out, upstream=os.environ["GATEWAY_URL"])
    claude = Claude(out, gw.url, config_dir=cfg)
    backup = borrow_settings(claude.settings_file)
    cases = [("ok", tok), ("tampered", tamper(tok))]
    if os.environ.get("LB_GUARD", "off") == "on":
        cases += [("sentinel", SENTINEL), ("missing", None)]
    try:
        for name, t in cases:
            s = {k: v for k, v in json.loads(json.loads(backup.read_text(encoding="utf-8"))["text"] or "{}").items() if k not in ("env", "hooks")}
            s["env"] = {"ANTHROPIC_CUSTOM_HEADERS": f"{PK}: {t}"} if t is not None else {}
            claude.write_settings(s)
            b = cred_state(cfg)
            mark = gw.mark()
            r = claude.oneshot("Reply with exactly: LIVE-OK")
            reqs = gw.messages(mark)
            a = cred_state(cfg)
            observe(f"{name}_result", classify(r["text"]))
            observe(f"{name}_attempts", "1" if len(reqs) == 1 else "many" if len(reqs) > 5 else len(reqs))
            observe(f"{name}_statuses", ",".join(sorted({str(x["status"]) for x in reqs})) or "none")
            observe(f"{name}_long", "yes" if r["seconds"] > 60 else "no")
            observe(f"{name}_login_rotated", "yes" if a.get("refresh") != b.get("refresh") else "no")
            observe(f"{name}_login_still_valid", "yes" if login_valid(a) else "no")
    finally:
        return_settings(claude.settings_file, backup)
        rmtree(claude.tmp)
        gw.close()


def scenario_client_live(out):
    """The whole thing for real: the client gets a JWT from the IdP (and broker), installs itself into a stored-login
    Claude Code (LOGIN_CONFIG_DIR, restored afterwards), and the precheck hook replaces an expired JWT before the turn."""
    cfg = Path(os.environ["LOGIN_CONFIG_DIR"]).expanduser()
    settings_file = cfg / "settings.json"
    backup = borrow_settings(settings_file)
    env = dict(os.environ, AIGW_CLAUDE_SETTINGS=str(settings_file))
    # Claude Code runs with a throwaway HOME, so tell the hooks where the client's config and sign-in live.
    env.setdefault("AIGW_CLAUDE_AUTH_DIR", str(Path.home() / ".config" / "aigw-claude-auth"))
    run = lambda *a: subprocess.run([sys.executable, str(CLIENT), *a], env=env, capture_output=True, encoding="utf-8", errors="replace", timeout=120)
    gw = Gateway(out, upstream=os.environ["GATEWAY_URL"])
    claude = Claude(out, gw.url, config_dir=cfg, env={"AIGW_CLAUDE_AUTH_DIR": env["AIGW_CLAUDE_AUTH_DIR"]})
    try:
        st = run("status")
        (out / "client.status.txt").write_text(st.stdout + st.stderr, encoding="utf-8")
        observe("signed_in", "yes" if any(l.split()[:3] == ["signed", "in", "yes"] for l in st.stdout.splitlines()) else "no")
        r = run("install", "--base-url", gw.url)
        observe("install_exit", r.returncode)
        r = run("sync", "--force")
        observe("sync_exit", r.returncode)
        tok = header_of(claude.settings())
        status, body, _ = gateway_request(tok, "sk-ant-oat01-invalid")
        observe("gateway_accepts_jwt", "yes" if status != 401 or "anthropic" in body else f"no ({status})")
        observe("turn_fresh", classify(claude.oneshot("Reply with exactly: LIVE-OK")["text"]))
        s = claude.settings()
        s["env"]["ANTHROPIC_CUSTOM_HEADERS"] = f"{PK}: {jwt(time.time() - 60, kind='gateway')}"   # an expired JWT
        claude.write_settings(s)
        mark = gw.mark()
        t = claude.oneshot("Reply with exactly: LIVE-OK")
        reqs = gw.messages(mark)
        observe("turn_after_expiry", classify(t["text"]))
        observe("turn_after_expiry_statuses", ",".join(sorted({str(x["status"]) for x in reqs})) or "none")
        observe("turn_after_expiry_fast", "yes" if t["seconds"] < 30 else f"no ({t['seconds']}s)")
    finally:
        return_settings(settings_file, backup)
        rmtree(claude.tmp)
        gw.close()


class Managed:
    """The OS managed-settings file (macOS /Library/Application Support/ClaudeCode, Linux /etc/claude-code), written
    with `sudo -n` (run.sh primes sudo) and removed after each case. Refuses to run if a managed-settings file is
    already there, so a real policy is never overwritten. The directory is removed again if this created it."""

    DIR = Path("/Library/Application Support/ClaudeCode" if sys.platform == "darwin" else "/etc/claude-code")
    MARK = "AIGW_REPRO_MANAGED"          # managed hooks act only in Claude Code processes started with this set

    def __init__(self, out):
        self.out, self.file, self.dropin = out, self.DIR / "managed-settings.json", self.DIR / "managed-settings.d"
        if self.file.exists() or (self.dropin.is_dir() and any(self.dropin.iterdir())):
            sys.exit(f"{self.DIR} already holds managed settings; not touching a real policy")
        self.dropin_files, self.made_dropin = [], False
        self.created_dir = not self.DIR.exists()
        self.sudo("mkdir", "-p", str(self.DIR))

    def sudo(self, *cmd):
        subprocess.run(["sudo", "-n", *cmd], check=True, capture_output=True, timeout=30)

    def write(self, d, dropins=None):
        """d: the managed-settings.json content (None: no such file); dropins: {file name: content} for managed-settings.d/."""
        if d is not None:
            src = self.out / "managed-settings.json"
            src.write_text(json.dumps(d, indent=2), encoding="utf-8")
            self.sudo("install", "-m", "644", str(src), str(self.file))       # root-owned, like an MDM-deployed file
        for name, content in (dropins or {}).items():
            if not self.dropin.is_dir():
                self.sudo("mkdir", "-p", str(self.dropin))
                self.made_dropin = True
            src = self.out / f"dropin.{name}"
            src.write_text(json.dumps(content, indent=2), encoding="utf-8")
            self.sudo("install", "-m", "644", str(src), str(self.dropin / name))
            self.dropin_files.append(name)

    def clear(self):
        self.sudo("rm", "-f", str(self.file))
        for name in self.dropin_files:                  # only the files this run wrote
            self.sudo("rm", "-f", str(self.dropin / name))
        self.dropin_files = []
        if self.made_dropin:
            self.sudo("rmdir", str(self.dropin))
            self.made_dropin = False

    def close(self):
        self.clear()
        if self.created_dir:
            self.sudo("rmdir", str(self.DIR))

    @classmethod
    def guarded(cls, command):
        return f'[ -n "${cls.MARK}" ] || exit 0; {command}'

    @classmethod
    def client_hooks(cls):
        client = f"{shlex.quote(sys.executable)} {shlex.quote(str(CLIENT))}"
        return {"UserPromptSubmit": [{"hooks": [{"type": "command", "command": cls.guarded(f"{client} hook precheck"), "timeout": 30}]}],
                "StopFailure": [{"hooks": [{"type": "command", "command": cls.guarded(f"{client} hook stop-failure"), "timeout": 30}]}]}


def managed_session(out, managed, managed_settings, user_hooks=True, capture=False, lock=None, initial="expired"):
    """One persistent session, two turns, with `managed_settings` in the OS managed-settings file (None: no file).
    The user's settings get the JWT (and the client hooks if user_hooks); capture adds a user-level capture hook.
    lock: "readonly" (chmod 444) or "immutable" (macOS chflags uchg) on the user's settings.json before the session."""
    gw, idp = Gateway(out), FakeIdP()
    claude = Claude(out, gw.url, env={"CLAUDE_CODE_OAUTH_TOKEN": OAUTH, Managed.MARK: "1"})
    client = Client(claude.tmp, idp)
    claude.env["AIGW_CLAUDE_AUTH_DIR"] = str(client.dir)
    obs = {}
    try:
        client.sign_in()
        client.run("install", "--base-url", gw.url, *([] if user_hooks else ["--no-hooks"]), settings=claude.settings_file)
        s = claude.settings()
        start_jwt = {"expired": jwt(time.time() - 60, kind="gateway"), "valid": fresh_jwt()}[initial]
        s["env"]["ANTHROPIC_CUSTOM_HEADERS"] = f"{PK}: {start_jwt}"
        if capture:
            s.setdefault("hooks", {})["UserPromptSubmit"] = s.get("hooks", {}).get("UserPromptSubmit", []) + [capture_hook(out, "user")]
        claude.write_settings(s)
        if managed_settings is not None:
            managed.write(managed_settings)
        if lock == "readonly":
            os.chmod(claude.settings_file, 0o444)
        elif lock == "immutable":
            if sys.platform != "darwin":
                return {"skipped": "macos-only"}
            subprocess.run(["chflags", "uchg", str(claude.settings_file)], check=True)
        if lock:
            r = client.run("sync", "--force", settings=claude.settings_file)
            obs["sync_exit"] = r.returncode
            obs["sync_wrote"] = "yes" if header_of(claude.settings()) not in (start_jwt, "") else "no"
        claude.start()
        for i in (1, 2):
            mark = gw.mark()
            t = claude.turn(f"managed turn {i}")
            reqs = gw.messages(mark)
            h = reqs[0]["headers"] if reqs else {}
            sent = h.get(PK, "")
            obs[f"turn{i}"] = classify(t["text"]) if reqs else ("blocked" if "AI gateway" in t["text"] or t["is_error"] else "no-request")
            obs[f"turn{i}_jwt"] = ("none" if not sent else "initial" if sent == mock_gateway.fingerprint(start_jwt)
                                   else "sentinel" if sent == mock_gateway.fingerprint(SENTINEL) else "renewed")
            obs[f"turn{i}_managed_header"] = "yes" if h.get("x-managed-test") else "no"
            obs[f"turn{i}_proxy_authorization"] = "yes" if h.get("proxy-authorization") else "no"
            if i == 1 and lock is None and initial == "valid":
                client.run("sync", "--force", settings=claude.settings_file)    # a renewal mid-session, managed file present
                time.sleep(3)
        obs["user_hook_ran"] = "yes" if payloads(out, "user") else "no"
        stream = (out / "claude.stream.jsonl").read_text(encoding="utf-8") if (out / "claude.stream.jsonl").exists() else ""
        obs["block_message"] = "yes" if "blocked by hook" in stream and "AI gateway" in stream else "no"
    finally:
        if lock == "immutable" and sys.platform == "darwin":
            subprocess.run(["chflags", "nouchg", str(claude.settings_file)])
        if lock:
            os.chmod(claude.settings_file, 0o600)
        if managed_settings is not None:
            managed.clear()
        claude.cleanup(), gw.close(), idp.close()
    return obs


S4_MARKER = "s4-marker"      # appears only in the unknown top-level key's value
S4_HOOK_SCRIPT = f'''import json, os, sys
raw = sys.stdin.read()
try:
    keys = sorted(json.loads(raw))
except ValueError:
    keys = []
# only AIGW_* variables are read from the environment, and only these are written
env = {{k: v for k, v in os.environ.items() if k.startswith("AIGW_") and k != "AIGW_REPRO_MANAGED"}}
with open(sys.argv[1], "a", encoding="utf-8") as f:
    f.write(json.dumps({{"aigw_env": env, "input_keys": keys, "marker_in_input": "aigwClaudeAuth" in raw or "{S4_MARKER}" in raw}}) + "\\n")
'''


def s4_hook(out, event, label):
    """A managed hook entry (guarded to this scenario's processes) that records the AIGW_* variables of the hook's
    environment, the top-level key names of its input JSON, and whether the unknown key's value is in that input.
    Goes to out/hookenv.<label>.jsonl."""
    script = out / "s4_hook.py"
    script.write_text(S4_HOOK_SCRIPT, encoding="utf-8")
    cmd = f"{shlex.quote(sys.executable)} {shlex.quote(str(script))} {shlex.quote(str(out / f'hookenv.{label}.jsonl'))}"
    return {event: [{"hooks": [{"type": "command", "command": Managed.guarded(cmd), "timeout": 30}]}]}


def s4_bash_command(out):
    """The command the Bash tool runs: the AIGW_* variables of its environment (and nothing else) into out/bash.env."""
    return f"env | grep '^AIGW_' | grep -v '^AIGW_REPRO_MANAGED=' | sort > {shlex.quote(str(out / 'bash.env'))}"


def s4_specs(out, url2):
    """The managed settings of each spike-S4 case: {case: {managed_settings, dropins, user_env}}. url2 is a second mock
    gateway; a managed ANTHROPIC_BASE_URL pointing at it shows that the managed source was applied. Writes only the
    hook script into out."""
    base = {"ANTHROPIC_BASE_URL": url2}
    up, sf = s4_hook(out, "UserPromptSubmit", "userprompt"), s4_hook(out, "StopFailure", "stopfailure")
    return {
        # an unknown top-level key next to env and hooks
        "unknownkey": dict(managed_settings={"aigwClaudeAuth": {"issuer": f"https://idp.invalid/{S4_MARKER}"}, "env": base, "hooks": {**up, **sf}}),
        # AIGW_* in managed env; the user's settings.json has one of the same keys and one of its own
        "envkeys": dict(managed_settings={"env": {**base, "AIGW_ISSUER": "managed-issuer", "AIGW_HOOK_LOGIN": "off"}, "hooks": {**up, **sf}},
                        user_env={"AIGW_ISSUER": "user-issuer", "AIGW_USER_ONLY": "user-only"}),
        # managed-settings.json plus two drop-ins; hooks for the same event in two files; a key set in all three files
        "dropin": dict(managed_settings={"env": {**base, "AIGW_FROM_MAIN": "main", "AIGW_CONFLICT": "main"}, "hooks": up},
                       dropins={"10-a.json": {"env": {"AIGW_FROM_10": "a", "AIGW_CONFLICT": "dropin10"}, "hooks": sf},
                                "20-b.json": {"env": {"AIGW_FROM_20": "b", "AIGW_CONFLICT": "dropin20"},
                                              "hooks": s4_hook(out, "UserPromptSubmit", "userprompt2")}}),
        # only a drop-in, no managed-settings.json
        "dropinonly": dict(managed_settings=None,
                           dropins={"10-only.json": {"env": {**base, "AIGW_ONLY_DROPIN": "yes"}, "hooks": {**up, **sf}}}),
    }


def records(out, label):
    f = out / f"hookenv.{label}.jsonl"
    return [json.loads(line) for line in f.read_text(encoding="utf-8").splitlines() if line.strip()] if f.exists() else []


def s4_session(out, managed, name):
    """Three turns in one session against two mock gateways: a normal one (UserPromptSubmit hook), one that makes the
    model call the Bash tool (its environment is recorded), and one the gateway fails with 403 (StopFailure hook).
    Records whether the managed source's ANTHROPIC_BASE_URL applied, which hooks ran, the AIGW_* variables each hook and
    the Bash tool saw, the hook input's key names, and any warning on stderr."""
    (out / "gw2").mkdir()
    gw, gw2 = Gateway(out), Gateway(out / "gw2")
    spec = s4_specs(out, gw2.url)[name]
    claude = Claude(out, gw.url, env={"CLAUDE_CODE_OAUTH_TOKEN": OAUTH, Managed.MARK: "1"})
    claude.args = ["--allowedTools", "Bash"]
    obs = {}
    try:
        claude.write_settings({"env": {"ANTHROPIC_CUSTOM_HEADERS": f"{PK}: {fresh_jwt()}", **spec.get("user_env", {})}})
        managed.write(spec["managed_settings"], spec.get("dropins"))
        for g in (gw, gw2):
            g.set(bash_command=s4_bash_command(out))
        claude.start()
        obs["turn1"] = classify(claude.turn("s4 turn 1")["text"])
        wait_until(lambda: len(records(out, "userprompt")) >= 1, timeout=10)
        n1, n2 = len(gw.messages()), len(gw2.messages())
        obs["base_url_from_managed"] = "yes" if n2 and not n1 else "no" if n1 and not n2 else "split"
        claude.turn("RUN-BASH please")
        wait_until(lambda: (out / "bash.env").exists(), timeout=10)
        for g in (gw, gw2):
            g.set(force=403)
        claude.turn("s4 turn 3")
        wait_until(lambda: len(records(out, "stopfailure")) >= 1, timeout=10)
        time.sleep(2)                                   # a moment for hooks that are still running
        fmt = lambda env: ",".join(f"{k}={v}" for k, v in sorted(env.items())) or "none"
        for label in ("userprompt", "userprompt2", "stopfailure"):
            rs = records(out, label)
            obs[f"hook_{label}_ran"] = "yes" if rs else "no"
            if label != "userprompt2":
                obs[f"env_{label}"] = fmt(rs[-1]["aigw_env"]) if rs else "no-hook"
        up = records(out, "userprompt")
        obs["hook_input_keys"] = ",".join(up[0]["input_keys"]) if up else "no-hook"
        obs["marker_in_hook_input"] = "yes" if any(r["marker_in_input"] for r in up + records(out, "stopfailure")) else "no"
        bash = out / "bash.env"
        obs["env_bash"] = fmt(dict(l.split("=", 1) for l in bash.read_text(encoding="utf-8").splitlines())) if bash.exists() else "no-bash"
        err = (out / "claude.stderr.txt").read_text(encoding="utf-8") if (out / "claude.stderr.txt").exists() else ""
        warn = [l for l in err.splitlines() if re.search(r"settings|managed|invalid|unknown|unrecogni[sz]ed", l, re.I)]
        (out / "warnings.txt").write_text("\n".join(warn) + "\n", encoding="utf-8")
        obs["stderr_warning"] = "yes" if warn else "no"
        stream = (out / "claude.stream.jsonl").read_text(encoding="utf-8") if (out / "claude.stream.jsonl").exists() else ""
        obs["stream_warning"] = "yes" if re.search(r"Invalid (managed )?settings|Settings (validation )?(error|warning)|unrecogni[sz]ed key", stream, re.I) else "no"
    finally:
        managed.clear()
        claude.cleanup(), gw.close(), gw2.close()
    return obs


def scenario_managed(out):
    """Managed settings (the OS managed-settings file, as MDM deploys it) next to the user's settings.json that the
    client rewrites: whether a managed ANTHROPIC_CUSTOM_HEADERS replaces the user's JWT header; the fleet layout (hooks
    from managed settings, JWT in the user file) with a mid-session renewal; allowManagedHooksOnly with and without
    managed hooks; a read-only or immutable user settings.json; and whether proxyAuthHelper reaches the gateway.
    Spike S4 cases (s4_session): an unknown top-level key, AIGW_* in managed env, managed-settings.d/ drop-ins.
    Needs sudo. Managed hooks are guarded so that they act only in this scenario's Claude Code processes."""
    only = set(filter(None, os.environ.get("MANAGED_CASES", "").split(",")))
    pk = {"ANTHROPIC_CUSTOM_HEADERS": "x-managed-test: managed"}
    cases = {
        "none": dict(managed_settings=None),
        "headers": dict(managed_settings={"env": pk}, initial="valid"),
        "fleet": dict(managed_settings={"hooks": Managed.client_hooks()}, user_hooks=False),
        "fleetreload": dict(managed_settings={"hooks": Managed.client_hooks()}, user_hooks=False, initial="valid"),
        "hooksonly": dict(managed_settings={"allowManagedHooksOnly": True}, capture=True),
        "hooksonlymanaged": dict(managed_settings={"allowManagedHooksOnly": True, "hooks": Managed.client_hooks()}, user_hooks=False, capture=True),
        "readonly": dict(managed_settings=None, lock="readonly"),
        "immutable": dict(managed_settings=None, lock="immutable"),
        "proxyauth": dict(managed_settings={"proxyAuthHelper": "echo 'Basic cmVwcm86cmVwcm8='"}, initial="valid"),
    }
    s4 = {k: dict(s4=True, **v) for k, v in s4_specs(out, "http://127.0.0.1:0").items()}     # spike S4: see s4_session
    cases = {k: v for k, v in {**cases, **s4}.items() if not only or k in only}
    managed = Managed(out) if any(v.get("managed_settings") is not None or v.get("dropins") for v in cases.values()) else None
    try:
        for name, kw in cases.items():
            sub = out / name
            sub.mkdir()
            obs = s4_session(sub, managed, name) if kw.get("s4") else managed_session(sub, managed, **kw)
            for k, v in obs.items():
                observe(f"{name}_{k}", v)
    finally:
        if managed:
            managed.close()


SCENARIOS ={name[len("scenario_"):].replace("_", "-"): fn for name, fn in globals().items() if name.startswith("scenario_")}


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("scenario", choices=sorted(SCENARIOS))
    ap.add_argument("--out", type=Path, required=True)
    a = ap.parse_args()
    a.out.mkdir(parents=True, exist_ok=True)
    SCENARIOS[a.scenario](a.out)


if __name__ == "__main__":
    main()
