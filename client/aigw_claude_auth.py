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
  proxy         run the local proxy in the foreground (mode "proxy"; the daemon does this in the background)
  token         print a valid JWT on stdout (for scripts and curl)
  status        show where the JWT comes from and when it expires (never the token itself)
  install       add ANTHROPIC_BASE_URL and the two hooks to the settings file (or print them for managed settings)
  logout        forget the refresh token and put the sentinel into the settings

Two client modes (`mode` in the config). file (default): the JWT lives in Claude Code's settings, as above. proxy: a local
proxy on 127.0.0.1 adds the JWT to each request (Claude Code reaches it through ANTHROPIC_BASE_URL), keeps the JWT in
memory only, answers a gateway refusal with 498 and streams responses through; `install` writes the proxy's address
and a per-user secret instead of a JWT. See the README, "Choose a mode". These are not Portkey's "Mode A" and "Mode B",
which are about what the JWT carries (below).

Where the JWT comes from (config file, see README):
  * an OIDC IdP token sent as it is (`broker_url` empty). In Portkey's terms that is "Mode A" when your IdP can add the
    gateway's claims to its tokens (you control the issuer; Keycloak can), or "Mode B" when it is a standard IdP token you
    cannot change (the gateway fills in organisation, workspace and limits from its own settings; hybrid gateway only), or
  * an OIDC IdP token exchanged at a token broker (`broker_url`) for a gateway-signed JWT: the broker adds the Mode A
    claims that an IdP such as Entra ID cannot, or
  * any command that prints a JWT (`token_command`).

When no JWT can be had and the one in the settings is unusable, `sync` writes the sentinel value (`expired`) instead
of an empty header. A load balancer rule can answer that sentinel with a non-401 status, which Claude Code shows at
once; a 401 would send a native-login Claude Code into its OAuth refresh-and-retry loop for about four minutes.

Python 3.8+, standard library only. macOS, Linux and native Windows (fcntl or msvcrt for locking, ctypes for the
Windows process check, a PowerShell toast and a Task Scheduler task on Windows).
"""
import argparse
import base64
import collections
import hashlib
import hmac
import http.client
import http.server
import ipaddress
import json
import os
import plistlib
import re
import secrets
import shlex
import shutil
import signal
import socket
import ssl
import stat
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import webbrowser
import zlib
from xml.sax.saxutils import escape as xml_escape
from contextlib import contextmanager
from pathlib import Path

if sys.platform == "win32":
    import msvcrt
else:
    import fcntl

VERSION = "1.8.1"
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
    "login_method": "auto",            # sign-in method for `login`: auto | device | pkce | pkce-print | pkce-paste (flags and AIGW_LOGIN_METHOD override)
    "hook_login": "auto",              # when signed out, the precheck starts a sign-in: auto (same choice as `login`) | device | off
    "device_unavailable_ttl": 86400,   # seconds to remember that the IdP refused the device grant (or the loopback redirect)
    "notify": "auto",                  # desktop notification (StopFailure renewal, hook sign-in result): auto | off | a command (gets the message as $1)
    "redirect_uri": "http://127.0.0.1:{port}/",  # PKCE loopback redirect; {port} is filled in
    "redirect_port": 0,                # 0 = any free port (fine for Entra and most IdPs); set if the IdP pins the port
    "secret_store": "auto",            # where the refresh token lives: auto (OS credential store, else file) | file (state.json)
    "debug_until": 0,                  # epoch seconds; while in the future, each renewal logs an `inspect` summary (`inspect --debug on` sets it in state.json)
    "mode": "file",                    # file (the JWT goes into settings.json) | proxy (a local proxy injects it; see "Mode 2")
    "proxy_listen": "127.0.0.1:18787", # proxy mode: loopback address and a fixed port (install writes ANTHROPIC_BASE_URL from it)
    "gateway_url": "",                 # proxy mode: the gateway the proxy forwards to (file mode keeps it in ANTHROPIC_BASE_URL)
    "proxy_log_requests": 100,         # proxy mode: how many recent requests the proxy keeps in memory for `requests` (0 = none)
    "fleet": False,                    # set by the fleet packages (packaging/): the fleet's login entry moves a personal install aside
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
        try:
            user = json.loads(path.read_text())
        except ValueError as e:                                 # a hand-edited file: a message, not a traceback
            raise AuthError(f"{path} is not valid JSON: {e}")
        if not isinstance(user, dict):
            raise AuthError(f"{path} must hold a JSON object")
        unknown = set(user) - set(DEFAULTS)
        if unknown:
            raise AuthError(f"unknown keys in {path}: {', '.join(sorted(unknown))}")
        cfg.update(user)
    if not cfg["token_command"] and not cfg["client_id"]:
        raise AuthError(f"no token source configured: set client_id (and issuer) or token_command in {path}")
    if cfg["idp_token"] not in ("access_token", "id_token"):
        raise AuthError("idp_token must be access_token or id_token")
    if cfg["hook_login"] not in ("auto", "device", "off"):
        raise AuthError("hook_login must be auto, device or off")
    if cfg["login_method"] not in ("auto",) + LOGIN_METHODS:
        raise AuthError("login_method must be auto, " + ", ".join(LOGIN_METHODS))
    if cfg["secret_store"] not in ("auto", "file"):
        raise AuthError("secret_store must be auto or file")
    if not cfg["sentinel"]:
        raise AuthError("sentinel must not be empty (an empty header can't be told apart from a missing one)")
    if cfg["mode"] not in ("file", "proxy"):
        raise AuthError("mode must be file or proxy")
    parse_listen(cfg["proxy_listen"])                   # refuses a non-loopback address, whatever the mode
    if isinstance(cfg["proxy_log_requests"], bool) or not isinstance(cfg["proxy_log_requests"], int) or not 0 <= cfg["proxy_log_requests"] <= 10000:
        raise AuthError("proxy_log_requests must be a whole number from 0 to 10000")
    if cfg["gateway_url"] and urllib.parse.urlsplit(str(cfg["gateway_url"])).scheme not in ("http", "https"):
        raise AuthError("gateway_url must be an http:// or https:// URL")
    return cfg


# Config keys a running proxy applies in place when config.json changes: where the JWT comes from, not where the proxy listens
# or forwards to. The rest (mode, proxy_listen, gateway_url, header, sentinel, secret_store) need a restart: a restart ends
# the streaming responses of a live Claude Code session, so it is never done on its own.
RELOAD_SAFE = frozenset(("issuer", "token_endpoint", "device_authorization_endpoint", "authorization_endpoint", "client_id", "scope",
                         "idp_token", "broker_url", "token_command", "refresh_before", "hook_wait", "block_on_failure", "login_method",
                         "hook_login", "device_unavailable_ttl", "notify", "redirect_uri", "redirect_port", "debug_until", "http_timeout",
                         "hook_http_timeout", "proxy_log_requests")) & frozenset(DEFAULTS)


def idp_identity(cfg):
    """Which IdP and client a refresh token belongs to. A refresh token is useless (and rejected, then deleted) anywhere else."""
    return f"{cfg['issuer'] or cfg['token_endpoint']}|{cfg['client_id']}"


def idp_label(identity):
    """The IdP part of an identity as a short host name for messages."""
    where = identity.split("|", 1)[0]
    return urllib.parse.urlsplit(where).netloc or where or "an unknown IdP"


def file_sig(path):
    """(mtime_ns, size) of a file, or None when it is not there."""
    try:
        st = os.stat(path)
        return st.st_mtime_ns, st.st_size
    except (OSError, TypeError):
        return None


def file_digest(path):
    """sha256 of a file's content, or None when it is not there. Change detection must not trust timestamps: rsync -t, cp -p, a
    coarse file system clock or touch -r change the content and leave stat() as it was. The files are tiny."""
    try:
        return hashlib.sha256(Path(path).read_bytes()).hexdigest()
    except (OSError, TypeError):
        return None


def config_fingerprint(cfg):
    """{key: short hash of its value} for every config key. Lets `status` compare a running proxy's settings with the file on
    disk without the proxy sending any value (token_command may hold a secret)."""
    return {k: hashlib.sha256(json.dumps(cfg.get(k), sort_keys=True, default=str).encode()).hexdigest()[:10] for k in DEFAULTS}


def restart_hint():
    if sys.platform == "darwin":
        return "launchctl kickstart -k gui/$(id -u)/aigw-claude-auth"
    if is_windows():
        return "schtasks /End /TN aigw-claude-auth, then schtasks /Run /TN aigw-claude-auth"
    return "systemctl --user restart aigw-claude-auth"


def proxy_config_state(info, config_path, cfg=None):
    """How a running proxy's settings relate to config.json, from its status answer: (kind, text). kind: ok, reloaded, restart,
    invalid, signin or old. With cfg (the file as this process just read it), the proxy's per-key fingerprints are compared with it,
    so memory against disk is a direct comparison and no timestamp is involved. A proxy from before 1.8 reports nothing and cannot
    reload: compare its start with the file's mtime."""
    c = info.get("config")
    if c is None:
        sig = file_sig(config_path)
        if sig and sig[0] / 1e9 > time.time() - info.get("uptime", 0) + 1:
            return "old", f"config.json changed after this proxy started, and a proxy older than 1.8 cannot reload it: restart it ({restart_hint()})"
        return "ok", ""
    if c.get("error"):
        return "invalid", f"config.json changed but is not valid, so the proxy keeps its old settings: {c['error']}"
    differ = sorted(k for k, h in config_fingerprint(cfg).items() if c["keys"].get(k) != h) if cfg is not None and c.get("keys") else []
    if differ or c.get("restart_needed"):
        return "restart", f"config.json changed: restart the proxy to apply {', '.join(differ or c['restart_needed'])} ({restart_hint()})"
    if c.get("signin_needed"):
        return "signin", "the IdP settings changed, so the stored sign-in no longer fits: run `aigw-claude-auth login`"
    if c.get("reloaded_at"):
        return "reloaded", f"config.json reloaded at {time.strftime('%H:%M:%S', time.localtime(c['reloaded_at']))}, no restart needed"
    return "ok", ""


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

    def get_line(self, name, data=None):
        for line in self._lines(self.load() if data is None else data):
            n, _, value = line.partition(":")
            if n.strip().lower() == name.lower():
                return value.strip()
        return ""

    def get(self):
        return self.get_line(self.header)

    def put(self, value):
        self.apply(put_lines={self.header: value})

    def merge(self, base_url=None, hook_command=None):
        """Add ANTHROPIC_BASE_URL and our two hooks; replaces earlier entries of ours, keeps everything else."""
        return self.apply(base_url=base_url, hook_command=hook_command)

    def apply(self, base_url=None, hook_command=None, put_lines=None, drop_lines=(), drop_base_url=None, drop_hooks=False):
        """One atomic write: ANTHROPIC_BASE_URL (or drop it, when drop_base_url(current) says so), our hooks (or drop
        them), and header lines in ANTHROPIC_CUSTOM_HEADERS (put_lines {name: value}; drop_lines [name]). Everything else
        stays as it is."""
        data = self.load()
        env = data.setdefault("env", {})
        if base_url:
            env["ANTHROPIC_BASE_URL"] = base_url
        elif drop_base_url and env.get("ANTHROPIC_BASE_URL") and drop_base_url(env["ANTHROPIC_BASE_URL"]):
            del env["ANTHROPIC_BASE_URL"]
        if hook_command:
            hooks = data.setdefault("hooks", {})
            for event, sub in (("UserPromptSubmit", "precheck"), ("StopFailure", "stop-failure")):
                entries = [e for e in hooks.get(event, []) if not MARKER.search(json.dumps(e))]
                entries.append(hook_entry(hook_command, sub))
                hooks[event] = entries
        elif drop_hooks and data.get("hooks"):
            hooks = data["hooks"]
            for event in list(hooks):
                hooks[event] = [e for e in hooks[event] if not MARKER.search(json.dumps(e))]
                if not hooks[event]:
                    del hooks[event]
            if not hooks:
                del data["hooks"]
        if put_lines or drop_lines:
            names = {n.lower() for n in list(put_lines or {}) + list(drop_lines)}
            lines = [l for l in self._lines(data) if l.partition(":")[0].strip().lower() not in names]
            lines += [f"{n}: {v}" for n, v in (put_lines or {}).items()]
            if lines:
                env["ANTHROPIC_CUSTOM_HEADERS"] = "\n".join(lines)
            else:
                env.pop("ANTHROPIC_CUSTOM_HEADERS", None)
        if not env:
            data.pop("env", None)
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
        self.store = None       # a SecretStore (set by main() when secret_store is auto and one is available); None = state.json

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

    # -- the refresh token: in the OS credential store when there is one, else in state.json (see "secret store")
    def get_refresh_token(self):
        if self.store:
            try:
                v = self.store.get()
                if v:
                    return v
            except SecretStoreError as e:
                warn_store(f"could not read the refresh token from the {self.store.name} ({e}); using state.json")
        return self.load().get("refresh_token") or ""

    def put_refresh_token(self, rt):
        """Store first, then drop any copy in state.json. A store failure falls back to the file (with a warning)."""
        st = self.load()
        if self.store and self._store_put(rt):
            if "refresh_token" in st:
                st.pop("refresh_token")
                self.save(st)
            return
        st["refresh_token"] = rt
        self.save(st)

    def drop_refresh_token(self):
        if self.store:
            try:
                self.store.delete()
            except SecretStoreError as e:
                warn_store(f"could not remove the refresh token from the {self.store.name} ({e})")
        st = self.load()
        if "refresh_token" in st:
            st.pop("refresh_token")
            self.save(st)

    def _store_put(self, rt):
        try:
            self.store.set(rt)
            if self.store.get() != rt:
                raise SecretStoreError("read-back differs")
            return True
        except SecretStoreError as e:
            warn_store(f"could not write the refresh token to the {self.store.name} ({e}); keeping it in state.json")
            return False

    def migrate(self):
        """secret_store auto: move a refresh token still in state.json into the store. Call under the lock."""
        rt = self.load().get("refresh_token")
        if not (self.store and rt):
            return False
        if self._store_put(rt):
            st = self.load()
            st.pop("refresh_token", None)
            self.save(st)
            log(f"moved the refresh token from state.json into the {self.store.name}")
            return True
        return False

    def token_location(self):
        """Where the refresh token is, for `status`: never its value. '' = nowhere."""
        if self.store:
            try:
                if self.store.get():
                    return self.store.name
            except SecretStoreError:
                pass
        return "state.json" if self.load().get("refresh_token") else ""

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


# --------------------------------------------------------------------------------------------- secret store
# Where the IdP refresh token lives when `secret_store` is auto: the macOS Keychain, libsecret on Linux, Credential
# Manager on Windows. Each store has name, get() -> str ("" = none), set(str), delete() and raises SecretStoreError.
# The entry is named after the state dir (service/target + a short hash of its path), so two configs don't collide.
# Where the secret travels: macOS stdin of `security -i` (see MacKeychain), Linux stdin of `secret-tool`, Windows an
# API call in this process. It is never in an argv.

class SecretStoreError(Exception):
    """The store failed; the caller falls back to state.json. The message never contains the secret."""


_warned = set()


def warn_store(msg):
    if msg not in _warned:                      # one line per message per process (the daemon would repeat it)
        _warned.add(msg)
        log(f"warning: {msg}")


STORE_SERVICE = "aigw-claude-auth"


def store_account(state_dir):
    """A stable name for this state dir: no secret, no user data beyond the path's hash."""
    return "state-" + hashlib.sha256(str(Path(state_dir).resolve()).encode()).hexdigest()[:12]


class MacKeychain:
    """macOS Keychain through /usr/bin/security.

    `add-generic-password -w <secret>` would put the secret in argv, where `ps` shows it to every local user, and a
    bare `-w` prompts on /dev/tty, not stdin. `security -i` reads commands from stdin, so the command (and the secret)
    goes there and argv only shows `security -i`. A secret made only of [A-Za-z0-9._~+/=-] (every IdP refresh token
    seen) is stored as is; anything else as "b64:" + urlsafe base64, so no quoting rule of security's command parser
    can matter. `security -i` reads at most ~4000 characters per command line (measured: 2500 ok, 4000 fails), so a
    longer secret raises SecretStoreError and the caller keeps it in state.json. `find-generic-password -w` output
    is on a pipe, not argv.
    keychain: a keychain file to use instead of the default search list (tests use a throwaway one).
    """
    name = "macOS Keychain"

    def __init__(self, account, service=STORE_SERVICE, keychain=None, run=None):
        self.account, self.service, self.keychain = account, service, keychain
        self.run = run or subprocess.run

    def _kc(self):
        return [str(self.keychain)] if self.keychain else []

    def _security(self, args, stdin=None):
        try:
            return self.run(["/usr/bin/security", *args], input=stdin, capture_output=True, text=True, timeout=30)
        except (OSError, subprocess.SubprocessError) as e:
            raise SecretStoreError(f"security: {type(e).__name__}")

    def get(self):
        p = self._security(["find-generic-password", "-s", self.service, "-a", self.account, "-w", *self._kc()])
        if p.returncode == 44:                  # errSecItemNotFound
            return ""
        if p.returncode != 0:
            raise SecretStoreError(f"security exit {p.returncode}")
        out = p.stdout.strip()
        if not out.startswith("b64:"):
            return out
        try:
            return base64.urlsafe_b64decode(out[4:] + "=" * (-len(out[4:]) % 4)).decode()
        except ValueError:
            raise SecretStoreError("unreadable entry")

    def set(self, value):
        enc = value if re.fullmatch(r"[A-Za-z0-9._~+/=-]+", value) else "b64:" + base64.urlsafe_b64encode(value.encode()).decode().rstrip("=")
        kc = "".join(' "%s"' % k.replace("\\", "\\\\").replace('"', '\\"') for k in self._kc())
        cmd = f'add-generic-password -U -s "{self.service}" -a "{self.account}" -w "{enc}"{kc}\n'
        if len(cmd) > 4000:
            raise SecretStoreError("secret too long for `security -i`")
        p = self._security(["-i"], cmd)
        if p.returncode != 0:
            raise SecretStoreError(f"security exit {p.returncode}")

    def delete(self):
        p = self._security(["delete-generic-password", "-s", self.service, "-a", self.account, *self._kc()])
        if p.returncode not in (0, 44):
            raise SecretStoreError(f"security exit {p.returncode}")


class LibSecret:
    """Linux Secret Service (GNOME Keyring, KWallet) through `secret-tool`; the secret goes on stdin."""
    name = "libsecret keyring"

    def __init__(self, account, service=STORE_SERVICE, run=None):
        self.attrs = ["service", service, "account", account]
        self.run = run or subprocess.run

    def _tool(self, args, stdin=None):
        try:
            return self.run(["secret-tool", *args], input=stdin, capture_output=True, text=True, timeout=30)
        except (OSError, subprocess.SubprocessError) as e:
            raise SecretStoreError(f"secret-tool: {type(e).__name__}")

    def get(self):
        p = self._tool(["lookup", *self.attrs])
        if p.returncode != 0:
            if not p.stdout and not p.stderr.strip():
                return ""                       # secret-tool says nothing when there is no match
            raise SecretStoreError(f"secret-tool exit {p.returncode}")
        return p.stdout

    def set(self, value):
        p = self._tool(["store", "--label=aigw-claude-auth refresh token", *self.attrs], value)
        if p.returncode != 0:
            raise SecretStoreError(f"secret-tool exit {p.returncode}")

    def delete(self):
        p = self._tool(["clear", *self.attrs])
        if p.returncode != 0 and p.stderr.strip():
            raise SecretStoreError(f"secret-tool exit {p.returncode}")


class WinCredApi:
    """CredWriteW / CredReadW / CredDeleteW through ctypes (generic credential, persisted for this machine)."""
    CRED_TYPE_GENERIC, CRED_PERSIST_LOCAL_MACHINE, ERROR_NOT_FOUND = 1, 2, 1168

    def __init__(self):
        import ctypes
        from ctypes import wintypes as w
        self.ct = ctypes

        class CREDENTIAL(ctypes.Structure):
            _fields_ = [("Flags", w.DWORD), ("Type", w.DWORD), ("TargetName", w.LPWSTR), ("Comment", w.LPWSTR),
                        ("LastWritten", w.FILETIME), ("CredentialBlobSize", w.DWORD),
                        ("CredentialBlob", ctypes.POINTER(ctypes.c_ubyte)), ("Persist", w.DWORD),
                        ("AttributeCount", w.DWORD), ("Attributes", ctypes.c_void_p),
                        ("TargetAlias", w.LPWSTR), ("UserName", w.LPWSTR)]
        self.CREDENTIAL = CREDENTIAL
        adv = ctypes.WinDLL("advapi32", use_last_error=True)
        adv.CredWriteW.argtypes, adv.CredWriteW.restype = [ctypes.POINTER(CREDENTIAL), w.DWORD], w.BOOL
        adv.CredReadW.argtypes, adv.CredReadW.restype = [w.LPCWSTR, w.DWORD, w.DWORD, ctypes.POINTER(ctypes.POINTER(CREDENTIAL))], w.BOOL
        adv.CredDeleteW.argtypes, adv.CredDeleteW.restype = [w.LPCWSTR, w.DWORD, w.DWORD], w.BOOL
        adv.CredFree.argtypes, adv.CredFree.restype = [ctypes.c_void_p], None
        self.adv = adv

    def write(self, target, user, blob):
        ct = self.ct
        buf = (ct.c_ubyte * len(blob)).from_buffer_copy(blob)
        c = self.CREDENTIAL(Type=self.CRED_TYPE_GENERIC, TargetName=target, CredentialBlobSize=len(blob),
                            CredentialBlob=buf, Persist=self.CRED_PERSIST_LOCAL_MACHINE, UserName=user)
        if not self.adv.CredWriteW(ct.byref(c), 0):
            raise SecretStoreError(f"CredWriteW error {ct.get_last_error()}")

    def read(self, target):
        ct = self.ct
        p = ct.POINTER(self.CREDENTIAL)()
        if not self.adv.CredReadW(target, self.CRED_TYPE_GENERIC, 0, ct.byref(p)):
            err = ct.get_last_error()
            if err == self.ERROR_NOT_FOUND:
                return None
            raise SecretStoreError(f"CredReadW error {err}")
        try:
            return ct.string_at(p.contents.CredentialBlob, p.contents.CredentialBlobSize)
        finally:
            self.adv.CredFree(p)

    def delete(self, target):
        ct = self.ct
        if not self.adv.CredDeleteW(target, self.CRED_TYPE_GENERIC, 0):
            err = ct.get_last_error()
            if err != self.ERROR_NOT_FOUND:
                raise SecretStoreError(f"CredDeleteW error {err}")


class WinCredential:
    """Windows Credential Manager. api: WinCredApi, or a stand-in with write/read/delete (tests on other OSes)."""
    name = "Windows Credential Manager"

    def __init__(self, account, service=STORE_SERVICE, api=None):
        self.target, self.user, self.api = f"{service}/{account}", account, api or WinCredApi()

    # One credential holds at most CRED_MAX_CREDENTIAL_BLOB_SIZE (2560) bytes; CredWriteW fails with 1783 beyond that.
    # A longer value is split: the main target holds a "aigw-chunks:<n>\n" header and the first part, and
    # "<target>#1" ... "#<n-1>" the rest. Values that fit stay a single plain credential.
    MAX_BLOB = 2560
    HEADER = b"aigw-chunks:"

    def _parts(self, blob):
        """(n, list of part blobs) for the value stored at the main target, reading the extra parts."""
        if not blob.startswith(self.HEADER):
            return 1, [blob]
        head, _, first = blob.partition(b"\n")
        n, parts = int(head[len(self.HEADER):]), [first]
        for i in range(1, n):
            part = self.api.read(f"{self.target}#{i}")
            if part is None:
                raise SecretStoreError("incomplete entry")
            parts.append(part)
        return n, parts

    def get(self):
        blob = self.api.read(self.target)
        if not blob:
            return ""
        try:
            return b"".join(self._parts(blob)[1]).decode("utf-8")
        except ValueError:
            raise SecretStoreError("unreadable entry")

    def set(self, value):
        blob = value.encode("utf-8")
        old = self.api.read(self.target)
        old_n = self._parts(old)[0] if old else 1
        if len(blob) <= self.MAX_BLOB and not blob.startswith(self.HEADER):
            parts = [blob]
        else:
            size = self.MAX_BLOB - len(self.HEADER) - 4      # room for "<n>\n" in the first part
            parts = [blob[i:i + size] for i in range(0, len(blob), size)]
        for i in range(len(parts) - 1, 0, -1):               # extra parts first, the header last
            self.api.write(f"{self.target}#{i}", self.user, parts[i])
        first = parts[0] if len(parts) == 1 else self.HEADER + str(len(parts)).encode() + b"\n" + parts[0]
        self.api.write(self.target, self.user, first)
        for i in range(len(parts), old_n):                    # a shorter value leaves no stale parts behind
            self.api.delete(f"{self.target}#{i}")

    def delete(self):
        blob = self.api.read(self.target)
        n = self._parts(blob)[0] if blob else 1
        for i in range(1, n):
            self.api.delete(f"{self.target}#{i}")
        self.api.delete(self.target)


def make_store(cfg, state_dir, platform=None):
    """The credential store for this machine, or None (use state.json): secret_store is file, or none is usable."""
    if cfg["secret_store"] == "file":
        return None
    platform, account = platform or sys.platform, store_account(state_dir)
    try:
        if platform == "darwin":
            return MacKeychain(account) if os.access("/usr/bin/security", os.X_OK) else None
        if platform == "win32":
            return WinCredential(account)
        if shutil.which("secret-tool") and (os.environ.get("DBUS_SESSION_BUS_ADDRESS") or
                                            os.path.exists(f"/run/user/{os.getuid()}/bus")):
            return LibSecret(account)
    except Exception as e:                                   # e.g. ctypes missing: just use the file
        warn_store(f"no credential store ({type(e).__name__}); keeping the refresh token in state.json")
    return None


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
            found["grant_types_supported"] = doc.get("grant_types_supported")
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
        self.got_refresh_token = bool(body.get("refresh_token"))
        if self.got_refresh_token:
            self.state.put_refresh_token(body["refresh_token"])     # store first; a rotation happens under sync's lock
        st = self.state.load()
        st["signed_in_at"] = st.get("signed_in_at") or int(time.time())
        if self.got_refresh_token or "idp" not in st:
            st["idp"] = idp_identity(self.cfg)                      # which IdP issued the refresh token that is stored now
        self.state.save(st)
        tok = body.get(self.cfg["idp_token"])
        if not tok:
            raise AuthError(f"the IdP response has no {self.cfg['idp_token']} (check scope and idp_token)")
        return tok

    def refresh(self):
        rt = self.state.get_refresh_token()
        if not rt:
            raise AuthError("not signed in to the gateway: run `aigw-claude-auth login`")
        bound = self.state.load().get("idp")
        if bound and bound != idp_identity(self.cfg):
            # never send it to an IdP that did not issue it: that gets it rejected (invalid_grant) and then deleted
            raise AuthError(f"the stored sign-in belongs to {idp_label(bound)}, but this process is configured for {idp_label(idp_identity(self.cfg))}. "
                            f"If config.json changed after this process started, restart it ({restart_hint()}); "
                            "if you moved to another IdP, run `aigw-claude-auth login`")
        status, body = self._token_request({"grant_type": "refresh_token", "refresh_token": rt, "scope": self.cfg["scope"]})
        if status == 200:
            return self._keep(body)
        if body.get("error") in ("invalid_grant", "interaction_required", "login_required"):
            self.state.drop_refresh_token()
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
            msg = f"device authorization failed: HTTP {status} {d.get('error', '')} {d.get('error_description', '')[:160]}".strip()
            if learn_refusal(self.state, "device", status, d, self.cfg):
                raise MethodUnavailable(msg)
            raise AuthError(msg)
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
        flow = PkceFlow(self)
        try:
            print(f"To sign in to the gateway, open {flow.url}", file=out or sys.stderr, flush=True)
            if open_browser:
                webbrowser.open(flow.url)
            params = flow.wait(300)
        finally:
            flow.close()
        return flow.finish(params)


# --------------------------------------------------------------------------------------------- sync

class Result:
    def __init__(self, ok, changed, message, token=""):
        self.ok, self.changed, self.message, self.token = ok, changed, message, token


def sync(cfg, state, settings, force=False, idp=None):
    """Make sure the settings hold a JWT valid for more than refresh_before seconds.

    Returns ok=False when no fresh JWT could be had. The current value is replaced by the sentinel only if it is
    no longer usable (less than 30 s left), so a short IdP outage doesn't throw away a JWT that still works.
    idp: an IdP token from a sign-in that just happened, used instead of a refresh.
    Proxy mode: the proxy holds the JWT, so this asks it to renew (nothing is written to the settings).
    """
    if cfg["mode"] == "proxy":
        return sync_proxy(cfg, state, force, idp)
    with state.lock():
        state.migrate()
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
        debug_summary(cfg, state, new)
        return Result(True, True, f"wrote a new JWT ({fingerprint(new)})", new)


# --------------------------------------------------------------------------------------------- sign-in method selection

LOGIN_METHODS = ("pkce", "pkce-print", "pkce-paste", "device")
LOOPBACK_METHODS = ("pkce", "pkce-print", "pkce-paste")
PENDING_SECONDS = 600           # a PKCE sign-in started by the hook is good for 10 minutes
DEVICE_GRANT = "urn:ietf:params:oauth:grant-type:device_code"
NEXT_STEPS = ("run `aigw-claude-auth login --paste` in a terminal (open the URL it prints in any browser, then paste the "
              "http://127.0.0.1:... address you end up on), or set redirect_port in the config and forward it with "
              "`ssh -L <port>:127.0.0.1:<port> <this host>`")


class MethodUnavailable(AuthError):
    """The IdP refused a method (and we remembered that); another method may work."""


# -- platform probes (small and separate so tests can mock them)

def platform_name():
    return "windows" if is_windows() else "darwin" if sys.platform == "darwin" else "linux"


def probe_macos_gui():
    """True if this user has a GUI login session (an ssh login on a Mac without one has none)."""
    try:
        return subprocess.run(["launchctl", "print", f"gui/{os.getuid()}"], capture_output=True, timeout=3).returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def probe_windows_interactive(env):
    """True in an interactive desktop session (console or RDP), false in a service or an ssh session."""
    name = env.get("SESSIONNAME", "")
    return bool(name) and name.lower() != "services" and not (env.get("SSH_CONNECTION") or env.get("SSH_CLIENT"))


def probe_container(env):
    return bool(env.get("KUBERNETES_SERVICE_HOST")) or os.path.exists("/.dockerenv") or os.path.exists("/run/.containerenv")


def probe_wsl_opener():
    """WSL can open the Windows browser (and reach localhost through it) when one of these exists."""
    return bool(shutil.which("wslview") or shutil.which("explorer.exe"))


def environment_signals(env=None):
    """Everything choose_method needs to know about this machine, as a plain dict."""
    env = os.environ if env is None else env
    plat = platform_name()
    sig = {"platform": plat,
           "ssh": bool(env.get("SSH_CONNECTION") or env.get("SSH_TTY")),
           "browser_env": bool(env.get("BROWSER")),
           "vscode": bool(env.get("VSCODE_IPC_HOOK_CLI") or "vscode" in env.get("BROWSER", "").lower()),
           "container": probe_container(env),
           "wsl": bool(env.get("WSL_DISTRO_NAME")),
           "wsl_opener": False, "desktop": False}
    if sig["wsl"]:
        sig["wsl_opener"] = probe_wsl_opener()
    if plat == "darwin":
        sig["desktop"] = probe_macos_gui()
    elif plat == "windows":
        sig["desktop"] = probe_windows_interactive(env)
    else:
        sig["desktop"] = bool(env.get("DISPLAY") or env.get("WAYLAND_DISPLAY"))
    return sig


def classify_environment(sig):
    """'gui' (a browser can be reached from the loopback listener) or 'headless'."""
    if sig["vscode"]:
        return "gui"                        # VS Code remote and dev containers forward ports and open the local browser
    if sig["ssh"] or sig["container"]:
        return "gui" if sig["browser_env"] else "headless"
    if sig["wsl"]:
        return "gui" if sig["wsl_opener"] or sig["browser_env"] else "headless"
    return "gui" if sig["desktop"] else "headless"


# -- what the IdP supports

def idp_support(src, tolerant=False):
    """{'device': bool, 'pkce': bool} from the discovery document (or the explicit endpoints in the config)."""
    try:
        ep = src.endpoints()
    except AuthError:
        if tolerant:
            return {"device": True, "pkce": True}
        raise
    grants = ep.get("grant_types_supported")
    dev = bool(ep.get("device_authorization_endpoint")) and (not grants or DEVICE_GRANT in grants)
    pk = bool(ep.get("authorization_endpoint")) and (not grants or "authorization_code" in grants)
    return {"device": dev, "pkce": pk}


def is_refused(st, key, now=None):
    return float((st.get(key) or {}).get("until", 0)) > (time.time() if now is None else now)


def learn_refusal(state, kind, status, body, cfg):
    """Remember that the IdP refused the device grant (kind 'device') or the loopback redirect ('pkce') for a while."""
    err, desc = str(body.get("error", "")), str(body.get("error_description", ""))
    codes = re.findall(r"AADSTS\d+", desc)
    if kind == "device":
        hit = status in (400, 401, 403) and (err in ("unauthorized_client", "invalid_grant", "access_denied") or bool(codes))
    else:
        hit = err in ("redirect_uri_mismatch", "invalid_redirect_uri") or any(c in ("AADSTS500113", "AADSTS50011") for c in codes)
    if not hit:
        return False
    try:
        st = state.load()
        st[kind + "_unavailable"] = {"until": int(time.time() + float(cfg["device_unavailable_ttl"])), "reason": (err + " " + " ".join(codes)).strip()}
        state.save(st)
    except OSError:
        pass
    return True


def record_login_method(state, method):
    """After a successful sign-in: remember the method, and forget a refusal of the family that just worked."""
    with state.lock():
        st = state.load()
        st["last_login_method"] = method
        st.pop("device_unavailable" if method == "device" else "pkce_unavailable", None)
        state.save(st)


# -- the choice

def method_viable(method, cls, support, st, cfg, hook=False, now=None):
    if method == "device":
        return support["device"] and not is_refused(st, "device_unavailable", now)
    if not support["pkce"] or is_refused(st, "pkce_unavailable", now):
        return False
    if method == "pkce":
        return cls == "gui"
    if method == "pkce-print":
        return cls == "gui" or int(cfg["redirect_port"]) > 0        # headless: only with a port the user can forward
    return not hook                                                  # pkce-paste needs a terminal


def choose_method(flag, env, cfg, st, support, sig, hook=False, now=None):
    """(method, why) by precedence: flag > AIGW_LOGIN_METHOD > config login_method > remembered > auto-detection.

    Pure: all inputs are arguments. `flag` is a method name or None; `env` a mapping; `cfg` the config; `st` the state
    dict; `support` from idp_support; `sig` from environment_signals. In a hook (hook=True) the flag is ignored and
    pkce-paste is never chosen. method is None when nothing is viable (why says what was tried).
    """
    if flag and not hook:
        return flag, "command-line flag"
    for value, source in ((env.get("AIGW_LOGIN_METHOD", ""), "AIGW_LOGIN_METHOD"), (cfg.get("login_method", "auto"), "config login_method")):
        value = {"paste": "pkce-paste"}.get(value.strip().lower(), value.strip().lower())
        if value in ("", "auto"):
            continue
        if value not in LOGIN_METHODS:
            raise AuthError(f"{source}: unknown sign-in method '{value}' (use auto, {', '.join(LOGIN_METHODS)})")
        if hook and value == "pkce-paste":
            return None, f"{source} is pkce-paste, which needs a terminal"
        return value, source
    cls = classify_environment(sig)
    last = st.get("last_login_method")
    if last in LOGIN_METHODS and method_viable(last, cls, support, st, cfg, hook, now):
        return last, "the method of the last sign-in"
    order = ("pkce", "device", "pkce-print", "pkce-paste") if cls == "gui" else ("device", "pkce-print", "pkce-paste")
    for m in order:
        if method_viable(m, cls, support, st, cfg, hook, now):
            return m, f"detected a {cls} environment"
    return None, f"{cls} environment; device {'refused' if is_refused(st, 'device_unavailable', now) else 'unsupported'}, no usable browser redirect"


def effective_hook_login(cfg, env=None):
    """hook_login from the config, overridden by AIGW_HOOK_LOGIN (auto | device | off)."""
    v = (os.environ if env is None else env).get("AIGW_HOOK_LOGIN", "").strip().lower()
    return v if v in ("auto", "device", "off") else cfg["hook_login"]


# -- PKCE with a loopback redirect

def parse_redirect(text):
    """The query parameters of a pasted redirect URL (or of a bare 'code=...&state=...' string)."""
    text = text.strip().strip("<>\"'")
    q = urllib.parse.urlsplit(text).query if "?" in text or "://" in text else text
    return {k: v[0] for k, v in urllib.parse.parse_qs(q.split("#")[0]).items()}


class PkceFlow:
    """One authorization-code + PKCE sign-in. listen=True opens the loopback listener (redirect_port, else any port)."""

    def __init__(self, src, listen=True):
        self.src = src
        cfg = src.cfg
        ep = src.endpoints().get("authorization_endpoint")
        if not ep:
            raise AuthError("the IdP has no authorization endpoint; use --device")
        self.verifier = secrets.token_urlsafe(64)
        challenge = base64.urlsafe_b64encode(hashlib.sha256(self.verifier.encode()).digest()).decode().rstrip("=")
        self.state = secrets.token_urlsafe(24)
        self.got = {}
        self.srv = None
        port = int(cfg["redirect_port"])
        if listen:
            flow = self

            class Callback(http.server.BaseHTTPRequestHandler):
                def log_message(self, *a):
                    pass

                def do_GET(self):
                    q = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
                    if "code" not in q and "error" not in q:          # favicon and the like
                        self.send_response(404)
                        self.end_headers()
                        return
                    flow.got.update({k: v[0] for k, v in q.items()})
                    ok = "code" in q and q.get("state", [""])[0] == flow.state
                    page = b"Signed in to the gateway. You can close this tab." if ok else b"Gateway sign-in failed. Check the terminal."
                    self.send_response(200)
                    self.send_header("Content-Type", "text/plain")
                    self.send_header("Content-Length", str(len(page)))
                    self.end_headers()
                    self.wfile.write(page)

            try:
                self.srv = http.server.HTTPServer(("127.0.0.1", port), Callback)
            except OSError as e:
                raise AuthError(f"cannot listen on 127.0.0.1:{port or 'any port'} for the browser redirect: {e}")
            port = self.srv.server_address[1]
        elif not port:                                                # nobody listens when pasting; any port will do
            import socket
            with socket.socket() as s:
                s.bind(("127.0.0.1", 0))
                port = s.getsockname()[1]
        self.port = port
        self.redirect = cfg["redirect_uri"].format(port=port)
        self.url = ep + ("&" if "?" in ep else "?") + urllib.parse.urlencode({
            "response_type": "code", "client_id": cfg["client_id"], "redirect_uri": self.redirect,
            "scope": cfg["scope"], "state": self.state, "code_challenge": challenge, "code_challenge_method": "S256"})

    def wait(self, timeout):
        """Serve the loopback listener until the browser arrives; returns the redirect's parameters."""
        self.srv.timeout = 1
        deadline = time.time() + timeout
        while not self.got and time.time() < deadline:
            self.srv.handle_request()
        if not self.got:
            raise AuthError("browser sign-in timed out")
        return self.got

    def close(self):
        if self.srv:
            self.srv.server_close()
            self.srv = None

    def finish(self, params):
        """Check the redirect's parameters (state first) and exchange the code; returns the IdP token."""
        cfg = self.src.cfg
        if params.get("state") != self.state:
            raise AuthError("browser sign-in returned the wrong state (a different or older sign-in?); try again")
        if "code" not in params:
            if learn_refusal(self.src.state, "pkce", 400, {"error": params.get("error", ""), "error_description": params.get("error_description", "")}, cfg):
                raise MethodUnavailable(f"the IdP refused the browser redirect: {params.get('error')}")
            raise AuthError(f"browser sign-in failed: {params.get('error')} {params.get('error_description', '')[:160]}")
        status, body = self.src._token_request({"grant_type": "authorization_code", "code": params["code"],
                                                "redirect_uri": self.redirect, "code_verifier": self.verifier})
        if status != 200:
            msg = f"code exchange failed: HTTP {status} {body.get('error', '')} {body.get('error_description', '')[:160]}".strip()
            if learn_refusal(self.src.state, "pkce", status, body, cfg):
                raise MethodUnavailable(msg)
            raise AuthError(msg)
        return self.src._keep(body)


def forward_hint(port, host="<this host>"):
    return f"ssh -L {port}:127.0.0.1:{port} {host}"


def login_paste(src, stdin=None, out=None):
    out = out or sys.stderr
    flow = PkceFlow(src, listen=False)
    print(f"To sign in to the gateway, open this in any browser:\n\n  {flow.url}\n\n"
          f"After you sign in the browser is sent to {flow.redirect}... and shows an error page (nothing listens there). "
          f"Copy the full address from the address bar and paste it here.", file=out, flush=True)
    print("Pasted address: ", end="", file=out, flush=True)
    line = (stdin or sys.stdin).readline()
    if not line.strip():
        raise AuthError("nothing pasted")
    return flow.finish(parse_redirect(line))


def run_login_method(src, method, cfg):
    if method == "device":
        return src.login_device()
    if method == "pkce-paste":
        return login_paste(src)
    if method == "pkce-print" and int(cfg["redirect_port"]) > 0:
        log(f"on a remote host, forward the port first: {forward_hint(cfg['redirect_port'])}")
    return src.login_pkce(open_browser=(method == "pkce"))


# -- in-session sign-in (the precheck hook)

def no_method_message(cfg):
    return ("AI gateway sign-in needed, but no sign-in can be started from inside this session. In a terminal run "
            "`aigw-claude-auth login --paste` (open the URL it prints in any browser, then paste the http://127.0.0.1:... address "
            "you end up on). To sign in from the session instead, set redirect_port in the config and forward it with "
            "`ssh -L <port>:127.0.0.1:<port> <this host>`.")


def start_hook_login(cfg, state, settings):
    """Start the background sign-in chosen for this session; returns the pending record, or None if no method is viable.

    The caller holds state.lock(). Raises AuthError when hook_login is `device` and that fails.
    """
    mode = effective_hook_login(cfg)
    src = TokenSource(cfg, state)
    for _ in range(3):
        if mode == "device":
            method = "device"
        else:
            method, why = choose_method(None, os.environ, cfg, state.load(), idp_support(src, tolerant=True), environment_signals(), hook=True)
            if method is None:
                log(f"no in-session sign-in method: {why}")
                return None
        try:
            return spawn_login_worker(cfg, state, settings, src, method)
        except MethodUnavailable:
            if mode == "device":
                raise
    return None


def spawn_login_worker(cfg, state, settings, src, method):
    cmd = [sys.executable, str(Path(__file__).resolve()), "--config", cfg["_config_path"], "--state-dir", str(state.dir),
           "--settings", str(settings.path), "hook-login-wait", "--method", method]
    d = None
    if method == "device":
        d = src.device_start()                          # a refusal is learned in device_start; the caller picks again
    elif method in LOOPBACK_METHODS and not idp_support(src, tolerant=True)["pkce"]:
        raise MethodUnavailable("the IdP does not offer the browser sign-in")
    with open(state.dir / "hook-login.log", "a", encoding="utf-8") as logf:
        child = spawn_detached(cmd, logf)
    if d is not None:
        child.stdin.write(json.dumps(d).encode())
    child.stdin.close()
    if d is not None:
        p = {"prompt": TokenSource.device_prompt(d), "uri": d.get("verification_uri_complete") or d.get("verification_uri") or d.get("verification_url"),
             "user_code": d.get("user_code", ""), "expires_at": d["deadline"], "pid": child.pid, "method": "device"}
        write_private(state.pending_file, json.dumps(p) + "\n")
        return p
    # PKCE: the worker owns the listener, so it writes the pending record (with the URL) itself; wait for it briefly.
    end = time.time() + max(3, float(cfg["hook_http_timeout"]))
    while time.time() < end:
        try:
            p = json.loads(state.pending_file.read_text(encoding="utf-8"))
            if p.get("pid") == child.pid:
                return p
        except (OSError, ValueError):
            pass
        if child.poll() is not None:
            break
        time.sleep(0.05)
    try:
        child.kill()
    except OSError:
        pass
    raise AuthError("the background sign-in did not start (see hook-login.log)")


def pkce_worker_login(src, cfg, state, method):
    """The hook's detached worker for PKCE: listen, publish the URL in the pending file, wait, exchange the code."""
    flow = PkceFlow(src)
    try:
        prompt = f"open {flow.url}"
        if method == "pkce-print" and (os.environ.get("SSH_CONNECTION") or int(cfg["redirect_port"]) > 0):
            prompt += f" (the browser must reach 127.0.0.1:{flow.port} on this host: {forward_hint(flow.port)})"
        write_private(state.pending_file, json.dumps({"prompt": prompt, "uri": flow.url, "user_code": "", "method": method,
                                                      "expires_at": int(time.time()) + PENDING_SECONDS, "pid": os.getpid()}) + "\n")
        if method == "pkce":
            webbrowser.open(flow.url)
        params = flow.wait(PENDING_SECONDS)
    finally:
        flow.close()
    return flow.finish(params)


# --------------------------------------------------------------------------------------------- inspect

PERSONAL_CLAIMS = ("sub", "email", "preferred_username", "upn", "unique_name", "name", "given_name", "family_name",
                   "oid", "groups", "roles", "wids")        # redacted unless --show-claims
DEBUG_HOURS = 24


def jwt_header(token):
    """Decoded JWT header, or {} (same leniency as jwt_claims)."""
    try:
        seg = token.split(".")[0]
        h = json.loads(base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4)))
        return h if isinstance(h, dict) else {}
    except (IndexError, ValueError, AttributeError):
        return {}


def _when(ts):
    if not isinstance(ts, (int, float)):
        return "none"
    return f"{time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(ts))} local, {time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(ts))} UTC"


def mask_secret(value):
    """A credential for logs and `status`: the scheme kept, 4 characters at each end at most, and the length. A short
    value shows only its length."""
    value = str(value)
    scheme, _, rest = value.partition(" ")
    if not rest:
        scheme, rest = "", value
    shown = f"{rest[:4]}...{rest[-4:]}" if len(rest) > 16 else "..."
    return (scheme + " " if scheme else "") + f"{shown} (len {len(rest)})"


CREDENTIAL_HEADERS = ("authorization", "proxy-authorization", "x-api-key")
LOGGED_HEADERS = ("anthropic-beta", "anthropic-version", "user-agent", "content-type", "x-app")
UPSTREAM_LOGGED = ("request-id", "retry-after")      # response headers kept in the request log: they say who answered a 429 or a 401


def log_headers(headers, gateway_header):
    """The request headers kept in the proxy's recent-request log, credentials partly masked. Never the proxy's own
    secret (x-aigw-local) or any header not listed here."""
    secret = set(CREDENTIAL_HEADERS) | {gateway_header.lower()}
    out = {}
    for k, v in headers.items():
        kl = k.lower()
        if kl in secret:
            out[kl] = mask_secret(v)
        elif kl in LOGGED_HEADERS:
            out[kl] = str(v)[:200]
    return out


def status_claims(claims):
    """The claims `status` shows, as {label: text}: who the JWT is for and where the gateway places the request."""
    out = {}

    def pick(label, *names):
        for n in names:
            if claims.get(n) not in (None, "") and not isinstance(claims[n], (dict, list)):
                out[label] = str(claims[n])
                return

    pick("iss", "iss")
    pick("sub", "sub")
    pick("email", "email_id", "email")
    pick("portkey_oid", "portkey_oid")
    pick("portkey_workspace", "portkey_workspace")
    if isinstance(claims.get("defaults"), dict) and claims["defaults"].get("config_slug"):
        out["config_slug"] = str(claims["defaults"]["config_slug"])
    pick("scope", "scope")
    return out


def jwks_url(cfg):
    """Where the JWT's signing keys are published, as far as the client can tell: the broker's /.well-known/jwks.json when a
    broker issues the JWT, else the IdP's jwks_uri from its discovery document. None when it can't be known (token_command).
    The gateway's own JWKS URL is a per-org setting the client cannot read."""
    if cfg["token_command"]:
        return None
    if cfg["broker_url"]:
        p = urllib.parse.urlsplit(cfg["broker_url"])
        return f"{p.scheme}://{p.netloc}/.well-known/jwks.json"
    if cfg["issuer"]:
        status, doc = http_json(cfg["issuer"].rstrip("/") + "/.well-known/openid-configuration", timeout=min(cfg["http_timeout"], 4))
        if status == 200 and isinstance(doc.get("jwks_uri"), str):
            return doc["jwks_uri"]
    return None


def jwks_rows(cfg, kid):
    """`status` rows for the JWKS: its URL and whether it publishes the JWT's key id. The client does not verify the signature."""
    try:
        url = jwks_url(cfg)
    except AuthError as e:
        return [("jwks", f"unknown ({e})")]
    if not url:
        return [("jwks", "unknown (token_command)" if cfg["token_command"] else "unknown (no discovery document)")]
    rows = [("jwks", url)]
    if not kid:
        return rows + [("jwks check", "the JWT header has no kid")]
    try:
        status, doc = http_json(url, timeout=min(cfg["http_timeout"], 4))
    except AuthError as e:
        return rows + [("jwks check", f"not reachable ({e})")]
    kids = [k.get("kid") for k in doc.get("keys", []) if isinstance(k, dict)] if status == 200 else []
    verdict = f"kid {kid} is published there" if kid in kids else f"kid {kid} is NOT in that JWKS" if kids else f"no keys (HTTP {status})"
    return rows + [("jwks check", verdict + "; this client does not verify the signature, the gateway does against its own JWKS URL")]


def token_source(cfg):
    if cfg["token_command"]:
        return "token_command"
    if cfg["broker_url"]:
        return "broker (gateway JWT from the token broker)"
    return f"IdP direct ({cfg['idp_token'].replace('_', ' ')})"


def inspect_token(token, cfg, show_claims=False, now=None):
    """Interpret a JWT without verifying it. Returns (rows, problems): rows are (label, text), problems are the
    findings that make the token unusable. Never returns the token or its signature."""
    now = now or time.time()
    rows, problems = [], []
    if not token or token == cfg["sentinel"]:
        return [("token", "sentinel (no usable JWT)")], ["no JWT in the settings (it holds the sentinel)"]
    rows.append(("token", fingerprint(token)))
    rows.append(("source", token_source(cfg)))
    claims = jwt_claims(token)
    if not claims:
        rows.append(("format", "not a JWT (opaque token)"))
        if not (cfg["token_command"] or cfg["broker_url"]):
            problems.append(f"the IdP {cfg['idp_token'].replace('_', ' ')} is opaque, the gateway can't validate it (Entra: check the scope's API, not Graph)")
        rows.append(("signature", "not verified"))
        return rows, problems
    hdr = jwt_header(token)
    rows.append(("header", " ".join(f"{k}={hdr.get(k)}" for k in ("alg", "kid", "typ") if k in hdr) or "none"))
    if str(hdr.get("alg", "")).lower() == "none":
        problems.append("alg is none: an unsigned token; the gateway must reject it")
    for k in ("iat", "nbf", "exp"):
        if k in claims:
            rows.append((k, _when(claims[k])))
    exp, nbf = claims.get("exp"), claims.get("nbf")
    if isinstance(exp, (int, float)):
        left = int(exp - now)
        rows.append(("time left", f"{left}s (refresh_before {cfg['refresh_before']}s: " +
                     ("renewal due" if left <= cfg["refresh_before"] else "no renewal needed yet") + ")"))
        if left <= 0:
            problems.append(f"expired {-left}s ago")
    else:
        problems.append("no exp claim")
    if isinstance(nbf, (int, float)) and nbf > now:
        problems.append(f"not valid yet (nbf is {int(nbf - now)}s ahead; check the clock)")
    # verdicts against configuration
    if cfg["issuer"] and not (cfg["token_command"] or cfg["broker_url"]):
        ok = str(claims.get("iss", "")).rstrip("/") == cfg["issuer"].rstrip("/")
        rows.append(("issuer", f"{claims.get('iss')} ({'matches' if ok else 'DIFFERS from'} the configured issuer)"))
        if not ok:
            problems.append("iss differs from the configured issuer")
    elif "iss" in claims:
        rows.append(("issuer", str(claims["iss"])))
    if "aud" in claims:
        aud = claims["aud"] if isinstance(claims["aud"], list) else [claims["aud"]]
        want = cfg.get("audience")                           # not a config key yet; a profile may add one
        if want:
            ok = want in aud
            rows.append(("audience", f"{', '.join(map(str, aud))} ({'contains' if ok else 'DOES NOT contain'} {want})"))
            if not ok:
                problems.append("aud does not contain the configured audience")
        else:
            rows.append(("audience", ", ".join(map(str, aud))))
    # Mode A claims
    for k in ("portkey_oid", "portkey_workspace"):
        if k in claims:
            rows.append((k, str(claims[k])))
    d = claims.get("defaults")
    if isinstance(d, dict):
        for k in ("config_slug", "config_id"):
            if k in d:
                rows.append((f"defaults.{k}", str(d[k])))
    flat = sorted(k for k in claims if k.startswith("defaults."))
    if flat:   # Okta claim expressions can't nest: a claim named "defaults.config_slug" stays a flat key (finding 21)
        problems.append(f"{', '.join(flat)}: a flat claim name with a dot, not a nested defaults object; the gateway "
                        "reads only defaults.<key> inside a defaults object (Okta: use a token inline hook or a broker)")
    # the rest
    shown = {"iss", "aud", "iat", "nbf", "exp", "portkey_oid", "portkey_workspace", "defaults"}
    for k in PERSONAL_CLAIMS:
        if k in claims:
            rows.append((k, json.dumps(claims[k]) if show_claims else "<redacted; --show-claims>"))
    shown.update(PERSONAL_CLAIMS)
    other = sorted(set(claims) - shown)
    if other:
        rows.append(("other claims", ", ".join(other) + " (names only)"))
    rows.append(("signature", "not verified (this view decodes; it does not prove the token is genuine)"))
    return rows, problems


def debug_active(cfg, state):
    until = max(float(cfg.get("debug_until") or 0), float(state.load().get("debug_until") or 0))
    return until if until > time.time() else 0


def debug_summary(cfg, state, token):
    """With debug on: one log line per renewal. Fingerprint and non-secret claims only. Off by itself at debug_until."""
    try:
        until = debug_active(cfg, state)
        if not until:
            return
        hdr, claims = jwt_header(token), jwt_claims(token)
        log(f"debug (until {time.strftime('%H:%M', time.localtime(until))}): renewed {fingerprint(token)} "
            f"alg={hdr.get('alg')} kid={hdr.get('kid')} iss={claims.get('iss')} workspace={claims.get('portkey_workspace')} "
            f"source={token_source(cfg).split(' ')[0]}")
    except Exception:
        pass                                              # debug output must never fail a renewal


def cmd_inspect(a, cfg, state, settings):
    if a.debug:
        with state.lock():
            st = state.load()
            if a.debug == "on":
                st["debug_until"] = int(time.time()) + DEBUG_HOURS * 3600
            else:
                st.pop("debug_until", None)
            state.save(st)
        if a.debug == "off":
            print("debug: off")
            return 0
    if a.fresh and a.live:
        raise AuthError("--fresh and --live are different views: pick one")
    if a.live or (cfg["mode"] == "proxy" and not a.fresh):
        # the token stays in the proxy; it sends back the rows and verdicts
        body = proxy_call(cfg, state, "GET", CONTROL_PREFIX + "inspect" + ("?claims=1" if a.show_claims else ""))
        rows, problems = [tuple(r) for r in body["rows"]], list(body["problems"])
        print("(live: asked the running proxy; the token never leaves it)")
    else:
        if a.fresh:
            with state.lock():
                token = TokenSource(cfg, state).gateway_jwt()      # minted, not written to the settings
            print("(fresh token: minted from the source, not written to the settings; a rotated refresh token is kept)")
        else:
            token = settings.get()
        rows, problems = inspect_token(token, cfg, show_claims=a.show_claims)
    for k, v in rows:
        print(f"{k:18} {v}")
    until = debug_active(cfg, state)
    if until:
        print(f"{'debug':18} ON until {time.strftime('%Y-%m-%d %H:%M', time.localtime(until))}: each renewal logs a summary; turn off with `inspect --debug off`")
    for p in problems:
        print(f"{'PROBLEM':18} {p}")
    return 1 if problems else 0


# --------------------------------------------------------------------------------------------- Mode 2: local proxy
# `mode: proxy`. A user-space process on loopback adds the gateway header to each request Claude Code sends (through
# ANTHROPIC_BASE_URL) and forwards it to `gateway_url`. The JWT lives in this process's memory only.
#
# Threat model (local exposure). Any process that can reach the loopback port would otherwise get the user's JWT
# injected into requests it makes. So: (1) the listener is bound to a loopback address only (parse_listen refuses
# anything else); (2) every request needs a per-user secret in the `x-aigw-local` header, compared in constant time.
# `install` writes the secret into the user's settings (env.ANTHROPIC_CUSTOM_HEADERS), which Claude Code sends on each
# request; the secret is also in the state dir (proxy-secret, mode 600), so the proxy and the CLI commands read it.
# A local process running as the same user can read both files and so can use the proxy: that is the same trust as
# reading settings.json in file mode. Another user on a shared host can't, nor can a web page in a browser (it can't
# send the header without a CORS preflight, which the proxy never approves). Without the secret the proxy answers 498
# with a fixed text that says nothing about tokens, upstream or configuration. (A 401 would send a stored login into
# its OAuth refresh loop, a 403 isn't shown as clearly.) The secret header is stripped before forwarding.
# The control channel (`/_aigw/...`: status, inspect, renew, forget) is on the same listener behind the same secret and
# never returns the token.

LOCAL_HEADER = "x-aigw-local"
CONTROL_PREFIX = "/_aigw/"
GUARD_MESSAGES = {   # the same bodies as the load balancer rules (gateway/alb-guard-ingress.yaml, repro/mock_gateway.py)
    "expired": "AI gateway token expired and could not be refreshed. Sign in to the gateway again, then retry.",
    "missing": "AI gateway token missing (no x-portkey-api-key). Sign in to the gateway, then retry.",
}
LOCAL_DENIED = "AI gateway local proxy: request not authorized. Run `aigw-claude-auth install` to refresh the Claude Code settings."
HOP_BY_HOP = {"connection", "keep-alive", "proxy-connection", "te", "trailer", "transfer-encoding", "upgrade", "host", "content-length"}
STREAM_CHUNK = 64 * 1024
MAX_401_BODY = 64 * 1024


def parse_listen(text):
    """(host, port) from proxy_listen, loopback only. 'localhost' means 127.0.0.1. Port 0 = any free port."""
    host, sep, port = str(text).strip().rpartition(":")
    if not sep or not port.isdigit() or int(port) > 65535:
        raise AuthError(f"proxy_listen must look like 127.0.0.1:18787, not {text!r}")
    host = host.strip("[]")
    if host.lower() == "localhost":
        host = "127.0.0.1"
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        raise AuthError(f"proxy_listen host must be a loopback IP address (127.0.0.1 or ::1), not {host!r}")
    if not ip.is_loopback:
        raise AuthError(f"proxy_listen must be a loopback address (127.0.0.1 or ::1): {host} would expose the gateway JWT to the network")
    return str(ip), int(port)


def fmt_hostport(host, port):
    return f"[{host}]:{port}" if ":" in host else f"{host}:{port}"


def proxy_hostport(cfg):
    return fmt_hostport(*parse_listen(cfg["proxy_listen"]))


def proxy_base_url(cfg):
    """The ANTHROPIC_BASE_URL that reaches the proxy. Needs a fixed port so the value in the settings stays valid."""
    if parse_listen(cfg["proxy_listen"])[1] == 0:
        raise AuthError("proxy_listen needs a fixed port (not 0): install writes it into ANTHROPIC_BASE_URL")
    return "http://" + proxy_hostport(cfg)


def is_proxy_url(cfg, url):
    try:
        return urllib.parse.urlsplit(str(url)).netloc == proxy_hostport(cfg)
    except (AuthError, ValueError):
        return False


def short_fp(token):
    """Fingerprint for the access log, the same format the mock gateway uses: length and a short hash."""
    return f"len{len(token)}:{hashlib.sha256(token.encode()).hexdigest()[:10]}" if token else None


def secret_file(state):
    return state.dir / "proxy-secret"


def proxy_secret(state, create=False):
    """The per-user secret ('' if there is none yet). create: make one (mode 600, under the state lock)."""
    def read():
        try:
            v = secret_file(state).read_text(encoding="utf-8").strip()
        except OSError:
            return ""
        return v if len(v) >= 32 else ""
    v = read()
    if v or not create:
        return v
    with state.lock():
        v = read()
        if not v:
            v = secrets.token_urlsafe(32)
            write_private(secret_file(state), v + "\n")
        return v


def secret_matches(expected, given):
    return bool(expected) and given is not None and hmac.compare_digest(expected.encode("utf-8", "replace"), str(given).encode("utf-8", "replace"))


class JwtHolder:
    """The gateway JWT, in memory. Renewed from the configured source like `sync` does (under the state lock, because a
    refresh token rotates), ahead of expiry by the daemon loop, on demand in the request path as a fallback."""

    def __init__(self, cfg, state, cooldown=10):
        self.cfg, self.state, self.cooldown = cfg, state, cooldown
        self.token = ""
        self.lock = threading.Lock()
        self.renewed_at = 0
        self.renewed_ts = 0.0          # the same moment, not rounded to seconds: compared with the proxy's config reload
        self.last_error = ""
        self.retry_at = 0.0            # request path: no new attempt before this (monotonic), so an IdP outage costs one slow request
        self.last_forced = -1e9        # monotonic time of the last renewal forced by a refusal

    def usable(self, tok=None):
        tok = self.token if tok is None else tok
        return bool(tok) and seconds_left(tok) > 0

    def _mint(self):
        """Mint and install a new JWT (caller holds self.lock). Returns (ok, message)."""
        try:
            with self.state.lock():
                self.state.migrate()
                new = TokenSource(self.cfg, self.state).gateway_jwt()
        except AuthError as e:
            return self._failed(str(e))
        except Exception as e:                                  # a bug must not take the proxy down
            return self._failed(f"{type(e).__name__}: {e}")
        left = seconds_left(new)
        if left < 60:
            return self._failed("refusing to use it: " + ("the new JWT has no exp claim" if left < 0 else f"the new JWT expires in {left}s"))
        self.token, self.renewed_at, self.renewed_ts, self.last_error = new, int(time.time()), time.time(), ""
        try:
            debug_summary(self.cfg, self.state, new)
        except Exception:
            pass
        return True, f"renewed the JWT ({fingerprint(new)})"

    def _failed(self, msg):
        self.last_error = msg
        self.retry_at = time.monotonic() + 10
        return False, msg

    def renew(self, force=False):
        """(ok, changed, message). Not forced: only when less than refresh_before is left."""
        with self.lock:
            if not force and seconds_left(self.token) > self.cfg["refresh_before"]:
                return True, False, f"current JWT still valid ({fingerprint(self.token)})"
            ok, msg = self._mint()
            if not ok and self.usable():
                return False, False, msg + " (the current JWT is kept)"
            return ok, ok, msg

    def get(self):
        """The JWT for a request, or None when there is no usable one (the caller fails closed)."""
        tok = self.token
        if seconds_left(tok) > self.cfg["refresh_before"]:
            return tok
        with self.lock:
            if seconds_left(self.token) <= self.cfg["refresh_before"] and time.monotonic() >= self.retry_at:
                self._mint()
            return self.token if self.usable() else None

    def renew_after_refusal(self, used):
        """The gateway refused `used`. A different, usable JWT to retry with, or None (nothing new to try)."""
        with self.lock:
            if self.token != used and self.usable():
                return self.token                               # another request already renewed it
            if time.monotonic() - self.last_forced < self.cooldown:
                return None
            self.last_forced = time.monotonic()
            self._mint()
            return self.token if self.token != used and self.usable() else None

    def forget(self):
        with self.lock:
            self.token, self.renewed_at = "", 0
            self.retry_at = 0.0


def classify_401(data, encoding=""):
    """'gateway' for the gateway's own refusal (a Portkey Error body), 'other' for anything else, Anthropic's relayed 401
    included (it carries "provider":"anthropic")."""
    enc = (encoding or "").lower()
    if "gzip" in enc or "deflate" in enc:
        try:
            data = zlib.decompress(data, 47)
        except zlib.error:
            pass
    compact = data.replace(b" ", b"")
    if b"Portkey Error:" in data and b'"provider":"anthropic"' not in compact:
        return "gateway"
    return "other"


class Upstream:
    """Connections to the gateway: TLS verified against the system store, HTTPS_PROXY / HTTP_PROXY / NO_PROXY honored
    (loopback upstreams are never proxied)."""

    def __init__(self, url, timeout=600):
        u = urllib.parse.urlsplit(url)
        self.scheme, self.host = u.scheme, u.hostname
        self.port = u.port or (443 if u.scheme == "https" else 80)
        self.base = u.path.rstrip("/")
        self.netloc = (f"[{u.hostname}]" if ":" in u.hostname else u.hostname) + (f":{u.port}" if u.port else "")
        self.timeout = timeout
        self.ctx = ssl.create_default_context() if u.scheme == "https" else None

    def _proxy(self):
        try:
            if ipaddress.ip_address(self.host).is_loopback or self.host == "localhost":
                return None
        except ValueError:
            if self.host == "localhost":
                return None
        try:
            if urllib.request.proxy_bypass(self.host):
                return None
            found = urllib.request.getproxies().get(self.scheme)
        except Exception:
            return None
        return urllib.parse.urlsplit(found) if found else None

    def connect(self):
        """(connection, request-target function)."""
        px = self._proxy()
        if px is None:
            if self.scheme == "https":
                return http.client.HTTPSConnection(self.host, self.port, timeout=self.timeout, context=self.ctx), lambda p: self.base + p
            return http.client.HTTPConnection(self.host, self.port, timeout=self.timeout), lambda p: self.base + p
        auth = {}
        if px.username:
            cred = f"{urllib.parse.unquote(px.username)}:{urllib.parse.unquote(px.password or '')}"
            auth = {"Proxy-Authorization": "Basic " + base64.b64encode(cred.encode()).decode()}
        phost, pport = px.hostname, px.port or (443 if px.scheme == "https" else 80)
        if self.scheme == "https":
            conn = http.client.HTTPSConnection(phost, pport, timeout=self.timeout, context=self.ctx) if px.scheme == "https" \
                else http.client.HTTPConnection(phost, pport, timeout=self.timeout)
            conn.set_tunnel(self.host, self.port, headers=auth)
            return conn, lambda p: self.base + p
        conn = http.client.HTTPConnection(phost, pport, timeout=self.timeout)
        return conn, lambda p: f"http://{self.netloc}{self.base}{p}"


class ProxyServer:
    """The Mode 2 proxy. start() binds and serves in a thread; stop() ends it."""

    CONFIG_POLL = 2.0                   # seconds between looks at config.json (tests shorten it)

    def __init__(self, cfg, state, settings, access_log=None, renew_cooldown=10):
        if not cfg.get("gateway_url"):
            raise AuthError("proxy mode needs gateway_url in the config (the gateway the proxy forwards to)")
        self.cfg, self.state, self.settings = cfg, state, settings
        self.listen = parse_listen(cfg["proxy_listen"])
        self.up = Upstream(cfg["gateway_url"], timeout=600)
        self.up_hostport = (self.up.host, self.up.port)
        if self.up_hostport == (self.listen[0], self.listen[1]) and self.listen[1]:
            raise AuthError("gateway_url points at the proxy itself")
        self.header = cfg["header"].lower()
        self.holder = JwtHolder(cfg, state, renew_cooldown)
        self.secret = proxy_secret(state, create=True)
        self.access_log, self.log_lock = access_log, threading.Lock()
        self.stats, self.stats_lock = {}, threading.Lock()
        n = cfg.get("proxy_log_requests", 0)
        self.recent = collections.deque(maxlen=n) if n > 0 else None       # the last n requests, for `requests`; credentials masked
        self.last_outcome, self.started = "", time.time()
        self.blocked = None                 # a preflight Error (dict): every request is answered 498 with it
        self.blocked_checked = 0.0
        self.signin_msg, self.signin_at = "", 0.0
        self.srv, self.port = None, 0
        self.config_path = cfg.get("_config_path")
        self.config_sig = file_digest(self.config_path)
        self.reload_lock, self.stopping = threading.Lock(), threading.Event()
        self.config_error, self.restart_needed, self.reloaded_at, self.signin_needed = "", [], 0.0, False

    # -- config.json changes
    def check_config(self):
        """Look at config.json and, when it changed, apply the keys in RELOAD_SAFE in place. The others are only reported
        (restart_needed). A file that does not load changes nothing: the old settings stay and config_error says why."""
        if not self.config_path:
            return
        sig = file_digest(self.config_path)
        with self.reload_lock:
            if sig == self.config_sig:
                return
            self.config_sig = sig                               # also after a failure: one log line per change, not one per look
            try:
                new = load_config(Path(self.config_path))
            except (AuthError, ValueError, OSError) as e:
                self.config_error = str(e) or type(e).__name__
                log(f"config.json changed but is not valid; keeping the old settings: {self.config_error}")
                return
            self.config_error = ""
            before = idp_identity(self.cfg)
            safe = [k for k in sorted(RELOAD_SAFE) if new.get(k) != self.cfg.get(k)]
            for k in safe:
                self.cfg[k] = new[k]
            self.restart_needed = sorted(k for k in DEFAULTS if k not in RELOAD_SAFE and new.get(k) != self.cfg.get(k))
            if "proxy_log_requests" in safe:
                n = self.cfg["proxy_log_requests"]
                with self.stats_lock:
                    self.recent = collections.deque(self.recent or (), maxlen=n) if n > 0 else None
            self.reloaded_at = time.time()
            if idp_identity(self.cfg) != before:
                self.signin_needed = True
                log(f"config.json reloaded: the IdP is now {idp_label(idp_identity(self.cfg))}; sign in again with `aigw-claude-auth login`")
            else:
                log("config.json reloaded" + (f" (applied: {', '.join(safe)})" if safe else "") +
                    (f"; restart the proxy to apply: {', '.join(self.restart_needed)}" if self.restart_needed else ""))

    def _watch_config(self):
        while not self.stopping.wait(self.CONFIG_POLL):
            try:
                self.check_config()
            except Exception as e:                              # a bug here must not take the proxy down
                log(f"config check failed: {type(e).__name__}: {e}")

    # -- local secret
    def authorized(self, given):
        if secret_matches(self.secret, given):
            return True
        fresh = proxy_secret(self.state)                        # `install` may have made a new one since we started
        if fresh and fresh != self.secret:
            self.secret = fresh
            return secret_matches(fresh, given)
        return False

    # -- fail closed
    def no_jwt_message(self):
        msg = GUARD_MESSAGES["expired"]
        cfg = self.cfg
        if cfg["token_command"] or effective_hook_login(cfg) == "off" or self.state.get_refresh_token():
            return msg
        if time.time() - self.signin_at > 20:                   # the pending sign-in is reused; don't probe the IdP per request
            self.signin_at = time.time()
            self.signin_msg = ""
            try:
                hcfg = dict(cfg, http_timeout=min(cfg["http_timeout"], cfg["hook_http_timeout"]))
                self.signin_msg = hook_login_reason(hcfg, self.state, self.settings)
            except Exception as e:
                log(f"could not start a sign-in from the proxy: {e}")
        return f"{msg} {self.signin_msg}".strip()

    def check_blocked(self):
        """The daemon loop sets self.blocked from the preflight; while it is set, look again every 5 s so a fix takes effect."""
        if self.blocked and time.time() - self.blocked_checked > 5:
            self.blocked_checked = time.time()
            errors = preflight_errors(self.cfg, self.state, self.settings)
            self.blocked = errors[0] if errors else None
        return self.blocked

    # -- accounting
    def record(self, entry):
        with self.stats_lock:
            self.stats[str(entry["status"])] = self.stats.get(str(entry["status"]), 0) + 1
            if entry.get("outcome"):
                self.last_outcome = entry["outcome"]
            if self.recent is not None:
                self.recent.append({k: v for k, v in entry.items() if k != "outcome"})
        if self.access_log:
            with self.log_lock:
                self.access_log.write(json.dumps({k: v for k, v in entry.items() if k != "outcome"}) + "\n")
                self.access_log.flush()
        elif entry["note"] or entry["status"] >= 500:           # the daemon is quiet unless something is off
            log(f"{entry['method']} {entry['path']} -> {entry['status']} {entry['note']} ({entry['ms']} ms, token {entry['token']})")

    def recent_requests(self, n):
        with self.stats_lock:
            return list(self.recent)[-n:] if self.recent is not None and n > 0 else []

    # -- control channel
    def status(self):
        tok = self.holder.token
        claims = jwt_claims(tok) if tok else {}
        return {"version": VERSION, "pid": os.getpid(), "listen": fmt_hostport(self.listen[0], self.port),
                "uptime": int(time.time() - self.started), "mode": "proxy",
                "gateway": f"{self.up.scheme}://{self.up.netloc}", "jwt": fingerprint(tok) if tok else "none",
                "usable": self.holder.usable(), "seconds_left": seconds_left(tok) if tok else -1,
                "renewed_at": self.holder.renewed_at, "last_error": self.holder.last_error, "last_outcome": self.last_outcome,
                "blocked": self.blocked["id"] if self.blocked else "", "requests": dict(self.stats),
                "kid": str(jwt_header(tok).get("kid", "")) if tok else "", "claims": status_claims(claims),
                "config": {"error": self.config_error, "restart_needed": list(self.restart_needed), "reloaded_at": int(self.reloaded_at),
                           "keys": config_fingerprint(self.cfg),
                           "signin_needed": self.signin_needed and self.holder.renewed_ts <= self.reloaded_at}}

    def inspect(self, show_claims=False):
        tok = self.holder.token
        if tok:
            rows, problems = inspect_token(tok, self.cfg, show_claims=show_claims)
        else:
            rows = [("token", "none (the proxy holds no JWT)")]
            problems = ["the proxy holds no JWT" + (f": {self.holder.last_error}" if self.holder.last_error else "")]
        rows += [("proxy", f"pid {os.getpid()}, up {int(time.time() - self.started)}s, gateway {self.up.scheme}://{self.up.netloc}"),
                 ("last outcome", self.last_outcome or "no refusal seen"),
                 ("renewed", _when(self.holder.renewed_at) if self.holder.renewed_at else "never")]
        return {"rows": rows, "problems": problems}

    def control(self, method, path):
        self.check_config()
        u = urllib.parse.urlsplit(path)
        name, q = u.path[len(CONTROL_PREFIX):], urllib.parse.parse_qs(u.query)
        if name == "status" and method == "GET":
            return 200, self.status()
        if name == "inspect" and method == "GET":
            return 200, self.inspect(show_claims="claims" in q)
        if name == "requests" and method == "GET":
            try:
                n = int(q.get("n", ["20"])[0])
            except ValueError:
                n = 20
            return 200, {"limit": self.recent.maxlen if self.recent is not None else 0, "requests": self.recent_requests(n)}
        if name == "renew" and method == "POST":
            ok, changed, msg = self.holder.renew(force="force" in q)
            return 200, {"ok": ok, "changed": changed, "message": msg}
        if name == "forget" and method == "POST":
            self.holder.forget()
            return 200, {"ok": True, "changed": True, "message": "the proxy forgot its JWT"}
        return 404, {"type": "error", "error": {"type": "not_found", "message": "unknown control path"}}

    # -- the listener
    def start(self):
        ps = self

        class Server(http.server.ThreadingHTTPServer):
            address_family = socket.AF_INET6 if ":" in ps.listen[0] else socket.AF_INET
            allow_reuse_address = not is_windows()              # on Windows SO_REUSEADDR would let a second instance bind the same port
            daemon_threads = True
            request_queue_size = 128

            def server_bind(self):
                if is_windows() and hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
                    self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
                super().server_bind()

            def handle_error(self, request, client_address):    # Claude Code drops idle keep-alive connections
                pass

        self.srv = Server(self.listen, self._handler())
        self.port = self.srv.server_address[1]
        write_private(self.state.dir / "proxy.json", json.dumps({"pid": os.getpid(), "host": self.listen[0], "port": self.port}) + "\n")
        threading.Thread(target=self.srv.serve_forever, kwargs={"poll_interval": 0.2}, daemon=True).start()
        if self.config_path:
            threading.Thread(target=self._watch_config, daemon=True).start()
        return self.port

    def stop(self):
        self.stopping.set()
        if self.srv:
            self.srv.shutdown()
            self.srv.server_close()
        try:
            if json.loads((self.state.dir / "proxy.json").read_text(encoding="utf-8")).get("pid") == os.getpid():
                (self.state.dir / "proxy.json").unlink()
        except (OSError, ValueError):
            pass

    def _handler(self):
        ps = self

        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"
            timeout = 600

            def log_message(self, *a):
                pass

            # -- replies
            def reply(self, code, body, ctype="application/json", extra=None):
                data = body if isinstance(body, bytes) else json.dumps(body).encode()
                self.send_response(code)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(data)))
                for k, v in (extra or {}).items():
                    self.send_header(k, v)
                self.end_headers()
                if self.command != "HEAD":
                    self.wfile.write(data)

            def refuse(self, message, kind="gateway_token_error"):      # the 498 the load balancer guard would send
                self.reply(498, {"type": "error", "error": {"type": kind, "message": message}})
                return 498

            # -- request body (Messages requests are JSON with a Content-Length; chunked is handled for completeness)
            def read_body(self):
                if "chunked" in (self.headers.get("Transfer-Encoding") or "").lower():
                    parts = []
                    while True:
                        size = int((self.rfile.readline(1024).split(b";")[0].strip() or b"0"), 16)
                        if size == 0:
                            while self.rfile.readline(1024).strip():     # trailers
                                pass
                            return b"".join(parts)
                        parts.append(self.rfile.read(size))
                        self.rfile.readline(4)
                n = self.headers.get("Content-Length")
                if n is None:
                    return None
                return self.rfile.read(int(n)) if int(n) > 0 else b""

            # -- one request
            def note_upstream(self, resp):
                self._up = {k: resp.getheader(k)[:200] for k in UPSTREAM_LOGGED if resp.getheader(k)}

            def handle_any(self):
                t0 = time.time()
                token, note, outcome = None, "", ""
                self._up = {}                                   # the handler lives across keep-alive requests
                try:
                    if not ps.authorized(self.headers.get(LOCAL_HEADER)):
                        self.close_connection = True            # the body is not read
                        status, note = self.refuse(LOCAL_DENIED, "proxy_auth_error"), "local-secret"
                    elif self.path.startswith(CONTROL_PREFIX):
                        code, obj = ps.control(self.command, self.path)
                        self.reply(code, obj)
                        return                                  # control calls are not requests to the gateway
                    else:
                        status, note, outcome, token = self.forward()
                except ValueError:                              # an unreadable Content-Length or chunk size
                    self.close_connection = True
                    status, note = self.refuse("bad request", "invalid_request_error"), "bad-request"
                except (BrokenPipeError, ConnectionError, socket.timeout) as e:
                    self.close_connection = True
                    status, note = 0, f"client-error:{type(e).__name__}"
                ps.record({"t": round(t0, 3), "ms": round((time.time() - t0) * 1000), "method": self.command,
                           "path": self.path.split("?")[0], "status": status, "note": note, "token": short_fp(token), "outcome": outcome,
                           "in": log_headers(self.headers, ps.header), "out": {ps.header: mask_secret(token)} if token else {},
                           "up": self._up})

            def forward(self):
                self._started = False
                blocked = ps.check_blocked()
                body = self.read_body()
                if blocked:
                    return self.refuse(block_message([blocked]), "gateway_config_error"), f"blocked:{blocked['id']}", "", None
                token = ps.holder.get()
                if token is None:
                    return self.refuse(ps.no_jwt_message()), "no-token", "no JWT", None
                try:
                    return self.relay(body, token)
                except (OSError, http.client.HTTPException) as e:
                    if getattr(self, "_started", False):
                        self.close_connection = True
                        return 0, f"upstream-error-mid-stream:{type(e).__name__}", "", token
                    self.reply(502, {"type": "error", "error": {"type": "proxy_error", "message": "could not reach the gateway"}})
                    return 502, f"upstream-error:{type(e).__name__}", "", token

            def send_upstream(self, body, token):
                fwd = {}
                drop = {h for h in (self.headers.get("Connection") or "").lower().replace(" ", "").split(",") if h}
                for k, v in self.headers.items():
                    kl = k.lower()
                    if kl not in HOP_BY_HOP and kl not in drop and kl not in (ps.header, LOCAL_HEADER):
                        fwd[k] = v
                fwd[ps.cfg["header"]] = token
                fwd["Host"] = ps.up.netloc
                conn, target = ps.up.connect()
                try:
                    conn.request(self.command, target(self.path), body=body, headers=fwd)
                    return conn, conn.getresponse()
                except BaseException:
                    conn.close()
                    raise

            def relay(self, body, token):
                self._started = False
                conn, resp = self.send_upstream(body, token)
                self.note_upstream(resp)
                try:
                    note, outcome = "", ""
                    if resp.status == 401:
                        data = resp.read(MAX_401_BODY)
                        if classify_401(data, resp.getheader("Content-Encoding")) == "other":
                            self.pass_small(resp, data)
                            return 401, "passthrough-401", "anthropic 401 (passed through)", token
                        # the gateway refused our JWT: renew and retry once, else turn it into 498
                        conn.close()
                        fresh = ps.holder.renew_after_refusal(token)
                        if fresh is None:
                            return self.refuse(GUARD_MESSAGES["expired"]), "gateway-401->498", "gateway refused the JWT (Portkey Error)", token
                        token = fresh
                        conn, resp = self.send_upstream(body, token)
                        self.note_upstream(resp)
                        note = "renewed-retry"
                        if resp.status == 401:
                            data = resp.read(MAX_401_BODY)
                            if classify_401(data, resp.getheader("Content-Encoding")) == "gateway":
                                return self.refuse(GUARD_MESSAGES["expired"]), "gateway-401->retry->498", "gateway refused the renewed JWT (Portkey Error)", token
                            self.pass_small(resp, data)
                            return 401, note + ":passthrough-401", "anthropic 401 (passed through)", token
                    self.stream(resp)
                    return resp.status, note, "", token
                finally:
                    conn.close()

            def pass_small(self, resp, data):
                self.reply(resp.status, data, resp.getheader("Content-Type", "application/json"),
                           {k: v for k, v in resp.getheaders() if k.lower() in ("request-id", "x-should-retry", "content-encoding", "retry-after")})

            def stream(self, resp):
                """Send the response as it arrives: read1 returns whatever is there, not 'wait for the buffer to fill'."""
                self._started = True
                self.send_response(resp.status)
                length = resp.getheader("Content-Length")
                bodyless = self.command == "HEAD" or resp.status in (204, 304) or resp.status < 200
                for k, v in resp.getheaders():
                    if k.lower() not in HOP_BY_HOP:
                        self.send_header(k, v)
                chunked = length is None and not bodyless
                if length is not None:
                    self.send_header("Content-Length", length)
                elif chunked:
                    self.send_header("Transfer-Encoding", "chunked")
                self.end_headers()
                self.wfile.flush()
                if bodyless:
                    return
                while True:
                    data = resp.read1(STREAM_CHUNK)
                    if not data:
                        break
                    self.wfile.write(f"{len(data):x}\r\n".encode() + data + b"\r\n" if chunked else data)
                    self.wfile.flush()
                if chunked:
                    self.wfile.write(b"0\r\n\r\n")
                    self.wfile.flush()

            do_GET = do_POST = do_PUT = do_DELETE = do_HEAD = do_PATCH = do_OPTIONS = handle_any

        return Handler


def proxy_endpoint(cfg, state):
    """(host, port) of the proxy, or None. Port 0 in proxy_listen: the running proxy wrote its port to proxy.json."""
    host, port = parse_listen(cfg["proxy_listen"])
    if port == 0:
        try:
            info = json.loads((state.dir / "proxy.json").read_text(encoding="utf-8"))
            host, port = info["host"], int(info["port"])
        except (OSError, ValueError, KeyError):
            return None
    return host, port


def probe_proxy(cfg, state, timeout=2):
    """Is the proxy up on proxy_listen? ('running', status dict) | ('down', '') | ('secret', detail) | ('taken', detail)."""
    where = proxy_endpoint(cfg, state)
    if where is None:
        return "down", ""
    host, port = where
    try:
        # Windows takes about 2 s to refuse a connection to a closed loopback port (it retries the SYN), longer than the
        # request timeout: connect first with room for that, so a closed port is 'down' and not 'taken'.
        socket.create_connection((host, port), timeout=max(timeout, 6)).close()
        status, body = control_call(host, port, proxy_secret(state), "GET", CONTROL_PREFIX + "status", timeout)
    except ConnectionRefusedError:
        return "down", ""
    except (OSError, http.client.HTTPException, ValueError) as e:
        return "taken", f"it did not answer like the proxy ({type(e).__name__})"
    if status == 200 and isinstance(body, dict) and body.get("mode") == "proxy":
        return "running", body
    if status == 498 and isinstance(body, dict) and (body.get("error") or {}).get("type") == "proxy_auth_error":
        return "secret", "an aigw-claude-auth proxy is running there but does not accept this user's secret (proxy-secret in the state dir)"
    return "taken", f"it answered HTTP {status}"


def control_call(host, port, secret, method, path, timeout=5):
    """One request to the proxy's control channel on loopback, never through an HTTP proxy. Returns (status, parsed JSON)."""
    conn = http.client.HTTPConnection(f"[{host}]" if ":" in host else host, port, timeout=timeout)
    try:
        conn.request(method, path, headers={LOCAL_HEADER: secret or "", "Content-Length": "0"} if method == "POST" else {LOCAL_HEADER: secret or ""})
        resp = conn.getresponse()
        raw = resp.read(1 << 20)
        return resp.status, json.loads(raw.decode("utf-8", "replace") or "null")
    finally:
        conn.close()


def proxy_call(cfg, state, method, path, timeout=5):
    """Ask the running proxy. AuthError when it isn't there. The answer never holds the JWT."""
    kind, info = probe_proxy(cfg, state, timeout=2)
    if kind == "down":
        raise AuthError("the proxy is not running: start the daemon (`aigw-claude-auth daemon`, or the launchd / systemd / Task Scheduler entry) or run `aigw-claude-auth proxy`")
    if kind != "running":
        raise AuthError(f"proxy_listen {cfg['proxy_listen']} is not our proxy: {info}")
    host, port = proxy_endpoint(cfg, state)
    status, body = control_call(host, port, proxy_secret(state), method, path, timeout)
    if status != 200:
        raise AuthError(f"the proxy refused the request (HTTP {status})")
    return body


def sync_proxy(cfg, state, force=False, idp=None):
    """`sync` in proxy mode: ask the running proxy to renew (it holds the JWT). Nothing is written to the settings."""
    try:
        body = proxy_call(cfg, state, "POST", CONTROL_PREFIX + "renew" + ("?force=1" if force else ""),
                          timeout=cfg["http_timeout"] + 10)
    except AuthError as e:
        if idp is not None:         # a sign-in just finished and stored the refresh token; the proxy will use it when it starts
            return Result(True, False, f"signed in; {e}")
        return Result(False, False, str(e))
    return Result(bool(body.get("ok")), bool(body.get("changed")), str(body.get("message", "")))


def run_proxy(cfg, state, settings, max_sleep=60, access_log=None):
    """The proxy as a foreground process (`proxy`) or as the daemon in proxy mode: serve, and renew ahead of every expiry."""
    stop = threading.Event()
    daemon_console_fix()
    try:
        ps = ProxyServer(cfg, state, settings, access_log=access_log)
        port = ps.start()
    except OSError as e:
        kind, info = probe_proxy(cfg, state)
        if kind == "running":
            log(f"the proxy is already running (pid {info.get('pid')}); this instance exits")
            return 0                            # exit 0: launchd and systemd do not restart a successful exit
        raise AuthError(f"cannot listen on {cfg['proxy_listen']}: {e}" + (f" ({info})" if info else ""))
    install_stop_signals(stop)
    log(f"proxy listening on {fmt_hostport(ps.listen[0], port)} -> {cfg['gateway_url']} (settings {settings.path})")
    backoff, blocked_by = 30, None
    try:
        while not stop.is_set():
            errors = preflight_errors(cfg, state, settings)     # a config Error: answer 498 with it, renew nothing, retry later
            ps.blocked, ps.blocked_checked = (errors[0] if errors else None), time.time()
            if errors:
                if blocked_by != errors[0]["message"]:
                    log(f"blocking requests: {errors[0]['message']} ({errors[0]['id']})")
                    blocked_by = errors[0]["message"]
                stop.wait(max(5, min(60, max_sleep)))
                continue
            blocked_by = None
            ok, changed, msg = ps.holder.renew()
            if changed or not ok:
                log(msg)
            if ok:
                backoff = 30
                wait = seconds_left(ps.holder.token) - cfg["refresh_before"]
            else:
                wait, backoff = backoff, min(backoff * 2, 300)
            stop.wait(max(5, min(wait, max_sleep)))
    finally:
        ps.stop()
    log("proxy stopped")
    return 0


def install_stop_signals(stop):
    for name in ("SIGTERM", "SIGINT", "SIGBREAK"):              # SIGBREAK exists on Windows only
        if hasattr(signal, name):
            signal.signal(getattr(signal, name), lambda *_: stop.set())


def daemon_console_fix():
    if is_windows() and sys.stderr is None:                     # started by Task Scheduler through pythonw: no console
        log_dir().mkdir(parents=True, exist_ok=True)
        sys.stderr = open(log_dir() / "daemon.log", "a", encoding="utf-8", buffering=1)


# --------------------------------------------------------------------------------------------- commands

def cmd_login(a, cfg, state, settings):
    if cfg["token_command"]:
        raise AuthError("token_command is configured; there is nothing to sign in to")
    src = TokenSource(cfg, state)
    flag = "device" if a.device else "pkce-print" if (a.pkce_print or (a.pkce and a.no_browser)) else "pkce" if a.pkce else "pkce-paste" if a.paste else None
    # No lock while the user signs in (that can take minutes and would stall the hooks); the old refresh token stays
    # usable until the new sign-in succeeds.
    for attempt in range(3):
        method, why = choose_method(flag, os.environ, cfg, state.load(), idp_support(src), environment_signals())
        if method is None:
            raise AuthError("no sign-in method is available here (" + why + "); " + NEXT_STEPS)
        log(f"signing in with {method} ({why})")
        try:
            idp = run_login_method(src, method, cfg)
            break
        except MethodUnavailable as e:
            if flag or attempt == 2:        # an explicit choice is not second-guessed
                raise
            log(f"{e}; trying another method")
    r = finish_login(cfg, state, settings, src, idp, method)
    log(r.message)
    return 0 if r.ok else 1


def finish_login(cfg, state, settings, src, idp, method=None):
    """After a sign-in: drop a stale refresh token if the IdP sent none, then write a JWT from the new IdP token."""
    if not src.got_refresh_token:
        with state.lock():
            state.drop_refresh_token()
        log("warning: the IdP returned no refresh token (is offline_access in scope?); you will have to sign in again when the JWT expires")
    r = sync(cfg, state, settings, force=True, idp=idp)
    if r.ok and method:
        record_login_method(state, method)
    return r


def browser_available():
    if os.environ.get("SSH_CONNECTION") or os.environ.get("SSH_TTY"):
        return False
    return sys.platform == "darwin" or bool(os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY"))


def cmd_logout(a, cfg, state, settings):
    if cfg["mode"] == "proxy":
        with state.lock():
            state.drop_refresh_token()
        try:
            proxy_call(cfg, state, "POST", CONTROL_PREFIX + "forget")
        except AuthError:
            pass                                # not running: it holds nothing
        log("signed out; the proxy no longer holds a JWT and answers 498 until you sign in")
        return 0
    with state.lock():
        state.drop_refresh_token()
        settings.put(cfg["sentinel"])
    log("signed out; the settings now hold the sentinel")
    return 0


def cmd_sync(a, cfg, state, settings):
    r = sync(cfg, state, settings, force=a.force)
    log(r.message, quiet=a.quiet and r.ok)
    return 0 if r.ok else 1


def cmd_token(a, cfg, state, settings):
    if cfg["mode"] == "proxy":              # the proxy keeps its JWT to itself: mint one for the caller, write nothing
        with state.lock():
            token = TokenSource(cfg, state).gateway_jwt()
        print(token)
        return 0
    r = sync(cfg, state, settings, force=a.force)
    if not r.ok:
        log(r.message)
        return 1
    print(r.token)
    return 0


def cmd_status(a, cfg, state, settings):
    loc = state.token_location()
    source = "token_command" if cfg["token_command"] else ("IdP + broker" if cfg["broker_url"] else "IdP token as the JWT")
    rows = [("version", VERSION), ("mode", cfg["mode"]), ("settings", str(settings.path)), ("header", cfg["header"]), ("source", source),
            ("signed in", "yes" if loc else ("n/a" if cfg["token_command"] else "no")),
            ("refresh token", loc or "none")]
    if cfg["mode"] == "proxy":
        kind, info = probe_proxy(cfg, state)
        rows.append(("proxy", f"running on {info['listen']}, pid {info['pid']}, up {info['uptime']}s" if kind == "running"
                     else "NOT RUNNING (start the daemon)" if kind == "down" else f"PROBLEM: {info}"))
        rows.append(("jwt", (info["jwt"] if info["jwt"] != "none" else "none (the proxy holds no JWT)") + " (in the proxy's memory)" if kind == "running" else "unknown"))
        if kind == "running":
            if info.get("last_outcome"):
                rows.append(("last outcome", info["last_outcome"]))
            if info.get("last_error"):
                rows.append(("last error", info["last_error"]))
            ck, ct = proxy_config_state(info, cfg.get("_config_path"), cfg)
            if ck != "ok":
                rows.append(("config", ct))
        shown, kid = (info.get("claims", {}), info.get("kid", "")) if kind == "running" else ({}, "")
    else:
        rows.append(("jwt", fingerprint(settings.get()) if settings.get() != cfg["sentinel"] else "sentinel (no usable JWT)"))
        shown, kid = status_claims(jwt_claims(settings.get())), str(jwt_header(settings.get()).get("kid", ""))
    for k, v in shown.items():
        rows.append((f"jwt {k}", v))
    if shown and not a.offline:                      # the JWKS check is the one network call here
        rows += jwks_rows(cfg, kid)
    p = state.pending()
    if p:
        rows.append(("pending", f"hook sign-in: open {p['uri']}{' and enter ' + p['user_code'] if p.get('user_code') else ''} (until {time.strftime('%H:%M', time.localtime(p['expires_at']))})"))
    for k, v in rows:
        print(f"{k:12} {v}")
    return 0


def cmd_status_unloadable(cdir, config_path, err):
    """`status` when config.json does not load, like `doctor` it still has to work: say so, and still ask a running proxy what it
    holds (it keeps running on its old settings). The proxy is found through proxy.json, which needs no config."""
    rows = [("version", VERSION), ("config", f"{config_path} does not load: {err}")]
    try:
        where = json.loads((cdir / "proxy.json").read_text(encoding="utf-8"))
        code, body = control_call(where["host"], int(where["port"]), proxy_secret(State(cdir)), "GET", CONTROL_PREFIX + "status", 3)
    except (OSError, ValueError, KeyError, http.client.HTTPException):
        code, body = 0, {}
    if code == 200 and isinstance(body, dict) and body.get("mode") == "proxy":
        rows.append(("proxy", f"running on {body.get('listen')}, pid {body.get('pid')}, up {body.get('uptime')}s, still on its old settings"))
        rows.append(("jwt", (body.get("jwt") or "none") + " (in the proxy's memory)"))
        for k, v in (body.get("claims") or {}).items():
            rows.append((f"jwt {k}", str(v)))
        ck, ct = proxy_config_state(body, config_path)
        if ck != "ok":
            rows.append(("proxy config", ct))
    else:
        rows.append(("proxy", "not reachable (no running proxy found through proxy.json)"))
    for k, v in rows:
        print(f"{k:12} {v}")
    return 1


def cmd_requests(a, cfg, state, settings):
    """The proxy's recent requests, oldest first. Credentials are partly masked: scheme, 4 characters at each end, length."""
    if cfg["mode"] != "proxy":
        raise AuthError("mode is file: only the local proxy (mode proxy) keeps a request log")
    body = proxy_call(cfg, state, "GET", CONTROL_PREFIX + f"requests?n={max(a.count, 1)}")
    reqs = body.get("requests", [])
    if a.json:
        print(json.dumps(reqs, indent=2))
        return 0
    if not body.get("limit"):
        print("the proxy keeps no request log (proxy_log_requests is 0 in the config)")
        return 0
    if not reqs:
        print(f"no requests yet (the proxy keeps the last {body['limit']})")
        return 0
    for e in reqs:
        print(f"{time.strftime('%H:%M:%S', time.localtime(e['t']))}  {e['method']} {e['path']} -> {e['status']}  {e['ms']} ms  token {e.get('token') or 'none'}"
              + (f"  [{e['note']}]" if e.get("note") else ""))
        for side in ("in", "out", "up"):
            for k, v in (e.get(side) or {}).items():
                print(f"    {side:3} {k}: {v}")
    print(f"-- {len(reqs)} shown; the proxy keeps the last {body['limit']} (proxy_log_requests), in memory only")
    return 0


def cmd_proxy(a, cfg, state, settings):
    """The proxy in the foreground, for debugging (the daemon runs it in proxy mode). Logs every request to stderr."""
    if cfg["mode"] != "proxy":
        log("note: mode is file in the config; running the proxy anyway")
        cfg = dict(cfg, mode="proxy")
    sink = open(a.access_log, "a", encoding="utf-8") if a.access_log and a.access_log != "-" else sys.stderr
    return run_proxy(cfg, state, settings, a.max_sleep, access_log=sink)


def cmd_daemon(a, cfg, state, settings):
    if cfg["mode"] == "proxy":
        return run_proxy(cfg, state, settings, a.max_sleep)
    stop = threading.Event()
    daemon_console_fix()
    install_stop_signals(stop)
    backoff, blocked_by = 30, None
    log(f"daemon started (settings {settings.path})")
    while not stop.is_set():
        errors = preflight_errors(cfg, state, settings)     # a config Error: write nothing, retry later (recovers by itself)
        if errors:
            if blocked_by != errors[0]["message"]:
                log(f"not renewing: {errors[0]['message']} ({errors[0]['id']})")
                blocked_by = errors[0]["message"]
            stop.wait(max(5, min(60, a.max_sleep)))
            continue
        blocked_by = None
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
    errors = preflight_errors(cfg, state, settings)         # a config Error (doctor) is the block reason; nothing is written
    if errors:
        print(json.dumps({"decision": "block", "reason": block_message(errors)}))
        return 0
    if cfg["mode"] == "proxy":
        return hook_precheck_proxy(cfg, state, settings)
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
        print(json.dumps({"decision": "block", "reason": block_reason(cfg, state, settings, r)}))
    else:
        log(r.message)
        if r.changed:          # we just wrote the sentinel: let the request carry it, so a load balancer rule answers 498
            time.sleep(cfg["hook_wait"])
    return 0


def block_reason(cfg, state, settings, r):
    """The precheck's block message for a failed renewal: the sign-in prompt when the user is signed out."""
    reason = f"AI gateway: {r.message}"
    if effective_hook_login(cfg) != "off" and not cfg["token_command"] and not state.get_refresh_token():
        try:
            reason = hook_login_reason(cfg, state, settings)
        except Exception as e:                              # fall back to the plain message
            log(f"could not start a sign-in from the hook: {e}")
    return reason


def hook_precheck_proxy(cfg, state, settings):
    """Proxy mode: the proxy renews by itself, so the precheck only makes sure it has a JWT. No settings reload to wait for."""
    try:
        st = proxy_call(cfg, state, "GET", CONTROL_PREFIX + "status", timeout=cfg["hook_http_timeout"])
    except AuthError as e:                                  # not running: Claude Code would only see connection errors
        print(json.dumps({"decision": "block", "reason": f"AI gateway: {e}"}))
        return 0
    if st["usable"] and st["seconds_left"] > cfg["refresh_before"]:
        return 0
    r = sync(cfg, state, settings)
    if r.ok:
        return 0
    if st["usable"]:                                        # renewal failed, but what the proxy holds still works for now
        log(r.message)
        return 0
    if cfg["block_on_failure"]:
        print(json.dumps({"decision": "block", "reason": block_reason(cfg, state, settings, r)}))
    else:
        log(r.message)
    return 0


def hook_login_reason(cfg, state, settings):
    """Start a sign-in in the background (or reuse the pending one) and return the block message for it.

    The waiting is done by a detached `hook-login-wait` process, so the hook returns at once. A device code goes to it
    on stdin (never on the command line or on disk) and its output goes to hook-login.log, not to the hook's stdout,
    which Claude Code reads until it closes. Prompts sent before the sign-in is done get the same code or URL again.
    """
    with state.lock():                                      # two sessions prompting at once start one sign-in
        p = state.pending()
        if not p:
            p = start_hook_login(cfg, state, settings)
            if p is None:
                return no_method_message(cfg)
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
    method = getattr(a, "method", "device")
    d = json.loads(sys.stdin.read()) if method == "device" else {}
    log(f"waiting for the device sign-in (code {d.get('user_code', '?')})" if method == "device" else f"waiting for the {method} sign-in")
    try:
        src = TokenSource(cfg, state)
        idp = src.device_poll(d) if method == "device" else pkce_worker_login(src, cfg, state, method)
        r = finish_login(cfg, state, settings, src, idp, method)
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
    proxy = cfg["mode"] == "proxy"
    if proxy:
        if a.base_url:
            raise AuthError("mode is proxy: ANTHROPIC_BASE_URL is the proxy's address; the gateway URL is `gateway_url` in the config (--base-url is for file mode)")
        if not cfg["gateway_url"]:
            raise AuthError("mode is proxy: set gateway_url in the config (the gateway the proxy forwards to)")
        base_url = proxy_base_url(cfg)
    else:
        base_url = a.base_url
    if a.print:
        snippet = {"hooks": {"UserPromptSubmit": [hook_entry(hook, "precheck")], "StopFailure": [hook_entry(hook, "stop-failure")]}}
        if base_url:
            snippet["env"] = {"ANTHROPIC_BASE_URL": base_url}
        print(json.dumps(snippet, indent=2))
        if proxy:
            log(f"the per-user secret ({LOCAL_HEADER}) is not part of this snippet: `install` writes it into each user's own settings")
        return 0
    hook_cmd = None if a.no_hooks else hook
    if proxy:
        # one write: the proxy's address, the local secret, no JWT (a JWT left over from file mode is removed)
        settings.apply(base_url=base_url, hook_command=hook_cmd, put_lines={LOCAL_HEADER: proxy_secret(state, create=True)}, drop_lines=[cfg["header"]])
        log(f"updated {settings.path} (ANTHROPIC_BASE_URL {base_url}, local secret, no JWT)")
        if a.linger and not sys.platform.startswith("linux"):
            log("--linger is for Linux (systemd); ignored")
        if a.no_service or a.no_hooks or cfg.get("fleet"):
            if a.linger:
                log("--linger ignored: no service is installed, and lingering is what keeps the service running after logout")
            log("mode proxy: no daemon service installed (" + ("fleet: the fleet's own entry runs the daemon" if cfg.get("fleet") else "--no-service" if a.no_service else "--no-hooks: the caller runs the daemon") + ")")
            service_ok = False
        else:
            service_ok, msg = service_install(cfg, linger=a.linger)
            log(("mode proxy: daemon service: " if service_ok else "warning: mode proxy: the daemon is NOT installed as a service: ") + msg)
        kind, info = probe_proxy(cfg, state)
        if kind != "running":
            hint = "it is starting; check with `aigw-claude-auth status`" if service_ok else "start the daemon (`aigw-claude-auth daemon`, or the launchd / systemd / Task Scheduler entry) before the next prompt"
            log(f"mode proxy: the proxy is not running yet; {hint}")
            return 0
        log(f"mode proxy: requests go to the proxy at {proxy_hostport(cfg)}; keep the daemon running, it renews the JWT")
        r = sync(cfg, state, settings)
        log(r.message)
        return install_status(r, state)
    # file mode; a proxy address and local secret left over from proxy mode are removed (the gateway URL replaces the address)
    back = a.base_url or cfg["gateway_url"] or None
    was_proxy = is_proxy_url(cfg, (settings.load().get("env") or {}).get("ANTHROPIC_BASE_URL", ""))
    settings.apply(base_url=back, hook_command=hook_cmd, drop_lines=[LOCAL_HEADER], drop_base_url=lambda u: is_proxy_url(cfg, u))
    log(f"updated {settings.path}")
    if was_proxy and not back:
        log("removed the proxy's ANTHROPIC_BASE_URL; run install again with --base-url <gateway URL> (or set gateway_url in the config)")
    log("mode file: the JWT is in settings.json; the hooks renew it before a prompt, and the daemon (optional) renews it in the background")
    r = sync(cfg, state, settings)
    log(r.message)
    return install_status(r, state)


def install_status(r, state):
    """Exit status of install. Being signed out is not a failure: the settings are written, and the sign-in comes later
    (`login`, or the first prompt when hook_login allows it), so unattended installs succeed."""
    if not r.ok and not state.get_refresh_token():
        log("not signed in yet: run `aigw-claude-auth login`, or sign in at the first prompt (hook_login)")
        return 0
    return 0 if r.ok else 1


# --------------------------------------------------------------------------------------------- proxy: the daemon as a service
# In proxy mode the daemon is the local proxy, so it has to keep running. `install` makes it a per-user service where the
# platform has one: a launchd agent (macOS), a systemd user unit (Linux), a Task Scheduler task (Windows). If that fails,
# the settings are already written; the caller gets the reason and install still exits 0.

def home_dir():
    return Path.home()              # read at call time so tests can point it at a throwaway home


def service_run(argv):
    """Run a service-manager command: (ok, output). A missing program or a timeout is a failure, not a crash."""
    try:
        r = subprocess.run(argv, capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.SubprocessError) as e:
        return False, str(e)
    return r.returncode == 0, (r.stderr or r.stdout or "").strip()


# Interpreters the service may run under, Homebrew first (it wins ties). sys.executable is the last resort and is not used
# from a virtualenv, whose path goes away with the venv.
SERVICE_PYTHONS = ("/opt/homebrew/bin/python3", "/usr/local/bin/python3", "/Library/Frameworks/Python.framework/Versions/Current/bin/python3", "/usr/bin/python3")


def python_version(path):
    """(major, minor) of the interpreter at path, or None when it does not run."""
    try:
        r = subprocess.run([path, "-c", "import sys; print(sys.version_info[0], sys.version_info[1])"], capture_output=True, text=True, timeout=10)
        return tuple(int(x) for x in r.stdout.split()[:2]) if r.returncode == 0 else None
    except (OSError, subprocess.SubprocessError, ValueError):
        return None


def service_python():
    """The newest usable interpreter (3.8+) among SERVICE_PYTHONS, Homebrew winning ties; None when there is none."""
    candidates = list(SERVICE_PYTHONS) + ([] if sys.prefix != sys.base_prefix else [sys.executable])
    best = None                                                 # (version, -position, path)
    for pos, path in enumerate(candidates):
        if not os.access(path, os.X_OK):
            continue
        v = python_version(path)
        if v and v >= (3, 8) and (best is None or (v, -pos) > best[:2]):
            best = (v, -pos, path)
    return best[2] if best else None


def systemd_unit_path():
    return Path(os.environ.get("XDG_CONFIG_HOME") or home_dir() / ".config") / "systemd" / "user" / f"{TASK_NAME}.service"


def linger_state():
    """'yes' or 'no' from loginctl for this user; None when it can't be read (no logind, no systemd)."""
    ok, out = service_run(["loginctl", "show-user", str(os.getuid()), "-p", "Linger", "--value"])
    return out.strip() if ok and out.strip() in ("yes", "no") else None


def linger_note(run, linger):
    """The lingering part of the Linux service message; with linger, turn it on first."""
    if not linger:
        return ("the proxy stops when your last login session ends. On an SSH-only or headless machine, or when Claude Code runs "
                "in tmux or screen past your login, run `aigw-claude-auth install --linger` (or `loginctl enable-linger`)")
    ok, out = run(["loginctl", "show-user", str(os.getuid()), "-p", "Linger", "--value"])
    if ok and out.strip() == "yes":
        return "lingering was already on, so the proxy keeps running after logout"
    ok, out = run(["loginctl", "enable-linger"])
    if ok:
        return "lingering is on: the proxy keeps running after logout and starts at boot (undo: `loginctl disable-linger`)"
    return f"warning: could not enable lingering ({out}); run `sudo loginctl enable-linger $USER` to keep the proxy running after logout"


def service_install(cfg, platform=None, run=None, linger=False):
    """Make the daemon a persistent per-user service. Returns (ok, message). linger (Linux): also `loginctl enable-linger`, so
    the proxy outlives the login session; a failure there is a warning in the message, not a failure of the service."""
    platform, run = platform or sys.platform, run or service_run
    python = str(Path(sys.executable).resolve()) if platform == "win32" else service_python()
    if not python:
        return False, "no Python 3.8 or later found (looked in Homebrew, python.org, /usr/bin and sys.executable outside a virtualenv)"
    script = str(Path(__file__).resolve())
    try:
        if platform == "darwin":
            path = home_dir() / "Library" / "LaunchAgents" / f"{TASK_NAME}.plist"
            log_path = home_dir() / "Library" / "Logs" / f"{TASK_NAME}.log"
            path.parent.mkdir(parents=True, exist_ok=True)
            with open(path, "wb") as f:
                plistlib.dump({"Label": TASK_NAME, "ProgramArguments": [python, script, "daemon"], "RunAtLoad": True,
                               "KeepAlive": {"SuccessfulExit": False}, "ThrottleInterval": 10,
                               "StandardOutPath": str(log_path), "StandardErrorPath": str(log_path)}, f)
            uid = os.getuid()
            label = f"gui/{uid}/{TASK_NAME}"
            run(["launchctl", "bootout", label])                             # replaces an earlier agent; "not loaded" is fine
            for _ in range(20):                                              # bootout returns before launchd forgets the label
                if not run(["launchctl", "print", label])[0]:
                    break
                time.sleep(0.5)
            ok, out = run(["launchctl", "bootstrap", f"gui/{uid}", str(path)])
            if not ok:
                time.sleep(1)                                                # one retry after a short wait
                ok, out = run(["launchctl", "bootstrap", f"gui/{uid}", str(path)])
            if not ok:
                return False, f"wrote {path}, but launchctl could not start it ({out}); it starts at your next desktop login"
            return True, f"launch agent {path} runs {python} (starts at login, restarted after a crash)"
        if platform.startswith("linux"):
            path = systemd_unit_path()
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("[Unit]\nDescription=aigw-claude-auth daemon (local proxy in proxy mode)\nAfter=network-online.target\n\n"
                            f"[Service]\nExecStart={shlex.quote(python)} {shlex.quote(script)} daemon\n"
                            "Restart=on-failure\nRestartSec=10\n\n[Install]\nWantedBy=default.target\n")
            ok, out = run(["systemctl", "--user", "daemon-reload"])
            if not ok:
                return False, f"wrote {path}, but no systemd user session answered ({out}); run install from a login session"
            ok, out = run(["systemctl", "--user", "enable", "--now", f"{TASK_NAME}.service"])
            if not ok:
                return False, f"wrote {path}, but systemd did not start it ({out})"
            return True, f"systemd user unit {path} is enabled; " + linger_note(run, linger)
        if platform == "win32":
            tmp = Path(tempfile.mkdtemp(prefix="aigw-task-")) / "task.xml"
            try:
                tmp.write_text(task_xml(current_user(), python, script), encoding="utf-16")
                ok, out = run(["schtasks.exe", "/Create", "/TN", TASK_NAME, "/XML", str(tmp), "/F"])
            finally:
                shutil.rmtree(tmp.parent, ignore_errors=True)
            if not ok:
                return False, f"Task Scheduler refused the task ({out})"
            return True, f"Task Scheduler task {TASK_NAME} runs at log on"
    except OSError as e:
        return False, f"could not write the service definition: {e}"
    return False, f"no service manager for {platform}; run `aigw-claude-auth daemon` yourself"


TASK_NAME = "aigw-claude-auth"


def task_xml(user, python, script):
    """Task Scheduler definition: at log on of `user`, one instance, restart on failure, no time limit."""
    pyw = Path(python).with_name("pythonw.exe")
    exe = str(pyw if pyw.exists() else python)
    return f"""<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><Description>Keeps the gateway JWT fresh (aigw-claude-auth daemon; in proxy mode it is the local proxy Claude Code talks to)</Description></RegistrationInfo>
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


# --------------------------------------------------------------------------------------------- fleet replaces personal
# A fleet install (packaging/: `fleet` in its config, which sits in the install dir; hooks and base URL in managed
# settings) replaces a personal one (README 1.3: config.json in the config dir, hooks in the user's settings, a launchd
# agent, systemd user unit or Task Scheduler task named TASK_NAME). Both use the same state dir, so the fleet would pick
# up the personal refresh token (perhaps from another IdP) and both daemons would write the JWT. The fleet's login entry
# calls take_over_personal() before its first run; doctor reports what is left (personal-install).

def personal_entry(platform=None):
    """The personal background entry as (kind, path or task name), or None."""
    platform = platform or sys.platform
    if platform == "darwin":
        p = Path.home() / "Library" / "LaunchAgents" / f"{TASK_NAME}.plist"
        return ("launchd", p) if p.exists() else None
    if platform == "win32":
        try:
            r = subprocess.run(["schtasks.exe", "/Query", "/TN", TASK_NAME], capture_output=True, text=True, timeout=10)
        except (OSError, subprocess.SubprocessError):
            return None
        return ("task", TASK_NAME) if r.returncode == 0 else None
    p = Path(os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config") / "systemd" / "user" / f"{TASK_NAME}.service"
    return ("systemd", p) if p.exists() else None


def personal_leftovers(cfg, state_dir, user_settings):
    """What of a personal install is still there next to a fleet one (empty when cfg is not a fleet config)."""
    if not cfg.get("fleet"):
        return []
    left = []
    if (Path(state_dir) / "config.json").exists():
        left.append(f"its config.json in {state_dir}")
    entry = personal_entry()
    if entry:
        left.append(f"its {entry[0]} entry ({entry[1]})")
    if MARKER.search(json.dumps((user_settings or {}).get("hooks") or {})):
        left.append("its hooks in the user's Claude Code settings")
    return left


def take_over_personal(cfg, state, settings, run=None, platform=None):
    """Fleet install: stop and remove this user's personal background entry, forget its refresh token in the OS store,
    drop its hooks from the user's settings and move its files from the state dir to <state dir>.personal-<time>.
    Returns what it did, one line per step."""
    if not cfg.get("fleet"):
        return []
    run, platform, d, done = run or subprocess.run, platform or sys.platform, state.dir, []
    entry, personal_cfg = personal_entry(platform), d / "config.json"
    hooks = MARKER.search(json.dumps(settings.load().get("hooks") or {}))
    if not (entry or personal_cfg.exists() or hooks):
        return []
    backup = d.with_name(f"{d.name}.personal-{time.strftime('%Y%m%d-%H%M%S')}")
    backup.mkdir(mode=0o700, parents=True, exist_ok=True)
    quiet = dict(capture_output=True, text=True, timeout=30)
    if entry:
        kind, where = entry
        if kind == "launchd":
            run(["launchctl", "bootout", f"gui/{os.getuid()}/{TASK_NAME}"], **quiet)
        elif kind == "systemd":
            run(["systemctl", "--user", "disable", "--now", f"{TASK_NAME}.service"], **quiet)
        else:
            run(["schtasks.exe", "/End", "/TN", TASK_NAME], **quiet)
            run(["schtasks.exe", "/Delete", "/TN", TASK_NAME, "/F"], **quiet)
        if kind != "task":
            shutil.move(str(where), str(backup / where.name))
            if kind == "systemd":
                run(["systemctl", "--user", "daemon-reload"], **quiet)
        done.append(f"stopped and removed the personal {kind} entry ({where})")
    if personal_cfg.exists():
        try:
            raw = json.loads(personal_cfg.read_text(encoding="utf-8-sig"))
        except (OSError, ValueError):
            raw = {}
        store = make_store({"secret_store": raw.get("secret_store", "auto")}, d, platform)
        if store is not None:
            try:
                store.delete()
                done.append("forgot the personal refresh token in the OS credential store")
            except SecretStoreError as e:
                done.append(f"could not forget the personal refresh token in the OS credential store: {e}")
        for item in list(d.iterdir()):
            try:
                shutil.move(str(item), str(backup / item.name))
            except OSError as e:
                done.append(f"could not move {item.name}: {e}")
        done.append(f"moved the personal config and state to {backup}")
    if hooks:
        settings.apply(drop_hooks=True)
        done.append(f"removed the personal hooks from {settings.path} (the managed settings carry the fleet's)")
    return done


# --------------------------------------------------------------------------------------------- doctor
# `doctor` and the preflight: read every config source, predict what Claude Code will send, name conflicts.
# Self-contained: every source has its own small reader (tests mock these), every finding its own check.
#
# Where each location comes from:
#   docs (https://code.claude.com/docs/en/managed-settings.md, "Where each mechanism stores the policy" and
#   "How Claude Code combines managed sources"): the managed file directories and managed-settings.d/ (merged after
#   managed-settings.json, *.json in alphabetical order, hidden files ignored), the macOS managed preferences domain
#   com.anthropic.claudecode, the Windows value `Settings` (REG_SZ/REG_EXPAND_SZ, JSON) under
#   HKLM\SOFTWARE\Policies\ClaudeCode and HKCU\SOFTWARE\Policies\ClaudeCode, the source ranking (remote > MDM plist or
#   HKLM > files > HKCU; the first source with a policy key wins unless managedSourcesBehavior is "merge"), and
#   "a managed document that is not a JSON object stops Claude Code from starting".
#   observed (repro `managed` scenario, README findings 11 and 15): a managed env ANTHROPIC_CUSTOM_HEADERS replaces the
#   user's value; allowManagedHooksOnly stops user hooks; unknown top-level keys are ignored; AIGW_* in managed env
#   reach hooks and win over the user's env; drop-ins merge in name order.
#   standard macOS, not from the docs: the plist file is /Library/Managed Preferences/com.anthropic.claudecode.plist
#   (or .../<user>/com.anthropic.claudecode.plist), read with plutil.
#   Server-managed settings are fetched by Claude Code at sign-in; the helper cannot read them (reported as unknown).

SEVERITIES = ("Error", "Warning", "Info")
POLICY_CONTROL_KEYS = ("wslInheritsWindowsSettings", "managedSourcesBehavior")
CREDENTIAL_ENV = ("ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "CLAUDE_CODE_OAUTH_TOKEN")
CHECKS = []             # (id, function), in report order


def check(check_id):
    def register(fn):
        CHECKS.append((check_id, fn))
        return fn
    return register


# ---- readers (one per source; tests mock these)

def managed_dir():
    if sys.platform == "darwin":
        return Path("/Library/Application Support/ClaudeCode")
    if is_windows():
        return Path(os.environ.get("ProgramFiles") or r"C:\Program Files") / "ClaudeCode"
    return Path("/etc/claude-code")


def read_json_file(path):
    """(dict, error). A missing file is ({}, ""); anything that is not a JSON object is an error."""
    try:
        text = Path(path).read_text(encoding="utf-8-sig")
    except FileNotFoundError:
        return {}, ""
    except OSError as e:
        return {}, f"cannot read {path}: {e}"
    try:
        data = json.loads(text) if text.strip() else {}
    except ValueError as e:
        return {}, f"{path} is not valid JSON ({e})"
    return (data, "") if isinstance(data, dict) else ({}, f"{path} is not a JSON object")


def read_helper_config(path):
    """The helper's own config file as written (before defaults): (dict, error)."""
    return read_json_file(path)


def read_user_settings(path):
    return read_json_file(path)


def deep_merge(base, over):
    """Later wins on scalars, dicts merge, lists concatenate (hooks for one event from several files all run: finding 15)."""
    out = dict(base)
    for k, v in over.items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = deep_merge(out[k], v)
        elif isinstance(v, list) and isinstance(out.get(k), list):
            out[k] = out[k] + v
        else:
            out[k] = v
    return out


def read_managed_files():
    """managed-settings.json, then managed-settings.d/*.json in name order. -> (merged dict or None, [paths], [errors])."""
    base = managed_dir()
    paths = [base / "managed-settings.json"]
    try:
        paths += sorted(p for p in (base / "managed-settings.d").iterdir() if p.suffix == ".json" and not p.name.startswith(".") and p.is_file())
    except OSError:
        pass
    merged, found, errors = {}, [], []
    for p in paths:
        if not p.exists():
            continue
        data, err = read_json_file(p)
        found.append(str(p))
        if err:
            errors.append(err)
        merged = deep_merge(merged, data)
    return (merged if found else None), found, errors


def plist_paths():
    import getpass
    root = Path("/Library/Managed Preferences")
    try:
        user = getpass.getuser()
    except Exception:
        user = ""
    return [root / "com.anthropic.claudecode.plist"] + ([root / user / "com.anthropic.claudecode.plist"] if user else [])


def read_plist_policy():
    """macOS managed preferences (MDM profile), read-only through plutil. -> (dict or None, error, location)."""
    if sys.platform != "darwin":
        return None, "", ""
    for p in plist_paths():
        if not p.exists():
            continue
        try:
            r = subprocess.run(["plutil", "-convert", "json", "-o", "-", str(p)], capture_output=True, text=True, timeout=5)
            data = json.loads(r.stdout) if r.returncode == 0 else None
        except (OSError, subprocess.TimeoutExpired, ValueError):
            data = None
        if not isinstance(data, dict):
            return None, f"{p} is not a readable plist with a dictionary", str(p)
        return data, "", str(p)
    return None, "", ""


def read_registry_policy(hive):
    """Windows: the JSON string `Settings` under <hive>\\SOFTWARE\\Policies\\ClaudeCode, read-only. hive: HKLM or HKCU."""
    if not is_windows():
        return None, "", ""
    where = fr"{hive}\SOFTWARE\Policies\ClaudeCode"
    try:
        import winreg
        root = {"HKLM": winreg.HKEY_LOCAL_MACHINE, "HKCU": winreg.HKEY_CURRENT_USER}[hive]
        with winreg.OpenKey(root, r"SOFTWARE\Policies\ClaudeCode", 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as k:
            value, kind = winreg.QueryValueEx(k, "Settings")
        data = json.loads(value) if kind in (winreg.REG_SZ, winreg.REG_EXPAND_SZ) else None
    except OSError:
        return None, "", ""
    except ValueError:
        data = None
    if not isinstance(data, dict):
        return None, f"{where} Settings is not a JSON object", where
    return data, "", where


def has_policy_key(d):
    return bool(d) and any(k not in POLICY_CONTROL_KEYS for k in d)


def managed_effective():
    """What the managed tier contributes, by the docs' ranking. -> dict(settings, source, sources, errors).

    source is the winning source ("plist", "HKLM", "file", "HKCU" or ""); sources lists every one found, with its
    location. HKCU only counts when no admin source is present (it is user-writable)."""
    found, errors = [], []
    plist, err, loc = read_plist_policy()
    if err:
        errors.append(err)
    if plist is not None or err:
        found.append(("plist", loc, plist or {}))
    hklm, err, loc = read_registry_policy("HKLM")
    if err:
        errors.append(err)
    if hklm is not None or err:
        found.append(("HKLM", loc, hklm or {}))
    files, paths, ferrs = read_managed_files()
    errors += ferrs
    if files is not None:
        found.append(("file", ", ".join(paths), files))
    if not found:
        hkcu, err, loc = read_registry_policy("HKCU")      # a malformed HKCU value never blocks Claude Code: no error
        if hkcu is not None:
            found.append(("HKCU", loc, hkcu))
    with_keys = [s for s in found if has_policy_key(s[2])]
    settings, source = {}, ""
    if with_keys:
        top = with_keys[0]
        if top[2].get("managedSourcesBehavior") == "merge":
            for _, _, d in reversed(with_keys):             # approximation of the docs' per-kind rules
                settings = deep_merge(settings, d)
        else:
            settings = top[2]
        source = top[0]
    return {"settings": settings, "source": source, "sources": [(n, l) for n, l, _ in found], "errors": errors}


def settings_blocker(path):
    """Why the user's settings.json can't be replaced by the user ("" if it can). The client renames over the file,
    so mode 444 is fine; an immutable flag or a directory the user can't write is not (finding 11)."""
    path = Path(path)
    if path.exists():
        st = path.stat()
        if getattr(st, "st_flags", 0) & (getattr(stat, "UF_IMMUTABLE", 0) | getattr(stat, "SF_IMMUTABLE", 0)):
            return f"{path} has the immutable flag (chflags nouchg)"
        if is_windows() and getattr(st, "st_file_attributes", 0) & 1:
            return f"{path} has the read-only attribute (attrib -r)"
        if sys.platform.startswith("linux") and shutil.which("lsattr"):
            try:
                r = subprocess.run(["lsattr", "-d", str(path)], capture_output=True, text=True, timeout=3)
                if r.returncode == 0 and "i" in (r.stdout.split() or [""])[0]:
                    return f"{path} has the immutable attribute (chattr -i)"
            except (OSError, subprocess.TimeoutExpired):
                pass
    parent = path.parent
    while not parent.exists() and parent != parent.parent:
        parent = parent.parent
    if not os.access(str(parent), os.W_OK | os.X_OK):
        return f"the directory {parent} is not writable by this user"
    return ""


# ---- findings

def finding(check_id, severity, message, fix):
    return {"id": check_id, "severity": severity, "message": message, "fix": fix}


def our_hooks(data, event, sub):
    """(argv words, timeout) of our hook entries for `event` in a settings dict. Exec form (args) keeps its words;
    a command string is split the way the platform's shell would (roughly)."""
    out = []
    for entry in (data.get("hooks") or {}).get(event) or []:
        for h in (entry.get("hooks") or []) if isinstance(entry, dict) else []:
            if not isinstance(h, dict):
                continue
            if h.get("args"):
                words = [str(h.get("command", ""))] + [str(x) for x in h["args"]]
            else:
                try:
                    words = split_command(str(h.get("command", "")), windows=is_windows())
                except ValueError:
                    words = str(h.get("command", "")).split()
            text = " ".join(words)
            if MARKER.search(text) and re.search(rf"\bhook\s+{sub}\b", text):
                out.append((words, h.get("timeout")))
    return out


def hook_target(words):
    """The aigw-claude-auth program a hook runs: (path or name, exists) or ("", False)."""
    for w in words:
        if MARKER.search(Path(w).name):
            return w, bool(os.path.exists(w) or shutil.which(w))
    return "", False


def ctx_env(ctx, who):
    env = ctx[who].get("env")
    return env if isinstance(env, dict) else {}


@check("config-invalid")
def chk_config(ctx):
    if ctx["config_error"]:
        empty = "sentinel must not be empty" in ctx["config_error"]
        return [finding("sentinel-empty" if empty else "config-invalid", "Error", ctx["config_error"],
                        "set the sentinel to the value the load balancer rule expects (an empty header can't be told from a missing one)" if empty
                        else f"fix {ctx['config_path']}")]


@check("sentinel")
def chk_sentinel(ctx):
    if ctx["cfg"]["sentinel"] and ctx["cfg"]["sentinel"] != DEFAULTS["sentinel"]:
        return [finding("sentinel-custom", "Info", f"sentinel is {ctx['cfg']['sentinel']!r}, not the documented default",
                        "the load balancer rule (gateway/alb-guard-ingress.yaml) must match this value; the helper can't read it")]


@check("user-settings-invalid")
def chk_user_invalid(ctx):
    if ctx["user_error"]:
        return [finding("user-settings-invalid", "Error", ctx["user_error"], "fix the JSON; the helper can't edit the file until then")]


@check("managed-unparseable")
def chk_managed_invalid(ctx):
    return [finding("managed-unparseable", "Error", e + "; Claude Code refuses to start with it", "fix or remove the managed document (IT)")
            for e in ctx["managed_info"]["errors"]]


@check("managed-custom-headers")
def chk_headers(ctx):
    if "ANTHROPIC_CUSTOM_HEADERS" in ctx_env(ctx, "managed"):
        if ctx["cfg"]["mode"] == "proxy":
            return [finding("managed-custom-headers", "Error",
                            f"managed settings ({ctx['managed_info']['source']}) define env.ANTHROPIC_CUSTOM_HEADERS; it replaces the user's value, so the per-user secret ({LOCAL_HEADER}) is not sent and the proxy refuses every request",
                            "remove it from managed settings (README finding 11)")]
        return [finding("managed-custom-headers", "Error",
                        f"managed settings ({ctx['managed_info']['source']}) define env.ANTHROPIC_CUSTOM_HEADERS; it replaces the user's value, so the JWT is not sent",
                        "remove it from managed settings and keep the JWT in the user's settings.json (README finding 11)")]


@check("hooks-only-missing")
def chk_hooks_only(ctx):
    if ctx["managed"].get("allowManagedHooksOnly") is True:
        miss = [sub for ev, sub in (("UserPromptSubmit", "precheck"), ("StopFailure", "stop-failure")) if not our_hooks(ctx["managed"], ev, sub)]
        if miss:
            return [finding("hooks-only-missing", "Error",
                            f"allowManagedHooksOnly is set and the managed hooks lack: {', '.join(miss)}; user hooks do not run",
                            "add the hooks to managed settings (aigw-claude-auth install --print)")]


@check("hook-entries")
def chk_hooks(ctx):
    out = []
    only = ctx["managed"].get("allowManagedHooksOnly") is True
    for ev, sub in (("UserPromptSubmit", "precheck"), ("StopFailure", "stop-failure")):
        mine = our_hooks(ctx["managed"], ev, sub) + ([] if only else our_hooks(ctx["user"], ev, sub))
        if not mine:
            if not (only and our_hooks(ctx["user"], ev, sub)):          # that case is hooks-only-missing
                out.append(finding("hook-missing", "Warning", f"no {ev} hook runs `hook {sub}`",
                                   "aigw-claude-auth install (or ship the entry in managed settings)"))
            continue
        for words, timeout in mine:
            if timeout is None:
                out.append(finding("hook-no-timeout", "Warning", f"the {ev} hook has no timeout; Claude Code's 30 s default may cut a slow precheck and send the prompt",
                                   f"add \"timeout\": {HOOK_TIMEOUT} (finding 8)"))
            target, exists = hook_target(words)
            if not target:
                continue
            if not exists:
                out.append(finding("hook-binary-missing", "Error", f"the {ev} hook runs {target}, which does not exist; Claude Code ignores the failure and sends the prompt",
                                   "re-run install, or point --hook-command at the installed copy"))
            elif os.path.exists(target) and Path(target).resolve() != Path(__file__).resolve():
                out.append(finding("hook-other-binary", "Warning", f"the {ev} hook runs {target}, not this copy ({Path(__file__).resolve()})",
                                   "make sure both are the same version, or re-run install"))
    return out


@check("settings-not-writable")
def chk_writable(ctx):
    why = settings_blocker(ctx["settings"].path)
    if why:
        return [finding("settings-not-writable", "Error", f"the user's settings can't be replaced: {why}; renewal fails",
                        "remove the flag or fix the permissions (mode 444 is fine, immutable is not; finding 11)")]


@check("base-url")
def chk_base_url(ctx):
    m, u = ctx_env(ctx, "managed").get("ANTHROPIC_BASE_URL"), ctx_env(ctx, "user").get("ANTHROPIC_BASE_URL")
    out = []
    if m and u and m.rstrip("/") != u.rstrip("/"):
        out.append(finding("base-url-mismatch", "Error", f"managed ANTHROPIC_BASE_URL ({m}) differs from the user's ({u}); the managed value wins",
                           "make them equal, or remove the user's"))
    if ctx["cfg"]["mode"] == "proxy":
        out += proxy_findings(ctx, m or u or "")
    else:
        ctx["na"]["proxy-listen"] = "mode is file"
    return out


def proxy_findings(ctx, url):
    """Mode 2: does Claude Code reach the proxy, is it running, does the settings carry the local secret and no JWT."""
    cfg, state, out = ctx["cfg"], ctx["state"], []
    try:
        listen = proxy_hostport(cfg)
    except AuthError as e:
        return [finding("proxy-listen", "Error", str(e), "fix proxy_listen in the helper config")]
    port0 = parse_listen(cfg["proxy_listen"])[1] == 0
    hostport = urllib.parse.urlsplit(url).netloc
    if not url:
        out.append(finding("proxy-listen", "Error", f"ANTHROPIC_BASE_URL is not set; Claude Code bypasses the proxy ({listen})", "aigw-claude-auth install"))
    elif not port0 and hostport != listen:
        out.append(finding("proxy-listen", "Error", f"ANTHROPIC_BASE_URL ({url}) is not proxy_listen ({listen}); requests bypass the proxy",
                           "set ANTHROPIC_BASE_URL to the proxy address (aigw-claude-auth install)"))
    if not cfg["gateway_url"]:
        out.append(finding("proxy-gateway-url", "Error", "mode is proxy but gateway_url is not set; the proxy has nowhere to forward to", "set gateway_url in the helper config"))
    elif urllib.parse.urlsplit(cfg["gateway_url"]).netloc == listen:
        out.append(finding("proxy-gateway-url", "Error", "gateway_url points at the proxy itself", "set gateway_url to the gateway"))
    kind, info = probe_proxy(cfg, state)
    if kind == "down":
        out.append(finding("proxy-not-running", "Error", f"the proxy is not running on {listen}; Claude Code's requests fail with connection errors",
                           "start the daemon (launchd / systemd / Task Scheduler entry, or `aigw-claude-auth daemon`)"))
    elif kind == "taken":
        out.append(finding("proxy-port-taken", "Error", f"something else is listening on {listen}: {info}", "free the port or set another proxy_listen (then run install)"))
    elif kind == "secret":
        out.append(finding("proxy-secret", "Error", info, "stop that proxy, or point proxy_listen at a free port"))
    if kind == "running":
        ck, ct = proxy_config_state(info, cfg.get("_config_path"), cfg)
        if ck in ("restart", "old"):
            out.append(finding("proxy-config", "Warning", ct, f"restart the proxy: {restart_hint()}"))
        elif ck == "invalid":
            out.append(finding("proxy-config", "Warning", ct, "fix config.json; the proxy picks the fix up by itself"))
        elif ck == "signin":
            out.append(finding("proxy-config", "Warning", ct, "aigw-claude-auth login"))
    if "ANTHROPIC_CUSTOM_HEADERS" not in ctx_env(ctx, "managed"):       # a managed value is the managed-custom-headers finding
        want, have = proxy_secret(state), ctx["settings"].get_line(LOCAL_HEADER, ctx["user"])
        if not have or (want and have != want):
            out.append(finding("proxy-secret", "Error", f"the settings carry no {LOCAL_HEADER} secret that matches this user's" if not have
                               else f"the {LOCAL_HEADER} secret in the settings differs from the one in the state dir; the proxy refuses requests",
                               "aigw-claude-auth install"))
    jwt_in = ctx["jwt"]
    if jwt_in and jwt_in != cfg["sentinel"]:
        out.append(finding("proxy-jwt-in-settings", "Warning", "mode is proxy but a JWT is still in settings.json (left over from file mode)",
                           "aigw-claude-auth install removes it"))
    return out


@check("settings-file-mismatch")
def chk_settings_file(ctx):
    cdir, mine = os.environ.get("CLAUDE_CONFIG_DIR"), ctx["settings"].path
    if cdir:
        theirs = Path(cdir) / "settings.json"
        if theirs.resolve() != mine.resolve():
            return [finding("settings-file-mismatch", "Error", f"this helper writes {mine}, but Claude Code (CLAUDE_CONFIG_DIR) reads {theirs}; the JWT lands in the wrong file",
                            "point --settings / AIGW_CLAUDE_SETTINGS at it, or run one helper per CLAUDE_CONFIG_DIR")]
    elif mine.resolve() != (Path.home() / ".claude" / "settings.json").resolve():
        return [finding("settings-file-mismatch", "Warning", f"this helper writes {mine}, not ~/.claude/settings.json, and CLAUDE_CONFIG_DIR is not set here",
                        "fine if Claude Code runs with CLAUDE_CONFIG_DIR pointing there; otherwise the JWT lands in the wrong file")]


@check("block-on-failure")
def chk_block(ctx):
    url = ctx_env(ctx, "managed").get("ANTHROPIC_BASE_URL") or ctx_env(ctx, "user").get("ANTHROPIC_BASE_URL") or ""
    host = urllib.parse.urlsplit(url).hostname or ""
    if ctx["cfg"]["block_on_failure"] is False and (host == "portkey.ai" or host.endswith(".portkey.ai")):
        return [finding("block-on-failure", "Error", "block_on_failure is false against the SaaS gateway; the sentinel gets a 401 and the OAuth loop",
                        "set block_on_failure to true")]


@check("credential-override")
def chk_credentials(ctx):
    m, env = ctx["managed"], ctx_env(ctx, "managed")
    keys = (["apiKeyHelper"] if m.get("apiKeyHelper") else []) + [k for k in CREDENTIAL_ENV if env.get(k)]
    if keys:
        return [finding("credential-override", "Warning", f"managed settings set {', '.join(keys)}; it replaces the Anthropic login the passthrough relies on",
                        "remove it unless the gateway is meant to use that credential")]


@check("allowed-providers")
def chk_allowed(ctx):
    if ctx_env(ctx, "managed").get("ANTHROPIC_BASE_URL") and ctx["managed"].get("allowedProviders") != ["customEndpoint"]:
        return [finding("allowed-providers", "Info", "managed settings set ANTHROPIC_BASE_URL but not allowedProviders [\"customEndpoint\"]; a user can point Claude Code at Anthropic directly",
                        "add allowedProviders: [\"customEndpoint\"] (Claude Code 2.1.285+, docs)")]


@check("managed-config-conflict")
def chk_conflict(ctx):
    out, raw = [], ctx["helper_raw"]
    for name, value in sorted(ctx_env(ctx, "managed").items()):
        if not name.startswith("AIGW_"):
            continue
        key = name[5:].lower()
        if key not in DEFAULTS:
            out.append(finding("managed-unknown-key", "Warning", f"managed env {name} is not a config key", "check the spelling"))
        elif key in raw and str(raw[key]) != str(value):
            sev = "Error" if key in ("mode", "issuer", "client_id", "header") else "Warning"
            out.append(finding("managed-config-conflict", sev, f"{name} in managed settings differs from {key} in the helper config; the managed value should win",
                               f"make them equal, or remove {key} from the helper config"))
    return out


@check("jwt-claims")
def chk_jwt(ctx):
    cfg, tok = ctx["cfg"], ctx["jwt"]
    claims = jwt_claims(tok) if tok and tok != cfg["sentinel"] else {}
    if claims and cfg["issuer"] and not cfg["broker_url"] and not cfg["token_command"]:
        iss = claims.get("iss")
        if iss and str(iss).rstrip("/") != cfg["issuer"].rstrip("/"):
            return [finding("jwt-claims", "Error", f"the current JWT's iss ({iss}) is not the configured issuer ({cfg['issuer']}); the gateway will refuse it",
                            "run `aigw-claude-auth sync --force` after fixing the configuration")]


@check("secret-store")
def chk_secret_store(ctx):
    if ctx["cfg"].get("secret_store", "auto") != "auto":
        ctx["na"]["secret-store"] = "secret_store is file"
        return
    if ctx["state"].load().get("refresh_token") and make_store(ctx["cfg"], ctx["state"].dir) is not None:
        return [finding("secret-store", "Warning", "the refresh token is in state.json although an OS credential store is available (secret_store: auto)",
                        "run `aigw-claude-auth login` once to migrate it")]


@check("proxy-linger")
def chk_proxy_linger(ctx):
    """Proxy mode on Linux under a systemd user unit: without lingering the proxy stops when the last login session ends. That
    only hurts when Claude Code can outlive the login (SSH, tmux, a headless machine), so only those sessions are told."""
    if ctx["cfg"]["mode"] != "proxy" or not sys.platform.startswith("linux"):
        ctx["na"]["proxy-linger"] = "mode is file" if ctx["cfg"]["mode"] != "proxy" else "not Linux"
        return
    if not systemd_unit_path().exists():
        ctx["na"]["proxy-linger"] = "no systemd user unit from install"
        return
    if linger_state() != "no":
        return                                              # on, or unreadable: nothing to say
    sig = environment_signals()
    if sig["ssh"] or not sig["desktop"]:
        return [finding("proxy-linger", "Warning", "the proxy runs as a systemd user unit but lingering is off, and this looks like an SSH or headless session: "
                        "the proxy stops when your last login session ends, and Claude Code's requests then fail with connection errors",
                        "aigw-claude-auth install --linger (or `sudo loginctl enable-linger $USER`); a desktop does not need it")]
    ctx["na"]["proxy-linger"] = "lingering is off, which is fine in a desktop session"


@check("personal-install")
def chk_personal(ctx):
    if not ctx["cfg"].get("fleet"):
        ctx["na"]["personal-install"] = "not a fleet install"
        return
    left = personal_leftovers(ctx["cfg"], ctx["state"].dir, ctx["user"])
    if left:
        return [finding("personal-install", "Warning", "a personal install is still here next to the fleet install: " + "; ".join(left),
                        "log out and back in (the fleet's login entry moves it aside), or remove it (README \"4. Teardown\")")]


@check("server-managed")
def chk_server(ctx):
    return [finding("server-managed", "Info", "server-managed settings can't be read by the helper; if your organization uses them they rank above everything checked here (unknown)",
                    "Claude Code's /status shows the sources it applied")]


# ---- running the checks

def _safe(fn, default):
    try:
        return fn()
    except Exception:
        return default


def doctor_context(cfg, state, settings, helper_raw=None, config_error="", config_path=""):
    user, user_error = read_user_settings(settings.path)
    info = managed_effective()
    if helper_raw is None:
        helper_raw, _ = read_helper_config(config_path or cfg.get("_config_path") or config_dir() / "config.json")
    return {"cfg": cfg, "state": state, "settings": settings, "user": user, "user_error": user_error, "managed": info["settings"],
            "managed_info": info, "helper_raw": helper_raw, "config_error": config_error, "config_path": str(config_path), "na": {},
            "jwt": _safe(lambda: settings.get(), "")}


def run_checks(ctx):
    findings = []
    for check_id, fn in CHECKS:
        try:
            findings += fn(ctx) or []
        except Exception as e:                                  # a broken check must not break the others
            findings.append(finding(check_id, "Warning", f"the check failed: {type(e).__name__}: {e}", "report this"))
    findings.sort(key=lambda f: SEVERITIES.index(f["severity"]))
    return findings


def findings_hash(findings):
    """Of Errors and Warnings only: Info rows never change and must not cause a notification."""
    rows = sorted(f"{f['id']}|{f['severity']}|{f['message']}" for f in findings if f["severity"] != "Info")
    return hashlib.sha256("\n".join(rows).encode()).hexdigest()[:16]


def preflight(cfg, state, settings):
    """All findings for this configuration."""
    return run_checks(doctor_context(cfg, state, settings, config_path=cfg.get("_config_path", "")))


def notify_on_change(cfg, state, findings):
    """Notify when the set of Errors/Warnings changes (an Error appears, or the last one clears); not on every run.
    The hash lives in preflight.json next to the state (no secrets)."""
    path, new = state.dir / "preflight.json", findings_hash(findings)
    errors = [f for f in findings if f["severity"] == "Error"]
    try:
        old = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        old = {}
    if old.get("hash") == new:
        return False
    try:
        write_private(path, json.dumps({"hash": new, "errors": len(errors)}) + "\n")
    except OSError:
        pass                                                    # can't remember: better to notify twice than never
    if errors:
        notify(cfg, f"AI gateway: {errors[0]['message']}. Fix: {errors[0]['fix']} (aigw-claude-auth doctor)")
    elif old.get("errors"):
        notify(cfg, "AI gateway: the configuration problem is fixed.")
    return True


def block_message(errors):
    f = errors[0]
    more = f" (+{len(errors) - 1} more)" if len(errors) > 1 else ""
    return f"AI gateway: {f['message']}. Fix: {f['fix']}{more}. Run `aigw-claude-auth doctor` for details. [{f['id']}]"


def preflight_errors(cfg, state, settings):
    """The Errors that stop a write or a prompt, [] if none. AIGW_CLAUDE_PREFLIGHT=off skips the gate (the repro
    harness uses it to observe Claude Code's own behavior; doctor ignores it). Never raises."""
    if os.environ.get("AIGW_CLAUDE_PREFLIGHT", "").lower() == "off":
        return []
    try:
        findings = preflight(cfg, state, settings)
        notify_on_change(cfg, state, findings)
        return [f for f in findings if f["severity"] == "Error"]
    except Exception as e:
        log(f"preflight failed: {e}")
        return []


def doctor_sources(ctx):
    cfg, info = ctx["cfg"], ctx["managed_info"]
    st = _safe(lambda: ctx["state"].load(), {})
    return {
        "helper_config": ctx["config_path"] or "defaults",
        "helper_state": {"path": str(ctx["state"].file), "signed_in": bool(st.get("refresh_token"))},
        "user_settings": {"path": str(ctx["settings"].path), "exists": ctx["settings"].path.exists()},
        "managed": {"winning_source": info["source"] or "none", "found": [{"source": n, "location": l} for n, l in info["sources"]]},
        "server_managed": "unknown (not readable by the helper)",
        "jwt": fingerprint(ctx["jwt"]) if ctx["jwt"] and ctx["jwt"] != cfg["sentinel"] else ("sentinel" if ctx["jwt"] else "none"),
        "mode": cfg.get("mode", "file"),
    }


def cmd_doctor(a, config_path, state, settings_path):
    raw, config_error = read_helper_config(config_path)
    cfg = dict(DEFAULTS)
    cfg.update({k: v for k, v in raw.items() if k in DEFAULTS})
    if not config_error:
        try:
            cfg = load_config(config_path)
        except (AuthError, ValueError) as e:
            config_error = str(e)
    cfg["_config_path"] = str(config_path)
    settings = Settings(settings_path or default_settings_path(), cfg["header"])
    ctx = doctor_context(cfg, state, settings, helper_raw=raw, config_error=config_error, config_path=config_path)
    findings = run_checks(ctx)
    errors, warnings = (sum(1 for f in findings if f["severity"] == s) for s in ("Error", "Warning"))
    report = {"version": VERSION, "platform": sys.platform, "python": sys.version.split()[0], "sources": doctor_sources(ctx),
              "findings": findings, "checked": [c for c, _ in CHECKS],
              "not_applicable": [{"id": k, "reason": v} for k, v in sorted(ctx["na"].items())],
              "hash": findings_hash(findings), "errors": errors, "warnings": warnings}
    if a.json:
        print(json.dumps(report, indent=2))
        return 1 if errors else 0
    s = report["sources"]
    print(f"aigw-claude-auth doctor {VERSION} ({sys.platform}, python {report['python']}, mode {s['mode']})")
    print("Sources")
    for label, value in (("helper config", s["helper_config"]),
                         ("helper state", f"{s['helper_state']['path']} (signed in: {'yes' if s['helper_state']['signed_in'] else 'no'})"),
                         ("user settings", f"{s['user_settings']['path']} ({'present' if s['user_settings']['exists'] else 'missing'})"),
                         ("managed", s["managed"]["winning_source"] + "".join(f"; {f['source']}: {f['location'] or 'present'}" for f in s["managed"]["found"])),
                         ("server-managed", s["server_managed"]), ("jwt", s["jwt"])):
        print(f"  {label:15} {value}")
    print("Findings")
    for f in findings:
        print(f"  [{f['severity']}] {f['id']}: {f['message']}\n      fix: {f['fix']}")
    if not findings:
        print("  none")
    for n in report["not_applicable"]:
        print(f"  [n/a] {n['id']}: {n['reason']}")
    print(f"Result: {errors} error(s), {warnings} warning(s), {len(findings) - errors - warnings} info")
    return 1 if errors else 0


HELP_EPILOG = """\
Two client modes (`mode` in config.json):
  file (default)  the JWT is written into Claude Code's settings.json; hooks and an optional daemon renew it
  proxy           a local proxy on 127.0.0.1 adds the JWT to each request and keeps it in memory; `install` also sets up
                  the daemon as a service (see `install --help`)

What the JWT carries is a separate matter, Portkey's "Mode A" and "Mode B":
  Mode A  you control the JWT issuer and add the gateway's claims (portkey_oid, portkey_workspace, defaults, limits):
          from your IdP if it can add custom claims, or from a token broker (`broker_url`) if it cannot (Entra ID)
  Mode B  a standard IdP token whose schema you cannot change (Okta, Auth0, Entra ID, Cognito): the gateway fills in
          organisation, workspace and limits from its own settings (hybrid gateway only)
https://portkey.ai/docs/aigw/product/enterprise-offering/org-management/jwt
"""


def main(argv=None):
    ap = argparse.ArgumentParser(prog="aigw-claude-auth", description=__doc__.split("\n\n")[0], epilog=HELP_EPILOG,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--config", type=Path, help="config file (default: <config dir>/config.json)")
    ap.add_argument("--state-dir", type=Path, help="where the refresh token lives (default: ~/.config/aigw-claude-auth, on Windows %%APPDATA%%\\aigw-claude-auth, or $AIGW_CLAUDE_AUTH_DIR)")
    ap.add_argument("--settings", type=Path, help="Claude Code settings file (default: $CLAUDE_CONFIG_DIR/settings.json or ~/.claude/settings.json)")
    ap.add_argument("--version", action="version", version=VERSION)
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("login", help="sign in to the IdP")
    g = p.add_mutually_exclusive_group()
    g.add_argument("--device", action="store_true", help="device code flow (any terminal, including ssh)")
    g.add_argument("--pkce", action="store_true", help="browser on this machine, loopback redirect")
    g.add_argument("--pkce-print", action="store_true", help="print the sign-in URL (loopback redirect; with ssh use `ssh -L <redirect_port>:127.0.0.1:<redirect_port>`)")
    g.add_argument("--paste", action="store_true", help="print the URL, sign in in any browser, paste the final http://127.0.0.1:... address back here")
    p.add_argument("--no-browser", action="store_true", help="with --pkce: print the URL instead of opening it")
    sub.add_parser("logout", help="forget the refresh token, write the sentinel")
    p = sub.add_parser("sync", help="renew the JWT in the settings if needed")
    p.add_argument("--force", action="store_true", help="renew even if the current JWT is still valid")
    p.add_argument("--quiet", action="store_true", help="say nothing on success")
    p = sub.add_parser("token", help="print a valid JWT")
    p.add_argument("--force", action="store_true")
    p = sub.add_parser("status", help="where the JWT comes from, when it expires, who it is for, and the JWKS that publishes its key")
    p.add_argument("--offline", action="store_true", help="skip the JWKS lookup (the one network call)")
    p = sub.add_parser("requests", help="proxy mode: the proxy's recent requests, with credentials partly masked")
    p.add_argument("-n", "--count", type=int, default=20, help="how many of the most recent requests (default: %(default)s; the proxy keeps proxy_log_requests)")
    p.add_argument("--json", action="store_true", help="machine-readable")
    p = sub.add_parser("inspect", help="decode the JWT: header, times, claims, verdicts against the config (never the token)")
    p.add_argument("--fresh", action="store_true", help="mint a token from the source without writing it, and decode that")
    p.add_argument("--live", action="store_true", help="ask the running proxy about the JWT it holds (proxy mode; the token never leaves it)")
    p.add_argument("--show-claims", action="store_true", help="show sub, email, groups and other personal claims (redacted by default)")
    p.add_argument("--debug", choices=["on", "off"], help="log an inspect summary at each renewal for 24 h (on) or stop (off)")
    p = sub.add_parser("daemon", help="renew ahead of every expiry until stopped")
    p.add_argument("--max-sleep", type=int, default=60, help="longest nap in seconds (bounds the catch-up after sleep)")
    p = sub.add_parser("proxy", help="run the local proxy in the foreground (mode proxy's daemon does this; this is for debugging)")
    p.add_argument("--max-sleep", type=int, default=60, help="longest nap in seconds between renewal checks")
    p.add_argument("--access-log", help="append one JSON line per request here ('-' or omitted: stderr); status, latency, token fingerprint and the request headers with credentials partly masked")
    p = sub.add_parser("hook", help="for Claude Code hooks; reads the hook JSON on stdin")
    p.add_argument("event", choices=["precheck", "stop-failure"])
    p = sub.add_parser("hook-login-wait", help="internal: the precheck hook's background sign-in (device code JSON on stdin)")
    p.add_argument("--method", choices=["device", "pkce", "pkce-print"], default="device")
    p = sub.add_parser("install", help="add ANTHROPIC_BASE_URL and the hooks to the settings file")
    p.add_argument("--base-url", help="the gateway URL for ANTHROPIC_BASE_URL")
    p.add_argument("--no-hooks", action="store_true", help="only the base URL (for example when IT ships the hooks)")
    p.add_argument("--hook-command", help="how hooks call this tool (default: this interpreter and file; must contain 'aigw-claude-auth')")
    p.add_argument("--print", action="store_true", help="print the snippet for managed settings instead of writing")
    p.add_argument("--no-service", action="store_true", help="proxy mode: do not install the daemon as a launchd agent, systemd unit or Task Scheduler task")
    p.add_argument("--linger", action="store_true", help="proxy mode on Linux: also run `loginctl enable-linger`, so the proxy keeps running after your last login "
                   "session ends and starts at boot. Use it on an SSH-only or headless machine, or when Claude Code runs in tmux or screen past your login. "
                   "A desktop does not need it. Off by default because it lets your processes run without a login; undo with `loginctl disable-linger`")
    p = sub.add_parser("doctor", help="read every config source, predict what Claude Code sends, report conflicts (exit 1 on an Error)")
    p.add_argument("--json", action="store_true", help="machine-readable report")
    p = sub.add_parser("task", help="Windows: install or remove the Task Scheduler task that runs the daemon at log on")
    p.add_argument("action", choices=["install", "remove", "print"], help="print shows the task definition (XML) and registers nothing")
    p.add_argument("--name", default=TASK_NAME, help="task name (default: %(default)s)")
    a = ap.parse_args(argv)

    cdir = a.state_dir or config_dir()
    try:
        if a.cmd == "task":                                     # needs no config
            return cmd_task(a, None, None, None)
        if a.cmd == "doctor":                                   # must work when the config itself is broken
            return cmd_doctor(a, a.config or cdir / "config.json", State(cdir), a.settings)
        config_path = a.config or cdir / "config.json"
        try:
            cfg = load_config(config_path)
        except (AuthError, ValueError) as e:
            if a.cmd == "status":                               # like doctor, it has to work when the config itself is broken
                return cmd_status_unloadable(cdir, config_path, e)
            raise
        cfg["_config_path"] = str((a.config or cdir / "config.json").resolve())   # for the hook's background sign-in
        state = State(cdir)
        state.store = make_store(cfg, cdir)
        settings = Settings(a.settings or default_settings_path(), cfg["header"])
        handler = {"login": cmd_login, "logout": cmd_logout, "sync": cmd_sync, "token": cmd_token, "status": cmd_status, "requests": cmd_requests, "inspect": cmd_inspect,
                   "daemon": cmd_daemon, "proxy": cmd_proxy, "hook": cmd_hook, "hook-login-wait": cmd_hook_login_wait, "install": cmd_install, "task": cmd_task}[a.cmd]
        return handler(a, cfg, state, settings)
    except AuthError as e:
        if a.cmd == "hook":                                  # hooks must never fail Claude Code's turn
            log(str(e))
            return 0
        log(f"error: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
