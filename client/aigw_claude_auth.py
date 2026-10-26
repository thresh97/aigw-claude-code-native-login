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
    "login_method": "auto",            # sign-in method for `login`: auto | device | pkce | pkce-print | pkce-paste (flags and AIGW_LOGIN_METHOD override)
    "hook_login": "auto",              # when signed out, the precheck starts a sign-in: auto (same choice as `login`) | device | off
    "device_unavailable_ttl": 86400,   # seconds to remember that the IdP refused the device grant (or the loopback redirect)
    "notify": "auto",                  # desktop notification (StopFailure renewal, hook sign-in result): auto | off | a command (gets the message as $1)
    "redirect_uri": "http://127.0.0.1:{port}/",  # PKCE loopback redirect; {port} is filled in
    "redirect_port": 0,                # 0 = any free port (fine for Entra and most IdPs); set if the IdP pins the port
    "secret_store": "auto",            # where the refresh token lives: auto (OS credential store, else file) | file (state.json)
    "debug_until": 0,                  # epoch seconds; while in the future, each renewal logs an `inspect` summary (`inspect --debug on` sets it in state.json)
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
    if cfg["hook_login"] not in ("auto", "device", "off"):
        raise AuthError("hook_login must be auto, device or off")
    if cfg["login_method"] not in ("auto",) + LOGIN_METHODS:
        raise AuthError("login_method must be auto, " + ", ".join(LOGIN_METHODS))
    if cfg["secret_store"] not in ("auto", "file"):
        raise AuthError("secret_store must be auto or file")
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
        self.state.save(st)
        tok = body.get(self.cfg["idp_token"])
        if not tok:
            raise AuthError(f"the IdP response has no {self.cfg['idp_token']} (check scope and idp_token)")
        return tok

    def refresh(self):
        rt = self.state.get_refresh_token()
        if not rt:
            raise AuthError("not signed in to the gateway: run `aigw-claude-auth login`")
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
    """
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
    # TODO(phase 4, proxy mode): `inspect --live` asks the running proxy over its control channel; not built yet.
    return 1 if problems else 0


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
    r = sync(cfg, state, settings, force=a.force)
    if not r.ok:
        log(r.message)
        return 1
    print(r.token)
    return 0


def cmd_status(a, cfg, state, settings):
    loc = state.token_location()
    source = "token_command" if cfg["token_command"] else ("IdP + broker" if cfg["broker_url"] else "IdP token as the JWT")
    rows = [("version", VERSION), ("settings", str(settings.path)), ("header", cfg["header"]), ("source", source),
            ("signed in", "yes" if loc else ("n/a" if cfg["token_command"] else "no")),
            ("refresh token", loc or "none"),
            ("jwt", fingerprint(settings.get()) if settings.get() != cfg["sentinel"] else "sentinel (no usable JWT)")]
    claims = jwt_claims(settings.get())
    for k in ("iss", "sub", "portkey_workspace"):
        if k in claims:
            rows.append((f"jwt {k}", str(claims[k])))
    p = state.pending()
    if p:
        rows.append(("pending", f"hook sign-in: open {p['uri']}{' and enter ' + p['user_code'] if p.get('user_code') else ''} (until {time.strftime('%H:%M', time.localtime(p['expires_at']))})"))
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
        if effective_hook_login(cfg) != "off" and not cfg["token_command"] and not state.get_refresh_token():
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
    if ctx["cfg"].get("mode", "file") == "proxy":
        ctx["na"]["managed-custom-headers"] = "proxy mode does not use ANTHROPIC_CUSTOM_HEADERS"
        return
    if "ANTHROPIC_CUSTOM_HEADERS" in ctx_env(ctx, "managed"):
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
    if ctx["cfg"].get("mode", "file") == "proxy":
        listen = str(ctx["cfg"].get("proxy_listen", ""))
        url = m or u or ""
        hostport = urllib.parse.urlsplit(url).netloc
        if listen and not listen.endswith(":0") and hostport and hostport != listen:
            out.append(finding("proxy-listen", "Error", f"ANTHROPIC_BASE_URL ({url}) is not proxy_listen ({listen}); requests bypass the proxy",
                               "set ANTHROPIC_BASE_URL to the proxy address"))
    else:
        ctx["na"]["proxy-listen"] = "n/a until mode 2 (proxy)"
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
        if key not in DEFAULTS and key != "mode":
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
    g.add_argument("--pkce-print", action="store_true", help="print the sign-in URL (loopback redirect; with ssh use `ssh -L <redirect_port>:127.0.0.1:<redirect_port>`)")
    g.add_argument("--paste", action="store_true", help="print the URL, sign in in any browser, paste the final http://127.0.0.1:... address back here")
    p.add_argument("--no-browser", action="store_true", help="with --pkce: print the URL instead of opening it")
    sub.add_parser("logout", help="forget the refresh token, write the sentinel")
    p = sub.add_parser("sync", help="renew the JWT in the settings if needed")
    p.add_argument("--force", action="store_true", help="renew even if the current JWT is still valid")
    p.add_argument("--quiet", action="store_true", help="say nothing on success")
    p = sub.add_parser("token", help="print a valid JWT")
    p.add_argument("--force", action="store_true")
    sub.add_parser("status", help="where the JWT comes from and when it expires")
    p = sub.add_parser("inspect", help="decode the JWT: header, times, claims, verdicts against the config (never the token)")
    p.add_argument("--fresh", action="store_true", help="mint a token from the source without writing it, and decode that")
    p.add_argument("--show-claims", action="store_true", help="show sub, email, groups and other personal claims (redacted by default)")
    p.add_argument("--debug", choices=["on", "off"], help="log an inspect summary at each renewal for 24 h (on) or stop (off)")
    p = sub.add_parser("daemon", help="renew ahead of every expiry until stopped")
    p.add_argument("--max-sleep", type=int, default=60, help="longest nap in seconds (bounds the catch-up after sleep)")
    p = sub.add_parser("hook", help="for Claude Code hooks; reads the hook JSON on stdin")
    p.add_argument("event", choices=["precheck", "stop-failure"])
    p = sub.add_parser("hook-login-wait", help="internal: the precheck hook's background sign-in (device code JSON on stdin)")
    p.add_argument("--method", choices=["device", "pkce", "pkce-print"], default="device")
    p = sub.add_parser("install", help="add ANTHROPIC_BASE_URL and the hooks to the settings file")
    p.add_argument("--base-url", help="the gateway URL for ANTHROPIC_BASE_URL")
    p.add_argument("--no-hooks", action="store_true", help="only the base URL (for example when IT ships the hooks)")
    p.add_argument("--hook-command", help="how hooks call this tool (default: this interpreter and file; must contain 'aigw-claude-auth')")
    p.add_argument("--print", action="store_true", help="print the snippet for managed settings instead of writing")
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
        cfg = load_config(a.config or cdir / "config.json")
        cfg["_config_path"] = str((a.config or cdir / "config.json").resolve())   # for the hook's background sign-in
        state = State(cdir)
        state.store = make_store(cfg, cdir)
        settings = Settings(a.settings or default_settings_path(), cfg["header"])
        handler = {"login": cmd_login, "logout": cmd_logout, "sync": cmd_sync, "token": cmd_token, "status": cmd_status, "inspect": cmd_inspect,
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
