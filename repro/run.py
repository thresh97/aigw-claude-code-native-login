#!/usr/bin/env python3
"""run.py: re-run this article's tests. See the README's "Re-run" section. Python 3.8+, standard library only; the
cross-platform equivalent of run.sh (macOS, Linux, Windows: `py -3 repro\\run.py ...`).

  run.py list                 scenarios, what each changes, how long it takes
  run.py check                read-only preflight: tools, env, credentials, versions
  run.py <scenario> [--yes]   one scenario; --yes is required for scenarios that change shared state
  run.py all [--yes]          every scenario

Results: repro/results/<date>-<scenario>/{run.log,summary.txt}. Verdict: PASS, CHANGED or ERROR (SKIP (windows) for
a scenario that cannot apply on Windows). Individual expectations that cannot apply on this platform are reported as
SKIP and do not count as differences. Exit code: 0 for PASS and CHANGED (as run.sh), 1 for ERROR, 2 for usage errors.

Settings come from repro/env (KEY=VALUE lines, optional: the offline scenarios need none) and the environment.
"""
import hashlib
import os
import re
import shlex
import shutil
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
CLIENT = ROOT / "client" / "aigw_claude_auth.py"
IS_WIN = sys.platform == "win32"

# ---------------------------------------------------------------- scenario text (expectations are the contract; see README Findings)
DESCRIBE = {
    'unit':
        "unit: the client's offline tests (fake IdP and broker): settings edits, refresh, sentinel, device/PKCE sign-in, hooks, daemon. Changes: nothing. Under 1 min.",
    'headers':
        'headers: install, then a running Claude Code session sends the Anthropic login in Authorization and the gateway JWT in x-portkey-api-key, and picks up a renewed JWT without a restart. Mock gateway. Changes: nothing. About 1 min.',
    'errors':
        'errors: how Claude Code (CLAUDE_CODE_OAUTH_TOKEN login) treats gateway 401, relayed Anthropic 401, 403, 407 and 498: attempts, speed, message, StopFailure error. Mock gateway. Changes: nothing. About 1 min.',
    'precheck':
        'precheck: the UserPromptSubmit hook renews an expired JWT before the request, does nothing while it is valid, blocks the prompt when no JWT can be had (also with a hanging IdP), offers a device code sign-in in the block message when signed out, and with block_on_failure off lets a load balancer guard answer 498. Mock gateway, fake IdP. Changes: nothing. About 3 min.',
    'stopfailure':
        'stopfailure: after the gateway refuses a JWT that still looks valid, the StopFailure hook renews it and notifies, and the retry works; an Anthropic-side failure is left alone. Mock gateway, fake IdP. Changes: nothing. About 1 min.',
    'proxy':
        'proxy: Claude Code (CLAUDE_CODE_OAUTH_TOKEN login) through the prototype local proxy (proxy_prototype.py) in front of the mock gateway: the gateway header injected and a client-supplied one stripped, a renewed token picked up, SSE passed through as it arrives, a gateway 401 turned into 498 (one attempt), an Anthropic 401 passed through, no token failing closed; then which Unix socket base URLs Claude Code can use (spike S11). Mock gateway. Changes: nothing. About 3 min.',
    'stored_login':
        'stored_login: a stored `claude login` (LOGIN_CONFIG_DIR) against the mock gateway: 498 fails at once and leaves the login alone; a gateway 401 runs the OAuth refresh loop (about 4 min). Changes: rotates the stored login at Anthropic, swaps LOGIN_CONFIG_DIR/settings.json for the run (--yes). About 4 min.',
    'stored_login_proxy':
        'stored_login_proxy: a stored `claude login` (LOGIN_CONFIG_DIR) through the prototype local proxy and the mock gateway: a refused JWT (gateway 401) becomes 498 at the proxy and fails in one attempt without the OAuth loop; no usable token fails the same way without reaching the gateway. Changes: rotates the stored login at Anthropic if the proxy did not work, swaps LOGIN_CONFIG_DIR/settings.json for the run (--yes). About 1 min.',
    'gateway':
        "gateway: the real gateway, request by request: missing, garbage and tampered JWTs and the sentinel are refused by the gateway (or the LB guard); a valid JWT, also with a Bearer prefix, reaches Anthropic with the caller's own login (passthrough). Changes: nothing (one model call on your plan if LOGIN_CONFIG_DIR is set). Under 1 min.",
    'live_login':
        'live_login: a stored `claude login` through the real gateway (via a local logging relay): a valid JWT works; a refused JWT costs the OAuth refresh loop (about 4 min); with LB_GUARD=on the sentinel and a missing header fail at once. Changes: rotates the stored login, swaps LOGIN_CONFIG_DIR/settings.json for the run (--yes). About 4 min.',
    'client_live':
        'client_live: the client end to end: JWT from your IdP (and broker), accepted by the gateway, installed into a stored-login Claude Code; the precheck hook replaces an expired JWT before the turn. Needs a prior `aigw_claude_auth.py login`. Changes: swaps LOGIN_CONFIG_DIR/settings.json for the run (--yes). About 1 min.',
    'keycloak':
        "keycloak: the client against a local Keycloak 26 in Docker (127.0.0.1 only, realm aigw-test, dummy user with a password made up for the run): device code and PKCE sign-in with the user's side done over HTTP, Mode A claims straight from the IdP (protocol mappers, nested defaults, no broker), refresh and Revoke Refresh Token behavior, offline_access vs SSO session end, Claude Code sending the IdP's JWT to the mock gateway, and Mode B (the plain IdP token). Needs Docker (or KEYCLOAK_URL and KEYCLOAK_ADMIN_PASSWORD for a Keycloak already running); SKIP (docker) without. Changes: starts and removes one container. About 4 min.",
    'managed':
        "managed: the OS managed-settings file next to the user's settings.json: a managed ANTHROPIC_CUSTOM_HEADERS vs the user's JWT; hooks from managed settings with the JWT in the user file; allowManagedHooksOnly; a read-only or immutable settings.json; proxyAuthHelper; spike S4 (an unknown top-level key, AIGW_* in managed env, managed-settings.d/ drop-ins). Mock gateway, fake IdP. Changes: writes /Library/Application Support/ClaudeCode/managed-settings.json (Linux: /etc/claude-code/) with sudo for a minute per case and removes it; refuses if a managed-settings file exists. Drop-in cases also write files in managed-settings.d/ (and remove them, and the directory if it created it). Other Claude Code sessions on the machine see each case's settings while it runs: close them first (--yes). About 8 min.",
}

EXPECT_HEADERS_0 = r'''
install_exit 0
settings_base_url gateway
settings_hooks StopFailure,UserPromptSubmit
turn1 ok
turn1_authorization oauth
turn1_gateway_header jwt1
renewed_by_rename yes
turn2 ok
turn2_gateway_header jwt2
turn2_hook_refreshed no
'''

EXPECT_ERRORS_0 = r'''
portkey401_attempts 2
portkey401_fast yes
portkey401_message portkey
portkey401_stopfailure_error authentication_failed
anthropic401_attempts 2
anthropic401_fast yes
anthropic401_message anthropic
anthropic401_stopfailure_error authentication_failed
403_attempts 1
403_fast yes
403_message status-shown
403_stopfailure_error authentication_failed
407_attempts 1
407_fast yes
407_message status-shown
407_stopfailure_error unknown
498_attempts 1
498_fast yes
498_message status-shown
498_stopfailure_error unknown
recovery ok
'''

EXPECT_PRECHECK_0 = r'''
# expired JWT, IdP fine: renewed before the first request
expired_turn1 ok
expired_turn1_requests 1
expired_turn1_jwt renewed
expired_turn1_fast yes
expired_turn2 ok
expired_settings_value jwt
# valid JWT: the hook does nothing
valid_turn1 ok
valid_turn1_jwt initial
valid_turn1_fast yes
valid_turn2_jwt initial
valid_turn2_fast yes
# hook_wait 0: the request goes out before Claude Code has reloaded the settings (why hook_wait exists)
nowait_turn1 portkey
nowait_turn1_jwt initial
nowait_turn2 ok
nowait_turn2_jwt renewed
# the IdP accepts connections but never answers: the hook still blocks inside Claude Code's hook timeout
idphang_turn1 blocked
idphang_turn1_requests 0
idphang_turn1_fast yes
idphang_turn2 blocked
idphang_settings_value sentinel
idphang_block_message yes
# not signed in: blocked at once with the sign-in message, nothing sent
signedout_turn1 blocked
signedout_turn1_requests 0
signedout_turn1_fast yes
signedout_turn2 blocked
signedout_settings_value sentinel
signedout_block_message yes
# not signed in, hook_login device: the block message carries a device code from a sign-in the hook started in the
# background; once the user finishes it, the next prompt goes through with the new JWT
hooklogin_turn1 blocked
hooklogin_turn1_requests 0
hooklogin_turn1_fast yes
hooklogin_code_in_message yes
hooklogin_device_flows 1
hooklogin_signed_in_in_background yes
hooklogin_turn2 ok
hooklogin_turn2_requests 1
hooklogin_turn2_jwt renewed
hooklogin_turn2_fast yes
hooklogin_settings_value jwt
hooklogin_block_message yes
# block_on_failure off, LB guard on: the request carries the sentinel and gets 498 at once
lbguard_turn1 gateway-token
lbguard_turn1_requests 1
lbguard_turn1_jwt sentinel
lbguard_turn1_fast yes
lbguard_turn2 gateway-token
lbguard_turn2_requests 1
'''

EXPECT_STOPFAILURE_0 = r'''
baseline ok
refused_turn portkey
jwt_replaced yes
notified renewed
retry_turn ok
anthropic_turn anthropic
anthropic_jwt_kept yes
'''

EXPECT_PROXY_0 = r'''
# a normal turn through the proxy
normal_result ok
normal_header_injected yes
normal_client_header_stripped yes
normal_authorization oauth
normal_beta_passed yes
normal_streamed yes
normal_proxy_logged_fingerprint yes
# the token file changes: the next request carries the new token
renewed_result ok
renewed_header_injected yes
# the gateway refuses the JWT (Portkey 401): the proxy answers 498, so one attempt (direct 401: 2 attempts, finding 5)
portkey401_attempts 1
portkey401_upstream_requests 1
portkey401_proxy_status 498
portkey401_proxy_note gateway-401->498
portkey401_fast yes
portkey401_message gateway-token
portkey401_498_shown yes
portkey401_stopfailure_error unknown
# Anthropic refuses the login (relayed 401): passed through, so Claude Code treats it as it does without a proxy
anthropic401_attempts 2
anthropic401_upstream_requests 2
anthropic401_proxy_status 401
anthropic401_proxy_note passthrough-401
anthropic401_fast yes
anthropic401_message anthropic
anthropic401_498_shown no
anthropic401_stopfailure_error authentication_failed
# no usable token (file missing, empty, sentinel): 498 from the proxy, nothing sent upstream
notoken_missing_attempts 1
notoken_missing_upstream_requests 0
notoken_missing_proxy_status 498
notoken_missing_proxy_note no-token:missing
notoken_missing_fast yes
notoken_missing_message gateway-token
notoken_missing_498_shown yes
notoken_missing_stopfailure_error unknown
notoken_empty_attempts 1
notoken_empty_upstream_requests 0
notoken_empty_proxy_status 498
notoken_empty_proxy_note no-token:missing
notoken_empty_fast yes
notoken_empty_message gateway-token
notoken_empty_498_shown yes
notoken_empty_stopfailure_error unknown
notoken_sentinel_attempts 1
notoken_sentinel_upstream_requests 0
notoken_sentinel_proxy_status 498
notoken_sentinel_proxy_note no-token:expired
notoken_sentinel_fast yes
notoken_sentinel_message gateway-token
notoken_sentinel_498_shown yes
notoken_sentinel_stopfailure_error unknown
recovery ok
# chunked SSE, events 0.6 s apart, read through the proxy: the first event arrives at once, the stream is chunked and whole
sse_status 200
sse_chunked yes
sse_first_event_early yes
sse_spread_over_time yes
sse_complete yes
# spike S11: socket base URL forms (a plain-HTTP listener on a Unix socket). Only ANTHROPIC_UNIX_SOCKET from the environment works
socket_unix_url no-request (still retrying after 15s)
socket_http_plus_unix no-request (still retrying after 15s)
socket_http_unix_colon no-request (still retrying after 15s)
socket_env_var reached-listener, reply ok
socket_env_var_gateway_header yes
socket_env_var_authorization oauth
socket_env_var_in_settings no-request (still retrying after 15s)
'''

EXPECT_STORED_LOGIN_0 = r'''
login_present yes
baseline ok
498_attempts 1
498_long no
498_login_rotated no
498_login_still_valid yes
portkey401_attempts many
portkey401_long yes
portkey401_login_rotated yes
portkey401_login_still_valid yes
recovery ok
'''

EXPECT_STORED_LOGIN_PROXY_0 = r'''
login_present yes
baseline ok
portkey401_attempts 1
portkey401_upstream_requests 1
portkey401_message gateway-token
portkey401_long no
portkey401_login_rotated no
portkey401_login_still_valid yes
notoken_attempts 1
notoken_upstream_requests 0
notoken_message gateway-token
notoken_long no
notoken_login_rotated no
notoken_login_still_valid yes
recovery ok
'''

EXPECT_GATEWAY_0 = r'''
missing $refused
garbage 401 portkey
tampered 401 portkey
bearer_prefixed 401 anthropic
sentinel $refused
valid_bad_login 401 anthropic
valid_no_login 401 anthropic
lb_guard $lb_guard
'''

EXPECT_LIVE_LOGIN_0 = r'''
ok_result ok
ok_attempts 1
ok_login_still_valid yes
tampered_result portkey
tampered_attempts many
tampered_statuses 401
tampered_long yes
tampered_login_rotated yes
tampered_login_still_valid yes
'''

EXPECT_LIVE_LOGIN_1 = r'''
sentinel_result gateway-token
sentinel_attempts 1
sentinel_statuses 498
sentinel_long no
sentinel_login_rotated no
missing_result gateway-token
missing_attempts 1
missing_statuses 498
missing_login_rotated no
'''

EXPECT_CLIENT_LIVE_0 = r'''
signed_in yes
install_exit 0
sync_exit 0
gateway_accepts_jwt yes
turn_fresh ok
turn_after_expiry ok
turn_after_expiry_statuses 200
turn_after_expiry_fast yes
'''

EXPECT_MANAGED_0 = r'''
# no managed file: the client hooks renew the expired JWT (control)
none_turn1 ok
none_turn1_jwt renewed
# managed env ANTHROPIC_CUSTOM_HEADERS: expected to replace the user's value, so the JWT isn't sent
headers_turn1_managed_header yes
headers_turn1_jwt none
headers_turn1 portkey
# fleet layout: hooks from managed settings, JWT in the user file; the managed precheck renews the expired JWT
fleet_turn1 ok
fleet_turn1_jwt renewed
fleet_turn2 ok
# fleet layout, valid JWT, the client renews it between turns: the session picks up the new one
fleetreload_turn1_jwt initial
fleetreload_turn2 ok
fleetreload_turn2_jwt renewed
# allowManagedHooksOnly without managed hooks: user hooks don't run, so nothing renews the expired JWT
hooksonly_user_hook_ran no
hooksonly_turn1 portkey
hooksonly_turn1_jwt initial
# allowManagedHooksOnly with the client hooks in managed settings: user hooks don't run, the managed ones do
hooksonlymanaged_user_hook_ran no
hooksonlymanaged_turn1 ok
hooksonlymanaged_turn1_jwt renewed
# chmod 444 on settings.json: the client's atomic rename replaces the file anyway
readonly_sync_exit 0
readonly_sync_wrote yes
readonly_turn1 ok
# macOS immutable flag (chflags uchg): the client can't write; the precheck blocks
immutable_sync_exit $immutable_exit
immutable_sync_wrote $immutable_wrote
immutable_turn1 $immutable_turn
# proxyAuthHelper (EAP) in managed settings: expected not to reach the gateway (it's for a forward proxy)
proxyauth_turn1 ok
proxyauth_turn1_proxy_authorization no
# Spike S4 (finding 15; first run 2026-10-25 confirmed every expectation below)
# an unknown top-level key (aigwClaudeAuth) in managed-settings.json: ignored; the rest of the file still applies
unknownkey_turn1 ok
unknownkey_base_url_from_managed yes
unknownkey_hook_userprompt_ran yes
unknownkey_hook_stopfailure_ran yes
unknownkey_marker_in_hook_input no
unknownkey_stderr_warning no
unknownkey_stream_warning no
# AIGW_* in managed env: in the environment of hooks and of the Bash tool; managed wins over the user's same key
# (as with ANTHROPIC_CUSTOM_HEADERS, finding 11), and the user's other AIGW_* key survives
envkeys_base_url_from_managed yes
envkeys_env_userprompt AIGW_HOOK_LOGIN=off,AIGW_ISSUER=managed-issuer,AIGW_USER_ONLY=user-only
envkeys_env_stopfailure AIGW_HOOK_LOGIN=off,AIGW_ISSUER=managed-issuer,AIGW_USER_ONLY=user-only
envkeys_env_bash AIGW_HOOK_LOGIN=off,AIGW_ISSUER=managed-issuer,AIGW_USER_ONLY=user-only
envkeys_stderr_warning no
# managed-settings.d/: merged with managed-settings.json, files in name order, a later file wins on a conflicting key;
# hooks for one event in different files all run
dropin_base_url_from_managed yes
dropin_hook_userprompt_ran yes
dropin_hook_userprompt2_ran yes
dropin_hook_stopfailure_ran yes
dropin_env_userprompt AIGW_CONFLICT=dropin20,AIGW_FROM_10=a,AIGW_FROM_20=b,AIGW_FROM_MAIN=main
dropin_env_stopfailure AIGW_CONFLICT=dropin20,AIGW_FROM_10=a,AIGW_FROM_20=b,AIGW_FROM_MAIN=main
dropin_env_bash AIGW_CONFLICT=dropin20,AIGW_FROM_10=a,AIGW_FROM_20=b,AIGW_FROM_MAIN=main
# a drop-in without managed-settings.json: applied
dropinonly_base_url_from_managed yes
dropinonly_hook_userprompt_ran yes
dropinonly_hook_stopfailure_ran yes
dropinonly_env_userprompt AIGW_ONLY_DROPIN=yes
'''

EXPECT_KEYCLOAK_0 = r'''
# the pinned Keycloak image (repro/keycloak/kc.py IMAGE)
keycloak_version 26.4.7
# Mode A from the IdP (no broker): device code sign-in, the user's side done over HTTP; token claims from the protocol mappers
device_prompt yes
device_login_exit 0
device_page_confirms yes
login_stores_refresh_token yes
state_file_mode 0o600
token_is_jwt yes
claim_iss_is_issuer yes
claim_aud_has_gateway yes
claim_defaults_keys config_id,config_slug
claim_defaults_nested_object yes
claim_config_slug yes
claim_config_id yes
claim_portkey_workspace yes
claim_portkey_oid_is_user_id yes
claim_kind gateway
token_lifetime_s 900
token_second_call_cached yes
refresh_token_typ Offline
settings_holds_token yes
# `inspect` decodes the stored JWT, redacted, and finds no problem
inspect_exit 0
inspect_problem_lines 0
inspect_shows_workspace yes
inspect_leaks_token no
# refresh: Keycloak's default keeps old refresh tokens valid; with Revoke Refresh Token on, a reused one is refused and revokes the chain
refresh_gives_new_jwt yes
refresh_token_replaced_by_client yes
old_refresh_token_still_valid_default yes
realm_revoke_set 204
revoke_on_client_refresh_ok yes
revoke_on_client_stores_new_token yes
revoke_on_old_token_rejected 400
revoke_on_reuse_kills_current_token yes
relogin_after_reuse_exit 0
# Claude Code sends the IdP's JWT to the mock gateway (Mode A, broker_url empty)
modea_broker_url_empty yes
modea_login_exit 0
modea_install_exit 0
modea_settings_has_jwt yes
modea_turn ok
modea_gateway_got_idp_jwt yes
modea_authorization_oauth yes
modeb_login_exit 0
modeb_install_exit 0
# Mode B: a client without the custom mappers; the plain IdP token (no portkey claims) reaches a gateway that accepts it
modeb_jwt_differs_from_modea yes
modeb_claim_iss_is_issuer yes
modeb_no_portkey_claims yes
modeb_has_sub_and_azp yes
modeb_turn ok
modeb_gateway_got_idp_jwt yes
# browser flow: PKCE S256 with a loopback redirect on any port; a client with PKCE enforced refuses the device flow (the client sends no code_challenge there)
pkce_login_exit 0
pkce_loopback_port_accepted yes
pkce_stores_refresh_token yes
pkce_enforced_device_login_exit 1
pkce_enforced_device_error code_challenge_method
pkce_enforced_pkce_login_exit 0
# offline_access: ending the SSO session kills a normal refresh token, not the offline one; the admin 'logout user' call also revokes offline tokens
normal_login_exit 0
normal_refresh_token_typ Refresh
normal_refresh_before_logout yes
sessions_before_logout sso+,offline+
sso_sessions_deleted 1
sessions_after_sso_end sso0,offline+
normal_refresh_after_sso_end_exit 1
normal_refresh_after_sso_end_message sign-in-expired
offline_refresh_after_sso_end_exit 0
offline_jwt_after_sso_end yes
admin_logout_status 204
offline_refresh_after_admin_logout_exit 1
offline_refresh_after_admin_logout_message sign-in-expired
'''


SCENARIOS = ["unit", "headers", "errors", "precheck", "stopfailure", "proxy", "stored_login", "stored_login_proxy",
             "gateway", "live_login", "client_live", "managed", "keycloak"]
EXPORTED = ("CLAUDE_BIN", "MODEL", "LOGIN_CONFIG_DIR", "GATEWAY_URL", "TOKEN_COMMAND", "LB_GUARD", "SENTINEL")


class Abort(Exception):
    """Ends the scenario with exit code `code` (the verdict is ERROR unless already printed)."""

    def __init__(self, code=1):
        self.code = code


def utc(fmt):
    return datetime.now(timezone.utc).strftime(fmt)


def load_env(path):
    """Read repro/env the way bash `source` would for the simple KEY=VALUE files env.example describes: optional
    `export`, quotes, comments, $VAR and a leading ~ expanded. Returns the assigned keys."""
    keys = []
    if not path.is_file():
        return keys
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[7:].lstrip()
        k, sep, v = line.partition("=")
        k = k.strip()
        if not sep or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", k):
            continue
        v = v.strip()
        if v[:1] in "\"'" and v.endswith(v[:1]) and len(v) >= 2:
            v = v[1:-1]
        else:
            v = re.sub(r"\s+#.*$", "", v)
        os.environ[k] = os.path.expanduser(os.path.expandvars(v))
        keys.append(k)
    return keys


def mask(text):
    """Applied to anything that might carry a secret."""
    return re.sub(r"[A-Za-z0-9+/_=-]{24,}", "<masked>", text)


def fp(path):
    """A secret file, safely: length, last 3 characters, short hash."""
    data = Path(path).read_bytes()
    tail = data[-3:].decode("utf-8", "replace").rstrip("\n")
    return f"len {len(data)} tail {tail} sha {hashlib.sha256(data).hexdigest()[:12]}"


def default_token_command():
    argv = [sys.executable, str(CLIENT), "token"]
    return subprocess.list2cmdline(argv) if IS_WIN else " ".join(shlex.quote(a) for a in argv)


def docker_missing():
    """None if `docker info` works, else why not."""
    if not shutil.which("docker"):
        return "not found"
    p = run_text(["docker", "info"], timeout=30)
    return None if p and p.returncode == 0 else "daemon not running"


def run_text(argv, **kw):
    """subprocess.run with utf-8 text capture, never raising on a missing program."""
    try:
        return subprocess.run(argv, capture_output=True, encoding="utf-8", errors="replace", **kw)
    except (OSError, subprocess.TimeoutExpired):
        return None


class Runner:
    def __init__(self, args):
        self.args = args
        self.out = None
        self.obs = self.diff = self.skipped = 0
        self.cleanup_steps = []
        self.seen = {}
        self.started = False
        self.claude = os.environ.get("CLAUDE_BIN") or "claude"
        self.claude_path = shutil.which(self.claude) or self.claude      # claude.exe on Windows

    # ------------------------------------------------------------ framework
    def log(self, msg):
        line = f"{utc('%H:%M:%SZ')} {msg}"
        print(line, flush=True)
        self.append("run.log", line)

    def append(self, name, line):
        with open(self.out / name, "a", encoding="utf-8") as f:
            f.write(line + "\n")

    def need(self, *names):
        for v in names:
            if not os.environ.get(v):
                print(f"ERROR: {v} is empty in env")
                raise Abort(2)

    def on_exit(self, desc, fn):
        self.cleanup_steps.append((desc, fn))               # undo steps run in reverse, even on failure

    def expect(self, what, want, got):
        self.obs += 1
        r = "ok"
        if want != got:
            r, self.diff = "DIFF", self.diff + 1
        line = f"{r:<4} {what}: expected {want}, observed {got}"
        print(line, flush=True)
        self.append("summary.txt", line)
        self.append("run.log", line)

    def skip(self, what, want, why):
        self.skipped += 1
        line = f"SKIP {what}: expected {want}, not applicable ({why})"
        print(line, flush=True)
        self.append("summary.txt", line)
        self.append("run.log", line)

    def cleanup(self):
        while self.cleanup_steps:
            desc, fn = self.cleanup_steps.pop()
            self.log(f"cleanup: {desc}")
            try:
                fn()
            except Exception as e:                           # noqa: BLE001
                self.log(mask(f"cleanup failed: {e}"))

    def start(self, scenario):
        d = f"{utc('%Y-%m-%d')}"
        for s in ("", "-b", "-c", "-d", "-e", "-f", "-g", "-h"):
            if not (HERE / "results" / f"{d}{s}-{scenario}").exists():
                break
        self.out = HERE / "results" / f"{d}{s}-{scenario}"
        self.out.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(self.out, 0o700)
        except OSError:
            pass
        (self.out / "summary.txt").write_text("", encoding="utf-8")
        self.obs = self.diff = self.skipped = 0
        self.started = True
        head = [f"scenario: {scenario}", f"date: {utc('%Y-%m-%dT%H:%M:%SZ')}", *self.versions()]
        with open(self.out / "summary.txt", "a", encoding="utf-8") as f:
            f.write("\n".join(head) + "\n")

    def finish(self, verdict=""):
        self.started = False
        self.cleanup()
        if not verdict:
            verdict = "ERROR" if self.obs == 0 else "CHANGED" if self.diff else "PASS"
        extra = f", {self.skipped} skipped" if self.skipped else ""
        line = f"verdict: {verdict} ({self.obs} observations, {self.diff} differ{extra})"
        print(line)
        self.append("summary.txt", line)
        print(f"results: {self.out}")
        return verdict

    def guard(self, name, why):
        if "--yes" not in self.args:
            print(f"ERROR: {name} changes shared state ({why}); re-run with --yes")
            raise Abort(2)

    # ------------------------------------------------------------ article-specific
    def versions(self):
        v = run_text([self.claude_path, "--version"], timeout=30)
        cc = (v.stdout.split() or ["unknown"])[0] if v and v.returncode == 0 else "unknown"
        c = run_text([sys.executable, str(CLIENT), "--version"], timeout=30)
        cl = c.stdout.strip() if c and c.returncode == 0 and c.stdout.strip() else "unknown"
        import platform
        os_ = f"{os.uname().sysname} {os.uname().release}" if hasattr(os, "uname") else f"Windows {platform.release()} {platform.version()}"
        return [f"claude-code: {cc}", f"aigw-claude-auth: {cl}", f"python: {platform.python_version()}", f"os: {os_}",
                f"model: {os.environ.get('MODEL') or 'claude-haiku-4-5'}", f"lb-guard: {os.environ.get('LB_GUARD') or 'off'}"]

    def check(self):
        if not shutil.which(self.claude):
            print(f"ERROR: {self.claude} not found")
            raise Abort(2)
        if sys.version_info < (3, 8):
            print("ERROR: python 3.8+ needed")
            raise Abort(2)
        print("\n".join(self.versions()))
        ldir = os.environ.get("LOGIN_CONFIG_DIR")
        if ldir:
            c = Path(os.path.expanduser(ldir)) / ".credentials.json"
            if c.is_file():
                print(f"stored login: {fp(c)}")
            else:
                print(f"stored login: none in {ldir} (sign in: CLAUDE_CONFIG_DIR={ldir} claude, then /login)")
        else:
            print("stored login: LOGIN_CONFIG_DIR not set (stored_login, live_login, client_live will refuse to run)")
        gw = os.environ.get("GATEWAY_URL")
        if gw:
            req = urllib.request.Request(gw.rstrip("/") + "/v1/messages", data=b"{}", method="POST", headers={"content-type": "application/json"})
            try:
                code = urllib.request.urlopen(req, timeout=15).status
            except urllib.error.HTTPError as e:
                code = e.code
            except Exception:                                # noqa: BLE001
                code = "000"
            print(f"gateway: HTTP {code} for an unauthenticated POST (expect 401, or 498 behind the LB guard)")
            cmd = os.environ.get("TOKEN_COMMAND") or default_token_command()
            p = run_text(cmd, shell=True, timeout=120)
            t = p.stdout.strip() if p and p.returncode == 0 else ""
            if t.count(".") >= 2:
                print(f"gateway JWT: len {len(t)} sha {hashlib.sha256(t.encode()).hexdigest()[:12]}")
            else:
                print(f"gateway JWT: TOKEN_COMMAND failed (sign in first: {sys.executable} {CLIENT} login)")
        else:
            print("gateway: GATEWAY_URL not set (gateway, live_login, client_live will refuse to run)")
        why = docker_missing()
        print("docker: ok (the keycloak scenario can run)" if not why else f"docker: {why} (the keycloak scenario will SKIP unless KEYCLOAK_URL is set)")
        print("check: ok")

    def harness(self, scenario):
        """Run repro/harness.py, keep its key=value observations in self.seen."""
        self.seen = {}
        env = dict(os.environ, PYTHONIOENCODING="utf-8")
        with open(self.out / "run.log", "ab") as errlog:
            p = subprocess.run([sys.executable, str(HERE / "harness.py"), scenario, "--out", str(self.out / "detail")],
                               stdout=subprocess.PIPE, stderr=errlog, env=env)
        for line in p.stdout.decode("utf-8", "replace").splitlines():
            k, _, v = line.partition("=")
            self.seen[k.strip()] = v.strip()
        self.log(f"harness {scenario}: {len(self.seen)} observations (details in {self.out / 'detail'})")
        if p.returncode != 0:
            self.log(f"harness {scenario} failed (exit {p.returncode}), see run.log")
            raise Abort(1)                                   # verdict ERROR

    def expect_seen(self, text, skip=None, subst=None):
        """text: "<key> <expected...>" lines (# comments allowed); compares each with the harness observation.
        skip: function key -> reason or None, for expectations that cannot apply on this platform."""
        for k, val in (subst or {}).items():
            text = text.replace("$" + k, val)
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            k, _, want = line.partition(" ")
            want = want.strip()
            why = skip(k) if skip else None
            if why:
                self.skip(k, want, why)
            else:
                self.expect(k, want, self.seen.get(k) or "missing")

    # ------------------------------------------------------------ scenarios
    def scenario_unit(self):
        self.start("unit")
        p = subprocess.run([sys.executable, "-m", "unittest", "client/test_aigw_claude_auth.py"], cwd=ROOT, stdout=subprocess.PIPE,
                           stderr=subprocess.STDOUT, encoding="utf-8", errors="replace")
        res = p.stdout.rstrip("\n")
        self.append("run.log", res)
        last = res.splitlines()[-1].split() if res else []
        self.expect("client unit tests", "OK", last[0] if last else "")
        self.expect("tests ran", "yes", "yes" if re.search(r"^Ran [1-9][0-9]* tests", res, re.M) else "no")
        self.finish()

    def simple(self, scenario, harness_name, texts, **kw):
        self.start(scenario)
        self.harness(harness_name)
        for t in texts:
            self.expect_seen(t, **kw)
        self.finish()

    def scenario_headers(self):
        self.simple("headers", "headers", [EXPECT_HEADERS_0])

    def scenario_errors(self):
        self.simple("errors", "errors", [EXPECT_ERRORS_0])

    def scenario_precheck(self):
        self.simple("precheck", "precheck", [EXPECT_PRECHECK_0])

    def scenario_stopfailure(self):
        self.simple("stopfailure", "stopfailure", [EXPECT_STOPFAILURE_0])

    def scenario_proxy(self):
        # Spike S11 (Unix socket base URLs) needs AF_UNIX, which Windows Python does not have: reported, not faked.
        skip = (lambda k: "no AF_UNIX in Windows Python" if k.startswith("socket_") else None) if IS_WIN else None
        self.simple("proxy", "proxy", [EXPECT_PROXY_0], skip=skip)

    def scenario_stored_login(self):
        self.need("LOGIN_CONFIG_DIR")
        self.guard("stored_login", "rotates the stored login in LOGIN_CONFIG_DIR at Anthropic")
        self.simple("stored_login", "stored-login", [EXPECT_STORED_LOGIN_0])

    def scenario_stored_login_proxy(self):
        self.need("LOGIN_CONFIG_DIR")
        self.guard("stored_login_proxy", "may rotate the stored login in LOGIN_CONFIG_DIR at Anthropic, and swaps its settings.json for the run")
        self.simple("stored_login_proxy", "stored-login-proxy", [EXPECT_STORED_LOGIN_PROXY_0])

    def scenario_gateway(self):
        self.need("GATEWAY_URL")
        self.start("gateway")
        self.harness("gateway")
        lb = os.environ.get("LB_GUARD") or "off"
        refused = "498 gateway-token" if lb == "on" else "401 portkey"
        self.expect_seen(EXPECT_GATEWAY_0, subst={"refused": refused, "lb_guard": lb})
        if os.environ.get("LOGIN_CONFIG_DIR"):
            self.expect("valid_real_login", "200 reply", self.seen.get("valid_real_login") or "missing")
        self.finish()

    def scenario_live_login(self):
        self.need("LOGIN_CONFIG_DIR", "GATEWAY_URL")
        self.guard("live_login", "rotates the stored login in LOGIN_CONFIG_DIR at Anthropic")
        self.start("live_login")
        self.harness("live-login")
        self.expect_seen(EXPECT_LIVE_LOGIN_0)
        if os.environ.get("LB_GUARD") == "on":
            self.expect_seen(EXPECT_LIVE_LOGIN_1)
        self.finish()

    def scenario_client_live(self):
        self.need("LOGIN_CONFIG_DIR", "GATEWAY_URL")
        self.guard("client_live", "swaps LOGIN_CONFIG_DIR/settings.json for the run")
        self.simple("client_live", "client-live", [EXPECT_CLIENT_LIVE_0])

    def scenario_managed(self):
        self.guard("managed", "writes the machine-wide managed-settings file while it runs")
        if IS_WIN:
            # needs sudo and the POSIX managed-settings locations; a person runs it, and it is not applicable here
            self.start("managed")
            print("SKIP managed: not applicable on Windows (needs sudo and /etc/claude-code or /Library/Application Support)")
            self.append("summary.txt", "managed: not applicable on Windows")
            self.finish("SKIP (windows)")
            return
        if subprocess.run(["sudo", "-v"]).returncode != 0:
            print("ERROR: managed needs sudo")
            raise Abort(2)
        self.start("managed")
        stop = threading.Event()

        def keepalive():                                      # keep sudo's timestamp fresh
            while not stop.wait(50):
                if subprocess.run(["sudo", "-n", "true"], capture_output=True).returncode != 0:
                    return
        threading.Thread(target=keepalive, daemon=True).start()
        self.on_exit("stop sudo keepalive", stop.set)
        self.harness("managed")
        imm = dict(immutable_exit="1", immutable_wrote="no", immutable_turn="blocked")
        if sys.platform != "darwin":
            imm = dict(immutable_exit="missing", immutable_wrote="missing", immutable_turn="missing")
            self.expect("immutable_skipped", "macos-only", self.seen.get("immutable_skipped") or "missing")
        self.expect_seen(EXPECT_MANAGED_0, subst=imm)
        self.finish()

    def scenario_keycloak(self):
        # Needs Docker, or an already running Keycloak (KEYCLOAK_URL, KEYCLOAK_ADMIN_PASSWORD); otherwise SKIP, as on Windows for managed.
        self.start("keycloak")
        why = None if os.environ.get("KEYCLOAK_URL") else docker_missing()
        if why:
            print(f"SKIP keycloak: docker is {why} (install/start Docker, or set KEYCLOAK_URL and KEYCLOAK_ADMIN_PASSWORD)")
            self.append("summary.txt", f"keycloak: docker {why}")
            self.finish("SKIP (docker)")
            return
        self.harness("keycloak")
        self.expect_seen(EXPECT_KEYCLOAK_0)
        self.finish()


USAGE = "\n".join(__doc__.split("\n")[3:8])


def main(argv):
    cmd = argv[1] if len(argv) > 1 else "list"
    args = argv[2:]
    if any(a != "--yes" for a in args):
        print(f"one scenario per run; unexpected: {' '.join(a for a in args if a != '--yes')}\n{USAGE}")
        return 2
    load_env(HERE / "env")
    r = Runner(args)
    try:
        if cmd == "list":
            for s in SCENARIOS:
                print(DESCRIBE[s])
        elif cmd == "check":
            r.check()
        elif cmd == "all":
            for s in SCENARIOS:
                getattr(r, f"scenario_{s}")()
        elif cmd in SCENARIOS:
            getattr(r, f"scenario_{cmd}")()
        else:
            print(USAGE)
            return 2
    except Abort as a:
        if r.started:
            r.finish("ERROR")
        return a.code
    except BaseException:                                     # noqa: BLE001  an unexpected error is an ERROR verdict too
        import traceback
        if r.started:
            r.append("run.log", traceback.format_exc())
            traceback.print_exc()
            r.finish("ERROR")
            return 1
        raise
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
