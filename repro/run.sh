#!/usr/bin/env bash
# run.sh: re-run this article's tests. See the README's "Re-run" section.
#   run.sh list                 scenarios, what each changes, how long it takes
#   run.sh check                read-only preflight: tools, env, credentials, versions
#   run.sh <scenario> [--yes]   one scenario; --yes is required for scenarios that change shared state
#   run.sh all [--yes]          every scenario
# Results: repro/results/<date>-<scenario>/{run.log,summary.txt}. Verdict: PASS, CHANGED or ERROR.
set -uo pipefail
(( BASH_VERSINFO[0] >= 4 )) || { echo "ERROR: needs bash 4+ (macOS: brew install bash, then run: $(command -v brew >/dev/null && echo "$(brew --prefix)/bin/bash" || echo bash) $0 ...)"; exit 2; }
HERE=$(cd "$(dirname "$0")" && pwd)
[[ -f $HERE/env ]] || { echo "ERROR: copy env.example to env and fill it in"; exit 2; }
# shellcheck source=/dev/null
source "$HERE/env"

# ---------------------------------------------------------------- framework (keep as is)
OUT= OBS=0 DIFF=0
CLEANUP=()
log()     { echo "$(date -u +%H:%M:%SZ) $*" | tee -a "$OUT/run.log"; }
mask()    { sed -E 's/[A-Za-z0-9+\/_=-]{24,}/<masked>/g'; }          # pipe anything that might carry a secret
sha()     { if command -v sha256sum >/dev/null; then sha256sum; else shasum -a 256; fi; }   # macOS may lack sha256sum
fp()      { echo "len $(wc -c < "$1" | tr -d ' ') tail $(tail -c3 "$1") sha $(sha < "$1" | cut -c1-12)"; }  # a secret file, safely
need()    { for v; do [[ -n ${!v:-} ]] || { echo "ERROR: $v is empty in env"; exit 2; }; done; }
on_exit() { CLEANUP+=("$*"); }                                    # registered undo steps run in reverse, even on failure
expect()  { # expect "<what>" "<expected>" "<observed>"
  OBS=$((OBS+1)); if [[ $2 == "$3" ]]; then r=ok; else r=DIFF; DIFF=$((DIFF+1)); fi
  printf '%-4s %s: expected %s, observed %s\n' "$r" "$1" "$2" "$3" | tee -a "$OUT/summary.txt" | tee -a "$OUT/run.log"; }
cleanup() { local i; for ((i=${#CLEANUP[@]}-1; i>=0; i--)); do log "cleanup: ${CLEANUP[i]}"; eval "${CLEANUP[i]}" 2>&1 | mask | tee -a "$OUT/run.log"; done; CLEANUP=(); }
start()   { # start <scenario>
  local d=$HERE/results/$(date -u +%F) s=; for s in "" -b -c -d -e -f -g -h; do [[ -e $d$s-$1 ]] || break; done
  OUT=$d$s-$1; mkdir -p "$OUT"; chmod 700 "$OUT"; : > "$OUT/summary.txt"; OBS=0 DIFF=0
  { echo "scenario: $1"; echo "date: $(date -u +%FT%TZ)"; versions; } >> "$OUT/summary.txt"; trap 'cleanup; finish ERROR' EXIT; }
finish()  { trap - EXIT; cleanup
  local v=${1:-}; [[ -n $v ]] || { ((OBS == 0)) && v=ERROR || { ((DIFF)) && v=CHANGED || v=PASS; }; }
  echo "verdict: $v ($OBS observations, $DIFF differ)" | tee -a "$OUT/summary.txt"; echo "results: $OUT"; }
guard()   { [[ " ${ARGS[*]:-} " == *" --yes "* ]] || { echo "ERROR: $1 changes shared state ($2); re-run with --yes"; exit 2; }; }

# ---------------------------------------------------------------- article-specific
export CLAUDE_BIN MODEL LOGIN_CONFIG_DIR GATEWAY_URL TOKEN_COMMAND LB_GUARD SENTINEL
[[ -n ${AIGW_CLAUDE_AUTH_DIR:-} ]] && export AIGW_CLAUDE_AUTH_DIR
CLAUDE=${CLAUDE_BIN:-claude}
CLIENT=$HERE/../client/aigw_claude_auth.py

versions() { # print "component: version" lines; "unknown" rather than failing
  echo "claude-code: $("$CLAUDE" --version 2>/dev/null | awk '{print $1}' || echo unknown)"
  echo "aigw-claude-auth: $(python3 "$CLIENT" --version 2>/dev/null || echo unknown)"
  echo "python: $(python3 -c 'import platform; print(platform.python_version())')"
  echo "os: $(uname -sr)"
  echo "model: ${MODEL:-claude-haiku-4-5}"
  echo "lb-guard: ${LB_GUARD:-off}"; }

check() {
  for t in python3 curl "$CLAUDE"; do command -v "$t" >/dev/null || { echo "ERROR: $t not found"; exit 2; }; done
  python3 -c 'import sys; sys.exit(sys.version_info < (3, 8))' || { echo "ERROR: python 3.8+ needed"; exit 2; }
  versions
  if [[ -n ${LOGIN_CONFIG_DIR:-} ]]; then
    local c=${LOGIN_CONFIG_DIR/#\~/$HOME}/.credentials.json
    if [[ -f $c ]]; then echo "stored login: $(fp "$c")"; else echo "stored login: none in $LOGIN_CONFIG_DIR (sign in: CLAUDE_CONFIG_DIR=$LOGIN_CONFIG_DIR claude, then /login)"; fi
  else echo "stored login: LOGIN_CONFIG_DIR not set (stored_login, live_login, client_live will refuse to run)"; fi
  if [[ -n ${GATEWAY_URL:-} ]]; then
    echo "gateway: HTTP $(curl -s -o /dev/null -w '%{http_code}' -m 15 "$GATEWAY_URL/v1/messages" -X POST -H 'content-type: application/json' -d '{}') for an unauthenticated POST (expect 401, or 498 behind the LB guard)"
    local t; if t=$(eval "${TOKEN_COMMAND:-python3 $CLIENT token}" 2>/dev/null) && [[ $t == *.*.* ]]; then
      echo "gateway JWT: len ${#t} sha $(printf %s "$t" | sha | cut -c1-12)"
    else echo "gateway JWT: TOKEN_COMMAND failed (sign in first: python3 $CLIENT login)"; fi
  else echo "gateway: GATEWAY_URL not set (gateway, live_login, client_live will refuse to run)"; fi
  if docker info >/dev/null 2>&1; then echo "docker: ok (the keycloak scenario can run)"; else echo "docker: not available (the keycloak scenario will SKIP unless KEYCLOAK_URL is set)"; fi
  echo "check: ok"; }

declare -A SEEN
harness() { # harness <scenario>: run repro/harness.py, keep its key=value observations in SEEN[]
  SEEN=(); local k v
  while IFS='=' read -r k v; do SEEN[$k]=$v; done < <(python3 "$HERE/harness.py" "$1" --out "$OUT/detail" 2>> "$OUT/run.log"; echo "__exit=$?")
  log "harness $1: $(( ${#SEEN[@]} - 1 )) observations (details in $OUT/detail)"
  [[ ${SEEN[__exit]} == 0 ]] || { log "harness $1 failed (exit ${SEEN[__exit]}), see run.log"; exit 1; }  # trap: verdict ERROR
  unset 'SEEN[__exit]'; }
expect_seen() { # stdin: "<key> <expected...>" lines (# comments allowed); compares each with SEEN[key]
  local k want; while read -r k want; do [[ -z $k || $k == \#* ]] && continue; expect "$k" "$want" "${SEEN[$k]:-missing}"; done; }

SCENARIOS=(unit headers errors precheck stopfailure proxy stored_login stored_login_proxy gateway live_login client_live managed keycloak)

describe_unit() { echo "unit: the client's offline tests (fake IdP and broker): settings edits, refresh, sentinel, device/PKCE sign-in, hooks, daemon. Changes: nothing. Under 1 min."; }
scenario_unit() {
  start unit
  local res; res=$(cd "$HERE/.." && python3 -m unittest client/test_aigw_claude_auth.py 2>&1); echo "$res" >> "$OUT/run.log"
  expect "client unit tests" "OK" "$(tail -1 <<< "$res" | awk '{print $1}')"
  expect "tests ran" "yes" "$(grep -qE '^Ran [1-9][0-9]* tests' <<< "$res" && echo yes || echo no)"
  finish; }

describe_headers() { echo "headers: install, then a running Claude Code session sends the Anthropic login in Authorization and the gateway JWT in x-portkey-api-key, and picks up a renewed JWT without a restart. Mock gateway. Changes: nothing. About 1 min."; }
scenario_headers() {
  start headers; harness headers
  expect_seen <<'EOF'
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
EOF
  finish; }

describe_errors() { echo "errors: how Claude Code (CLAUDE_CODE_OAUTH_TOKEN login) treats gateway 401, relayed Anthropic 401, 403, 407 and 498: attempts, speed, message, StopFailure error. Mock gateway. Changes: nothing. About 1 min."; }
scenario_errors() {
  start errors; harness errors
  expect_seen <<'EOF'
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
EOF
  finish; }

describe_precheck() { echo "precheck: the UserPromptSubmit hook renews an expired JWT before the request, does nothing while it is valid, blocks the prompt when no JWT can be had (also with a hanging IdP), offers a device code sign-in in the block message when signed out, and with block_on_failure off lets a load balancer guard answer 498. Mock gateway, fake IdP. Changes: nothing. About 3 min."; }
scenario_precheck() {
  start precheck; harness precheck
  expect_seen <<'EOF'
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
EOF
  finish; }

describe_stopfailure() { echo "stopfailure: after the gateway refuses a JWT that still looks valid, the StopFailure hook renews it and notifies, and the retry works; an Anthropic-side failure is left alone. Mock gateway, fake IdP. Changes: nothing. About 1 min."; }
scenario_stopfailure() {
  start stopfailure; harness stopfailure
  expect_seen <<'EOF'
baseline ok
refused_turn portkey
jwt_replaced yes
notified renewed
retry_turn ok
anthropic_turn anthropic
anthropic_jwt_kept yes
EOF
  finish; }

describe_proxy() { echo "proxy: Claude Code (CLAUDE_CODE_OAUTH_TOKEN login) through the real local proxy of the client (mode 2) in front of the mock gateway: the per-user secret header required and stripped, the gateway header injected and a client-supplied one stripped, a renewed token picked up, SSE passed through as it arrives, a refused JWT renewed and retried once, a gateway 401 turned into 498 (one attempt), an Anthropic 401 passed through, no token failing closed, the control channel; then which Unix socket base URLs Claude Code can use (spike S11). Mock gateway. Changes: nothing. About 3 min."; }
scenario_proxy() {
  start proxy; harness proxy
  expect_seen <<'EOF'
# a normal turn through the proxy
normal_result ok
normal_header_injected yes
normal_client_header_stripped yes
normal_authorization oauth
normal_beta_passed yes
normal_streamed yes
normal_secret_stripped yes
normal_proxy_logged_fingerprint yes
# a new JWT from the source (a renewal): the next request carries it
renewed_result ok
renewed_header_injected yes
# the gateway refuses the JWT in use and the source has a fresh one: the proxy renews and retries once, the turn succeeds
retry_result ok
retry_attempts 1
retry_upstream_requests 2
retry_first_try_refused_jwt yes
retry_second_try_fresh_jwt yes
retry_proxy_status 200
retry_proxy_note renewed-retry
# the gateway refuses the JWT (Portkey 401) and the source has nothing new: the proxy answers 498, so one attempt (direct 401: 2 attempts, finding 5)
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
# no usable token (the source gives nothing: file missing, empty, sentinel): 498 from the proxy, nothing sent upstream
notoken_missing_attempts 1
notoken_missing_upstream_requests 0
notoken_missing_proxy_status 498
notoken_missing_proxy_note no-token
notoken_missing_fast yes
notoken_missing_message gateway-token
notoken_missing_498_shown yes
notoken_missing_stopfailure_error unknown
notoken_empty_attempts 1
notoken_empty_upstream_requests 0
notoken_empty_proxy_status 498
notoken_empty_proxy_note no-token
notoken_empty_fast yes
notoken_empty_message gateway-token
notoken_empty_498_shown yes
notoken_empty_stopfailure_error unknown
notoken_sentinel_attempts 1
notoken_sentinel_upstream_requests 0
notoken_sentinel_proxy_status 498
notoken_sentinel_proxy_note no-token
notoken_sentinel_fast yes
notoken_sentinel_message gateway-token
notoken_sentinel_498_shown yes
notoken_sentinel_stopfailure_error unknown
recovery ok
# the per-user secret: without it or with a wrong one the proxy answers 498 and nothing reaches the gateway
secret_missing_status 498
secret_missing_leaks no
secret_wrong_status 498
secret_wrong_leaks no
secret_upstream_requests 0
# the control channel summarizes the JWT in memory, never the token, and needs the secret
control_inspect_status 200
control_inspect_token_absent yes
control_inspect_fingerprint yes
control_without_secret_status 498
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
EOF
  finish; }

describe_stored_login() { echo "stored_login: a stored \`claude login\` (LOGIN_CONFIG_DIR) against the mock gateway: 498 fails at once and leaves the login alone; a gateway 401 runs the OAuth refresh loop (about 4 min). Changes: rotates the stored login at Anthropic, swaps LOGIN_CONFIG_DIR/settings.json for the run (--yes). About 4 min."; }
scenario_stored_login() {
  need LOGIN_CONFIG_DIR; guard stored_login "rotates the stored login in LOGIN_CONFIG_DIR at Anthropic"
  start stored_login; harness stored-login
  expect_seen <<'EOF'
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
EOF
  finish; }

describe_stored_login_proxy() { echo "stored_login_proxy: a stored \`claude login\` (LOGIN_CONFIG_DIR) through the real local proxy of the client and the mock gateway: a refused JWT (gateway 401) becomes 498 at the proxy and fails in one attempt without the OAuth loop; no usable token fails the same way without reaching the gateway. Changes: rotates the stored login at Anthropic if the proxy did not work, swaps LOGIN_CONFIG_DIR/settings.json for the run (--yes). About 1 min."; }
scenario_stored_login_proxy() {
  need LOGIN_CONFIG_DIR; guard stored_login_proxy "may rotate the stored login in LOGIN_CONFIG_DIR at Anthropic, and swaps its settings.json for the run"
  start stored_login_proxy; harness stored-login-proxy
  expect_seen <<'EOF'
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
EOF
  finish; }

describe_gateway() { echo "gateway: the real gateway, request by request: missing, garbage and tampered JWTs and the sentinel are refused by the gateway (or the LB guard); a valid JWT, also with a Bearer prefix, reaches Anthropic with the caller's own login (passthrough). Changes: nothing (one model call on your plan if LOGIN_CONFIG_DIR is set). Under 1 min."; }
scenario_gateway() {
  need GATEWAY_URL
  start gateway; harness gateway
  local refused="401 portkey"; [[ ${LB_GUARD:-off} == on ]] && refused="498 gateway-token"
  expect_seen <<EOF
missing $refused
garbage 401 portkey
tampered 401 portkey
bearer_prefixed 401 anthropic
sentinel $refused
valid_bad_login 401 anthropic
valid_no_login 401 anthropic
lb_guard ${LB_GUARD:-off}
EOF
  [[ -n ${LOGIN_CONFIG_DIR:-} ]] && expect "valid_real_login" "200 reply" "${SEEN[valid_real_login]:-missing}"
  finish; }

describe_live_login() { echo "live_login: a stored \`claude login\` through the real gateway (via a local logging relay): a valid JWT works; a refused JWT costs the OAuth refresh loop (about 4 min); with LB_GUARD=on the sentinel and a missing header fail at once. Changes: rotates the stored login, swaps LOGIN_CONFIG_DIR/settings.json for the run (--yes). About 4 min."; }
scenario_live_login() {
  need LOGIN_CONFIG_DIR GATEWAY_URL; guard live_login "rotates the stored login in LOGIN_CONFIG_DIR at Anthropic"
  start live_login; harness live-login
  expect_seen <<'EOF'
ok_result ok
ok_attempts 1
ok_login_still_valid yes
tampered_result portkey
tampered_attempts many
tampered_statuses 401
tampered_long yes
tampered_login_rotated yes
tampered_login_still_valid yes
EOF
  if [[ ${LB_GUARD:-off} == on ]]; then expect_seen <<'EOF'
sentinel_result gateway-token
sentinel_attempts 1
sentinel_statuses 498
sentinel_long no
sentinel_login_rotated no
missing_result gateway-token
missing_attempts 1
missing_statuses 498
missing_login_rotated no
EOF
  fi
  finish; }

describe_client_live() { echo "client_live: the client end to end: JWT from your IdP (and broker), accepted by the gateway, installed into a stored-login Claude Code; the precheck hook replaces an expired JWT before the turn. Needs a prior \`aigw_claude_auth.py login\`. Changes: swaps LOGIN_CONFIG_DIR/settings.json for the run (--yes). About 1 min."; }
scenario_client_live() {
  need LOGIN_CONFIG_DIR GATEWAY_URL; guard client_live "swaps LOGIN_CONFIG_DIR/settings.json for the run"
  start client_live; harness client-live
  expect_seen <<'EOF'
signed_in yes
install_exit 0
sync_exit 0
gateway_accepts_jwt yes
turn_fresh ok
turn_after_expiry ok
turn_after_expiry_statuses 200
turn_after_expiry_fast yes
EOF
  finish; }

describe_managed() { echo "managed: the OS managed-settings file next to the user's settings.json: a managed ANTHROPIC_CUSTOM_HEADERS vs the user's JWT; hooks from managed settings with the JWT in the user file; allowManagedHooksOnly; a read-only or immutable settings.json; proxyAuthHelper; spike S4 (an unknown top-level key, AIGW_* in managed env, managed-settings.d/ drop-ins); doctor findings (what `doctor --json` reports per case, and that the precheck blocks on an Error). Mock gateway, fake IdP. Changes: writes /Library/Application Support/ClaudeCode/managed-settings.json (Linux: /etc/claude-code/) with sudo for a minute per case and removes it; refuses if a managed-settings file exists. Drop-in cases also write files in managed-settings.d/ (and remove them, and the directory if it created it). Other Claude Code sessions on the machine see each case's settings while it runs: close them first (--yes). About 12 min."; }
scenario_managed() {
  guard managed "writes the machine-wide managed-settings file while it runs"
  sudo -v || { echo "ERROR: managed needs sudo"; exit 2; }
  start managed
  ( while sleep 50; do sudo -n true || exit; done ) & on_exit "kill $! 2>/dev/null"   # keep sudo's timestamp fresh
  harness managed
  local immutable_exit=1 immutable_wrote=no immutable_turn=blocked immutable_doctor=settings-not-writable:Error
  [[ $(uname -s) == Darwin ]] || { immutable_exit=missing immutable_wrote=missing immutable_turn=missing immutable_doctor=missing; expect "immutable_skipped" "macos-only" "${SEEN[immutable_skipped]:-missing}"; }
  expect_seen <<EOF
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
# doctor (the preflight): what `doctor --json` reports for each case, in "id:Severity,..." form (server-managed Info left out)
none_doctor none
none_doctor_exit 0
headers_doctor managed-custom-headers:Error
headers_doctor_exit 1
fleet_doctor none
fleetreload_doctor none
hooksonly_doctor hooks-only-missing:Error
hooksonlymanaged_doctor none
readonly_doctor none
immutable_doctor $immutable_doctor
proxyauth_doctor none
# the preflight is on: the precheck blocks the prompt with the finding, nothing reaches the gateway
gateheaders_doctor managed-custom-headers:Error
gateheaders_turn1 blocked
gateheaders_block_message yes
gateheaders_turn1_jwt none
# a managed ANTHROPIC_BASE_URL that differs from the user's (and no allowedProviders)
baseurl_doctor allowed-providers:Info,base-url-mismatch:Error
baseurl_turn1 blocked
baseurl_block_message yes
# managed hooks without a timeout: a warning only; the hooks run and renew the expired JWT
hooknotimeout_doctor hook-no-timeout:Warning
hooknotimeout_turn1 ok
hooknotimeout_turn1_jwt renewed
# AIGW_ISSUER in managed env that differs from the helper config's issuer
envconf_doctor managed-config-conflict:Error
envconf_turn1 blocked
envconf_block_message yes
# a managed apiKeyHelper: a warning (what Claude Code sends then is not asserted)
apikeyhelper_doctor credential-override:Warning
# allowManagedHooksOnly with the hooks split over two managed-settings.d files: doctor merges them; user hooks don't run, the managed ones do
dropinhooks_doctor none
dropinhooks_user_hook_ran no
dropinhooks_turn1 ok
dropinhooks_turn1_jwt renewed
EOF
  finish; }

describe_keycloak() { echo "keycloak: the client against a local Keycloak 26 in Docker (127.0.0.1 only, realm aigw-test, dummy user with a password made up for the run): device code and PKCE sign-in with the user's side done over HTTP, Mode A claims straight from the IdP (protocol mappers, nested defaults, no broker), refresh and Revoke Refresh Token behavior, offline_access vs SSO session end, Claude Code sending the IdP's JWT to the mock gateway, and Mode B (the plain IdP token). Needs Docker (or KEYCLOAK_URL and KEYCLOAK_ADMIN_PASSWORD for a Keycloak already running); SKIP (docker) without. Changes: starts and removes one container. About 4 min."; }
scenario_keycloak() {
  start keycloak
  if [[ -z ${KEYCLOAK_URL:-} ]] && ! docker info >/dev/null 2>&1; then
    echo "SKIP keycloak: docker is not available (install/start Docker, or set KEYCLOAK_URL and KEYCLOAK_ADMIN_PASSWORD)"; finish "SKIP (docker)"; return; fi
  harness keycloak
  expect_seen <<'EOF'
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
EOF
  finish; }

# ---------------------------------------------------------------- dispatch (keep as is)
cmd=${1:-list}; shift || true; ARGS=("$@")
case $cmd in
  list)  for s in "${SCENARIOS[@]}"; do "describe_$s"; done ;;
  check) check ;;
  all)   for s in "${SCENARIOS[@]}"; do "scenario_$s"; done ;;
  *)     if declare -F "scenario_$cmd" >/dev/null; then "scenario_$cmd"; else sed -n '2,7p' "$0"; exit 2; fi ;;
esac
