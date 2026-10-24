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

SCENARIOS=(unit headers errors precheck stopfailure stored_login gateway live_login client_live)

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

# ---------------------------------------------------------------- dispatch (keep as is)
cmd=${1:-list}; shift || true; ARGS=("$@")
case $cmd in
  list)  for s in "${SCENARIOS[@]}"; do "describe_$s"; done ;;
  check) check ;;
  all)   for s in "${SCENARIOS[@]}"; do "scenario_$s"; done ;;
  *)     if declare -F "scenario_$cmd" >/dev/null; then "scenario_$cmd"; else sed -n '2,7p' "$0"; exit 2; fi ;;
esac
