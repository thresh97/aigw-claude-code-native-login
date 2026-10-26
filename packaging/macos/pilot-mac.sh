#!/bin/bash
# Emulated pilot on this Mac: a real privileged install of the fleet .pkg, checks for the console user and an optional
# second local user (logged in by hand with fast user switching), then uninstall and restore. A person runs this, from a
# terminal that is not a Claude Code session: the managed drop-in reroutes every Claude Code on the machine.
#
#   pilot-mac.sh install <fleet.json> [--with-user]   build + `sudo installer`; sets a personal install aside first;
#                                                     --with-user also creates the standard user `aigwpilot`
#   pilot-mac.sh check                                checks for the console user and aigwpilot (if logged in)
#   pilot-mac.sh uninstall                            purge the users the pilot touched, uninstall, delete aigwpilot,
#                                                     restore the personal install
#
# Work dir, backups and logs: ~/.aigw-pilot (AIGW_PILOT_DIR). Never prints tokens or the proxy secret (hashes only).
# bash 3.2 (macOS /bin/bash).
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
W="${AIGW_PILOT_DIR:-$HOME/.aigw-pilot}"
STATE="$W/state"
LIBEXEC=/usr/local/libexec/aigw-claude-auth
MANAGED_DIR="/Library/Application Support/ClaudeCode"
PILOT_USER=aigwpilot
IDENTIFIER=org.aigw.claude-auth
PERSONAL_PLIST="$HOME/Library/LaunchAgents/aigw-claude-auth.plist"
PERSONAL_LABEL=aigw-claude-auth
PERSONAL_DIR="$HOME/.config/aigw-claude-auth"

say() { printf '%s\n' "$*"; }
step() { printf '\n== %s\n' "$*"; }
die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
ok() { printf '  ok    %s\n' "$*"; }
bad() { printf '  FAIL  %s\n' "$*"; FAILS=$((FAILS + 1)); }
FAILS=0

load_state() { [ -f "$STATE" ] || die "no pilot state in $STATE (run install first)"; . "$STATE"; }

json_field() { /usr/bin/python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get(sys.argv[2], ""))' "$@"; }

# ---------------------------------------------------------------------------------------------------------- install
cmd_install() {
    local fleet="${1:-}" with_user=0
    [ -n "$fleet" ] && [ -f "$fleet" ] || die "usage: pilot-mac.sh install <fleet.json> [--with-user]"
    [ "${2:-}" = "--with-user" ] && with_user=1
    [ -n "${CLAUDECODE:-}" ] && die "this is a Claude Code session; quit it and run from a plain terminal"
    [ -f "$STATE" ] && die "a pilot is already installed ($STATE); run uninstall first"
    [ -e "$MANAGED_DIR/managed-settings.json" ] && die "$MANAGED_DIR/managed-settings.json exists; not touching it"
    [ -d "$LIBEXEC" ] && die "$LIBEXEC exists already"
    /usr/sbin/pkgutil --pkg-info "$IDENTIFIER" >/dev/null 2>&1 && die "package $IDENTIFIER is installed already"
    local name mode
    name="$(json_field "$fleet" name)"; mode="$(json_field "$fleet" mode)"
    mkdir -p "$W" && chmod 700 "$W"

    step "build"
    rm -rf "$W/dist"
    /usr/bin/python3 "$REPO/packaging/build.py" macos --fleet "$fleet" --out "$W/dist" >"$W/build.log" 2>&1 || { cat "$W/build.log"; die "build failed"; }
    local pkg; pkg="$(ls "$W"/dist/*.pkg | head -1)"
    ok "built $(basename "$pkg")"

    step "set the personal install aside"
    local backup="$W/personal-backup"
    mkdir -p "$backup"
    cp -p "$HOME/.claude/settings.json" "$backup/settings.json" 2>/dev/null && ok "copied ~/.claude/settings.json"
    if [ -f "$PERSONAL_PLIST" ]; then
        /bin/launchctl bootout "gui/$(id -u)/$PERSONAL_LABEL" >/dev/null 2>&1
        ok "stopped the personal LaunchAgent $PERSONAL_LABEL (plist left in place)"
    fi
    if [ -d "$PERSONAL_DIR" ]; then
        mv "$PERSONAL_DIR" "$backup/config" && ok "moved $PERSONAL_DIR aside"
    fi
    cat >"$STATE" <<EOF
NAME='$name'
MODE='$mode'
LABEL='$name.fleet'
BACKUP='$backup'
PILOT_CREATED=0
EOF

    step "sudo installer (asks for your password)"
    sudo /usr/sbin/installer -pkg "$pkg" -target / || die "installer failed"
    ok "installed"

    if [ "$with_user" = 1 ]; then
        step "create the standard user $PILOT_USER"
        if id "$PILOT_USER" >/dev/null 2>&1; then
            say "  $PILOT_USER exists already; not creating it (and uninstall won't delete it)"
        else
            local pw; pw="$(LC_ALL=C tr -dc 'A-Za-z0-9' </dev/urandom | head -c 16)"
            sudo /usr/sbin/sysadminctl -addUser "$PILOT_USER" -fullName "aigw pilot" -password "$pw" >/dev/null 2>&1 \
                || die "sysadminctl -addUser failed"
            sed -i '' 's/^PILOT_CREATED=0$/PILOT_CREATED=1/' "$STATE"
            say "  created $PILOT_USER; its password (shown once, not stored): $pw"
            say "  log in as $PILOT_USER with fast user switching, wait for the desktop, switch back, then run: $0 check"
        fi
    fi
    step "checks"
    cmd_check
}

# ------------------------------------------------------------------------------------------------------------ check
user_report() {   # user: background agent, settings.json, doctor
    local u="$1" uid; uid="$(id -u "$u")"
    say "  -- $u (uid $uid)"
    local st; st="$(sudo /bin/launchctl print "gui/$uid/$LABEL" 2>/dev/null | awk -F' = ' '/^\tstate = /{s=$2} /^\tpid = /{p=$2} END{print s" "p}')"
    case "$st" in running*) ok "LaunchAgent $LABEL running (pid ${st#running })" ;; " ") bad "LaunchAgent $LABEL not loaded in gui/$uid" ;; *) bad "LaunchAgent $LABEL state: $st" ;; esac
    sudo -u "$u" -H /usr/bin/python3 - "$MODE" <<'PY'
import hashlib, json, os, sys
mode = sys.argv[1]
p = os.path.expanduser("~/.claude/settings.json")
try:
    s = json.load(open(p))
except Exception as e:
    print(f"  FAIL  settings.json: {type(e).__name__}"); sys.exit()
env = s.get("env") or {}
lines = dict(l.split(":", 1) for l in (env.get("ANTHROPIC_CUSTOM_HEADERS") or "").splitlines() if ":" in l)
lines = {k.strip().lower(): v.strip() for k, v in lines.items()}
fp = lambda v: f"len {len(v)} sha256 {hashlib.sha256(v.encode()).hexdigest()[:10]}"
print(f"  info  settings.json header names: {sorted(lines)}; ANTHROPIC_BASE_URL: {env.get('ANTHROPIC_BASE_URL', '(none)')}")
pk, local = lines.get("x-portkey-api-key"), lines.get("x-aigw-local")
if mode == "proxy":
    print(f"  {'ok   ' if local else 'FAIL '} x-aigw-local secret {fp(local) if local else 'missing'}")
    print(f"  {'ok   ' if not pk else 'FAIL '} no JWT line" + ("" if not pk else f" ({fp(pk)})"))
else:
    kind = "sentinel" if pk == "expired" else ("JWT" if pk and pk.count(".") == 2 else "missing" if not pk else "other")
    print(f"  {'ok   ' if pk else 'FAIL '} x-portkey-api-key: {kind}" + (f" ({fp(pk)})" if pk else ""))
PY
    sudo -u "$u" -H /usr/bin/python3 "$LIBEXEC/aigw_claude_auth.py" --config "$LIBEXEC/config.json" doctor --json 2>/dev/null \
        | /usr/bin/python3 -c '
import json, sys
try:
    r = json.load(sys.stdin)
except Exception:
    print("  FAIL  doctor --json gave no JSON"); sys.exit()
fs = r.get("findings", [])
err = [f["id"] for f in fs if f["severity"] == "Error"]
print(("  FAIL  doctor errors: %s" % err) if err else "  ok    doctor: no errors")
for f in fs:
    if f["severity"] != "Error":
        print("  info  doctor [%s] %s" % (f["severity"], f["id"]))'
    local log; log="$(eval echo "~$u")/Library/Logs/aigw-claude-auth.log"
    sudo test -f "$log" && { say "  info  last lines of $log:"; sudo tail -4 "$log" | sed 's/^/          /'; }
}

cmd_check() {
    load_state
    local u
    step "machine"
    [ -f "$LIBEXEC/aigw_claude_auth.py" ] && ok "client in $LIBEXEC" || bad "client missing in $LIBEXEC"
    local drop="$MANAGED_DIR/managed-settings.d/50-$NAME.json"
    if /usr/bin/python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); sys.exit("ANTHROPIC_CUSTOM_HEADERS" in d.get("env", {}))' "$drop" 2>/dev/null; then
        ok "drop-in $drop is valid JSON, no ANTHROPIC_CUSTOM_HEADERS"
    else
        bad "drop-in $drop missing, invalid, or sets ANTHROPIC_CUSTOM_HEADERS"
    fi
    [ -e "$MANAGED_DIR/managed-settings.json" ] && bad "managed-settings.json exists" || ok "no managed-settings.json"
    /usr/bin/plutil -lint "/Library/LaunchAgents/$LABEL.plist" >/dev/null 2>&1 && ok "plist /Library/LaunchAgents/$LABEL.plist lints" || bad "plist missing or invalid"
    /usr/sbin/pkgutil --pkg-info "$IDENTIFIER" >/dev/null 2>&1 && ok "receipt $IDENTIFIER" || bad "no receipt $IDENTIFIER"
    if [ "$MODE" = proxy ]; then
        say "  info  listeners on the proxy port:"
        local port; port="$(/usr/bin/python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("proxy_listen","127.0.0.1:18787").rsplit(":",1)[1])' "$LIBEXEC/config.json")"
        sudo /usr/sbin/lsof -nP -iTCP:"$port" -sTCP:LISTEN 2>/dev/null | awk 'NR>1{print "          "$1" pid "$2" user "$3" "$9}'
    fi
    step "users"
    for u in "$(stat -f%Su /dev/console)" "$PILOT_USER"; do
        id "$u" >/dev/null 2>&1 || continue
        if [ "$u" = "$PILOT_USER" ] && ! who | awk '{print $1}' | grep -qx "$PILOT_USER"; then
            say "  -- $u: not logged in (log in with fast user switching, then check again)"; continue
        fi
        user_report "$u"
    done
    step "result: $FAILS failure(s)"
}

# -------------------------------------------------------------------------------------------------------- uninstall
cmd_uninstall() {
    load_state
    [ -n "${CLAUDECODE:-}" ] && die "this is a Claude Code session; quit it and run from a plain terminal"
    local u touched="$(id -un)"
    id "$PILOT_USER" >/dev/null 2>&1 && touched="$touched $PILOT_USER"
    step "purge the users the pilot touched ($touched), not every account"
    for u in $touched; do
        [ -f "$LIBEXEC/aigw_launch.py" ] && sudo -u "$u" -H /usr/bin/python3 "$LIBEXEC/aigw_launch.py" purge-user 2>&1 | tail -1 | sed 's/^/  /'
    done
    step "uninstall.sh (without --purge-users)"
    [ -x "$LIBEXEC/uninstall.sh" ] && sudo "$LIBEXEC/uninstall.sh" | sed 's/^/  /'
    [ -e "$LIBEXEC" ] && bad "$LIBEXEC still there" || ok "$LIBEXEC gone"
    [ -e "$MANAGED_DIR/managed-settings.d/50-$NAME.json" ] && bad "drop-in still there" || ok "drop-in gone"
    [ -e "/Library/LaunchAgents/$LABEL.plist" ] && bad "plist still there" || ok "plist gone"
    /usr/sbin/pkgutil --pkg-info "$IDENTIFIER" >/dev/null 2>&1 && bad "receipt still there" || ok "receipt gone"
    sudo /bin/launchctl print "gui/$(id -u)/$LABEL" >/dev/null 2>&1 && bad "agent still loaded for $(id -un)" || ok "agent not loaded for $(id -un)"
    security find-generic-password -s aigw-claude-auth >/dev/null 2>&1 && bad "a Keychain item for service aigw-claude-auth is left" || ok "no Keychain item left"
    if [ "$PILOT_CREATED" = 1 ] && id "$PILOT_USER" >/dev/null 2>&1; then
        step "delete $PILOT_USER"
        if who | awk '{print $1}' | grep -qx "$PILOT_USER"; then
            bad "$PILOT_USER is still logged in; log it out (Apple menu > Log Out, as $PILOT_USER) and run uninstall again"
            step "result: $FAILS failure(s)"; return 1
        fi
        sudo /usr/sbin/sysadminctl -deleteUser "$PILOT_USER" >/dev/null 2>&1 && ok "deleted $PILOT_USER and its home" || bad "sysadminctl -deleteUser failed"
    fi
    step "restore the personal install"
    if [ -d "$BACKUP/config" ]; then
        rm -rf "$PERSONAL_DIR" && mv "$BACKUP/config" "$PERSONAL_DIR" && ok "restored $PERSONAL_DIR"
    fi
    [ -f "$BACKUP/settings.json" ] && cp -p "$BACKUP/settings.json" "$HOME/.claude/settings.json" && ok "restored ~/.claude/settings.json"
    if [ -f "$PERSONAL_PLIST" ]; then
        /bin/launchctl bootstrap "gui/$(id -u)" "$PERSONAL_PLIST" >/dev/null 2>&1 && ok "restarted $PERSONAL_LABEL" || bad "could not restart $PERSONAL_LABEL"
    fi
    step "result: $FAILS failure(s)"
    [ "$FAILS" = 0 ] && rm -f "$STATE" && rm -rf "$BACKUP" && say "pilot state removed; build output and logs stay in $W"
}

case "${1:-}" in
    install) shift; cmd_install "$@" ;;
    check) cmd_check ;;
    uninstall) cmd_uninstall ;;
    *) sed -n '2,13p' "$0" | sed 's/^# \{0,1\}//'; exit 2 ;;
esac
