#!/bin/sh
# Runs INSIDE a throwaway debian:12 container (never on a host): install the .deb, check, run as a user, remove, check.
#   docker run --rm -v <dir with the .deb>:/pkg:ro debian:12 sh /pkg/container-test-deb.sh   (copied there by the caller)
set -eu
export DEBIAN_FRONTEND=noninteractive
step() { echo "== $*"; }
fail() { echo "FAIL: $*"; exit 1; }
DIR=/usr/lib/aigw-claude-auth
MANAGED=/etc/claude-code/managed-settings.d/50-aigw-claude-auth.json
UNIT=aigw-claude-auth-fleet.service

step "install"
apt-get update -qq >/dev/null
apt-get install -y -qq systemd /pkg/*.deb >/dev/null 2>&1 || apt-get install -y /pkg/*.deb
for f in $DIR/aigw_claude_auth.py $DIR/aigw_launch.py $DIR/config.json $MANAGED /usr/lib/systemd/user/$UNIT; do
    [ -f "$f" ] || fail "missing $f"; echo "ok $f"
done
[ -L /etc/systemd/user/default.target.wants/$UNIT ] || fail "unit not enabled globally"
echo "ok unit enabled: $(systemctl --global is-enabled $UNIT)"
echo "stat: $(stat -c '%U:%G %a' $DIR/aigw_claude_auth.py $MANAGED)"

step "client runs"
python3 $DIR/aigw_claude_auth.py --version
python3 -c "import json;d=json.load(open('$MANAGED'));assert 'ANTHROPIC_CUSTOM_HEADERS' not in d['env'];print('managed keys:',sorted(d),'env keys:',sorted(d['env']))"

step "doctor --json as a fresh user (reads the managed drop-in)"
useradd -m tester
su tester -c "python3 $DIR/aigw_claude_auth.py --config $DIR/config.json doctor --json" > /tmp/doctor.json || true
python3 - <<'PY'
import json
d = json.load(open("/tmp/doctor.json"))
print("version", d["version"], "errors", d["errors"], "warnings", d["warnings"], "managed source:", d["sources"]["managed"]["winning_source"])
print("findings:", [(f["severity"], f["id"]) for f in d["findings"]])
PY

step "first run for the user (launcher: install --no-hooks, then the daemon; stopped after 6 s)"
su tester -c "timeout 6 python3 $DIR/aigw_launch.py daemon" 2>&1 | sed 's/^/  /' || true
S=/home/tester/.claude/settings.json
[ -f "$S" ] || fail "no per-user settings written"
python3 -c "
import json;d=json.load(open('$S'))
print('user settings keys:', sorted(d), 'env keys:', sorted(d.get('env',{})), 'hooks in user file:', 'hooks' in d)
assert 'hooks' not in d"

step "remove"
apt-get remove -y -qq aigw-claude-auth >/dev/null 2>&1
for f in $DIR $MANAGED /usr/lib/systemd/user/$UNIT /etc/systemd/user/default.target.wants/$UNIT; do
    [ ! -e "$f" ] || fail "still present: $f"
done
echo "ok: package files and the global enable symlink are gone"
[ -d /etc/claude-code ] && echo "note: /etc/claude-code/managed-settings.d left: $(ls -A /etc/claude-code/managed-settings.d | wc -l) entries"
echo "ALL OK"
