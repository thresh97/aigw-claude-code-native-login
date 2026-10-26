#!/bin/sh
# Runs INSIDE a throwaway rockylinux:9 container (never on a host): install the .rpm, check, remove, check.
set -eu
fail() { echo "FAIL: $*"; exit 1; }
DIR=/usr/lib/aigw-claude-auth
MANAGED=/etc/claude-code/managed-settings.d/50-aigw-claude-auth.json
UNIT=aigw-claude-auth-fleet.service
dnf -q -y install python3 /pkg/*.rpm >/dev/null 2>&1 || dnf -y install python3 /pkg/*.rpm
for f in $DIR/aigw_claude_auth.py $DIR/aigw_launch.py $DIR/config.json $MANAGED /usr/lib/systemd/user/$UNIT; do
    [ -f "$f" ] || fail "missing $f"; echo "ok $f"
done
[ -L /etc/systemd/user/default.target.wants/$UNIT ] || fail "unit not enabled globally"
echo "ok unit enabled (symlink in /etc/systemd/user/default.target.wants)"
python3 $DIR/aigw_claude_auth.py --version
python3 $DIR/aigw_claude_auth.py --config $DIR/config.json doctor --json | python3 -c "import json,sys;d=json.load(sys.stdin);print('doctor errors',d['errors'],'warnings',d['warnings'])"
rpm -V aigw-claude-auth && echo "rpm -V clean"
dnf -q -y remove aigw-claude-auth >/dev/null 2>&1
for f in $DIR $MANAGED /usr/lib/systemd/user/$UNIT /etc/systemd/user/default.target.wants/$UNIT; do
    [ ! -e "$f" ] || fail "still present: $f"
done
echo "ok: removed, enable symlink gone"
echo "ALL OK"
