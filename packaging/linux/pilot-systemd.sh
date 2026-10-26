#!/usr/bin/env bash
# Emulated Linux pilot: a real privileged install of the .deb or .rpm in a container running systemd as PID 1, two users
# "logging in" (systemd user managers), checks, uninstall, per-user purge. Local only: no sign-in, no gateway requests.
#   packaging/linux/pilot-systemd.sh --fleet <fleet.json> --pkg deb|rpm [--out DIR] [--keep]
# Needs Docker (privileged container: systemd needs cgroups). Builds packages and images into --out (default: a mktemp dir,
# never the repo tree); removes its container and image at the end unless --keep. Output never carries secrets: the
# x-aigw-local secret is compared by hash only, and only finding ids (not messages) are printed.
set -u
FLEET= PKG= OUT= KEEP=0 INSIDE=0
while [ $# -gt 0 ]; do
    case $1 in
        --fleet) FLEET=$2; shift 2 ;; --pkg) PKG=$2; shift 2 ;; --out) OUT=$2; shift 2 ;; --keep) KEEP=1; shift ;;
        --inside) INSIDE=1; shift ;; *) echo "unknown arg $1" >&2; exit 2 ;;
    esac
done

# ------------------------------------------------------------------------------------------ inside the container
if [ "$INSIDE" = 1 ]; then
    export DEBIAN_FRONTEND=noninteractive
    NAME=aigw-claude-auth
    DIR=/usr/lib/$NAME
    MANAGED=/etc/claude-code/managed-settings.d/50-$NAME.json
    UNIT=$NAME-fleet.service
    FAILS=0
    step() { echo; echo "== $*"; }
    ok() { echo "ok   $*"; }
    bad() { echo "FAIL $*"; FAILS=$((FAILS + 1)); }
    check() { local d=$1; shift; if "$@" >/dev/null 2>&1; then ok "$d"; else bad "$d"; fi; }
    MODE=$(python3 -c "import json;print(json.load(open('/fleet.json'))['mode'])")
    PORT=$(python3 -c "import json;print(json.load(open('/fleet.json'))['proxy_listen'])")
    uidof() { id -u "$1"; }
    asuser() { local u=$1; shift; runuser -u "$u" -- env XDG_RUNTIME_DIR=/run/user/"$(uidof "$u")" HOME=/home/"$u" "$@"; }
    uctl() { local u=$1; shift; asuser "$u" systemctl --user "$@"; }
    secret_of() {   # a hash of the x-aigw-local value in the user's settings.json, never the value
        python3 - "$1" <<'PY'
import hashlib, json, sys
d = json.load(open(f"/home/{sys.argv[1]}/.claude/settings.json"))
h = d.get("env", {}).get("ANTHROPIC_CUSTOM_HEADERS", "")
v = [l.split(":", 1)[1].strip() for l in h.splitlines() if l.lower().startswith("x-aigw-local")]
print(hashlib.sha256(v[0].encode()).hexdigest()[:12] + " len=" + str(len(v[0])) if v else "none")
PY
    }
    wait_active() { local u=$1; for _ in $(seq 1 25); do [ "$(uctl "$u" is-active $UNIT 2>/dev/null)" = active ] && return 0; sleep 1; done; return 1; }
    login() {   # emulate a login: a pam_systemd session via machinectl shell starts user@UID.service like a real login
        local u=$1
        # the session is held open (sleep): without one logind stops the user manager seconds after the last session ends
        machinectl shell "$u@.host" /bin/sleep 86400 >/dev/null 2>&1 &
        sleep 2
        if loginctl list-sessions --no-legend | grep -qw "$u"; then echo "login($u): machinectl shell (pam_systemd session, held open)"
        else echo "login($u): no session; falling back to linger + user@uid"; loginctl enable-linger "$u"; systemctl start "user@$(uidof "$u").service"; fi
        wait_active "$u"
    }
    ports() { ss -ltnp 2>/dev/null | grep ":${PORT##*:} " | sed 's/^/   /'; }

    step "system is up (systemd as PID 1)"
    echo "pid1: $(ps -o comm= -p 1) state: $(systemctl is-system-running 2>&1 | head -1)"

    step "1. privileged install of the $PKG"
    if [ "$PKG" = deb ]; then apt-get install -y -qq /pkg/*.deb >/dev/null 2>&1 || apt-get install -y /pkg/*.deb
    else dnf -q -y install /pkg/*.rpm >/dev/null 2>&1 || dnf -y install /pkg/*.rpm; fi
    for f in $DIR/aigw_claude_auth.py $DIR/aigw_launch.py $DIR/config.json $MANAGED /usr/lib/systemd/user/$UNIT; do check "file $f" test -f "$f"; done
    echo "owner/mode: $(stat -c '%U:%G %a' $DIR/aigw_claude_auth.py $DIR/config.json $MANAGED | tr '\n' ' ')"
    check "managed drop-in is valid JSON without ANTHROPIC_CUSTOM_HEADERS" python3 -c "import json;d=json.load(open('$MANAGED'));assert 'ANTHROPIC_CUSTOM_HEADERS' not in d.get('env',{})"
    echo "managed keys: $(python3 -c "import json;d=json.load(open('$MANAGED'));print(sorted(d), 'env:', sorted(d['env']))")"
    check "user unit globally enabled" test "$(systemctl --global is-enabled $UNIT)" = enabled
    python3 $DIR/aigw_claude_auth.py --version

    step "2. two users log in (mode: $MODE)"
    for u in pilot1 pilot2; do useradd -m -s /bin/bash $u; done
    for u in pilot1 pilot2; do login $u; done
    for u in pilot1 pilot2; do
        echo "-- $u"
        if [ "$MODE" = proxy ] && [ $u = pilot2 ]; then   # known limitation on shared hosts: one fixed loopback port; observed, not a failure
            [ "$(uctl $u is-active $UNIT 2>&1)" = active ] && echo "OBSERVED $u: $UNIT active" || echo "OBSERVED $u: $UNIT not active ($(uctl $u is-active $UNIT 2>&1)): the port is taken by pilot1's proxy"
        else check "$u: $UNIT active" test "$(uctl $u is-active $UNIT 2>&1)" = active; fi
        uctl $u status $UNIT --no-pager -n 12 2>&1 | cut -c1-200 | sed 's/^/   /'
        check "$u: settings.json written by first run" test -f /home/$u/.claude/settings.json
        python3 - $u "$MODE" <<'PY'
import json, sys
u, mode = sys.argv[1:3]
d = json.load(open(f"/home/{u}/.claude/settings.json"))
env = d.get("env", {})
hdr = env.get("ANTHROPIC_CUSTOM_HEADERS", "")
names = [l.split(":", 1)[0].strip().lower() for l in hdr.splitlines() if l.strip()]
print(f"   settings keys={sorted(d)} env keys={sorted(env)} header names={names} hooks_in_user_file={'hooks' in d}")
base = env.get("ANTHROPIC_BASE_URL", "")
if mode == "file":
    ok = names == ["x-portkey-api-key"] and "ANTHROPIC_BASE_URL" not in env and "hooks" not in d
else:
    ok = names == ["x-aigw-local"] and base.startswith("http://127.0.0.1") and "hooks" not in d
sys.exit(0 if ok else 1)
PY
        [ $? = 0 ] && ok "$u: settings content as expected for $MODE mode" || bad "$u: settings content not as expected for $MODE mode"
        asuser $u python3 $DIR/aigw_claude_auth.py --config $DIR/config.json doctor --json > /tmp/doctor-$u.json 2>/tmp/doctor-$u.err
        echo "   doctor exit=$?"
        python3 - $u <<'PY'
import json, sys
d = json.load(open(f"/tmp/doctor-{sys.argv[1]}.json"))
print(f"   doctor: version={d['version']} errors={d['errors']} warnings={d['warnings']} managed_source={d['sources']['managed']['winning_source']}")
print("   findings:", [(f["severity"], f["id"]) for f in d["findings"]])
sys.exit(1 if d["errors"] else 0)
PY
        if [ $? = 0 ]; then ok "$u: doctor has no Error findings"
        elif [ "$MODE" = proxy ] && [ $u = pilot2 ]; then echo "OBSERVED $u: doctor Error (expected while another user's proxy owns the port)"
        else bad "$u: doctor has Error findings"; fi
    done

    if [ "$MODE" = proxy ]; then
        step "2b. proxy mode: secrets and the shared loopback port ($PORT)"
        s1=$(secret_of pilot1); s2=$(secret_of pilot2)
        echo "secret hash pilot1: $s1 | pilot2: $s2"
        [ "$s1" != "$s2" ] && [ "$s1" != none ] && ok "different secrets per user" || bad "secrets not different"
        echo "listeners on :${PORT##*:}:"; ports
        for u in pilot1 pilot2; do
            echo "-- $u proxy: unit=$(uctl $u is-active $UNIT 2>&1) NRestarts=$(uctl $u show $UNIT -p NRestarts --value 2>&1) Result=$(uctl $u show $UNIT -p Result --value 2>&1)"
            ps -u $u -o pid,etime,args | grep -E 'aigw_launch|aigw_claude_auth' | grep -v grep | cut -c1-150 | sed 's/^/   proc: /'
            journalctl _SYSTEMD_USER_UNIT=$UNIT _UID="$(uidof $u)" --no-pager -o cat -n 8 2>&1 | cut -c1-220 | sed 's/^/   log: /'
        done
        echo "-- pilot2 after 25 s (RestartSec in the unit: $(grep -h '^Restart' /usr/lib/systemd/user/$UNIT | tr '\n' ' '))"
        sleep 25
        echo "   pilot2 unit=$(uctl pilot2 is-active $UNIT 2>&1) NRestarts=$(uctl pilot2 show $UNIT -p NRestarts --value 2>&1); owner of the port: $(ss -ltnp | grep ":${PORT##*:} " | grep -o 'pid=[0-9]*') (pilot1 pid $(uctl pilot1 show $UNIT -p MainPID --value))"
        echo "-- who answers on the port (a request without credentials to the local proxy only)"
        asuser pilot2 python3 - "$PORT" <<'PY'
import http.client, sys
h, p = sys.argv[1].split(":")
try:
    c = http.client.HTTPConnection(h, int(p), timeout=5); c.request("GET", "/__probe"); r = c.getresponse()
    print("   GET with no secret -> HTTP", r.status, "body bytes", len(r.read()))
except Exception as e:
    print("   probe error:", type(e).__name__, e)
PY
    fi

    step "2c. second login: restart each user manager"
    declare -A before
    for u in pilot1 pilot2; do before[$u]=$(secret_of $u); done
    for u in pilot1 pilot2; do systemctl restart user@"$(uidof $u)".service; done
    for u in pilot1 pilot2; do
        wait_active $u || true
        after=$(secret_of $u); echo "$u unit=$(uctl $u is-active $UNIT 2>&1) secret before=${before[$u]} after=$after"
        [ "${before[$u]}" = "$after" ] && ok "$u: settings stable across a second login" || bad "$u: settings changed across login"
    done
    if [ "$MODE" = proxy ]; then
        echo "listeners:"; ports
        for u in pilot1 pilot2; do echo "-- $u: $(uctl $u is-active $UNIT 2>&1)"; journalctl _SYSTEMD_USER_UNIT=$UNIT _UID="$(uidof $u)" --no-pager -o cat -n 6 2>&1 | cut -c1-220 | sed 's/^/   log: /'; done
    fi

    step "3. per-user files before purge"
    for u in pilot1 pilot2; do echo "-- $u"; (cd /home/$u && find .claude .config .local -type f 2>/dev/null | sort | sed 's/^/   /'); done

    step "4. purge pilot2 (before removal, as the README says), remove the package, then try pilot1 after removal"
    asuser pilot2 python3 $DIR/aigw_launch.py purge-user 2>&1 | cut -c1-200 | sed 's/^/   /'
    echo "pilot2 files after purge:"; (cd /home/pilot2 && find .claude .config -type f 2>/dev/null | sort | sed 's/^/   /')
    echo "pilot2 unit right after purge: $(uctl pilot2 is-active $UNIT 2>&1)"
    sleep 3
    echo "pilot2 files 3 s later:"; (cd /home/pilot2 && find .claude .config -type f 2>/dev/null | sort | sed 's/^/   /')
    if [ "$PKG" = deb ]; then apt-get remove -y -qq $NAME >/dev/null 2>&1; else dnf -q -y remove $NAME >/dev/null 2>&1; fi
    for f in $DIR $MANAGED /usr/lib/systemd/user/$UNIT /etc/systemd/user/default.target.wants/$UNIT; do check "gone after remove: $f" test ! -e "$f"; done
    echo "managed-settings.d entries: $(ls -A /etc/claude-code/managed-settings.d 2>/dev/null | wc -l); /etc/claude-code exists: $([ -d /etc/claude-code ] && echo yes || echo no)"
    echo "leftover system dirs: $(find /etc/claude-code /usr/lib/$NAME 2>/dev/null | tr '\n' ' ')"
    echo "pilot1 unit after remove (daemon still running?): $(uctl pilot1 is-active $UNIT 2>&1)"
    echo "pilot1: purge after the package is removed:"
    asuser pilot1 python3 $DIR/aigw_launch.py purge-user 2>&1 | tail -2 | cut -c1-200 | sed 's/^/   /'
    echo "pilot1 files left:"; (cd /home/pilot1 && find .claude .config -type f 2>/dev/null | sort | sed 's/^/   /')
    python3 - <<'PY'
import json
d = json.load(open("/home/pilot1/.claude/settings.json"))
print("   pilot1 settings.json env keys left:", sorted(d.get("env", {})))
PY
    echo; echo "RESULT $PKG/$MODE: failures=$FAILS"
    [ $FAILS = 0 ]; exit $?
fi

# ------------------------------------------------------------------------------------------------------ on the host
[ -f "$FLEET" ] && [ -n "$PKG" ] || { echo "usage: $0 --fleet <fleet.json> --pkg deb|rpm [--out DIR] [--keep]" >&2; exit 2; }
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
FLEET=$(cd "$(dirname "$FLEET")" && pwd)/$(basename "$FLEET")
OUT=${OUT:-$(mktemp -d "${TMPDIR:-/tmp}/aigw-pilot.XXXXXX")}; mkdir -p "$OUT"
MODE=$(python3 -c "import json,sys;print(json.load(open(sys.argv[1]))['mode'])" "$FLEET")
TAG=aigw-pilot-$PKG-$MODE-$$; IMG=$TAG; CTR=$TAG
cleanup() {
    if [ "$KEEP" = 1 ]; then echo "kept container $CTR and image $IMG"; return; fi
    docker rm -f "$CTR" >/dev/null 2>&1; docker rmi -f "$IMG" >/dev/null 2>&1; echo "removed container $CTR and image $IMG"
}
trap cleanup EXIT
PKGDIR=$OUT/pkg-$PKG-$MODE; mkdir -p "$PKGDIR"
python3 "$ROOT/packaging/build.py" linux --fleet "$FLEET" --out "$PKGDIR" $([ "$PKG" = rpm ] && echo --rpm) >/dev/null 2>"$OUT/build-$PKG-$MODE.log" \
    || { echo "build failed, see $OUT/build-$PKG-$MODE.log"; exit 1; }
if [ "$PKG" = deb ]; then
    find "$PKGDIR" -maxdepth 1 -name '*.rpm' -delete
    docker build -q -t "$IMG" - >/dev/null <<'DF'
FROM debian:12
ENV DEBIAN_FRONTEND=noninteractive container=docker
RUN apt-get update -qq && apt-get install -y -qq systemd systemd-sysv systemd-container dbus dbus-user-session python3 iproute2 procps >/dev/null
STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
DF
else
    find "$PKGDIR" -maxdepth 1 -name '*.deb' -delete
    docker build -q -t "$IMG" - >/dev/null <<'DF'
FROM rockylinux:9
ENV container=docker
RUN dnf -q -y install systemd systemd-container dbus-daemon python3 iproute procps-ng util-linux >/dev/null
STOPSIGNAL SIGRTMIN+3
CMD ["/usr/sbin/init"]
DF
fi
docker run -d --name "$CTR" --privileged --cgroupns=host --tmpfs /run --tmpfs /run/lock --tmpfs /tmp "$IMG" >/dev/null || exit 1
docker exec "$CTR" mkdir -p /pkg
docker cp "$PKGDIR/." "$CTR:/pkg/" && docker cp "$FLEET" "$CTR:/fleet.json" && docker cp "$0" "$CTR:/pilot.sh"
for _ in $(seq 1 30); do docker exec "$CTR" systemctl is-system-running 2>/dev/null | grep -qE 'running|degraded' && break; sleep 1; done
docker exec "$CTR" bash /pilot.sh --inside --pkg "$PKG" 2>&1 | tee "$OUT/run-$PKG-$MODE.log"
rc=${PIPESTATUS[0]}
echo "verdict $PKG/$MODE: $([ "$rc" = 0 ] && echo PASS || echo FAIL) (log: $OUT/run-$PKG-$MODE.log)"
exit "$rc"
