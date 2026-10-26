#!/usr/bin/env bash
# Linux smoke test of proxy mode on the latest Ubuntu LTS with systemd as PID 1. Local only: a fake JWT from token_command,
# a mock gateway inside the container, no IdP, no real gateway, no secrets. Needs Docker (a privileged container: systemd
# needs cgroups). Builds an image and a container and removes both at the end unless --keep.
#   packaging/linux/smoke-proxy-systemd.sh --client client/aigw_claude_auth.py [--keep]
# Checks: install in proxy mode writes and starts the systemd user unit; status shows the email claim and the JWKS rows;
# a request through the proxy reaches the gateway with the JWT injected and the local secret stripped; `requests` lists it
# with credentials partly masked; systemd restarts the proxy after a kill; a second install is harmless; teardown.
set -u
CLIENT= KEEP=0 INSIDE=0
while [ $# -gt 0 ]; do
    case $1 in --client) CLIENT=$2; shift 2 ;; --keep) KEEP=1; shift ;; --inside) INSIDE=1; shift ;; *) echo "unknown arg $1" >&2; exit 2 ;; esac
done

if [ "$INSIDE" = 1 ]; then
    FAILS=0
    step() { echo; echo "== $*"; }
    ok() { echo "ok   $*"; }
    bad() { echo "FAIL $*"; FAILS=$((FAILS + 1)); }
    check() { local d=$1; shift; if "$@" >/dev/null 2>&1; then ok "$d"; else bad "$d"; fi; }
    U=dev
    BIN=/home/$U/.local/bin/aigw-claude-auth
    useradd -m -s /bin/bash $U
    UIDN=$(id -u $U)
    asuser() { runuser -u $U -- env XDG_RUNTIME_DIR=/run/user/$UIDN HOME=/home/$U DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/$UIDN/bus "$@"; }
    uctl() { asuser systemctl --user "$@"; }
    cli() { asuser python3 $BIN "$@"; }

    step "system"
    . /etc/os-release; echo "$PRETTY_NAME, $(python3 -V), $(uname -m), pid1 $(ps -o comm= -p 1), $(systemctl is-system-running 2>&1 | head -1)"

    step "login (a pam_systemd session, held open, starts the user manager)"
    machinectl shell "$U@.host" /bin/sleep 86400 >/dev/null 2>&1 &
    sleep 3
    loginctl list-sessions --no-legend | grep -qw $U || { echo "no session: linger + user@uid"; loginctl enable-linger $U; systemctl start "user@$UIDN.service"; }
    for _ in $(seq 1 20); do uctl is-system-running 2>/dev/null | grep -qE 'running|degraded' && break; sleep 1; done
    echo "user manager: $(uctl is-system-running 2>&1 | head -1)"

    step "set up: client, fake JWT source, mock gateway"
    asuser mkdir -p /home/$U/.local/bin /home/$U/.config/aigw-claude-auth /home/$U/.claude      # as the user: install -d would make the parents root-owned
    install -o $U -g $U -m 755 /smoke/aigw_claude_auth.py $BIN
    cat > /home/$U/mkjwt.py <<'PY'
import base64, json, time
b = lambda o: base64.urlsafe_b64encode(json.dumps(o).encode()).decode().rstrip("=")
print(f"{b({'alg': 'RS256', 'kid': 'smoke-kid', 'typ': 'JWT'})}.{b({'sub': 'smoke-user', 'email_id': 'smoke@example.com', 'portkey_workspace': 'ws-smoke', 'exp': int(time.time()) + 3600})}.c2ln")
PY
    cat > /home/$U/gw.py <<'PY'
import hashlib, http.server, json
class H(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        self.rfile.read(int(self.headers.get("Content-Length") or 0))
        pk = self.headers.get("x-portkey-api-key") or ""
        with open("/tmp/gw.log", "a") as f:
            f.write(json.dumps({"portkey_len": len(pk), "portkey_sha": hashlib.sha256(pk.encode()).hexdigest()[:10],
                                "has_local_secret": "x-aigw-local" in {k.lower() for k in self.headers},
                                "bearer_forwarded": (self.headers.get("Authorization") or "").startswith("Bearer ")}) + "\n")
        body = b'{"ok":true}'
        self.send_response(200); self.send_header("Content-Type", "application/json"); self.send_header("Content-Length", str(len(body))); self.send_header("request-id", "req_smoke"); self.end_headers(); self.wfile.write(body)
    def log_message(self, *a): pass
http.server.ThreadingHTTPServer(("127.0.0.1", 19099), H).serve_forever()
PY
    chown $U:$U /home/$U/mkjwt.py /home/$U/gw.py
    cat > /home/$U/.config/aigw-claude-auth/config.json <<EOF
{"token_command": "python3 /home/$U/mkjwt.py", "mode": "proxy", "gateway_url": "http://127.0.0.1:19099", "proxy_listen": "127.0.0.1:18787",
 "hook_login": "off", "notify": "off", "secret_store": "file"}
EOF
    chown $U:$U /home/$U/.config/aigw-claude-auth/config.json; chmod 600 /home/$U/.config/aigw-claude-auth/config.json
    asuser nohup python3 /home/$U/gw.py >/dev/null 2>&1 &
    sleep 1
    check "client runs: $(cli --version 2>&1)" cli --version

    step "1. install in proxy mode writes the settings and the systemd user unit"
    cli install 2>&1 | sed 's/^/   /'
    UNIT=/home/$U/.config/systemd/user/aigw-claude-auth.service
    check "unit file written" test -f $UNIT
    echo "   ExecStart: $(grep ^ExecStart= $UNIT)"
    for _ in $(seq 1 20); do [ "$(uctl is-active aigw-claude-auth 2>/dev/null)" = active ] && break; sleep 1; done
    [ "$(uctl is-active aigw-claude-auth 2>/dev/null)" = active ] && ok "unit active" || bad "unit active ($(uctl is-active aigw-claude-auth 2>&1))"
    [ "$(uctl is-enabled aigw-claude-auth 2>/dev/null)" = enabled ] && ok "unit enabled" || bad "unit enabled"
    check "settings point at the proxy" python3 -c "import json,sys; d=json.load(open('/home/$U/.claude/settings.json')); sys.exit(0 if d['env']['ANTHROPIC_BASE_URL']=='http://127.0.0.1:18787' else 1)"

    step "2. status: claims including the email, the JWKS rows"
    for _ in $(seq 1 15); do cli status --offline 2>/dev/null | grep -q "running on" && break; sleep 1; done
    cli status 2>&1 | grep -E "^(version|mode|proxy|jwt)" | sed 's/^/   /'
    cli status 2>&1 | grep -qE "^jwt email +smoke@example.com" && ok "status shows the email claim" || bad "status shows the email claim"
    cli status 2>&1 | grep -qE "^jwks +unknown \(token_command\)" && ok "jwks row says unknown for a token_command" || bad "jwks row for a token_command"
    cli status --offline 2>&1 | grep -q "^jwks" && bad "--offline still prints jwks" || ok "--offline skips the jwks lookup"

    step "3. requests through the proxy reach the gateway with the JWT injected; the request log masks credentials"
    SECRET=$(python3 -c "import json; h=json.load(open('/home/$U/.claude/settings.json'))['env']['ANTHROPIC_CUSTOM_HEADERS']; print([l.split(':',1)[1].strip() for l in h.splitlines() if l.lower().startswith('x-aigw-local')][0])")
    BEARER="sk-ant-oat01-smokesmokesmokesmoke"
    for i in 1 2 3; do
        CODE=$(curl -s -o /dev/null -w '%{http_code}' -X POST "http://127.0.0.1:18787/v1/messages?i=$i" -H "x-aigw-local: $SECRET" \
            -H "Authorization: Bearer $BEARER" -H "anthropic-beta: oauth-2025-04-20" -H "Content-Type: application/json" -d '{}')
        [ "$CODE" = 200 ] && ok "request $i -> 200" || bad "request $i -> $CODE"
    done
    CODE=$(curl -s -o /dev/null -w '%{http_code}' -X POST http://127.0.0.1:18787/v1/messages -H "x-aigw-local: wrong-secret-value" -d '{}')
    [ "$CODE" = 498 ] && ok "a wrong local secret -> 498" || bad "a wrong local secret -> $CODE"
    tail -1 /tmp/gw.log | python3 -c "import json,sys; d=json.loads(sys.stdin.read()); print('   gateway saw:', d); sys.exit(0 if d['portkey_len']>100 else 1)" && ok "gateway received the injected x-portkey-api-key" || bad "gateway received the injected x-portkey-api-key"
    tail -1 /tmp/gw.log | grep -q '"has_local_secret": false' && ok "x-aigw-local was stripped before the gateway" || bad "x-aigw-local was stripped before the gateway"
    echo "--- aigw-claude-auth requests -n 6 ---"
    cli requests -n 6 > /tmp/requests.out 2>&1; sed 's/^/   /' /tmp/requests.out
    grep -q "POST /v1/messages -> 200" /tmp/requests.out && ok "requests lists the 200s" || bad "requests lists the 200s"
    grep -q "local-secret" /tmp/requests.out && ok "requests lists the 498 local-secret refusal" || bad "requests lists the refusal"
    grep -q "authorization: Bearer sk-a\.\.\.moke (len 33)" /tmp/requests.out && ok "bearer partly masked" || bad "bearer partly masked"
    grep -q "out x-portkey-api-key: eyJ" /tmp/requests.out && ok "injected x-portkey-api-key partly masked" || bad "injected x-portkey-api-key partly masked"
    grep -q "up  request-id: req_smoke" /tmp/requests.out && ok "the gateway's request-id is listed" || bad "the gateway's request-id is listed"
    if grep -qE "$BEARER|$SECRET|wrong-secret-value|[A-Za-z0-9_-]{40,}" /tmp/requests.out; then bad "no full credential in the output"; else ok "no full credential in the output"; fi

    step "4. systemd restarts the proxy after it is killed"
    P1=$(uctl show -p MainPID --value aigw-claude-auth)
    uctl kill -s KILL aigw-claude-auth
    for _ in $(seq 1 40); do P2=$(uctl show -p MainPID --value aigw-claude-auth); [ "$(uctl is-active aigw-claude-auth 2>/dev/null)" = active ] && [ "$P2" != "$P1" ] && [ "$P2" != 0 ] && break; sleep 1; done
    [ "${P2:-0}" != "$P1" ] && [ "${P2:-0}" != 0 ] && ok "restarted (pid $P1 -> $P2)" || bad "restarted (pid $P1 -> ${P2:-none})"
    for _ in $(seq 1 15); do cli status --offline 2>/dev/null | grep -q "running on" && break; sleep 1; done
    cli status --offline 2>&1 | grep -q "running on" && ok "proxy answers again" || bad "proxy answers again"

    step "5. reinstall is idempotent and teardown removes the service"
    cli install >/dev/null 2>&1 && ok "second install exits 0" || bad "second install exits 0"
    [ "$(uctl is-active aigw-claude-auth 2>/dev/null)" = active ] && ok "still active after reinstall" || bad "still active after reinstall"
    uctl disable --now aigw-claude-auth >/dev/null 2>&1; rm -f $UNIT; uctl daemon-reload
    sleep 1
    ss -ltn 2>/dev/null | grep -q ':18787 ' && bad "port 18787 closed after teardown" || ok "port 18787 closed after teardown"

    echo; echo "RESULT: $FAILS failure(s)"
    exit $((FAILS > 0))
fi

# ------------------------------------------------------------------------------------------ outside (the host)
[ -f "$CLIENT" ] || { echo "need --client <path to aigw_claude_auth.py>" >&2; exit 2; }
IMG=aigw-smoke-ubuntu CTR=aigw-smoke-$$
cleanup() { [ "$KEEP" = 1 ] && { echo "kept container $CTR and image $IMG"; return; }; docker rm -f "$CTR" >/dev/null 2>&1; docker rmi "$IMG" >/dev/null 2>&1; }
trap cleanup EXIT
docker build -q -t "$IMG" - >/dev/null <<'DF' || exit 1
FROM ubuntu:latest
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update -qq && apt-get install -y -qq systemd systemd-sysv systemd-container dbus dbus-user-session python3 iproute2 procps curl >/dev/null
CMD ["/sbin/init"]
DF
docker run -d --name "$CTR" --privileged --cgroupns=host --tmpfs /run --tmpfs /run/lock --tmpfs /tmp "$IMG" >/dev/null || exit 1
docker exec "$CTR" mkdir -p /smoke
docker cp "$CLIENT" "$CTR:/smoke/aigw_claude_auth.py"
docker cp "$0" "$CTR:/smoke/smoke.sh"
for _ in $(seq 1 30); do docker exec "$CTR" systemctl is-system-running 2>/dev/null | grep -qE 'running|degraded' && break; sleep 1; done
docker exec "$CTR" bash /smoke/smoke.sh --inside
