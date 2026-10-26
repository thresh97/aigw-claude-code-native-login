#!/usr/bin/env bash
# Drives packaging/windows/pilot-vm.ps1 over ssh from any machine with bash (emulated pilot on a disposable Windows VM).
# No tenant data here: the fleet file is passed in, the host is an ssh alias.
#
#   pilot-ssh.sh push    <file|proxy> <fleet.json>     build the Windows package and copy it and the driver to the VM
#   pilot-ssh.sh phase   <file|proxy> <phase> [user]   run one phase (install, check, concurrent, uninstall, cleanup)
#   pilot-ssh.sh logon   <file|proxy> <user>           logon-prep, wait for the reboot, wait for ssh, then check
#
# Env: PILOT_HOST (required: an ssh host or alias for the disposable VM), PILOT_WORK (default C:\aigw-pilot), PILOT_OUT (default a temp dir for the build).
set -euo pipefail
[ -z "${PILOT_TRACE:-}" ] || set -x
HOST="${PILOT_HOST:?set PILOT_HOST to the ssh host or alias of a disposable Windows VM}"
WORK="${PILOT_WORK:-C:\\aigw-pilot}"
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
SSH=(ssh -o ConnectTimeout=10 -o ServerAliveInterval=15 "$HOST")

vm() { "${SSH[@]}" "$@" 2> >(grep -v -e '^\*\*' >&2); }
run_phase() {  # mode phase [user]
  local extra=""
  [ -n "${3:-}" ] && extra="-User $3"
  vm "powershell -NoProfile -ExecutionPolicy Bypass -File $WORK\\pilot-vm.ps1 -Phase $2 -Mode $1 $extra"
}

cmd="${1:?usage: see header}"; shift
case "$cmd" in
  push)
    mode="$1"; fleet="$2"
    out="${PILOT_OUT:-$(mktemp -d)}/dist-$mode"
    python3 "$REPO/packaging/build.py" windows --fleet "$fleet" --out "$out" >/dev/null
    vm "New-Item -ItemType Directory -Force -Path $WORK | Out-Null; Remove-Item -Recurse -Force $WORK\\dist -ErrorAction SilentlyContinue; exit 0"
    scp -q -r "$out/windows" "$HOST:C:/aigw-pilot/dist" 2> >(grep -v -e '^\*\*' >&2)
    scp -q "$HERE/pilot-vm.ps1" "$HOST:C:/aigw-pilot/pilot-vm.ps1" 2> >(grep -v -e '^\*\*' >&2)
    echo "pushed $mode build to $HOST:$WORK"
    ;;
  phase) run_phase "$1" "$2" "${3:-}" ;;
  logon)
    mode="$1"; user="$2"
    run_phase "$mode" logon-prep "$user"
    echo "waiting for the VM to go down ..."
    for _ in $(seq 1 30); do sleep 4; "${SSH[@]}" -o ConnectTimeout=3 true >/dev/null 2>&1 || break; done
    echo "waiting for ssh to come back ..."
    for _ in $(seq 1 90); do sleep 5; "${SSH[@]}" -o ConnectTimeout=4 true >/dev/null 2>&1 && break; done
    run_phase "$mode" check "$user"
    ;;
  *) echo "unknown command $cmd" >&2; exit 2 ;;
esac
