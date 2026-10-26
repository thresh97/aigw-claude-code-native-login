#!/bin/sh
# Uninstall @NAME@ (generated from packaging/macos/uninstall.sh by build.py). Run with sudo.
#   uninstall.sh                 stop the agent for every user, remove the package's files, forget the receipt
#   uninstall.sh --purge-users   also, for each local user: forget the refresh token, remove our header lines from
#                                their Claude Code settings, delete ~/.config/aigw-claude-auth (run before the files go)
# DESTDIR=<dir> works on a copy of the tree (dry run): nothing live is touched, no launchctl, no pkgutil.
set -u
ROOT="${DESTDIR:-}"
ROOT="${ROOT%/}"
LIBEXEC="$ROOT@INSTALL_DIR@"
PLIST="$ROOT@PLIST@"
MANAGED="$ROOT@MANAGED@"
LABEL="@LABEL@"
PURGE=0
[ "${1:-}" = "--purge-users" ] && PURGE=1

if [ -z "$ROOT" ]; then
    for uid in $(/usr/bin/dscl . -list /Users UniqueID | /usr/bin/awk '$2 >= 500 {print $2}'); do
        /bin/launchctl bootout "gui/$uid/$LABEL" >/dev/null 2>&1
    done
fi
if [ "$PURGE" = 1 ] && [ -z "$ROOT" ]; then
    /usr/bin/dscl . -list /Users UniqueID | /usr/bin/awk '$2 >= 500 {print $1}' | while read -r u; do
        home="$(/usr/bin/dscl . -read "/Users/$u" NFSHomeDirectory | /usr/bin/awk '{print $2}')"
        [ -d "$home" ] && /usr/bin/sudo -u "$u" -H "@PYTHON@" "$LIBEXEC/aigw_launch.py" purge-user
    done
fi

rm -f "$PLIST" "$MANAGED"
rm -rf "$LIBEXEC"
# remove the directories only if we leave them empty (they may belong to Claude Code or another package)
rmdir "$(dirname "$MANAGED")" "$(dirname "$(dirname "$MANAGED")")" 2>/dev/null
rmdir "$(dirname "$LIBEXEC")" 2>/dev/null
[ -z "$ROOT" ] && /usr/sbin/pkgutil --forget @IDENTIFIER@ >/dev/null 2>&1
echo "removed @NAME@"
exit 0
