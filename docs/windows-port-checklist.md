# Windows port checklist (Phase 2 input)

These POSIX-only or non-portable spots were found by reading the code while the S7 probe (`repro/winprobe.py`) was built
on 2026-10-25. None of them has been tried on Windows yet. Line numbers are as of commit `218c030`.

## client/aigw_claude_auth.py

- `:34` `import fcntl`; `:285-293` `fcntl.flock`. Windows needs a named mutex or `msvcrt.locking`.
- `:176` `os.kill(pid, 0)` terminates the process on Windows. Use `OpenProcess` via `ctypes`.
- `:673` `start_new_session`. Windows needs `DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP`.
- `:588-589` `signal.SIGTERM` handler. Windows has only `SIGINT`/`SIGBREAK`.
- `:723-733` notify: `osascript`/`notify-send`, with no toast path. Use PowerShell 5.1 WinRT with `-EncodedCommand`.
- `:739` hook commands quoted with `shlex.quote`. S7 (README finding 17): this runs under Git Bash but not under Windows
  PowerShell 5.1, which Claude Code uses when Git for Windows is absent. Use a form that parses in both. Per the hooks docs
  (not run here): exec form (`"command": "<python.exe>", "args": [...]`) spawns the executable with no shell on any
  platform, which avoids quoting entirely; `command` must be a real `.exe`, not a `.cmd` shim. A per-hook
  `shell: "bash" | "powershell"` field also exists. Try exec form on the VM first.
- `:94`, `:100` default `~/.config` instead of `%APPDATA%`.
- `:156-165` `mkdir(mode=0o700)` and `chmod` don't restrict access on Windows. Needs a user-only ACL.
- Settings rename: retry `os.replace` on `PermissionError`. S7 saw none in 60 replacements (finding 17); keep a short retry.

## repro/harness.py

- `UnixGateway` read `socket.AF_UNIX` at import (fixed: `getattr`), which stopped the probe importing `harness` on Windows.
- `:34` imports `test_aigw_claude_auth` → client → `fcntl`, so it can't be imported on Windows (the probe stubs `fcntl`).
- `:37` `CLAUDE` assumes a bare `claude`; `:625` `Managed.DIR` is macOS/Linux only.
- `:123-133` the clean environment for Claude Code lacks `SystemRoot`, `ComSpec`, `PATHEXT`, `USERPROFILE`, `APPDATA`,
  `LOCALAPPDATA` and `TEMP`.
- `:117`, `:161` `text=True` with no `encoding` uses the locale codec (cp1252) on Windows.
- `read_text`/`write_text`/`open` without `encoding`: `:79 82 105 109 141 144 160 170 249 258 269 382 390 538`.
- `:110` `os.chmod(0o600)` only sets the read-only flag on Windows.
- `:197-201`, `:482` `stop()` doesn't kill the process tree (`taskkill /T`), so `rmtree` can fail on open files.
- `:236`, `:424-425`, `:495`, `:653-659` hook and notify commands use POSIX quoting, `#!/bin/sh` and `[ -n "$X" ]`;
  `TOKEN_COMMAND` runs with `shell=True`.
- `:301-304` the `st_ino` rename check may behave differently on NTFS.
- `:635-649`, `:683-714` `sudo`, `chmod 444` and `chflags` are POSIX-only.

## repro/run.sh

The whole runner is bash 4+ and needs a Python replacement. It uses `BASH_VERSINFO`, `declare -A`, process substitution,
`date -u`, `sha256sum`/`shasum`, `tail`, `wc`, `sed`, `awk`, `curl`, `uname`, `sudo`, `mkdir -p`, `chmod 700`,
`eval "$TOKEN_COMMAND"`, and a hard-coded `python3` (Windows has `py -3`).

## repro/mock_gateway.py

Portable. `open()` without `encoding` at `:109` and `:133` is harmless because the data is ASCII JSON.
