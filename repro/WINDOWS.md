# Spike S7 on Windows: running `winprobe.py`

`repro/winprobe.py` answers the three S7 questions in `docs/design-v2.md` on native Windows. Nothing is installed: it runs
Claude Code in a throwaway HOME, USERPROFILE, APPDATA and `CLAUDE_CONFIG_DIR` under the output directory, against a mock
gateway on 127.0.0.1, with dummy credentials. It does not touch your Claude Code settings or login. It does not need a Claude account.

## Set up the VM

1. Windows 10 or 11, a normal interactive desktop session (RDP is fine; a toast needs a logged-on desktop, and Focus
   Assist / Do Not Disturb off, or it will not be seen).
2. Python 3.8+ from python.org (tick "py launcher"; either per-user or "for all users" is fine; "for all users" puts
   `python.exe` under `C:\Program Files`, a path with a space, which is a useful extra data point). Not the Microsoft Store
   stub.
3. Claude Code: the native installer or `npm i -g @anthropic-ai/claude-code`. `claude --version` must work in the terminal
   you start the probe from.
4. Git for Windows: first run **with** it installed, then (if Claude Code still starts) a second run **without** it
   (uninstall it, open a new terminal, check `where git` finds nothing). If Claude Code refuses to start without Git, say so;
   that is the answer for that run. Whether it refuses is not established here.
5. Copy the repo's `repro\` and `client\` directories to the VM (the probe imports `harness.py`, `mock_gateway.py` and the
   client's tests and module; it does not run the client).

## Commands

From `cmd.exe` or Windows PowerShell, in the repo root. Use a fresh output directory each time:

```
py -3 repro\winprobe.py --out C:\winprobe\git-yes > C:\winprobe\git-yes.txt
type C:\winprobe\git-yes.txt
```

The default run takes about 2 minutes. Toasts appear near the end; note whether you saw them, or add `--ask` to be asked.
Do not redirect stdout when using `--ask`.

Optional, for S7.2 with the real TUI instead of the headless session (you type prompts while the probe replaces the file):

```
py -3 repro\winprobe.py --out C:\winprobe\git-yes-tui --only interactive
```

It prints the path of a `run-tui.cmd` / `run-tui.ps1`. Start that in a second terminal and keep sending short prompts until
the probe prints `probe_done=yes`.

Run once from `cmd.exe` and once from PowerShell if you can: the probe's own environment is inherited by Claude Code and
could influence which shell it picks. Run again after the Git for Windows change in step 4.

## What to send back

For each run: the stdout text file (`*.txt`) and the whole output directory zipped. It holds only dummy tokens, hook dumps
(argv, a handful of named variables, process names) and request logs with credential fingerprints. Look it over before
sending if you like; there is no real account data in it. Also write down by hand, for each of the four toasts
(`ps_aumid` and `own_aumid`, from the hook and direct), whether it appeared, and whether any console window flashed.

## Which result answers which question

| Question | Keys in the output | Details in the output dir |
|---|---|---|
| Basics | `os`, `windows_build`, `python_version`, `claude_version`, `git_for_windows_bash_exe`, `git_on_path`, `powershell_5_1` (includes the language mode), `pwsh_on_path` | |
| S7.1 which shell | `hook_shell_guess`, `hook_ancestors`, `hook_env`, `hook_env_present`, `hook_psmodulepath_has_windowspowershell`, `hook_raw_cmdline_dq`, `hook_parent_cmdline_dq` | `probe files\dumps\*.json` |
| S7.1 quoting | per form `hook_<form>_ran`, `_argv`, `_as_intended`; forms are listed in `hooks\hook_commands.txt`. `sq` is what the client's `install` writes today (`shlex.quote`); `dq` is the plain double-quoted form | `hooks\hook_events.jsonl` has Claude Code's own hook results, including stderr of forms that failed |
| S7.2 locking | `lock_control_*` (must show a PermissionError on Windows: it proves the detector works), `lock_permission_errors`, `lock_rounds_with_error`, `lock_max_wait_ms`, `lock_error_codes` (winerror 5 or 32 means locked), `lock_gave_up` | `lock\gateway.log.jsonl` |
| S7.2 pickup | `lock_pickup_1..3_seconds`, `lock_pickup_ok`, `lock_turn_errors` | |
| S7.3 toast | `toast_hook_*_exit`, `_seconds`, `_stderr`, `toast_hook_total_seconds` (must stay well under 30), `toast_direct_*` (same script outside Claude Code, the control), your manual notes | `probe files\dumps\toast_*.json` |

Read `hook_<form>_as_intended=no` with the `_argv` next to it: for `back\slash` an unquoted backslash that arrives as
`backslash` means a POSIX-style shell (Git Bash) ate it; for `%WINPROBE_VAR%` a literal `%WINPROBE_VAR%` means no cmd.exe
expansion, and `$WINPROBE_VAR` expanding means a POSIX shell or PowerShell.

To build the VM with Terraform on Azure, see `infra/windows-test-vm/README.md`.
