# Fleet packaging

> This page is the implementation reference and the test record. The operator-facing guide, with the maturity label, the shortcomings and the supported OS and mode matrix, is [docs/fleet-deployment.md](../docs/fleet-deployment.md).

Artifacts to roll aigw-claude-auth out to many machines: one fleet file in, a macOS `.pkg`, a Linux `.deb`/`.rpm` and a
Windows PowerShell installer out. Nothing here is signed yet and nothing has run on a real fleet; the checks below are
offline (see "What was tested"). The client stays one stdlib file, copied as is.

## The fleet file

`fleet.example.json` (placeholders only; keep your real copy out of git):

| Key | Meaning |
| --- | --- |
| `name` | Package and drop-in name; must contain `aigw` (the client finds its hooks by that) |
| `gateway_url` | File mode: managed `ANTHROPIC_BASE_URL`. Proxy mode: where the proxy forwards (`gateway_url` in the config) |
| `mode`, `proxy_listen` | `file` or `proxy`; proxy mode needs a fixed loopback port, and managed `ANTHROPIC_BASE_URL` becomes `http://<proxy_listen>`. Proxy mode is for one logged-in user per machine: see "Several users at once" |
| `idp` | Any client config keys: `issuer`, `client_id`, `scope`, `broker_url`, `redirect_port`, `login_method`, `hook_login`, ... (validated with the client's own `load_config`) |
| `options` | `pin_allowed_providers` (managed `allowedProviders: ["customEndpoint"]`, default on), `allow_managed_hooks_only`, `notify` |
| `python` | Interpreter per OS (`macos`, `linux`, `windows`) used by the hooks, launcher and background entry |

## Build

```bash
python3 packaging/build.py render  --fleet my-fleet.json --out dist          # just the rendered files, per OS
python3 packaging/build.py macos   --fleet my-fleet.json --out dist [--sign "Developer ID Installer: Org (TEAMID)"]
python3 packaging/build.py linux   --fleet my-fleet.json --out dist [--rpm]  # needs Docker (debian:12, rockylinux:9)
python3 packaging/build.py windows --fleet my-fleet.json --out dist          # dist/windows/: two scripts + payload/
```

Real builds refuse a fleet file that still holds `<placeholders>`; `--allow-placeholders` is for dry builds. The
generator imports the client, so the hooks are `hook_entry()` output, the proxy URL is `proxy_base_url()`, the config is
checked by `load_config()` and the Windows task is the client's `task_xml()` changed to the local Users group.

## What lands where

| | macOS `.pkg` | Linux `.deb` / `.rpm` | Windows `Install-AigwClaudeAuth.ps1` |
| --- | --- | --- | --- |
| Client, launcher, `config.json` | `/usr/local/libexec/aigw-claude-auth/` | `/usr/lib/aigw-claude-auth/` | `C:\Program Files\aigw-claude-auth\` |
| Managed settings (drop-in) | `/Library/Application Support/ClaudeCode/managed-settings.d/50-<name>.json` | `/etc/claude-code/managed-settings.d/50-<name>.json` | `C:\Program Files\ClaudeCode\managed-settings.d\50-<name>.json` |
| Background start for all users | `/Library/LaunchAgents/<name>.fleet.plist` (loads at each login; the postinstall also starts it for the console user) | `/usr/lib/systemd/user/<name>-fleet.service`, `systemctl --global enable` | Scheduled task `aigw-claude-auth-fleet`: at log on of any member of the local Users group, runs as that user (`task.xml`) |
| Uninstall | `/usr/local/libexec/aigw-claude-auth/uninstall.sh [--purge-users]` | `apt remove` / `dnf remove` | `Uninstall-AigwClaudeAuth.ps1 [-PurgeCurrentUser]` |

Managed settings: base URL, the two hooks (command = the packaged client with `--config <install dir>/config.json`),
`allowedProviders`, and `AIGW_*` env for the profile keys (finding 15, so `doctor` can compare them with the config).
**Never `ANTHROPIC_CUSTOM_HEADERS`**: a managed value replaces the user's, so the JWT (or in proxy mode the local secret)
would not be sent (finding 11). Drop-ins never touch an existing `managed-settings.json`.

The config is read from the install directory by the hooks, the launcher and the `aigw-claude-auth.cmd` wrapper (Windows),
not copied per user, so a package upgrade changes it for everyone. On macOS/Linux there is no wrapper on `PATH`: run the
client as `python3 <install dir>/aigw_claude_auth.py --config <install dir>/config.json login` (a `PATH` shim is a follow-up).

Windows: the drop-in file was chosen over the `HKLM\SOFTWARE\Policies\ClaudeCode` `Settings` value because Claude Code merges
`managed-settings.d` on Windows like elsewhere, it needs no registry write, uninstalling is deleting a file, and it never
overwrites an existing `managed-settings.json`. If the organization already has HKLM policy, the registry wins and the file is
ignored (first source with a policy key wins unless `managedSourcesBehavior` is `merge`); then deliver the same JSON
(`payload\50-<name>.json`) as the `Settings` value by GPO or Intune. `doctor` shows the winning source.

## Per-user first run

Nothing per user is done at install time. At each login the background entry runs `aigw_launch.py daemon`, which:

1. runs `install --no-hooks` with the fleet config as that user: file mode writes the JWT line (the sentinel while signed
   out) into the user's `settings.json`; proxy mode writes the proxy address and the user's own random secret
   (`x-aigw-local`) and no JWT. It is idempotent, so a secret is stable across logins and different for every user;
2. starts the daemon (in proxy mode that is the proxy).

The user then signs in once: with `hook_login` not `off`, the first Claude Code prompt is blocked with a sign-in URL and
code (nothing to run); otherwise `aigw-claude-auth login` in a terminal. After that everything renews in the background.

## Interpreter

macOS needs the Command Line Tools for `/usr/bin/python3`; Linux packages depend on `python3 >= 3.8`; Windows has no Python,
so the installer refuses to run when the `python.windows` path is missing. A fleet should ship a bundled interpreter (or
one compiled binary) and point `python` at it. Out of scope for now: the pilot uses the system Python (Windows: Python installed for all users).

## Signing

Out of scope for now (the pilot installs unsigned packages). When needed:

- macOS: `--sign "<Developer ID Installer identity>"` is passed to `productbuild --sign`; notarize with
  `xcrun notarytool submit ... --wait` and `xcrun stapler staple`. Unsigned pkgs need a right-click open or an MDM push.
- Linux: sign the `.rpm` with `rpmsign --addsign` and publish `.deb` in a signed apt repository; not scripted here.
- Windows: `Set-AuthenticodeSignature` on the two scripts and the Python files you ship; WiX (MSI) is a follow-up so
  Intune/SCCM can use native install detection.

## A personal install on the same machine

The fleet replaces a personal install (README 1.3); the two are not meant to run side by side. Both would use the same state
folder (the fleet would pick up the personal refresh token, maybe from another IdP) and both daemons would write the JWT. The
fleet's config carries `"fleet": true`, and at each login the launcher, before its first run, moves a personal install of that
user aside (client 1.4.1, `take_over_personal`):

- stops and removes the personal background entry: `~/Library/LaunchAgents/aigw-claude-auth.plist`, `~/.config/systemd/user/aigw-claude-auth.service`
  (moved into the backup folder), or the Task Scheduler task `aigw-claude-auth`;
- forgets the personal refresh token in the OS credential store and moves the personal `config.json`, `state.json` etc. to
  `~/.config/aigw-claude-auth.personal-<time>` (Windows `%APPDATA%\aigw-claude-auth.personal-<time>`): renamed, not deleted;
- removes our hook entries from the user's `settings.json` (the managed settings carry the fleet's).

The user then signs in once through the fleet. The personal client file (`~/.local/bin/aigw-claude-auth`) stays; it does nothing
without its entry and config. `doctor` reports a personal install that is still there as Warning `personal-install`. The
Linux fleet unit is `<name>-fleet.service` so that a personal `aigw-claude-auth.service` in `~/.config/systemd/user` can't shadow it.

## Uninstall and what it leaves

All three remove their files, the background entry and the drop-in. Per-user data (refresh token, `~/.config/aigw-claude-auth`,
header lines in `~/.claude/settings.json`) is not touched by default because the installer cannot act as every user:
`python3 <install dir>/aigw_launch.py purge-user` run as a user (macOS `uninstall.sh --purge-users` does it for every local
user with UID 500 or above via `sudo -u`, including admin accounts; Windows `-PurgeCurrentUser` for the caller) logs out, removes our header lines and deletes the state folder.
Without the managed base URL and hooks, the leftovers are inert. Running daemons stop at the next logout (Linux/Windows
disable the entry; macOS `uninstall.sh` boots the agent out).

## Several users at once (not supported / untested)

Machines where several users are logged in at the same time (terminal servers, fast user switching) are out of scope for now.

- **Proxy mode: not supported.** The port is fixed, so only the first user's proxy listens; a second user's proxy exits with
  "Address already in use" and that user's Claude Code gets 498 from the other proxy (observed on Linux, see below). Use file mode on
  shared hosts. A per-user port would need the base URL in user settings instead of managed settings (not built).
- **Windows, file mode: untested.** The fleet task (one task for the Users group) has `MultipleInstancesPolicy IgnoreNew`; whether a
  second user's at-logon start is dropped while the first user's daemon runs was not observed.
- **macOS and Linux, file mode:** each user gets their own LaunchAgent / user unit instance; the Linux pilot ran two users at once in
  file mode (both active).

## What was tested (offline, 2026-10-26)

- `python3 -m unittest -v packaging/test_packaging.py`: generator, launcher, pkg payload and dry run.
- macOS: `pkgutil --expand` / `--payload-files`, `plutil -lint`, postinstall and `uninstall.sh` with `DESTDIR` into a temp dir. The pkg was not installed.
- Linux: `packaging/linux/container-test-deb.sh` (debian:12) and `container-test-rpm.sh` (rockylinux:9) inside `docker run --rm`: files land, the unit is enabled globally, `--version` and `doctor --json` run, a fresh user's first run writes only the JWT line, removal leaves nothing.
- Windows: `-WhatIf` writes nothing; an install into an alternate `-Root` (task registration skipped), `task.xml` parses, the client, `doctor` and the launcher run from it, and the uninstall into the same root removes everything.
- Emulated pilot (Linux), 2026-10-26: `packaging/linux/pilot-systemd.sh --fleet <fleet.json> --pkg deb|rpm` installs the package for real in a privileged
  debian:12 / rockylinux:9 container with systemd as PID 1 (`--privileged --cgroupns=host`, tmpfs on `/run`), logs two users in
  through `machinectl shell` (a pam_systemd session, held open: with no session logind stops the user manager seconds later), and
  checks files, the managed drop-in (no `ANTHROPIC_CUSTOM_HEADERS`), the global enable, the user unit, the first-run `settings.json`,
  `doctor --json`, a second login (user-manager restart), uninstall and `purge-user`. No sign-in and no gateway request. Four runs
  (deb and rpm, file and proxy mode) passed.
  - File mode: both users' units active; only the sentinel `x-portkey-api-key` line written; `doctor` 0 errors, 0 warnings (one Info, `server-managed`).
  - Proxy mode: users got different secrets, each stable across a second login. The proxy port is fixed, so only the first user's
    proxy listens; the second user's unit exits with "cannot listen ... Address already in use (an aigw-claude-auth proxy is running
    there but does not accept this user's secret)" and `Restart=on-failure` / `RestartSec=10` retries it forever (never active while the
    first proxy lives). That user's `doctor` shows Error `proxy-secret`, and their Claude Code would get 498 from the other user's proxy. Proxy mode on a
    shared Linux host (several simultaneous users) does not work with one fixed `proxy_listen`; a per-user port is needed (open item).
  - Uninstall: files, unit, global enable and drop-in are removed; the rpm used to leave empty `/etc/claude-code/managed-settings.d` (fixed: the spec owns the dirs).
    Running daemons were still active after removal (stop at logout: from reading the unit, not observed). `purge-user` must run before removal (the launcher is gone
    afterwards: "can't open file"); it removes our header lines and `~/.config/aigw-claude-auth` but leaves the `~/.claude/settings.json` file itself. Without purge the user keeps
    `~/.config/aigw-claude-auth/*` and the header line in `settings.json` (inert without the managed base URL and hooks).

- Emulated pilot (Windows, 2026-10-26; Windows 11 Pro VM, Python 3.13 for all users, driver `windows/pilot-vm.ps1` + `windows/pilot-ssh.sh`; disposable VM only, no IdP sign-in, no request to the gateway), file mode and proxy mode, each a full cycle:
  - Elevated install into the real `C:\Program Files`: files land, the drop-in is valid JSON without `ANTHROPIC_CUSTOM_HEADERS`, no `HKLM\SOFTWARE\Policies\ClaudeCode` key, the task registers with principal `GroupId=Users`, `LogonType=Group`, `RunLevel=Limited`; the install folder and the drop-in are not writable by Users.
  - Two standard local users each got a real interactive logon (Winlogon autologon for one logon, then reboot; the autologon values were removed right after, `DefaultPassword` verified absent). Each time the task fired at logon (`LastRunTime` after boot, `LastTaskResult` 0x41301 = running) and the daemon ran as that user. The launcher's first run wrote only the sentinel `x-portkey-api-key` line (file mode) or the loopback `ANTHROPIC_BASE_URL` plus the user's own `x-aigw-local` secret and no JWT (proxy mode). `doctor --json` run in the user's own session: 0 errors, 0 warnings, one Info (`server-managed`), managed source `file`.
  - Proxy mode: the two users' secrets differ (43 characters each, different hashes); user 1's is unchanged after a third logon; the fixed port 127.0.0.1:18787 was free after each reboot and bound by the logged-on user's proxy. With one user's proxy running, a second launcher (started as the admin with redirected state, see below) failed with `cannot listen on 127.0.0.1:18787 ... an aigw-claude-auth proxy is running there but does not accept this user's secret`; the first proxy kept the port. Starting the task by hand while an instance runs is refused (`0x800710E0`), the effect of `MultipleInstancesPolicy IgnoreNew`.
  - Uninstall: task, drop-in, install folder (and the empty `ClaudeCode` folders) gone, no daemon left. Per user, as documented: the user who ran `purge-user` has no header line and no state folder (the log folder stays while the running daemon holds `daemon.log`); the other user keeps the state folder, the log folder and the inert header line.
  - Bugs found and fixed: the installer's `PayloadDir` default used `$PSScriptRoot`, which is empty under `powershell -File` (so the installer did not run that way); `purge-user` now also removes the Windows log folder.

- Emulated pilot (macOS, 2026-10-26; macOS 26.6, person-run `macos/pilot.sh`, file mode, the console user only): `sudo installer` of the
  unsigned pkg succeeds; drop-in valid without `ANTHROPIC_CUSTOM_HEADERS`, plist lints, receipt present; the postinstall's `launchctl bootstrap`
  started the LaunchAgent for the console user, whose first run wrote only the sentinel line (the launcher logs `install --no-hooks exit 1`:
  not signed in); `doctor` 0 errors, 0 warnings (Info `server-managed`). Uninstall (purge of the console user, then `uninstall.sh`) removed
  files, drop-in, plist, receipt, the loaded agent and any Keychain item; that run's driver also set a personal install aside and restored it (removed since: the fleet now takes a personal install over, client 1.4.1).
  Not run on macOS: a second user's login (LaunchAgent at login), proxy mode, sign-in from the first prompt.

- Live fleet run (macOS, 2026-10-26; client 1.4.1, file mode, Okta, the real hybrid gateway, Claude Code 2.1.308): `macos/pilot.sh install` on a
  Mac with a personal install. The postinstall started the fleet agent, whose first run took the personal install over (launchd entry
  stopped and moved aside, refresh token forgotten in the Keychain, config and state moved to `aigw-claude-auth.personal-<time>`); `check`
  then: sentinel, `doctor` 0 errors, no `personal-install`. (A `check` run within a second of the install still saw the personal JWT and the
  `personal-install` Warning: it ran before the agent's first run.) The first `claude` prompt was blocked with a PKCE sign-in, the browser
  sign-in to Okta succeeded ("Signed in to the AI gateway; send your prompt again"), and Claude Code then worked through the gateway with the
  fleet's Okta JWT and the user's claude.ai login. A Claude Code `/logout` + `/login` (a new claude.ai login) kept working. Then proxy
  mode (uninstall, install with the proxy fleet file, sign in again): the user's settings hold only the loopback base URL and the
  `x-aigw-local` secret, the proxy listens on 127.0.0.1:18787 as the user with the Okta JWT in memory, and Claude Code works through it.

Not covered: a real MDM/Intune push, the macOS LaunchAgent starting at a real macOS login, signing, a logged-in-user `launchctl bootstrap` from the postinstall.
Not covered on Windows: two users logged on at the same time (the VM had one autologon, `Start-Process -Credential` from ssh fails with 0xC0000142 and a standard user may not run password tasks), so whether the second user's At-logon trigger is dropped by `IgnoreNew` while the first user's daemon runs is inferred from the manual start above, not observed; in proxy mode that user would have no proxy (the fixed port is taken anyway). A user signing in to the IdP, renewal, and Claude Code itself against the gateway were not run.

## What the emulated pilot needs

- A real (non-placeholder) fleet file: gateway URL, IdP profile, and for Windows an interpreter path that exists on the VM.
- macOS: sudo on a disposable user account or machine; `sudo installer -pkg ... -target /`, then log in as a second user to see the
  agent start; `uninstall.sh --purge-users` afterwards. Note the managed file applies to every Claude Code on the machine.
- Linux: a VM or container with systemd (`systemd --user` sessions) for `systemctl --user status` after login.
- Windows: done for one VM (see "What was tested"); `windows/pilot-ssh.sh` repeats it. Still open: two simultaneous sessions (fast user switching or a terminal server) and a real sign-in.
- Pilot checks: `doctor` clean (hooks resolve, no `managed-config-conflict`), first prompt shows the sign-in, a renewal, proxy mode
  with two users getting different secrets, uninstall leaves no managed file.
