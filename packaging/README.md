# Fleet packaging (client 1.4.0)

Artifacts to roll aigw-claude-auth out to many machines: one fleet file in, a macOS `.pkg`, a Linux `.deb`/`.rpm` and a
Windows PowerShell installer out. Nothing here is signed yet and nothing has run on a real fleet; the checks below are
offline (see "What was tested"). The client stays one stdlib file, copied as is.

## The fleet file

`fleet.example.json` (placeholders only; keep your real copy out of git):

| Key | Meaning |
| --- | --- |
| `name` | Package and drop-in name; must contain `aigw` (the client finds its hooks by that) |
| `gateway_url` | File mode: managed `ANTHROPIC_BASE_URL`. Proxy mode: where the proxy forwards (`gateway_url` in the config) |
| `mode`, `proxy_listen` | `file` or `proxy`; proxy mode needs a fixed loopback port, and managed `ANTHROPIC_BASE_URL` becomes `http://<proxy_listen>` |
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
| Background start for all users | `/Library/LaunchAgents/<name>.fleet.plist` (loads at each login; the postinstall also starts it for the console user) | `/usr/lib/systemd/user/<name>.service`, `systemctl --global enable` | Scheduled task `aigw-claude-auth-fleet`: at log on of any member of the local Users group, runs as that user (`task.xml`) |
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
one compiled binary) and point `python` at it. This is the main open item before a real rollout.

## Signing

- macOS: `--sign "<Developer ID Installer identity>"` is passed to `productbuild --sign`; notarize with
  `xcrun notarytool submit ... --wait` and `xcrun stapler staple`. Unsigned pkgs need a right-click open or an MDM push.
- Linux: sign the `.rpm` with `rpmsign --addsign` and publish `.deb` in a signed apt repository; not scripted here.
- Windows: `Set-AuthenticodeSignature` on the two scripts and the Python files you ship; WiX (MSI) is a follow-up so
  Intune/SCCM can use native install detection.

## Uninstall and what it leaves

All three remove their files, the background entry and the drop-in. Per-user data (refresh token, `~/.config/aigw-claude-auth`,
header lines in `~/.claude/settings.json`) is not touched by default because the installer cannot act as every user:
`python3 <install dir>/aigw_launch.py purge-user` run as a user (macOS `uninstall.sh --purge-users` does it for every local
user via `sudo -u`; Windows `-PurgeCurrentUser` for the caller) logs out, removes our header lines and deletes the state folder.
Without the managed base URL and hooks, the leftovers are inert. Running daemons stop at the next logout (Linux/Windows
disable the entry; macOS `uninstall.sh` boots the agent out).

## What was tested (offline, 2026-10-26)

- `python3 -m unittest -v packaging/test_packaging.py`: generator, launcher, pkg payload and dry run.
- macOS: `pkgutil --expand` / `--payload-files`, `plutil -lint`, postinstall and `uninstall.sh` with `DESTDIR` into a temp dir. The pkg was not installed.
- Linux: `packaging/linux/container-test-deb.sh` (debian:12) and `container-test-rpm.sh` (rockylinux:9) inside `docker run --rm`: files land, the unit is enabled globally, `--version` and `doctor --json` run, a fresh user's first run writes only the JWT line, removal leaves nothing.
- Windows: `-WhatIf` writes nothing; an install into an alternate `-Root` (task registration skipped), `task.xml` parses, the client, `doctor` and the launcher run from it, and the uninstall into the same root removes everything.

- Emulated pilot (Windows, 2026-10-26; Windows 11 Pro VM, Python 3.13 for all users, driver `windows/pilot-vm.ps1` + `windows/pilot-mac.sh`; disposable VM only, no IdP sign-in, no request to the gateway), file mode and proxy mode, each a full cycle:
  - Elevated install into the real `C:\Program Files`: files land, the drop-in is valid JSON without `ANTHROPIC_CUSTOM_HEADERS`, no `HKLM\SOFTWARE\Policies\ClaudeCode` key, the task registers with principal `GroupId=Users`, `LogonType=Group`, `RunLevel=Limited`; the install folder and the drop-in are not writable by Users.
  - Two standard local users each got a real interactive logon (Winlogon autologon for one logon, then reboot; the autologon values were removed right after, `DefaultPassword` verified absent). Each time the task fired at logon (`LastRunTime` after boot, `LastTaskResult` 0x41301 = running) and the daemon ran as that user. The launcher's first run wrote only the sentinel `x-portkey-api-key` line (file mode) or the loopback `ANTHROPIC_BASE_URL` plus the user's own `x-aigw-local` secret and no JWT (proxy mode). `doctor --json` run in the user's own session: 0 errors, 0 warnings, one Info (`server-managed`), managed source `file`.
  - Proxy mode: the two users' secrets differ (43 characters each, different hashes); user 1's is unchanged after a third logon; the fixed port 127.0.0.1:18787 was free after each reboot and bound by the logged-on user's proxy. With one user's proxy running, a second launcher (started as the admin with redirected state, see below) failed with `cannot listen on 127.0.0.1:18787 ... an aigw-claude-auth proxy is running there but does not accept this user's secret`; the first proxy kept the port. Starting the task by hand while an instance runs is refused (`0x800710E0`), the effect of `MultipleInstancesPolicy IgnoreNew`.
  - Uninstall: task, drop-in, install folder (and the empty `ClaudeCode` folders) gone, no daemon left. Per user, as documented: the user who ran `purge-user` has no header line and no state folder (the log folder stays while the running daemon holds `daemon.log`); the other user keeps the state folder, the log folder and the inert header line.
  - Bugs found and fixed: the installer's `PayloadDir` default used `$PSScriptRoot`, which is empty under `powershell -File` (so the installer did not run that way); `purge-user` now also removes the Windows log folder.

Not covered: a real MDM/Intune push, LaunchAgent/systemd actually starting at login, signing, a logged-in-user `launchctl bootstrap` from the postinstall.
Not covered on Windows: two users logged on at the same time (the VM had one autologon, `Start-Process -Credential` from ssh fails with 0xC0000142 and a standard user may not run password tasks), so whether the second user's At-logon trigger is dropped by `IgnoreNew` while the first user's daemon runs is inferred from the manual start above, not observed; in proxy mode that user would have no proxy (the fixed port is taken anyway). A user signing in to the IdP, renewal, and Claude Code itself against the gateway were not run.

## What the emulated pilot needs

- A real (non-placeholder) fleet file: gateway URL, IdP profile, and for Windows an interpreter path that exists on the VM.
- macOS: sudo on a disposable user account or machine; `sudo installer -pkg ... -target /`, then log in as a second user to see the
  agent start; `uninstall.sh --purge-users` afterwards. Note the managed file applies to every Claude Code on the machine.
- Linux: a VM or container with systemd (`systemd --user` sessions) for `systemctl --user status` after login.
- Windows: done for one VM (see "What was tested"); `windows/pilot-mac.sh` repeats it. Still open: two simultaneous sessions (fast user switching or a terminal server) and a real sign-in.
- Pilot checks: `doctor` clean (hooks resolve, no `managed-config-conflict`), first prompt shows the sign-in, a renewal, proxy mode
  with two users getting different secrets, uninstall leaves no managed file.
