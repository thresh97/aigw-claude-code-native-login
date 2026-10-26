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
    afterwards: "can't open file"); it removes our header lines and `~/.config/aigw-claude-auth` but leaves the `~/.claude/settings.json` file itself, Without purge the user keeps
    `~/.config/aigw-claude-auth/*` and the header line in `settings.json` (inert without the managed base URL and hooks).

Not covered: macOS and Windows privileged installs, LaunchAgent/Task Scheduler actually starting at login (systemd is covered above), the group-principal task
registering and firing, a real MDM push, signing, a logged-in-user `launchctl bootstrap` from the postinstall.

## What the emulated pilot needs

- A real (non-placeholder) fleet file: gateway URL, IdP profile, and for Windows an interpreter path that exists on the VM.
- macOS: sudo on a disposable user account or machine; `sudo installer -pkg ... -target /`, then log in as a second user to see the
  agent start; `uninstall.sh --purge-users` afterwards. Note the managed file applies to every Claude Code on the machine.
- Linux: a VM or container with systemd (`systemd --user` sessions) for `systemctl --user status` after login.
- Windows: elevated run of the installer on the VM, then logon as a second local user to confirm the group-principal task fires
  (`Get-ScheduledTask`, `Get-ScheduledTaskInfo`); registration of that XML has not been tried yet.
- Pilot checks: `doctor` clean (hooks resolve, no `managed-config-conflict`), first prompt shows the sign-in, a renewal, proxy mode
  with two users getting different secrets, uninstall leaves no managed file.
