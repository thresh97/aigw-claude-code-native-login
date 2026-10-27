# Fleet deployment (pilot / administrator preview)

> **Status: pilot.** This is a way to try rolling `aigw-claude-auth` out to many machines. It is not the supported baseline: the
> per-user install in the [README](../README.md) is. Nothing here has run on a real fleet, the packages are unsigned, and some paths are
> untested. Read "What to expect" before you plan around it.

One fleet file in; a macOS `.pkg`, a Linux `.deb` or `.rpm` and a Windows PowerShell installer out. They install the client, a
managed-settings drop-in (base URL, the two hooks, `allowedProviders`) and a login-time background entry for all users. At each login that
entry sets up the user's own settings and starts the daemon (in proxy mode, the proxy). The user signs in once, from the first Claude Code
prompt. The client stays one file, copied as is. The builder reads the client, so a package always carries the client's `VERSION`.

## Which OS and mode

| | File mode | Proxy mode |
|---|---|---|
| **macOS** | Emulated pilot passed (macOS 26.6, console user); one live fleet run with Okta and the real gateway (client 1.4.1). Not run: a second user's login, an MDM push | Live on one user (same run). Not run as a pilot |
| **Linux** (systemd user units) | Emulated pilot passed with two users at once, `.deb` on Debian 12 and `.rpm` on Rocky 9 | **One user per machine.** A second user's proxy cannot bind the fixed port and that user's Claude Code gets 498 from the first user's proxy. Passed with one user |
| **Windows** 11 | Emulated pilot passed (one VM, two standard users logging on one after the other, Python for all users). Two users logged on at the same time: untested | Emulated pilot passed, same limits. One user per machine, as on Linux |

*Emulated pilot* means a real privileged install and real logons on a disposable machine, without an MDM and without an IdP sign-in. The
dated record is in [packaging/README.md](../packaging/README.md#what-was-tested-offline-2026-10-26); the versions behind it are in the
[support matrix](support-matrix.md).

## What to expect

These are the shortcomings today, in the order they are likely to matter:

1. **Unsigned.** macOS needs a right-click open or an MDM push to get past Gatekeeper; Linux repositories are not signed or published; Windows scripts are not Authenticode signed. [Signing notes](../packaging/README.md#signing).
2. **No bundled interpreter.** macOS needs the Command Line Tools for `/usr/bin/python3`; Linux packages need `python3 >= 3.8`; Windows has no Python and the installer refuses to run without the `python.windows` path in your fleet file. A fleet that cannot assume Python must ship one (or compile the client) and point the fleet file at it.
3. **No upgrade or rollback policy.** The config is read from the install directory, not copied per user, so installing a newer package changes it for everyone at the next login. There is no tested rollback other than installing the previous package, and no staged-rollout tooling.
4. **Proxy mode is single-user.** See the table. Use file mode on shared hosts and terminal servers.
5. **The drop-in applies to every Claude Code on the machine**, not just the managed users. Plan the pilot on machines where that is acceptable.
6. **No MDM, Intune or SCCM delivery has been exercised**, and the Windows installer is a script, not an MSI, so those tools get no native install detection.
7. **A personal install is replaced**, not left alongside. The fleet's first run moves the user's personal config and background entry aside (renamed, not deleted) and forgets the personal refresh token in the credential store. The user signs in again through the fleet.

## Before you start

- Decide the mode with the README's guidance (file mode needs no daemon; proxy mode keeps the JWT in memory and answers 498 itself). Everything about the gateway, the IdP app and the passthrough config in the README applies unchanged.
- Get `doctor` clean on one machine installed by hand first. The fleet file's `idp` section takes any client config keys and is validated with the client's own validation when you build.
- Never put `ANTHROPIC_CUSTOM_HEADERS` in managed settings: a managed value replaces the user's, so the JWT (or in proxy mode the local secret) would not be sent. The generator does not.

## Build

```bash
cp packaging/fleet.example.json my-fleet.json      # keep the real one out of git; placeholders only in the example
python3 packaging/build.py render  --fleet my-fleet.json --out dist          # just the rendered files, per OS
python3 packaging/build.py macos   --fleet my-fleet.json --out dist [--sign "Developer ID Installer: Org (TEAMID)"]
python3 packaging/build.py linux   --fleet my-fleet.json --out dist [--rpm]  # needs Docker
python3 packaging/build.py windows --fleet my-fleet.json --out dist          # two scripts and a payload
```

The fleet file's keys and what lands where on each OS are in [packaging/README.md](../packaging/README.md#the-fleet-file).

## Pilot it

1. Render and read the files. Check the drop-in has your base URL, the hooks and no `ANTHROPIC_CUSTOM_HEADERS`.
2. Install on a **disposable** machine, with the emulated-pilot scripts if you want the whole cycle scripted: `packaging/linux/pilot-systemd.sh`, `packaging/macos/pilot.sh`, `packaging/windows/pilot-ssh.sh`. They are in [packaging/README.md](../packaging/README.md#what-the-emulated-pilot-needs).
3. Log in as a user and run `doctor`: no errors, and the hooks resolve. Send a prompt: it is blocked with a sign-in URL and a code. Sign in. The next prompt works.
4. Roll to one real user, then a few, watching `doctor` and `status` (`requests` in proxy mode shows what the proxy relayed).
5. Check uninstall on a pilot machine before you need it.

## Uninstall

All three remove their files, the background entry and the drop-in. Per-user data (the refresh token, `~/.config/aigw-claude-auth`, the header
lines in `settings.json`) is left, because an installer cannot act as every user; without the managed base URL and hooks it is inert.
Run `purge-user` as each user **before** removing the package (the launcher is gone afterwards), or use the macOS `uninstall.sh --purge-users` /
Windows `-PurgeCurrentUser`. Details: [packaging/README.md](../packaging/README.md#uninstall-and-what-it-leaves).

## Where the detail is

[packaging/README.md](../packaging/README.md) is the implementation reference and the test record: the fleet file, the install layout, per-user first
run, the takeover of a personal install, signing options and every pilot run with its findings. [Architecture](architecture.md) says how the
client works; the [support matrix](support-matrix.md) says what has been tested on which versions.
