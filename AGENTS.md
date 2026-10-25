# AGENTS.md

Guidance for coding agents running or changing this repo. Read README.md first.

## What running this touches

- **Client install** (README 1.3, on a user's machine): `~/.local/bin/aigw-claude-auth`, `~/.config/aigw-claude-auth/`
  (`config.json`, `state.json` with the IdP refresh token, mode 600; while a hook-started sign-in is pending,
  `hook-login.json` and its `hook-login.log`), and edits to Claude Code's `settings.json`
  (`ANTHROPIC_BASE_URL`, the JWT in `env.ANTHROPIC_CUSTOM_HEADERS`, two hook entries). Optionally a systemd user unit or
  launchd agent.
- **Gateway** (README 1.1, 1.2, manual): a passthrough config in a workspace, and optionally ALB listener rules in front
  of the gateway. Both are shared infrastructure: get the operator's go-ahead first.
- **Offline scenarios** (`unit headers errors precheck stopfailure`): local only. Throwaway HOME, config dir and fake
  IdP under the run's results dir; a mock gateway on 127.0.0.1. Dummy credentials only.
- **`winprobe`** (`repro/winprobe.py`, spike S7): local only, no sudo or `--yes`. Throwaway HOME, USERPROFILE, APPDATA and
  Claude config dir under its `--out` dir, mock gateway on 127.0.0.1, dummy credentials. On Windows it also launches
  `powershell.exe` toasts (no registry or settings changes). Setup: `repro/WINDOWS.md`.
- **`gateway`**: requests to the real gateway with the JWT from `TOKEN_COMMAND` (default: the client's `token`), and
  one request with the stored login's access token from `LOGIN_CONFIG_DIR` (read, not refreshed).
- **`stored_login`, `live_login`, `client_live`** (need `--yes`): run Claude Code with the stored login in
  `LOGIN_CONFIG_DIR`. Claude Code's OAuth refresh rotates that login at Anthropic (it stays valid, but other copies of
  the old login stop working). The `settings.json` in that dir is replaced for the run and restored afterwards;
  the original is kept in `settings.json.repro-backup` (mode 600) until then, so after a killed run the next run of
  one of these scenarios restores it. `client_live` also
  refreshes the client's sign-in in `AIGW_CLAUDE_AUTH_DIR`.
- **`managed`** (needs `--yes` and sudo): writes the OS managed-settings file (`/Library/Application Support/ClaudeCode/`
  or `/etc/claude-code/`) as root for each case, and files in `managed-settings.d/` for the drop-in cases. It removes
  what it wrote, and the directories too if it created them. Refuses if a managed-settings file or a drop-in exists. Every Claude Code on the machine reads that file while a case runs; the scenario's
  hooks are guarded to act only in its own processes. A person runs this, not an agent: it needs the sudo password,
  and the managed settings would apply to an agent's own Claude Code too.
- **Results** (`repro/results/`, gitignored): request logs with credential fingerprints (length and a short hash),
  decoded non-secret claims, Claude Code's output. Never tokens.

## Rules

- **Secrets.** Never print, log or commit tokens, API keys, client secrets or JWTs. When inspecting JSON from a CLI
  or API that may carry secrets, select known-safe fields (`jq '{id, name}'`, or `jq 'keys'` first); don't rely on
  deleting the field names you expect.
- **Tenant data stays out of git.** Keep deployment facts in gitignored files. Don't add tenant or account IDs, URLs
  of your deployment, real IPs or customer names to tracked files; use placeholders (`<gateway>`, `<workspace uuid>`).
- **Only touch what you created.** Never delete objects you didn't create; others may share the tenant.
- **Report what you observe.** A result counts only if a log or response shows it. If a claim comes from docs or code
  reading rather than a run, say so.

## Cleanup (always finish with this)

1. The scenarios clean up after themselves (mock gateway, throwaway dirs, settings restore). Check that
   `LOGIN_CONFIG_DIR` has no leftover `settings.json.repro-backup`.
2. A client install on a real machine: README "4. Teardown".
3. Gateway passthrough config and ALB rules: remove only if you created them and nothing else uses them, with the
   operator's go-ahead.

## Changing the code

- `client/aigw_claude_auth.py` is one file, Python 3.8+, **standard library only**, macOS and Linux. Users copy it as
  is; don't split it or add dependencies. Bump `VERSION` when behavior changes.
- Run `python3 -m unittest -v client/test_aigw_claude_auth.py` (about 20 s, the `unit` scenario). New behavior needs a
  test against the `FakeIdP` there.
- Keep these in step:
  - config keys: `DEFAULTS` in the client, `client/config.example.json`, the README's config table;
  - commands and flags: the client's argparse, the README's client reference;
  - the sentinel and the 498 bodies: client `sentinel`, `gateway/alb-guard-ingress.yaml`, `GUARD_MESSAGES` in
    `repro/mock_gateway.py`, `SENTINEL` in `repro/env.example`;
  - hook entries: `hook_entry()` (used by `install` and `install --print`).
- Hooks must finish well inside Claude Code's 30 s hook timeout, or Claude Code ignores their decision. Anything
  that does network I/O in a hook uses `hook_http_timeout`. Anything that waits for the user (the precheck's sign-in)
  runs in a detached process whose stdout is not the hook's: Claude Code reads the hook's stdout until it closes.
- `repro/harness.py` drives Claude Code and prints `key=value` observations; `repro/run.sh` compares them with the
  expected values. Changing an expectation means the Findings in the README change too.
