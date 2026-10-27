# Re-run the tests

The offline scenarios take about 10 minutes and the live ones about 15, because two live scenarios wait out the OAuth loop.

1. Prerequisites: Python 3.8+ and Claude Code. `repro/run.py` is the runner on every OS (`py -3 repro\run.py` on Windows); `repro/run.sh` (bash 4+, curl; on macOS `brew install bash`) carries the same expectations and stays as the reference until it is retired, so change an expectation in both. For the live scenarios you also need:
   - everything in [What you need](../../README.md#what-you-need);
   - a dedicated Claude Code config dir with a stored login;
   - a prior `aigw-claude-auth login`, or a `TOKEN_COMMAND`.
   Run it outside a coding agent's sandbox: the scenarios listen on 127.0.0.1, and a sandbox that forbids that turns every scenario into `ERROR` with `PermissionError: [Errno 1] Operation not permitted`.
2. `cp repro/env.example repro/env` and fill it in. The offline scenarios need nothing in it.
3. `repro/run.py check` (read-only preflight).
4. `repro/run.py all --yes` (or one scenario from `repro/run.py list`). `stored_login`, `stored_login_proxy`, `live_login` and `client_live` require `--yes` because they:
   - rotate the stored login at Anthropic (it stays valid; `stored_login_proxy` should not rotate it, and checks that);
   - replace the `settings.json` in `LOGIN_CONFIG_DIR` for the run, restoring it afterwards. Until then the original sits in `settings.json.repro-backup`, so if a run is killed, the next one restores it.

   `managed` requires `--yes` and sudo. It writes the machine-wide managed-settings file for each case and removes it afterwards, and it refuses to run if one exists already. While it runs, other Claude Code sessions on the machine see each case's managed settings, so close them first. Its hooks only act in the scenario's own Claude Code processes.
5. Read `repro/results/<date>-<scenario>/summary.txt`:
   - `PASS`: matches Findings.
   - `CHANGED`: Claude Code or the gateway now behaves differently. For example, if a 401 no longer loops for a stored login, the LB guard and the StopFailure hook matter less. If hook timeouts or the settings reload changed, the client needs updating.
   - `ERROR`: the run broke; fix the environment, not the scripts.
   - `SKIP (windows)`: on Windows, the proxy scenario's Unix-socket tries (no `AF_UNIX` in Windows Python) and `managed` (sudo; not ported).

   Details are in `detail/`: request logs with credential fingerprints, and Claude Code's output.
