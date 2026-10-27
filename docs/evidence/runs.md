# Run log

What was run, on which versions and where, in the order it happened. [Findings](findings.md) takes its component, environment and date fields from here. Add a line when you rerun something; do not edit an old line to match a newer result.

Tested 2026-10-24 against:
- Claude Code 2.1.286 and aigw-claude-auth 1.0.0, on Linux with Python 3.10 to 3.12; aigw-claude-auth 1.1.0 (the precheck's sign-in, finding 10) in the offline scenarios;
- the offline scenarios also on macOS 26.6 (Apple silicon) with Claude Code 2.1.308 and Python 3.13, plus by hand there: device code and browser (PKCE) sign-in against Entra ID, with 1.1.0 the precheck's sign-in against Entra ID, the launchd agent, the hooks in an interactive session and the Notification Center notice;
- on 2026-10-25, the `proxy` scenario on macOS 26.6 with Claude Code 2.1.308 and Python 3.13 (the prototype proxy, `repro/proxy_prototype.py`; findings 12 to 14), and `stored_login_proxy` with a stored login kept in the macOS Keychain (finding 13);
- on 2026-10-25, the `managed` scenario on macOS 26.6 with Claude Code 2.1.308, first with aigw-claude-auth 1.1.0, then with 1.1.1, which fixes the immutable case (finding 11); later the same day with the spike S4 cases (finding 15);
- on 2026-10-25, by hand, the Claude desktop app 3.6556.2 on macOS 26.6 (finding 16);
- on 2026-10-25, the `winprobe` probe (spike S7) on an Azure Windows 11 24H2 VM with Claude Code 2.1.310 and Python 3.13.15 installed for all users, three runs: from Windows PowerShell over SSH with and without Git for Windows 2.56, and from cmd.exe in the RDP desktop session with Git (finding 17);
- on 2026-10-26, aigw-claude-auth 1.4.0 (`mode: proxy`): `proxy` on macOS and the Windows 11 VM, and `stored_login_proxy` with a stored login on macOS, all `PASS`;
- on 2026-10-26, by hand, aigw-claude-auth 1.3.0 against an Okta Integrator org: device code sign-in, refresh rotation and replay, claims (finding 21);
- on 2026-10-26, the `gateway` scenario with Okta JWTs (aigw-claude-auth 1.4.0) against the hybrid gateway behind the ALB guard, with and without `completions.write`, and `client_live` with Okta and Claude Code 2.1.308, `PASS` (finding 22);
- on 2026-10-26, aigw-claude-auth 1.3.0 (credential store, sign-in method selection, `doctor`, `inspect`): the `managed` scenario on macOS 26.6 with Claude Code 2.1.308, 19 cases (finding 19), and the `keycloak` scenario against Keycloak 26.4.7 in Docker (finding 18); the offline scenarios again with 1.3.0, all `PASS` on macOS and on the Windows 11 VM (Claude Code 2.1.310);
- on 2026-10-26, aigw-claude-auth 1.2.0 (the Windows port) with `repro/run.py`: the offline scenarios `unit headers errors precheck stopfailure proxy` all `PASS` on the same Windows 11 VM (proxy: 55 observations, 7 Unix-socket ones `SKIP`) and on macOS 26.6 with Claude Code 2.1.308;
- a hybrid AI Gateway (`gateway_enterprise` 2.29.0) with JWT auth: Mode A, with Entra ID and a token broker, behind an AWS ALB with the guard rules.

Behavior may change in later releases.
