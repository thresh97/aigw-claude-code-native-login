# Known limitations and open questions

Gaps, not tested here. The README keeps the short ranked version; this is the full list. When something here gets run, move it to the [run log](runs.md) and the [findings](findings.md) and delete it from this page.

Open questions and gaps, not tested here:

- **Claude desktop app and Cowork.** This client can't route them: the app ignores `ANTHROPIC_BASE_URL` from settings (finding 16). See [Claude desktop app and Cowork](desktop-and-cowork.md) for the documented route, which wasn't run here. Cowork itself wasn't run.
- **Native Windows** (client 1.2.0; WSL works too: it's Linux). The offline scenarios pass on Windows 11, but these weren't run:
  - any live scenario (real IdP, gateway or stored login) on Windows;
  - the Task Scheduler task at a real log on, and its restart after a failure (only registered, read back and removed);
  - user-only permissions on `%APPDATA%\aigw-claude-auth` (no icacls; it relies on the profile's defaults);
  - a locked-down corporate image (AppLocker, Constrained Language Mode, which can block the toast);
  - `managed` (not ported) and the proxy's Unix-socket tries (no `AF_UNIX` in Windows Python).
- **More IdPs.** Ping (no dev tenant yet). Okta: no repro scenario yet (finding 21 by hand; finding 22 is the `gateway` scenario with an Okta JWT), no PKCE sign-in against it, no token inline hook, and the in-session sign-in (precheck) wasn't run against it. Mode A with a nested `defaults` straight from the IdP is shown only with Keycloak (finding 18). On Linux the Secret Service store ran only mocked (no `secret-tool` here).
- **Sign-in method by hand.** The detection rules ran only with mocked signals: no real `ssh -L`, container with a published port, VS Code dev container or WSL2 run yet.
- **`doctor` limits.** It reads files, not Claude Code's merged config. It checks the JWT's `iss` only (no config key for `aud` or the Mode A claims yet). It tells a SaaS gateway apart only by a `portkey.ai` host name. 8 of its findings have a `managed` case (finding 19); the rest have unit tests only.
- **SaaS gateway.** Per the notes above: Mode A only, `defaults.config_id`, no load balancer for the guard, so hooks only and `block_on_failure` stays `true`. No scenario has run against it.
- **Gateway API keys** instead of a JWT (see [Without a JWT](../../README.md#without-a-jwt-gateway-api-keys)): service and user keys, a revoked key's 401, and per-user attribution of user keys.
- **Also untested:**
  - 403 and 407 with a stored login;
  - on macOS: the live scenarios other than `stored_login_proxy` (the harness reads the stored login from the login Keychain and passes the real `HOME` to Claude Code for them), `claude -p` while signed out, and device code expiry.
- **Protecting the JWT and the refresh token at rest.** In file mode the JWT sits in the settings file; `mode: proxy` (1.4.0) keeps it in memory only. With a stored login through it (`stored_login_proxy`, 1.4.0, against the mock), a refused or missing JWT fails in one attempt and the login isn't rotated. The proxy against the real gateway has been run only by hand (2026-10-26: macOS with Claude Code 2.1.308, and an Ubuntu 26.04 container with Claude Code 2.1.311), not as a scenario. The refresh token is in the OS credential store since 1.3.0 (the file is the fallback). Options not built yet:
  - Claude Code permission rules that deny reading the files;
  - sender-constrained tokens, if the gateway ever supports them.

  Claude Code has no documented helper that supplies headers for model requests (as of 2.1.286). `apiKeyHelper` doesn't fit, since its value replaces the Anthropic login, and `proxyAuthHelper` doesn't reach the gateway (finding 11).
- **Token lifetime guidance.** The broker default is 1 h, renewed 5 min before expiry. A shorter JWT narrows the window for a stolen token or an offboarded user, because a Mode A JWT can't be revoked before it expires. A longer one means fewer IdP and broker calls and fewer renewals at prompt time. There's no recommendation yet. Also untested: how renewals behave across sleep, and the gateway's clock-skew tolerance on `exp`.
