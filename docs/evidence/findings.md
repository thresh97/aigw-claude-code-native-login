# Findings

Each record is one claim the project relies on, with what is needed to judge it later: the claim, the component versions it was observed
with, the environment, the method, the date, its status, and the command that reruns it. The claims are the README's former findings
table, word for word; the other fields come from the dated run log ([runs](runs.md)). Numbers are stable: the README, the code and the
design record refer to "finding N".

**Status** is *observed* (a run or a test showed it), *reported* (someone told us; not run) or *inferred* (read from code or documentation;
not run). A record can carry more than one. Behavior may change in later Claude Code or gateway releases: when a rerun disagrees, the
scenario reports `CHANGED`, and the record is updated with the new versions and date instead of being overwritten without trace.

### Finding 1

**The user's login and a gateway JWT travel together**

- **Claim:** With the passthrough config, Claude Code's own login in `Authorization` plus a gateway JWT in `x-portkey-api-key` (from `ANTHROPIC_CUSTOM_HEADERS`) gets a normal reply through the gateway
- **Component and version:** aigw-claude-auth 1.0.0; Claude Code 2.1.286 (Linux), 2.1.308 (macOS); hybrid gateway `gateway_enterprise` 2.29.0 (live)
- **Environment:** Linux (Python 3.10 to 3.12) and macOS 26.6 (Python 3.13); live against Entra ID, the broker and the gateway
- **Method:** `headers`, `gateway`, `client_live`
- **Date:** 2026-10-24
- **Status:** observed
- **Rerun:** `repro/run.py headers`; `repro/run.py gateway --yes` (live: your gateway, your IdP and a stored login; see [rerun](rerun.md)); `repro/run.py client_live --yes` (live: your gateway, your IdP and a stored login; see [rerun](rerun.md))

### Finding 2

**The gateway's refusals and Anthropic's look different**

- **Claim:** The gateway's own refusals (missing, garbage or tampered JWT) are 401 `Portkey Error: ...`. With a valid JWT, Anthropic's refusal of the login is relayed as 401 `anthropic error: ...` with `"provider":"anthropic"`. A `Bearer `-prefixed JWT is accepted
- **Component and version:** aigw-claude-auth 1.0.0; Claude Code 2.1.286 / 2.1.308; hybrid gateway 2.29.0
- **Environment:** live gateway
- **Method:** `gateway`
- **Date:** 2026-10-24
- **Status:** observed
- **Rerun:** `repro/run.py gateway --yes` (live: your gateway, your IdP and a stored login; see [rerun](rerun.md))

### Finding 3

**A gateway 401 starts Claude Code's own OAuth loop**

- **Claim:** With a stored login, Claude Code treats a gateway 401 as its own expired login: 13 attempts over about 4 minutes (the same against the mock), refreshing and rotating the Anthropic login each time; the login stays valid
- **Component and version:** Claude Code 2.1.286 / 2.1.308; hybrid gateway 2.29.0
- **Environment:** stored `claude login`, live gateway and the mock gateway
- **Method:** `live_login`, `stored_login`
- **Date:** 2026-10-24
- **Status:** observed
- **Rerun:** `repro/run.py live_login --yes` (live: your gateway, your IdP and a stored login; see [rerun](rerun.md)); `repro/run.py stored_login --yes` (live: your gateway, your IdP and a stored login; see [rerun](rerun.md))

### Finding 4

**A 498 is one attempt and leaves the login alone**

- **Claim:** With a stored login, a 498 is one attempt, shown at once, with the login untouched
- **Component and version:** Claude Code 2.1.286 / 2.1.308; hybrid gateway 2.29.0
- **Environment:** stored `claude login`, live gateway and the mock gateway
- **Method:** `live_login`, `stored_login`
- **Date:** 2026-10-24
- **Status:** observed
- **Rerun:** `repro/run.py live_login --yes` (live: your gateway, your IdP and a stored login; see [rerun](rerun.md)); `repro/run.py stored_login --yes` (live: your gateway, your IdP and a stored login; see [rerun](rerun.md))

### Finding 5

**Retries and StopFailure error types per status**

- **Claim:** With a `CLAUDE_CODE_OAUTH_TOKEN` login: 401 is 2 attempts; 403, 407 and 498 are 1 attempt each. The StopFailure hook gets `error: authentication_failed` for 401 and 403, `unknown` for 407 and 498
- **Component and version:** Claude Code 2.1.286 / 2.1.308
- **Environment:** `CLAUDE_CODE_OAUTH_TOKEN` login, mock gateway
- **Method:** `errors`, `stopfailure`
- **Date:** 2026-10-24
- **Status:** observed
- **Rerun:** `repro/run.py errors`; `repro/run.py stopfailure`

### Finding 6

**The load balancer rules answer the sentinel and a missing header**

- **Claim:** The ALB rules answer the sentinel and a missing header (on OAuth requests) with 498 before the gateway
- **Component and version:** hybrid gateway 2.29.0 behind an AWS ALB with the guard rules; Claude Code 2.1.308
- **Environment:** live gateway
- **Method:** `gateway`, `live_login`
- **Date:** 2026-10-24
- **Status:** observed
- **Rerun:** `repro/run.py gateway --yes` (live: your gateway, your IdP and a stored login; see [rerun](rerun.md)); `repro/run.py live_login --yes` (live: your gateway, your IdP and a stored login; see [rerun](rerun.md))

### Finding 7

**Claude Code re-reads a rewritten settings.json about 1 s later**

- **Claim:** A running Claude Code session picks up a rewritten `settings.json` (atomic rename) about 1 s later. With no wait, the next request still carries the old JWT
- **Component and version:** Claude Code 2.1.286 / 2.1.308
- **Environment:** Linux and macOS, mock gateway
- **Method:** `headers`, `precheck`
- **Date:** 2026-10-24
- **Status:** observed
- **Rerun:** `repro/run.py headers`; `repro/run.py precheck`

### Finding 8

**UserPromptSubmit hooks: timeout, fail-open, block**

- **Claim:** UserPromptSubmit hooks: a hook running past the default 30 s timeout is killed and the prompt is sent (fail-open); the entry's `timeout` field is honored; `{"decision":"block","reason":...}` blocks the prompt and shows the reason
- **Component and version:** Claude Code 2.1.286 / 2.1.308
- **Environment:** Linux and macOS, mock gateway
- **Method:** `precheck`
- **Date:** 2026-10-24
- **Status:** observed
- **Rerun:** `repro/run.py precheck`

### Finding 9

**The precheck renews an expired JWT before the turn**

- **Claim:** The client renews an expired JWT in the precheck before the turn, and the turn succeeds on the first request (live: Entra ID → broker → gateway → Anthropic). It blocks in time when the IdP hangs, and writes the sentinel when blocking is off
- **Component and version:** aigw-claude-auth 1.0.0; Claude Code 2.1.286 / 2.1.308
- **Environment:** offline, and live: Entra ID, broker, gateway, Anthropic
- **Method:** `precheck`, `client_live`
- **Date:** 2026-10-24
- **Status:** observed
- **Rerun:** `repro/run.py precheck`; `repro/run.py client_live --yes` (live: your gateway, your IdP and a stored login; see [rerun](rerun.md))

### Finding 10

**Signed out, the precheck starts a device code sign-in**

- **Claim:** Signed out, the precheck starts a device code sign-in in a detached process and blocks the prompt with the URL and code; Claude Code shows the reason as "UserPromptSubmit operation blocked by hook: AI gateway sign-in needed: ...". A second prompt before the sign-in is done gets the same code (one device flow). Once the user signs in, the JWT is written and the next prompt goes through on its first request. If the user declines at the IdP, the detached process logs and notifies the error (Entra: `authorization_declined AADSTS700171`) and the next prompt gets a new code. Repro against the fake IdP; also by hand against Entra ID on macOS
- **Component and version:** aigw-claude-auth 1.1.0; Claude Code 2.1.308
- **Environment:** offline against the fake IdP; also by hand against Entra ID on macOS 26.6
- **Method:** `precheck` (`hooklogin`), `unit`
- **Date:** 2026-10-24
- **Status:** observed
- **Rerun:** `repro/run.py precheck`; `repro/run.py unit`

### Finding 11

**Managed settings next to the user's settings**

- **Claim:** Managed settings (machine-wide file, root-owned) next to the user's `settings.json`: a managed `env.ANTHROPIC_CUSTOM_HEADERS` replaces the user's value, so the JWT isn't sent (401 from the gateway). Hooks and `ANTHROPIC_BASE_URL` from managed settings with the JWT in the user's file work: the precheck renews an expired JWT, and a JWT renewed during a session is picked up. With `allowManagedHooksOnly`, user hooks don't run and managed hooks do. A `settings.json` with mode 444 doesn't stop the client. With `chflags uchg` on it, renewal fails. 1.1.0's precheck let the prompt through with the expired JWT. 1.1.1 blocks it with "AI gateway: cannot renew the JWT: [Errno 1] Operation not permitted: ...", and no request reaches the gateway. A managed `proxyAuthHelper` adds no `Proxy-Authorization` header to requests to the gateway
- **Component and version:** aigw-claude-auth 1.1.0, then 1.1.1 (fixes the immutable case); Claude Code 2.1.308
- **Environment:** macOS 26.6, root-owned managed settings file
- **Method:** `managed`
- **Date:** 2026-10-25
- **Status:** observed
- **Rerun:** `repro/run.py managed --yes`, run by a person (it writes the machine-wide managed-settings file and needs sudo)

### Finding 12

**A local proxy can inject the gateway header**

- **Claim:** Through a local proxy that injects `x-portkey-api-key` from a file (prototype `repro/proxy_prototype.py`; `CLAUDE_CODE_OAUTH_TOKEN` login, mock gateway): the injected value reaches the gateway and a different JWT in the user's `ANTHROPIC_CUSTOM_HEADERS` is gone; `Authorization` and `anthropic-beta` arrive as sent; a token file changed between turns is used by the next request; chunked SSE sent 0.6 s apart through the proxy arrives event by event
- **Component and version:** prototype `repro/proxy_prototype.py` (client 1.4.0 later passes the same scenario); Claude Code 2.1.308
- **Environment:** macOS 26.6 (Python 3.13), mock gateway
- **Method:** `proxy`
- **Date:** 2026-10-25
- **Status:** observed
- **Rerun:** `repro/run.py proxy`

### Finding 13

**A proxy that turns a gateway 401 into 498 acts like the load balancer**

- **Claim:** A proxy that turns the gateway's 401 (`Portkey Error:`) into 498 with the load balancer guard's body behaves like the load balancer: 1 attempt, shown at once ("API Error: 498 ... AI gateway token expired ..."), StopFailure `error: unknown` (finding 5: direct 401 is 2 attempts, `authentication_failed`). Anthropic's relayed 401, passed through, is still 2 attempts with `authentication_failed`. With no usable token (file missing, empty, or the sentinel) the proxy answers 498 at once and sends nothing upstream (1 attempt, 0 upstream requests). With a stored `claude login` (macOS, kept in the login Keychain) through the proxy, a gateway 401 and a missing token are each 1 attempt, shown at once, the login neither rotated nor invalidated, and the next turn with a good token works (compare finding 3: 13 attempts without the proxy)
- **Component and version:** prototype proxy (2026-10-25); aigw-claude-auth 1.4.0 (2026-10-26); Claude Code 2.1.308
- **Environment:** macOS 26.6, stored login in the login Keychain, mock gateway
- **Method:** `proxy`, `stored_login_proxy`
- **Date:** 2026-10-25 and 2026-10-26
- **Status:** observed
- **Rerun:** `repro/run.py proxy`; `repro/run.py stored_login_proxy --yes` (live: your gateway, your IdP and a stored login; see [rerun](rerun.md))

### Finding 14

**Claude Code has no socket form of ANTHROPIC_BASE_URL**

- **Claim:** Claude Code 2.1.308 has no socket form of `ANTHROPIC_BASE_URL`: `unix://<path>`, `http+unix://<encoded path>` and `http://unix:<path>:/` reach no listener on the socket, and Claude Code retries the connection error with backoff (still going after 15 s; the debug log shows "API error (attempt N/11) ... Connection error."). The undocumented environment variable `ANTHROPIC_UNIX_SOCKET=<path>` (found as a string in the Claude Code binary) works from the process environment together with a plain `http://` `ANTHROPIC_BASE_URL`: the request, with `Authorization`, `anthropic-beta` and the custom header, reaches the listener and the reply is shown. Put in `settings.json` `env`, it had no effect (no request reached the socket). From reading the binary, not from a run: the variable is for socket-proxied sessions (it needs `CLAUDE_CODE_OAUTH_TOKEN`, otherwise requests carry no claude.ai login, and it skips the model catalog and bootstrap calls), so a stored `claude login` would not be sent through a socket
- **Component and version:** Claude Code 2.1.308
- **Environment:** macOS 26.6, mock gateway
- **Method:** `proxy`
- **Date:** 2026-10-25
- **Status:** observed; the note about what `ANTHROPIC_UNIX_SOCKET` is for is read from the binary, not run
- **Rerun:** `repro/run.py proxy`

### Finding 15

**Managed settings and the helper's own keys (spike S4)**

- **Claim:** Managed settings and the helper's own keys (spike S4). An unknown top-level key (`aigwClaudeAuth`) in `managed-settings.json` is ignored without a warning on stderr or in the stream output, and the rest of the file applies (its `ANTHROPIC_BASE_URL` and hooks). The key's value is not in the hooks' input JSON. `AIGW_*` keys in managed `env` reach the environment of the UserPromptSubmit and StopFailure hooks and of the Bash tool; for the same key, the managed value wins over the user's `settings.json` `env`, and the user's other `AIGW_*` keys stay. `managed-settings.d/*.json` drop-ins are merged with `managed-settings.json`: `env` keys from every file apply, a later file (by name) wins on a conflicting key, and hooks for the same event from different files all run. A drop-in with no `managed-settings.json` applies on its own
- **Component and version:** aigw-claude-auth 1.1.1; Claude Code 2.1.308
- **Environment:** macOS 26.6
- **Method:** `managed`
- **Date:** 2026-10-25
- **Status:** observed
- **Rerun:** `repro/run.py managed --yes`, run by a person (it writes the machine-wide managed-settings file and needs sudo)

### Finding 16

**The Claude desktop app ignores ANTHROPIC_BASE_URL from settings**

- **Claim:** The Claude desktop app (3.6556.2, macOS, signed in with claude.ai) runs Code sessions with its bundled Claude Code 2.1.308, started with the real `HOME`, no `CLAUDE_CONFIG_DIR`, `CLAUDE_CODE_ENTRYPOINT=claude-desktop`, `--setting-sources=user,project,local` and `ANTHROPIC_BASE_URL=https://api.anthropic.com` in its environment. Those sessions read `~/.claude/settings.json` and the project's `.claude/settings.json`: their `env` keys reach the session (`ANTHROPIC_CUSTOM_HEADERS`, `AIGW_*`), their hooks run (SessionStart, UserPromptSubmit, StopFailure; hooks added to a project file mid-session were picked up), and a UserPromptSubmit block shows its reason as is with nothing sent. But `ANTHROPIC_BASE_URL` from either file is ignored: requests stay on `api.anthropic.com` and no request reached the mock gateway. The CLI with the same base URL in its environment and the same project file uses the file's value. So the desktop app can't be routed to the gateway through settings; per the docs (not a run) it ignores managed settings for routing too and routes only through its third-party inference configuration, which replaces the claude.ai login
- **Component and version:** Claude desktop app 3.6556.2 (bundled Claude Code 2.1.308)
- **Environment:** macOS 26.6
- **Method:** by hand (mock gateway, logging hooks)
- **Date:** 2026-10-25
- **Status:** observed (by hand)
- **Rerun:** by hand; there is no scenario for it yet

### Finding 17

**Native Windows: hook shell and quoting (spike S7)**

- **Claim:** Native Windows (spike S7). **Hook shell:** with Git for Windows installed, Claude Code runs hook commands with Git Bash (`bash.exe -c "<command>"`, `MSYSTEM=UCRT64`), started from cmd.exe or from Windows PowerShell alike. Without Git for Windows it runs them with Windows PowerShell 5.1 (FullLanguage). **Quoting:** the client's current form (`shlex.quote`, single-quoted paths) works under Git Bash but doesn't run under PowerShell (parse error). A double-quoted program path as the first word doesn't run under PowerShell either (it needs `&`). Git Bash drops an unquoted backslash. Two forms ran in both shells: `py -3 "<script>" ...` and `powershell -NoProfile -Command "& '<python>' '<script>' '<arg>'"`. The second passed every argument intact in both. `%VAR%` is not expanded in either shell. Exec form (`"command": "<python.exe>"`, `"args": [...]`, from the hooks docs) ran in both cases, started directly by `claude.exe` with every argument verbatim (`$VAR` and `%VAR%` too), as did `"shell": "powershell"` with an `&` command. **Settings file:** 60 atomic replacements of `settings.json`, 0.1 s apart, during a running session got no PermissionError (a control that held the file open got winerror 5). The longest wait was 20 ms, and the new JWT was used 1.3 to 1.8 s later. **Toast:** a Windows PowerShell 5.1 WinRT toast from a hook exits 0 in about 1 s, with the PowerShell app ID and with its own app ID, and both appeared on the RDP desktop. On first use PowerShell writes a CLIXML progress record to stderr.
- **Component and version:** Claude Code 2.1.310; Git for Windows 2.56; Python 3.13.15
- **Environment:** Azure Windows 11 24H2 VM; three runs: PowerShell over SSH with and without Git, cmd.exe in an RDP session
- **Method:** `winprobe`
- **Date:** 2026-10-25
- **Status:** observed
- **Rerun:** `python3 repro/winprobe.py --out <dir>` on a Windows machine (see [repro/WINDOWS.md](../../repro/WINDOWS.md))

### Finding 18

**Keycloak: Mode A from the IdP, Mode B, refresh behaviour**

- **Claim:** Keycloak 26.4.7 (local, in Docker, dummy user). Discovery, device code (Keycloak always shows a consent page) and PKCE with a loopback redirect `http://127.0.0.1/*` on any port work with no client change. Protocol mappers emit the Mode A claims directly: a claim name with dots (`defaults.config_slug`) becomes a nested object, so Mode A needs no broker (Entra ID does); Claude Code sent that JWT to the mock gateway and the turn worked (Mode A from the IdP, `broker_url` empty). Mode B, a plain IdP token without those claims, reached the mock gateway too. Refresh: by default Keycloak returns a new refresh token but the old one stays valid; with "Revoke Refresh Token" on, replaying an old one revokes the whole chain and the user must sign in again. With `offline_access` the refresh token is an offline token that survives the end of the SSO session (a normal one doesn't); the admin "logout user" call revokes offline tokens too. A client that enforces PKCE (S256) refuses the device grant (`Missing parameter: code_challenge_method`): leave that setting off on clients used for device code. The default access-token lifespan (5 min) equals `refresh_before`, so the client would renew on every call: set it longer
- **Component and version:** aigw-claude-auth 1.3.0; Keycloak 26.4.7; Claude Code 2.1.308
- **Environment:** Docker on macOS 26.6, dummy user, mock gateway
- **Method:** `keycloak`
- **Date:** 2026-10-26
- **Status:** observed
- **Rerun:** `repro/run.py keycloak`

### Finding 19

**doctor and the preflight against real managed settings**

- **Claim:** `doctor` and the preflight against real managed settings (macOS, Claude Code 2.1.308): in every `managed` case `doctor --json` reports the expected finding. With managed `ANTHROPIC_CUSTOM_HEADERS`, a managed `ANTHROPIC_BASE_URL` other than the user's, or managed `AIGW_*` values that contradict the helper config, the precheck blocks the prompt with the finding and no request carries a JWT. A managed hook without `timeout` is a Warning and the turn still renews the JWT. With `allowManagedHooksOnly` and the hooks split over two drop-ins in `managed-settings.d/`, `doctor` finds nothing, the user's hook doesn't run and the JWT is renewed. A managed `apiKeyHelper` is a Warning. Findings 8, 11 and 15 are unchanged (their cases run with the preflight off)
- **Component and version:** aigw-claude-auth 1.3.0; Claude Code 2.1.308
- **Environment:** macOS 26.6, 19 managed cases
- **Method:** `managed`
- **Date:** 2026-10-26
- **Status:** observed
- **Rerun:** `repro/run.py managed --yes`, run by a person (it writes the machine-wide managed-settings file and needs sudo)

### Finding 20

**Windows Credential Manager: value size and network logons**

- **Claim:** Windows Credential Manager (Windows 11, interactive desktop session): one generic credential holds at most 2560 bytes (`CredWriteW` error 1783 beyond that), so the client splits longer values across `<target>`, `<target>#1`, ...; the round trip passes, nothing is left behind. In an ssh session every credential call fails with error 1312 (no credential set for a network logon), and the client falls back to `state.json` with a warning
- **Component and version:** aigw-claude-auth 1.3.0
- **Environment:** Windows 11, interactive desktop session and an ssh session
- **Method:** `unit` (real tests on Windows)
- **Date:** 2026-10-26
- **Status:** observed
- **Rerun:** `repro/run.py unit`

### Finding 21

**Okta by hand: claims, rotation and what Okta drops**

- **Claim:** Okta (Integrator org, custom authorization server `default`, Native app, device code): discovery offers the device grant and PKCE S256, and sign-in, refresh and `inspect` work with no client change; the access token lasts 1 h, `aud` is `api://default`. Custom claims reach the access token only when set for the Access Token; a literal value without double quotes is dropped without an error (an invalid expression), also from the ID token. A claim named `defaults.config_slug` arrives as a flat key with a dot, not a nested `defaults` object (Keycloak nests it, finding 18), so the gateway won't read it: `inspect` flags it (1.3.1). Refresh tokens rotate; the previous one still works within Okta's grace period (replayed at once: 200), and replayed after 35 s it's refused with `invalid_grant` and **the current refresh token is revoked too**: the user must sign in again. So two copies of `state.json` (a copied config, a restored backup) end the sign-in; the client's lock keeps one machine from replaying
- **Component and version:** aigw-claude-auth 1.3.0 (1.3.1 flags a flat `defaults.*` claim); Okta Integrator org, custom authorization server
- **Environment:** by hand
- **Method:** by hand
- **Date:** 2026-10-26
- **Status:** observed (by hand)
- **Rerun:** by hand; there is no scenario for it yet

### Finding 22

**Okta JWT against the hybrid gateway**

- **Claim:** Okta JWT against the hybrid gateway (`gateway` scenario, ALB guard on): with the broker's and Okta's JWKS URLs in one comma-separated value, Okta's JWT (Mode A claims, no `defaults`) is accepted (the broker's JWT wasn't sent in this run). The config then comes from the workspace: with the passthrough saved as a workspace config and set as the workspace's "default config for user API keys" (the config run: `provider` `anthropic`, `api_key` `unused`, `forward_headers` `authorization`, `api_key`, `anthropic-beta`, `anthropic-version`; it forwards `api_key` where [gateway/passthrough-config.json](../../gateway/passthrough-config.json) forwards `x-api-key`, and Claude Code sends neither with a claude.ai login; the repo's file wasn't run on this gateway), a valid JWT plus a real login gets Claude's reply, a bad login Anthropic's 401, no login Anthropic's 401 (`invalid x-api-key`); before that, the workspace's other default answered from Bedrock whatever the login. A config change took about 1 to 3 minutes to reach the gateway. With the org's `block_inline_config`, `x-portkey-config` is refused with 403 (even without a JWT) and `x-portkey-provider: anthropic` is ignored with a valid JWT. A saved config target with `provider` but no `api_key` is accepted by the UI and refused per request (400 `Invalid config passed`). A token without the `completions.write` scope gets the same results. `Bearer <jwt>` in `x-portkey-api-key` gets 400 (`Either x-portkey-config or x-portkey-provider header is required`): it isn't refused, but no default config applies. `client_live` with the Okta sign-in passes: Claude Code sends the client's Okta JWT, gets replies, and the precheck replaces an expired JWT before the turn (200, under 30 s)
- **Component and version:** aigw-claude-auth 1.4.0; hybrid gateway 2.29.0 behind the ALB guard; Claude Code 2.1.308; Okta Integrator org
- **Environment:** live gateway
- **Method:** `gateway`, `client_live`
- **Date:** 2026-10-26
- **Status:** observed
- **Rerun:** `repro/run.py gateway --yes` (live: your gateway, your IdP and a stored login; see [rerun](rerun.md)); `repro/run.py client_live --yes` (live: your gateway, your IdP and a stored login; see [rerun](rerun.md))
