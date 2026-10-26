# aigw-claude-code-native-login

Claude Code users who sign in with their own Anthropic account (`claude login`, for example a Claude Enterprise seat) can still go through the AI Gateway, so the gateway sees, logs, guards and attributes every request. Claude Code keeps sending its Anthropic login in `Authorization: Bearer`, and the gateway passes it through to Anthropic. The gateway identifies the user by a short-lived JWT in a second header, `x-portkey-api-key`, or by a gateway API key in that header (see [Without a JWT](#without-a-jwt-gateway-api-keys)).

This article ships a small client, `aigw-claude-auth` (one Python file, standard library only). It gets that JWT from your IdP, directly or through a token broker, and keeps it fresh in Claude Code's settings. It also makes gateway auth failures fail fast. Without that, a gateway 401 sends a logged-in Claude Code into its own Anthropic OAuth refresh-and-retry loop for several minutes.

Use it when the users' Anthropic plan stays the billing and policy anchor, and the gateway adds identity, logging and guardrails on top.

> **Disclaimer:** This is a simple, art-of-the-possible example. It is **not** an official Palo Alto Networks, Portkey or Anthropic project, it is **not** a recommended or supported production design, and it comes with **no support**. Use it at your own risk, under the [MIT License](LICENSE).

![How it fits together: the client keeps a gateway JWT in Claude Code's settings; every request carries the user's Anthropic login and the JWT; the gateway checks the JWT and forwards the login to Anthropic](docs/flow.svg)

Shown with Entra ID and a token broker (Mode A), as tested. Without a broker (Mode B, or Mode A from an IdP that can emit Portkey's claims), the client puts the IdP's own token into the header.

| Piece                                    | What it does                                                                                                                                     | Where                                                              |
| ---------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------ |
| Gateway passthrough config               | Sends the request to Anthropic with the caller's own `Authorization` and `anthropic-beta` headers instead of a provider key                      | [gateway/passthrough-config.json](gateway/passthrough-config.json) |
| Gateway JWT auth                         | The gateway accepts a JWT: "Mode A" carries Portkey's own claims, from your IdP or a broker; "Mode B" is a plain IdP token (hybrid gateway only) | Your gateway (prerequisite)                                        |
| `aigw-claude-auth`                       | Signs in to the IdP once, then keeps a valid JWT in `env.ANTHROPIC_CUSTOM_HEADERS` of Claude Code's settings                                     | [client/aigw_claude_auth.py](client/aigw_claude_auth.py)           |
| Precheck hook (UserPromptSubmit)         | Before each prompt: renews an expired JWT and waits for Claude Code to reload it, or blocks the prompt with a sign-in message                    | `aigw-claude-auth hook precheck`                                   |
| StopFailure hook                         | After a turn failed on a gateway auth error: renews the JWT and notifies the user, so the retry works                                            | `aigw-claude-auth hook stop-failure`                               |
| LB guard (optional, hybrid gateway only) | Answers "no usable JWT" with 498 at the load balancer, which Claude Code shows at once                                                           | [gateway/alb-guard-ingress.yaml](gateway/alb-guard-ingress.yaml)   |

## Without a JWT: gateway API keys

A JWT isn't the only way to authenticate to the gateway. The gateway's own API keys go in the same header, `x-portkey-api-key`, and the rest of the layout stays as it is: Claude Code's Anthropic login in `Authorization`, and the passthrough config forwarding it.

- **AI Gateway service API keys:** one key per workspace, team or machine. The gateway knows the key, not the person.
- **AI Gateway user API keys:** one key per user, so requests are attributed to the person. This needs the SCM tenant onboarded with the customer's directory through Cloud Identity Engine (CIE), so the gateway knows the users.

Set it once, in `env.ANTHROPIC_CUSTOM_HEADERS` of Claude Code's settings (`x-portkey-api-key: <key>`), with the passthrough config bound to the key (or as the workspace default, see [The passthrough config](#what-you-need)). No client, broker or IdP sign-in is needed. The trade-offs, compared with the JWT:
- The key is a long-lived secret in the settings file. Rotation is manual, or done by another tool such as an MDM that rewrites the settings. Revoking it takes effect at once, unlike a JWT, which stays valid until it expires.
- A revoked or wrong key gets the gateway's 401, which sends a logged-in Claude Code into the OAuth loop described below. The StopFailure hook can't help: there's nothing to renew. The LB guard can only catch a missing header.

API keys are untested in the scope of this article, which covers the JWT path.

## Why the extra parts are needed

Claude Code sends whatever is in `ANTHROPIC_CUSTOM_HEADERS` and reloads the settings file when it changes, so a JWT in that header works. The hard part is what happens when the JWT is missing, expired or refused, because Claude Code can't tell a gateway 401 from an Anthropic 401:

| The gateway answers | Stored `claude login` | Login from `CLAUDE_CODE_OAUTH_TOKEN` |
|---|---|---|
| 401 (gateway refused the JWT, or Anthropic refused the login) | Treated as an expired Anthropic login: refresh at Anthropic and retry, 13 attempts over about 4 minutes, then "Failed to authenticate". Each refresh rotates the Anthropic login (it stays valid) | 2 attempts within seconds, then the message |
| 498 | 1 attempt; the status and message show at once; the login is untouched | 1 attempt, shown at once |
| 403, 407 | not tested | 1 attempt, shown at once |

So the client makes sure Claude Code seldom sends an unusable JWT, and turns "no JWT available" into something other than a 401:

1. **The daemon** renews the JWT 5 minutes before it expires. Normally that's all that runs.
2. **The precheck hook** covers the gaps, such as a laptop that slept through the expiry or a daemon that isn't running.
   - If the JWT is expired or nearly expired, the hook renews it and then waits 3 s, because Claude Code picks up the change about 1 s after the write.
   - If no JWT can be had, it **blocks the prompt**. Nothing reaches the gateway, so there is no 401 and no OAuth loop.
   - When the reason is that the user is signed out, the hook also starts a device code sign-in in the background, and the block message says what to do: "AI gateway sign-in needed: open <the IdP's device page> and enter the code ABCD-EFGH (within 15 min), then send your prompt again." Once the user has signed in, in any browser on any device, a background process stores the refresh token, writes a JWT and sends a notification. The resent prompt goes through. A prompt sent too early gets the same code again. So nobody has to leave the session for a terminal, and it works over ssh as well as on a desktop.
   - For other failures (IdP unreachable, broker refusing) the message is the error, e.g. "AI gateway: cannot reach ...".
3. **The sentinel.** When the client can't get a JWT and the current one is unusable, it writes `x-portkey-api-key: expired` instead of an old or empty value. With the optional LB guard, that request gets a 498 at once, also on machines where the hooks are off.
4. **The StopFailure hook** handles the rest: the gateway refused a JWT that still looked valid (revoked, or the signing key rotated). By then Claude Code has already failed the turn, so the hook renews the JWT and tells the user to retry.

## What you need

- **An AI Gateway that accepts a JWT** in `x-portkey-api-key` (for gateway API keys instead, see [Without a JWT](#without-a-jwt-gateway-api-keys)), in one of two ways:
  - **"Mode A":** the JWT carries Portkey's own claims (`portkey_oid`, `portkey_workspace`, a nested `defaults` object) and is signed by a key the gateway trusts. Your IdP can issue it directly if it can emit nested JSON claims (Keycloak can, finding 18). IdPs that can't need a broker that exchanges the IdP token for one: Entra ID (see article `aigw-entra-jwt-broker`), and Okta for the nested `defaults` (its claim expressions can't nest; Portkey's [JWT authentication with Okta](https://portkey.ai/docs/aigw/product/enterprise-offering/org-management/jwt/okta#jwt-authentication-with-okta) adds `defaults` through a token inline hook instead; finding 21);
  - **"Mode B":** your IdP's ordinary token; the gateway works out the organization and workspace from its own settings. Hybrid gateway only: the SaaS gateway takes Mode A only.
- **The passthrough config** ([gateway/passthrough-config.json](gateway/passthrough-config.json)), as the config the users' requests get. Either:
  - bind it to the credential: named in the JWT's claims, or bound to the service or user API key. Different users or groups in one workspace can then get different configs, and Claude Code's settings (or the MDM or Claude Enterprise policy that manages them) need to know nothing about configs or workspaces;
  - or make it the workspace default. That's simpler, but then everyone in the workspace who doesn't name a config gets that one.

  In the JWT, the hybrid gateway reads `defaults.config_slug` and ignores `defaults.config_id`; the SaaS gateway reads `defaults.config_id` (reported 2026-10-24, SaaS not tested here). The broker `aigw-entra-jwt-broker` sends both, with `config_id` falling back to the slug. The config's `api_key` is a placeholder. `forward_headers` sends the caller's `authorization` and `anthropic-beta` to Anthropic, so Anthropic sees the user's own login.
- **An IdP public client** (no secret) for the client to sign in with:
  - device code flow allowed (Entra: "Allow public client flows"), and/or the loopback redirect URI `http://127.0.0.1` for the browser flow (Entra: platform "Mobile and desktop applications"; it accepts any port on loopback). Without it, the browser sign-in fails with `AADSTS500113` (no reply address registered);
  - `offline_access` granted, so the IdP issues a refresh token;
  - with a broker, permission for its API scope (Entra: `api://<broker app>/access_as_user`).
- **Okta specifics** (finding 21; Portkey's setup: [JWT authentication with Okta](https://portkey.ai/docs/aigw/product/enterprise-offering/org-management/jwt/okta#jwt-authentication-with-okta)):
  - a custom authorization server (`https://<org>.okta.com/oauth2/default` or your own); the gateway's JWKS URL is `<issuer>/v1/keys` and must start with the token's `iss`;
  - an OIDC **Native Application** with the grant types Authorization Code, Refresh Token and Device Authorization, sign-in redirect URI exactly `http://127.0.0.1:<port>/` with the same port in the client's `redirect_port` (Okta matches exactly), no custom-scheme redirect; the server's access policy rule must allow the same grant types;
  - the claims on the **access token** (Include in token type: Access Token; Include in: Any scope): `portkey_oid`, `portkey_workspace`, and `scopes` = `access.scope` (the gateway reads `scope` or `scopes`, Okta writes `scp`). A literal value needs double quotes (`"my-workspace"`): unquoted, it's an expression, and a failing expression drops the claim without an error;
  - a custom scope `completions.write` (User consent: Implicit) on the authorization server, as in Portkey's setup, requested by the client: `"scope": "openid offline_access completions.write"`. Seen 2026-10-26: Okta then lists it in both `scp` and `scopes`. The hybrid gateway doesn't require it: a token without it got the same results (finding 22);
  - `defaults` only through a token inline hook or a broker; check the token with `aigw-claude-auth inspect`. For mapping Okta groups to workspaces, defaults and limits, see the design's [Mapping IdP groups to gateway workspaces](docs/design-v2.md#mapping-idp-groups-to-gateway-workspaces-mode-a): the broker is the recommended route; the Okta-native route uses the reference hook in [gateway/okta-token-hook/](gateway/okta-token-hook/) (offline tests only so far). Put every Mode A claim in the hook: it fails open.
- **Users with an Anthropic login** in Claude Code (`claude`, then `/login`).
- **Python 3.8+** on the users' machines: macOS, Linux or native Windows (`py -3` from python.org). No packages.
- **Optional, for the LB guard:** an AWS ALB in front of a hybrid gateway. Any L7 load balancer that can match headers and return a fixed response works the same way. With the SaaS gateway there's no load balancer of yours in front of it, and an L4/TLS passthrough load balancer can't match headers; in both cases rely on the hooks alone (a refused or missing JWT is then the gateway's 401).

## 1. Build

### 1.1 Gateway

1. Create the passthrough config from [gateway/passthrough-config.json](gateway/passthrough-config.json) in the users' workspace, and make it the config their requests get: bound to the credential (the JWT's `defaults.config_slug` on a hybrid gateway or `defaults.config_id` on SaaS, or the API key), or as the workspace default (see What you need).
2. Check that the gateway's JWT validation (JWKS URL, issuer, audience) accepts your IdP's or broker's tokens. The JWKS URL setting is per org and takes a comma-separated list, so one gateway can trust a broker and an IdP at once (operator's statement; with both listed, Okta's JWT is accepted, finding 22). Without `defaults` in the JWT, set the passthrough as the workspace's default config ("default config for user API keys"); a per-request `x-portkey-config` is refused when the org blocks inline config (finding 22).

### 1.2 Optional: answer token problems at the load balancer

[gateway/alb-guard-ingress.yaml](gateway/alb-guard-ingress.yaml) has the rules as AWS Load Balancer Controller annotations. They are evaluated in this order:

1. `x-portkey-api-key: expired` (the client's sentinel) → 498 `gateway_token_error` "expired".
2. Any other `x-portkey-api-key` → forward to the gateway.
3. No `x-portkey-api-key`, and `anthropic-beta` contains `oauth-2025-04-20` (a native-login Claude Code request) → 498 "missing".
4. Everything else → forward.

How the rules behave:
- Only requests without a usable JWT get a fixed response. Everything else is forwarded unchanged, at no extra cost.
- A present but invalid JWT still gets the gateway's 401. The hooks handle that case.
- An ALB condition can't single out an empty header value: `*` matches it too, and rule values can't be empty. That's why the client writes the sentinel and never an empty header.

With a plain ALB listener (no Kubernetes), create the same three rules with `aws elbv2 create-rule`, at priorities ahead of the default forward.

### 1.3 Client, per user

```bash
# 1. Install (one file). Keep "aigw-claude-auth" in the name: install uses it to find its own hook entries.
mkdir -p ~/.local/bin ~/.config/aigw-claude-auth
cp client/aigw_claude_auth.py ~/.local/bin/aigw-claude-auth && chmod +x ~/.local/bin/aigw-claude-auth

# 2. Configure (see "Client reference" below; the example is Mode A with Entra ID and a broker).
#    Desktop notifications are on by default ("notify": "auto"); set "notify" to "off" or a command to change that.
cp client/config.example.json ~/.config/aigw-claude-auth/config.json && ${EDITOR:-vi} ~/.config/aigw-claude-auth/config.json

# 3. Sign in to the IdP once: browser flow on a desktop, device code over ssh or without a display (--device forces it)
aigw-claude-auth login

# 4. Point Claude Code at the gateway and add the hooks (edits ~/.claude/settings.json, or $CLAUDE_CONFIG_DIR/settings.json)
aigw-claude-auth install --base-url https://<gateway host>

# 5. Keep the JWT fresh in the background
#    Linux (systemd user unit):
mkdir -p ~/.config/systemd/user && cp client/service/aigw-claude-auth.service ~/.config/systemd/user/
systemctl --user daemon-reload && systemctl --user enable --now aigw-claude-auth
#    macOS (launchd):
#    sed "s#HOME_DIR#$HOME#g" client/service/aigw-claude-auth.plist > ~/Library/LaunchAgents/aigw-claude-auth.plist
#    launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/aigw-claude-auth.plist

# 6. Sign in to Anthropic in Claude Code as usual, if not done yet
claude        # then /login
```

**Fleet packages.** For many machines, build packages from one fleet file with `packaging/build.py` (macOS `.pkg`, Linux `.deb`/`.rpm`, a Windows PowerShell installer; see [packaging/README.md](packaging/README.md)). They install the client, a managed-settings drop-in (`managed-settings.d/50-aigw-claude-auth.json`: base URL, hooks, `allowedProviders`, `AIGW_*` env, never `ANTHROPIC_CUSTOM_HEADERS`) and a login-time background entry for all users. At each login that entry runs `install --no-hooks` for the user (the JWT line in file mode, the user's own proxy secret in proxy mode) and then the daemon; the user only signs in once. Unsigned. Emulated pilot (real privileged installs, real logons, no MDM) passed on Linux (systemd container) and the Windows VM; macOS is person-run with `packaging/macos/pilot-mac.sh`. Several users logged in at once is out of scope: proxy mode doesn't support it, Windows file mode is untested (packaging/README.md, "Several users at once").

On native Windows (Windows PowerShell; Python 3.8+ from python.org as `py -3`), the same steps with Windows paths. The
config folder is `%APPDATA%\aigw-claude-auth`, and the background refresher is a Task Scheduler task:

```powershell
New-Item -ItemType Directory -Force "$env:USERPROFILE\.local\bin", "$env:APPDATA\aigw-claude-auth" | Out-Null
Copy-Item client\aigw_claude_auth.py "$env:USERPROFILE\.local\bin\aigw-claude-auth.py"
Copy-Item client\config.example.json "$env:APPDATA\aigw-claude-auth\config.json"; notepad "$env:APPDATA\aigw-claude-auth\config.json"
$a = "$env:USERPROFILE\.local\bin\aigw-claude-auth.py"
py -3 $a login
py -3 $a install --base-url https://<gateway host>
py -3 $a task install      # at log on, as you, one instance, restart on failure, pythonw (no window)
```

On Windows, `install` writes the hooks in Claude Code's exec form (`command` is the absolute `python.exe`, `args` start
with the script path). That form uses no shell, so the hooks work whether or not Git for Windows is installed (finding 17).

`install` keeps everything else in the settings file, including other headers in `ANTHROPIC_CUSTOM_HEADERS`, other hooks and other keys. It's safe to run again: it replaces only its own entries.

**The background refresher (step 5).** The systemd unit or launchd agent runs `aigw-claude-auth daemon` from login onward:
- About once a minute it runs `sync`. That's a local check of the JWT's expiry in the settings file, with no network traffic until a renewal is due.
- Within `refresh_before` (5 min) of expiry, it renews through the IdP (and broker) and rewrites the settings. Running Claude Code sessions pick that up about 1 s later.
- After sleep, it catches up within a minute of waking.
- On failures (IdP unreachable, signed out) it retries with backoff from 30 s to 5 min, keeps a JWT that still works, and writes the sentinel only when the JWT is about to run out. After `aigw-claude-auth login` it carries on by itself.
- It logs renewals and failures only: `journalctl --user -u aigw-claude-auth` on Linux, `~/Library/Logs/aigw-claude-auth.log` on macOS (never rotated; it grows slowly), `%LOCALAPPDATA%\aigw-claude-auth\logs\daemon.log` on Windows (not rotated either).
- The service manager restarts it if it crashes, but not after a clean stop.

It's optional. Without it, the precheck hook renews before the prompt that needs it, at the cost of a pause of about 3 s. To check it's working: `systemctl --user status aigw-claude-auth` or `launchctl print gui/$(id -u)/aigw-claude-auth | head`, and `aigw-claude-auth status` shows a new fingerprint and expiry after each renewal. On macOS the agent runs `/usr/bin/python3`, which works only with the Xcode Command Line Tools installed (`xcode-select --install`). With a different Python, change the path in the plist.

**Trial install (your everyday Claude Code untouched).** Claude Code re-reads its settings about a second after they change. So `install` on `~/.claude/settings.json` reroutes every running Claude Code session, including an agent doing the install. To try it first, use a separate Claude Code config dir. That dir needs its own `/login`:

```bash
export CLAUDE_CONFIG_DIR=~/.claude-aigw
claude                                                   # /login once, then exit
aigw-claude-auth install --base-url https://<gateway host>   # edits only ~/.claude-aigw/settings.json
CLAUDE_CONFIG_DIR=~/.claude-aigw claude                  # a session through the gateway
```

For the daemon, set the same `CLAUDE_CONFIG_DIR` in the unit (`Environment=`) or the plist (`EnvironmentVariables`). The hooks need nothing: they inherit the environment of the Claude Code that runs them, `CLAUDE_CONFIG_DIR` included. To go live later, run `install` again without `CLAUDE_CONFIG_DIR`.

**Fleet rollout (managed settings).** IT can ship the hooks and `ANTHROPIC_BASE_URL` in Claude Code's managed settings:
1. Print the snippet with `aigw-claude-auth install --print --base-url https://<gateway host> --hook-command /usr/local/bin/aigw-claude-auth`.
2. For each user, run `aigw-claude-auth install --no-hooks`, which only writes the JWT.

Constraints (finding 11):
- Managed settings must **not** set `ANTHROPIC_CUSTOM_HEADERS`. A managed value replaces the user's whole value, so the JWT isn't sent. The JWT has to live in the user's settings file, which the client rewrites.
- With `allowManagedHooksOnly`, user hooks don't run, so the hooks must come from managed settings.
- The user's `settings.json` must stay writable for the user. A read-only mode (444) is fine, because the client replaces the file. An immutable flag (macOS `chflags uchg`) isn't: the client can't renew the JWT, and from 1.1.1 the precheck blocks the prompt with the error.

## 2. Quick check

```bash
aigw-claude-auth status          # signed in? JWT fingerprint, expiry, iss/sub/portkey_workspace (never the token)

# The gateway accepts the JWT and passes a (deliberately invalid) Anthropic login through:
curl -s https://<gateway host>/v1/messages -H "x-portkey-api-key: $(aigw-claude-auth token)" \
  -H 'content-type: application/json' -H 'anthropic-version: 2023-06-01' \
  -H 'authorization: Bearer sk-ant-oat01-invalid' -H 'anthropic-beta: oauth-2025-04-20' \
  -d '{"model":"claude-haiku-4-5","max_tokens":8,"messages":[{"role":"user","content":"hi"}]}'
# expect: 401 ... "anthropic error: OAuth access token is invalid." ... "provider":"anthropic"

# A real turn with the user's own login:
claude -p "Reply with exactly: OK" < /dev/null
```

If the curl shows `Portkey Error: ...` (for example `Invalid API Key. Error Code: 03` or `JWT verification failed`), the gateway refused the JWT. Check the gateway's JWT validation and the claims in `aigw-claude-auth status`.

## 3. End-to-end test

`repro/run.sh` tests the whole design (how to run it: [Re-run](#re-run)). The offline scenarios run the real Claude Code against a mock gateway and a fake IdP, so they need no accounts. The live ones use your gateway, IdP and Anthropic login.

| Scenario | Shows | Needs |
|---|---|---|
| `unit` | The client's 30 unit tests: settings edits, refresh, sentinel, device and PKCE sign-in, hooks, daemon | Python |
| `headers` | `install`; Claude Code sends both credentials; a running session picks up a renewed JWT | Claude Code |
| `errors` | How Claude Code treats 401 (gateway and Anthropic), 403, 407 and 498 with an env-token login | Claude Code |
| `precheck` | Renew before the request; no-op while valid; why `hook_wait` matters; block when no JWT can be had (signed out, IdP hanging); the device code sign-in offered in the block message and the resent prompt going through; the LB guard path with blocking off | Claude Code |
| `stopfailure` | Renew and notify after a refused JWT; Anthropic-side failures left alone | Claude Code |
| `proxy` | The client's local proxy (`mode: proxy`, 1.4.0; [design-v2](docs/design-v2.md), Mode 2) in front of the mock: per-user secret header required and stripped, renew and retry once on a gateway 401, header injected, client value stripped, SSE streamed, a gateway 401 turned into 498 (one attempt), an Anthropic 401 passed through, no token fails closed; which Unix socket base URLs Claude Code accepts | Claude Code |
| `stored_login` | Stored login against the mock: 498 fails once; a gateway 401 runs the OAuth loop | a stored login |
| `stored_login_proxy` | Stored login through the client's proxy and the mock: a refused JWT fails in one attempt, no OAuth loop | a stored login |
| `gateway` | The real gateway, request by request: which failures are the gateway's, and passthrough works | gateway, JWT |
| `live_login` | Real gateway and stored login: a refused JWT costs the OAuth loop; with the LB guard, sentinel and missing header fail at once | gateway, JWT, stored login |
| `client_live` | The client for real: IdP (and broker) → JWT → gateway → Anthropic; the precheck replaces an expired JWT before the turn | everything, after `aigw-claude-auth login` |
| `managed` | Managed settings next to the user's file: a managed `ANTHROPIC_CUSTOM_HEADERS` vs the user's JWT, hooks from managed settings, `allowManagedHooksOnly`, a read-only or immutable `settings.json`, `proxyAuthHelper` | Claude Code, sudo, no managed settings on the machine yet |

## 4. Teardown

Per user:

```bash
systemctl --user disable --now aigw-claude-auth && rm ~/.config/systemd/user/aigw-claude-auth.service   # Linux
launchctl bootout gui/$(id -u)/aigw-claude-auth && rm ~/Library/LaunchAgents/aigw-claude-auth.plist      # macOS
py -3 $env:USERPROFILE\.local\bin\aigw-claude-auth.py task remove                                          # Windows
aigw-claude-auth logout          # forgets the refresh token, writes the sentinel
```

Then:
1. In `~/.claude/settings.json`, remove `ANTHROPIC_BASE_URL`, the `x-portkey-api-key` line in `ANTHROPIC_CUSTOM_HEADERS`, and the two hook entries whose command contains `aigw-claude-auth`.
2. Delete `~/.config/aigw-claude-auth` and `~/.local/bin/aigw-claude-auth` (Windows: `%APPDATA%\aigw-claude-auth` and `%USERPROFILE%\.local\bin\aigw-claude-auth.py`).

On the gateway side, remove the passthrough config and the LB rules if nothing else uses them.

## Client reference

Usage: `aigw-claude-auth <command>`. Global options: `--config FILE`, `--state-dir DIR`, `--settings FILE`, `--version`.

| Command | What it does |
|---|---|
| `login [--device \| --pkce \| --pkce-print \| --paste] [--no-browser]` | Sign in to the IdP, then write a JWT. `--pkce` opens a browser here; `--pkce-print` (or `--pkce --no-browser`) prints the URL, and that browser must reach `127.0.0.1:<redirect_port>` on this host (for example `ssh -L <port>:127.0.0.1:<port> <host>`); `--paste` prints the URL, you sign in in any browser and paste the `http://127.0.0.1:...` address you end up on (no listener, no device grant); `--device` uses a device code. With no flag, see [Sign-in method](#sign-in-method) |
| `install [--base-url URL] [--no-hooks] [--hook-command CMD] [--print]` | Add `ANTHROPIC_BASE_URL` and the hooks to the settings file (or print the snippet), then `sync`. On Windows the hooks are in exec form; `--hook-command` is still a shell string |
| `sync [--force] [--quiet]` | Make sure the settings hold a JWT valid for more than `refresh_before` seconds |
| `daemon [--max-sleep 60]` | Run `sync` ahead of every expiry. It naps at most `--max-sleep` seconds, so it catches up within a minute after a laptop wakes. On failures it backs off from 30 s to 5 min |
| `token [--force]` | Print a valid JWT on stdout (for curl and scripts); also updates the settings |
| `status` | Settings file, token source, sign-in state, where the refresh token lives (never its value), JWT fingerprint, expiry and the `iss`/`sub`/`portkey_workspace` claims |
| `proxy` | Run the local proxy in the foreground (proxy mode; `daemon` runs it in the background under the single-instance lock). The launchd agent (`KeepAlive`), systemd unit (`Restart=on-failure`) and Task Scheduler task (restart on failure) restart it after a crash |
| `inspect [--live] [--fresh] [--show-claims] [--debug on\|off]` | Decode the JWT: header, times, Mode A claims, verdicts against the config, its source. Prints a `PROBLEM` line and exits 1 for `alg: none`, expired, not yet valid, no `exp`, issuer mismatch (Mode B), opaque token or the sentinel. Never prints the token or signature; redacts `sub`, email and groups unless `--show-claims`. `--fresh` mints a token without writing it. `--debug on` logs a summary at each renewal for 24 h |
| `doctor [--json]` | Read every config source (helper config, user settings, the managed file and `managed-settings.d/`, the macOS managed preferences, the Windows `HKLM`/`HKCU` policy, `AIGW_*` keys in managed `env`) and list findings as Error, Warning or Info, each with a fix. Exits 1 on any Error. Works with a broken config. Server-managed settings show as unknown |
| `hook precheck`, `hook stop-failure` | The two Claude Code hooks. They read the hook payload on stdin and always exit 0 |
| `hook-login-wait` | Internal: the precheck's background sign-in. It reads the device authorization response on stdin, waits for the user, writes the JWT, notifies and exits |
| `logout` | Forget the refresh token, write the sentinel |
| `task install \| remove \| print [--name NAME]` | Windows: register or remove a Task Scheduler task that runs `daemon` at log on (current user, one instance, restart on failure, `pythonw.exe`). `print` shows the task XML and registers nothing, on any OS |

**Files and locking:**
- `~/.config/aigw-claude-auth/config.json` (Windows: `%APPDATA%\aigw-claude-auth\config.json`) holds your config. The refresh token is in the OS credential store (macOS Keychain, Linux Secret Service through `secret-tool`, Windows Credential Manager; service `aigw-claude-auth`, account `state-<hash of the state dir>`) unless `secret_store` is `file` or no store works; then `state.json` holds it. `state.json` (mode 600) also holds the discovered endpoints, the last sign-in method and learned refusals, never the JWT. A token found in `state.json` moves to the store on the next run. Limits: on macOS a secret over about 3900 characters stays in the file (`security -i` line limit); on Linux the store needs `secret-tool` and a session bus; on Windows an ssh or service session has no credential store (error 1312), so the file is used there, and values over 2560 bytes are split across several credentials (finding 20). Override the directory with `AIGW_CLAUDE_AUTH_DIR`. Mode 600 means nothing on Windows; the folder relies on the profile's default user-only permissions.
- While a sign-in started by the precheck is pending, `hook-login.json` (mode 600) next to `state.json` holds its user code, URL, expiry and the waiting process's pid. The device code itself is passed to that process on stdin and never written. The process logs to `hook-login.log` there. `status` shows a pending sign-in.
- The settings file is the first of: `--settings`, `AIGW_CLAUDE_SETTINGS`, `$CLAUDE_CONFIG_DIR/settings.json`, `~/.claude/settings.json`.
- Every write is atomic (temp file, fsync, rename, mode 600).
- A lock serializes the daemon and the hooks. The interactive part of `login` runs outside it, so a slow sign-in doesn't stall the hooks.

**Config keys** (unknown keys are an error):

| Key | Default | Meaning |
|---|---|---|
| `issuer` | | OIDC issuer; endpoints come from its discovery document |
| `token_endpoint`, `device_authorization_endpoint`, `authorization_endpoint` | | Set explicitly to override discovery |
| `client_id` | | The IdP public client |
| `scope` | `openid offline_access` | Add the gateway's or broker's scope. `offline_access` is what gets a refresh token |
| `idp_token` | `access_token` | Which IdP token to use: `access_token` or `id_token` |
| `broker_url` | | Full exchange URL (Mode A through a broker). The IdP token is sent as `Authorization: Bearer`, and the response's `token` (or `access_token`) is the gateway JWT. Empty: the IdP token itself is the JWT (Mode B, or Mode A from an IdP that emits Portkey's claims) |
| `token_command` | | Instead of an IdP: a command that prints a JWT, for example a corporate token tool. `login` doesn't apply then |
| `header` | `x-portkey-api-key` | The header the gateway reads the JWT from |
| `sentinel` | `expired` | Written when no usable JWT can be had. Must match the LB rule, and can't be empty |
| `refresh_before` | `300` | Renew when fewer seconds than this are left |
| `hook_wait` | `3` | Seconds the precheck hook waits after a write, so the request carries the new value |
| `block_on_failure` | `true` | When there's no usable JWT, the precheck blocks the prompt. With `false` the prompt goes out with the sentinel, for setups that rely on the LB guard (never with the SaaS gateway, where the sentinel gets a 401 and the OAuth loop) |
| `hook_login` | `auto` | When signed out, what the precheck does: `auto` uses the same choice as `login` (see [Sign-in method](#sign-in-method)), preferring the last method that worked, and puts a device code or a sign-in URL into the block message; `device` always uses a device code; `off` only says to run `aigw-claude-auth login`. `AIGW_HOOK_LOGIN` (`auto`, `device`, `off`) overrides it: set `off` in CI and for `claude -p` |
| `login_method` | `auto` | `auto`, `device`, `pkce`, `pkce-print` or `pkce-paste`. Overridden by `login` flags and `AIGW_LOGIN_METHOD` |
| `device_unavailable_ttl` | `86400` | Seconds to remember that the IdP refused the device grant or the loopback redirect |
| `secret_store` | `auto` | `auto`: refresh token in the OS credential store, the file if none works; `file`: `state.json` only |
| `mode` | `file` | `file`: the JWT is written into `settings.json`. `proxy`: a local proxy (run by `daemon`, or `proxy` in the foreground) keeps the JWT in memory, injects it, and turns a gateway refusal into 498 after one renew-and-retry; `install` then writes `ANTHROPIC_BASE_URL=http://<proxy_listen>` and the per-user secret header, no JWT |
| `proxy_listen` | `127.0.0.1:18787` | The proxy's address. Loopback only; non-loopback addresses are refused. Every request must carry the per-user secret in `x-aigw-local` (written by `install` into `ANTHROPIC_CUSTOM_HEADERS`, kept in the state dir with mode 600, stripped before forwarding), so other local users and web pages can't use the proxy |
| `gateway_url` | | Proxy mode: the gateway the proxy forwards to (required) |
| `debug_until` | `0` | Set by `inspect --debug on`; while in the future, each renewal logs a summary (no `sub`, no token) |
| `notify` | `auto` | Desktop notification after a StopFailure renewal and when the precheck's background sign-in succeeds or fails: `auto` (macOS Notification Center, `notify-send` on Linux, a Windows PowerShell toast on Windows), `off`, or a command that gets the message as `$1` |
| `redirect_uri`, `redirect_port` | `http://127.0.0.1:{port}/`, `0` | PKCE loopback redirect; port `0` picks a free port. Set a fixed port where the IdP needs an exact match (Okta, Ping), or to forward it with `ssh -L` or publish it from a container |
| `http_timeout` | `30` | Seconds per IdP or broker request, outside hooks |
| `hook_http_timeout` | `5` | Seconds per request inside hooks (see "Hook time budget" below) |

### Sign-in method

First match wins: a `login` flag; `AIGW_LOGIN_METHOD`; config `login_method`; the method of the last successful sign-in, if it works here; auto-detection. Auto-detection treats ssh and containers as headless (unless `BROWSER` is set), VS Code remote as a desktop, WSL as a desktop when `wslview` or `explorer.exe` exists, macOS as a desktop when `launchctl print gui/$UID` succeeds, Linux as a desktop with `DISPLAY` or `WAYLAND_DISPLAY`, and Windows as a desktop in an interactive, non-ssh session. On a desktop it tries `pkce`, `device`, `pkce-print`, `pkce-paste`; headless `device`, `pkce-print` (only with a fixed `redirect_port`), `pkce-paste`. It skips what the IdP's discovery document doesn't offer, and for `device_unavailable_ttl` what the IdP refused (`unauthorized_client`, `invalid_grant`, `access_denied` or an `AADSTS` code on the device grant; `redirect_uri_mismatch`, `AADSTS500113` or `AADSTS50011` on the redirect). In a Claude Code session a blocked prompt carries a device code or a sign-in URL; when neither works, it gives the next steps (`aigw-claude-auth login --paste`, or the `ssh -L` command for a fixed port).

**Preflight.** The `doctor` checks also run before each daemon write and in the precheck. An Error blocks the prompt with the finding and writes nothing; a notification goes out only when the findings change, and it recovers by itself once the cause is fixed. `AIGW_CLAUDE_PREFLIGHT=off` skips the gate, for debugging only.

**When `sync` can't get a new JWT:**
- It keeps the current JWT while more than 30 s are left, so a short IdP outage doesn't throw away a JWT that works. After that it writes the sentinel.
- It refuses a new JWT that has no `exp` or has less than 60 s left.
- `invalid_grant`, `interaction_required` and `login_required` from the IdP mean the sign-in is over (refresh token expired or revoked, password changed, policy). The client drops the refresh token and asks for `aigw-claude-auth login`.

## Operating notes

- **Hook time budget.** By default Claude Code waits 30 s for a UserPromptSubmit hook. After that it kills the hook and sends the prompt anyway, ignoring a block. Claude Code honors a hook entry's `"timeout"`, and `install` writes `"timeout": 30`. Inside hooks the client caps each request at `hook_http_timeout` (5 s), so discovery, refresh, broker and `hook_wait` together stay well inside the budget, even when the IdP hangs.
- **Reload delay.** Claude Code picks up a changed settings file, including one replaced by atomic rename, about 1 s after the write. A request sent sooner carries the old value. The `precheck` scenario's `hook_wait 0` case shows this.
- **Scripts and CI.** `claude -p` runs the same hooks. Give it stdin (`< /dev/null` when there is no input), as the repro does.
- **Several Claude Code config dirs.** A daemon serves one settings file. Run one daemon per `CLAUDE_CONFIG_DIR` (set it in the unit), or let the hooks alone handle the others.
- **The JWT at rest** sits in the settings file with mode 600, like Claude Code's own credentials file. It's short-lived. The long-lived secret is the refresh token in `state.json`.
- **`Bearer ` prefix.** The gateway also accepts `x-portkey-api-key: Bearer <jwt>`. The client writes the JWT bare.
- **Telling the 401s apart by hand.** The gateway's own refusals say `Portkey Error: ...`. Anthropic's, relayed, say `anthropic error: ...` and carry `"provider":"anthropic"`. Claude Code doesn't distinguish them, but the StopFailure hook does (it acts only on the gateway's).

## Re-run

The offline scenarios take about 10 minutes and the live ones about 15, because two live scenarios wait out the OAuth loop.

1. Prerequisites: Python 3.8+ and Claude Code. `repro/run.py` is the runner on every OS (`py -3 repro\run.py` on Windows); `repro/run.sh` (bash 4+, curl; on macOS `brew install bash`) carries the same expectations and stays as the reference until it is retired, so change an expectation in both. For the live scenarios you also need:
   - everything in [What you need](#what-you-need);
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

## Findings

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

| # | Finding | Scenario |
|---|---|---|
| 1 | With the passthrough config, Claude Code's own login in `Authorization` plus a gateway JWT in `x-portkey-api-key` (from `ANTHROPIC_CUSTOM_HEADERS`) gets a normal reply through the gateway | `headers`, `gateway`, `client_live` |
| 2 | The gateway's own refusals (missing, garbage or tampered JWT) are 401 `Portkey Error: ...`. With a valid JWT, Anthropic's refusal of the login is relayed as 401 `anthropic error: ...` with `"provider":"anthropic"`. A `Bearer `-prefixed JWT is accepted | `gateway` |
| 3 | With a stored login, Claude Code treats a gateway 401 as its own expired login: 13 attempts over about 4 minutes (the same against the mock), refreshing and rotating the Anthropic login each time; the login stays valid | `live_login`, `stored_login` |
| 4 | With a stored login, a 498 is one attempt, shown at once, with the login untouched | `live_login`, `stored_login` |
| 5 | With a `CLAUDE_CODE_OAUTH_TOKEN` login: 401 is 2 attempts; 403, 407 and 498 are 1 attempt each. The StopFailure hook gets `error: authentication_failed` for 401 and 403, `unknown` for 407 and 498 | `errors`, `stopfailure` |
| 6 | The ALB rules answer the sentinel and a missing header (on OAuth requests) with 498 before the gateway | `gateway`, `live_login` |
| 7 | A running Claude Code session picks up a rewritten `settings.json` (atomic rename) about 1 s later. With no wait, the next request still carries the old JWT | `headers`, `precheck` |
| 8 | UserPromptSubmit hooks: a hook running past the default 30 s timeout is killed and the prompt is sent (fail-open); the entry's `timeout` field is honored; `{"decision":"block","reason":...}` blocks the prompt and shows the reason | `precheck` |
| 9 | The client renews an expired JWT in the precheck before the turn, and the turn succeeds on the first request (live: Entra ID → broker → gateway → Anthropic). It blocks in time when the IdP hangs, and writes the sentinel when blocking is off | `precheck`, `client_live` |
| 10 | Signed out, the precheck starts a device code sign-in in a detached process and blocks the prompt with the URL and code; Claude Code shows the reason as "UserPromptSubmit operation blocked by hook: AI gateway sign-in needed: ...". A second prompt before the sign-in is done gets the same code (one device flow). Once the user signs in, the JWT is written and the next prompt goes through on its first request. If the user declines at the IdP, the detached process logs and notifies the error (Entra: `authorization_declined AADSTS700171`) and the next prompt gets a new code. Repro against the fake IdP; also by hand against Entra ID on macOS | `precheck` (`hooklogin`), `unit` |
| 11 | Managed settings (machine-wide file, root-owned) next to the user's `settings.json`: a managed `env.ANTHROPIC_CUSTOM_HEADERS` replaces the user's value, so the JWT isn't sent (401 from the gateway). Hooks and `ANTHROPIC_BASE_URL` from managed settings with the JWT in the user's file work: the precheck renews an expired JWT, and a JWT renewed during a session is picked up. With `allowManagedHooksOnly`, user hooks don't run and managed hooks do. A `settings.json` with mode 444 doesn't stop the client. With `chflags uchg` on it, renewal fails. 1.1.0's precheck let the prompt through with the expired JWT. 1.1.1 blocks it with "AI gateway: cannot renew the JWT: [Errno 1] Operation not permitted: ...", and no request reaches the gateway. A managed `proxyAuthHelper` adds no `Proxy-Authorization` header to requests to the gateway | `managed` |
| 12 | Through a local proxy that injects `x-portkey-api-key` from a file (prototype `repro/proxy_prototype.py`; `CLAUDE_CODE_OAUTH_TOKEN` login, mock gateway): the injected value reaches the gateway and a different JWT in the user's `ANTHROPIC_CUSTOM_HEADERS` is gone; `Authorization` and `anthropic-beta` arrive as sent; a token file changed between turns is used by the next request; chunked SSE sent 0.6 s apart through the proxy arrives event by event | `proxy` |
| 13 | A proxy that turns the gateway's 401 (`Portkey Error:`) into 498 with the load balancer guard's body behaves like the load balancer: 1 attempt, shown at once ("API Error: 498 ... AI gateway token expired ..."), StopFailure `error: unknown` (finding 5: direct 401 is 2 attempts, `authentication_failed`). Anthropic's relayed 401, passed through, is still 2 attempts with `authentication_failed`. With no usable token (file missing, empty, or the sentinel) the proxy answers 498 at once and sends nothing upstream (1 attempt, 0 upstream requests). With a stored `claude login` (macOS, kept in the login Keychain) through the proxy, a gateway 401 and a missing token are each 1 attempt, shown at once, the login neither rotated nor invalidated, and the next turn with a good token works (compare finding 3: 13 attempts without the proxy) | `proxy`, `stored_login_proxy` |
| 14 | Claude Code 2.1.308 has no socket form of `ANTHROPIC_BASE_URL`: `unix://<path>`, `http+unix://<encoded path>` and `http://unix:<path>:/` reach no listener on the socket, and Claude Code retries the connection error with backoff (still going after 15 s; the debug log shows "API error (attempt N/11) ... Connection error."). The undocumented environment variable `ANTHROPIC_UNIX_SOCKET=<path>` (found as a string in the Claude Code binary) works from the process environment together with a plain `http://` `ANTHROPIC_BASE_URL`: the request, with `Authorization`, `anthropic-beta` and the custom header, reaches the listener and the reply is shown. Put in `settings.json` `env`, it had no effect (no request reached the socket). From reading the binary, not from a run: the variable is for socket-proxied sessions (it needs `CLAUDE_CODE_OAUTH_TOKEN`, otherwise requests carry no claude.ai login, and it skips the model catalog and bootstrap calls), so a stored `claude login` would not be sent through a socket | `proxy` |
| 15 | Managed settings and the helper's own keys (spike S4). An unknown top-level key (`aigwClaudeAuth`) in `managed-settings.json` is ignored without a warning on stderr or in the stream output, and the rest of the file applies (its `ANTHROPIC_BASE_URL` and hooks). The key's value is not in the hooks' input JSON. `AIGW_*` keys in managed `env` reach the environment of the UserPromptSubmit and StopFailure hooks and of the Bash tool; for the same key, the managed value wins over the user's `settings.json` `env`, and the user's other `AIGW_*` keys stay. `managed-settings.d/*.json` drop-ins are merged with `managed-settings.json`: `env` keys from every file apply, a later file (by name) wins on a conflicting key, and hooks for the same event from different files all run. A drop-in with no `managed-settings.json` applies on its own | `managed` |
| 16 | The Claude desktop app (3.6556.2, macOS, signed in with claude.ai) runs Code sessions with its bundled Claude Code 2.1.308, started with the real `HOME`, no `CLAUDE_CONFIG_DIR`, `CLAUDE_CODE_ENTRYPOINT=claude-desktop`, `--setting-sources=user,project,local` and `ANTHROPIC_BASE_URL=https://api.anthropic.com` in its environment. Those sessions read `~/.claude/settings.json` and the project's `.claude/settings.json`: their `env` keys reach the session (`ANTHROPIC_CUSTOM_HEADERS`, `AIGW_*`), their hooks run (SessionStart, UserPromptSubmit, StopFailure; hooks added to a project file mid-session were picked up), and a UserPromptSubmit block shows its reason as is with nothing sent. But `ANTHROPIC_BASE_URL` from either file is ignored: requests stay on `api.anthropic.com` and no request reached the mock gateway. The CLI with the same base URL in its environment and the same project file uses the file's value. So the desktop app can't be routed to the gateway through settings; per the docs (not a run) it ignores managed settings for routing too and routes only through its third-party inference configuration, which replaces the claude.ai login | by hand (mock gateway, logging hooks) |
| 17 | Native Windows (spike S7). **Hook shell:** with Git for Windows installed, Claude Code runs hook commands with Git Bash (`bash.exe -c "<command>"`, `MSYSTEM=UCRT64`), started from cmd.exe or from Windows PowerShell alike. Without Git for Windows it runs them with Windows PowerShell 5.1 (FullLanguage). **Quoting:** the client's current form (`shlex.quote`, single-quoted paths) works under Git Bash but doesn't run under PowerShell (parse error). A double-quoted program path as the first word doesn't run under PowerShell either (it needs `&`). Git Bash drops an unquoted backslash. Two forms ran in both shells: `py -3 "<script>" ...` and `powershell -NoProfile -Command "& '<python>' '<script>' '<arg>'"`. The second passed every argument intact in both. `%VAR%` is not expanded in either shell. Exec form (`"command": "<python.exe>"`, `"args": [...]`, from the hooks docs) ran in both cases, started directly by `claude.exe` with every argument verbatim (`$VAR` and `%VAR%` too), as did `"shell": "powershell"` with an `&` command. **Settings file:** 60 atomic replacements of `settings.json`, 0.1 s apart, during a running session got no PermissionError (a control that held the file open got winerror 5). The longest wait was 20 ms, and the new JWT was used 1.3 to 1.8 s later. **Toast:** a Windows PowerShell 5.1 WinRT toast from a hook exits 0 in about 1 s, with the PowerShell app ID and with its own app ID, and both appeared on the RDP desktop. On first use PowerShell writes a CLIXML progress record to stderr. | `winprobe` |
| 18 | Keycloak 26.4.7 (local, in Docker, dummy user). Discovery, device code (Keycloak always shows a consent page) and PKCE with a loopback redirect `http://127.0.0.1/*` on any port work with no client change. Protocol mappers emit the Mode A claims directly: a claim name with dots (`defaults.config_slug`) becomes a nested object, so Mode A needs no broker (Entra ID does); Claude Code sent that JWT to the mock gateway and the turn worked (Mode A from the IdP, `broker_url` empty). Mode B, a plain IdP token without those claims, reached the mock gateway too. Refresh: by default Keycloak returns a new refresh token but the old one stays valid; with "Revoke Refresh Token" on, replaying an old one revokes the whole chain and the user must sign in again. With `offline_access` the refresh token is an offline token that survives the end of the SSO session (a normal one doesn't); the admin "logout user" call revokes offline tokens too. A client that enforces PKCE (S256) refuses the device grant (`Missing parameter: code_challenge_method`): leave that setting off on clients used for device code. The default access-token lifespan (5 min) equals `refresh_before`, so the client would renew on every call: set it longer | `keycloak` |
| 19 | `doctor` and the preflight against real managed settings (macOS, Claude Code 2.1.308): in every `managed` case `doctor --json` reports the expected finding. With managed `ANTHROPIC_CUSTOM_HEADERS`, a managed `ANTHROPIC_BASE_URL` other than the user's, or managed `AIGW_*` values that contradict the helper config, the precheck blocks the prompt with the finding and no request carries a JWT. A managed hook without `timeout` is a Warning and the turn still renews the JWT. With `allowManagedHooksOnly` and the hooks split over two drop-ins in `managed-settings.d/`, `doctor` finds nothing, the user's hook doesn't run and the JWT is renewed. A managed `apiKeyHelper` is a Warning. Findings 8, 11 and 15 are unchanged (their cases run with the preflight off) | `managed` |
| 20 | Windows Credential Manager (Windows 11, interactive desktop session): one generic credential holds at most 2560 bytes (`CredWriteW` error 1783 beyond that), so the client splits longer values across `<target>`, `<target>#1`, ...; the round trip passes, nothing is left behind. In an ssh session every credential call fails with error 1312 (no credential set for a network logon), and the client falls back to `state.json` with a warning | `unit` (real tests on Windows) |
| 21 | Okta (Integrator org, custom authorization server `default`, Native app, device code): discovery offers the device grant and PKCE S256, and sign-in, refresh and `inspect` work with no client change; the access token lasts 1 h, `aud` is `api://default`. Custom claims reach the access token only when set for the Access Token; a literal value without double quotes is dropped without an error (an invalid expression), also from the ID token. A claim named `defaults.config_slug` arrives as a flat key with a dot, not a nested `defaults` object (Keycloak nests it, finding 18), so the gateway won't read it: `inspect` flags it (1.3.1). Refresh tokens rotate; the previous one still works within Okta's grace period (replayed at once: 200), and replayed after 35 s it's refused with `invalid_grant` and **the current refresh token is revoked too**: the user must sign in again. So two copies of `state.json` (a copied config, a restored backup) end the sign-in; the client's lock keeps one machine from replaying | by hand |
| 22 | Okta JWT against the hybrid gateway (`gateway` scenario, ALB guard on): with the broker's and Okta's JWKS URLs in one comma-separated value, Okta's JWT (Mode A claims, no `defaults`) is accepted (the broker's JWT wasn't sent in this run). The config then comes from the workspace: with the passthrough saved as a workspace config and set as the workspace's "default config for user API keys" (the config run: `provider` `anthropic`, `api_key` `unused`, `forward_headers` `authorization`, `api_key`, `anthropic-beta`, `anthropic-version`; it forwards `api_key` where [gateway/passthrough-config.json](gateway/passthrough-config.json) forwards `x-api-key`, and Claude Code sends neither with a claude.ai login; the repo's file wasn't run on this gateway), a valid JWT plus a real login gets Claude's reply, a bad login Anthropic's 401, no login Anthropic's 401 (`invalid x-api-key`); before that, the workspace's other default answered from Bedrock whatever the login. A config change took about 1 to 3 minutes to reach the gateway. With the org's `block_inline_config`, `x-portkey-config` is refused with 403 (even without a JWT) and `x-portkey-provider: anthropic` is ignored with a valid JWT. A saved config target with `provider` but no `api_key` is accepted by the UI and refused per request (400 `Invalid config passed`). A token without the `completions.write` scope gets the same results. `Bearer <jwt>` in `x-portkey-api-key` gets 400 (`Either x-portkey-config or x-portkey-provider header is required`): it isn't refused, but no default config applies. `client_live` with the Okta sign-in passes: Claude Code sends the client's Okta JWT, gets replies, and the precheck replaces an expired JWT before the turn (200, under 30 s) | `gateway`, `client_live` |

Run by hand, not by the repro: device code and browser (PKCE) sign-in with `aigw-claude-auth login` against Entra ID on macOS. The browser sign-in needed the loopback redirect URI on the app registration first (see What you need). The precheck's sign-in (finding 10) against Entra ID on macOS: blocked at once with the code, the same code on a second prompt, signed in in the background, the resent prompt answered, and the decline case; code expiry and `claude -p` weren't tried. Run `aigw-claude-auth login` once against your IdP to confirm the flow you use.

## Claude desktop app and Cowork

This client covers Claude Code in a terminal or IDE. The Claude desktop app (its Chat, Cowork and Code tabs) ignores `ANTHROPIC_BASE_URL` in `settings.json` (finding 16), so the steps above don't put it behind the gateway; signed in to claude.ai, it talks to Anthropic directly.

The documented way to put the Claude apps on an AI gateway is [Claude Desktop on 3P](https://claude.com/docs/third-party/claude-desktop/gateway): set `inferenceProvider` to `gateway` and `inferenceGatewayBaseUrl` in the app's managed configuration, and authenticate users with `inferenceGatewayOidc` (SSO with your IdP, the IdP token sent as the bearer) or a credential helper. In that mode the app doesn't use the user's claude.ai login: the gateway forwards with the organization's own provider credential, so usage is billed to the organization, not to each user's plan. The gateway needs a config with a real upstream credential (not the passthrough config) and JWT validation for the IdP's token. From the docs; not run here:

- [Connect Claude Code to an LLM gateway → Desktop app](https://code.claude.com/docs/en/llm-gateway-connect#desktop-app)
- [Roll out an LLM gateway → Distribute through managed settings](https://code.claude.com/docs/en/llm-gateway-rollout#distribute-through-managed-settings)
- [Claude Desktop on 3P: overview](https://claude.com/docs/third-party/claude-desktop/overview)
- [Claude Desktop on 3P with an LLM gateway](https://claude.com/docs/third-party/claude-desktop/gateway)
- [Claude Desktop on 3P: credential helper](https://claude.com/docs/third-party/claude-desktop/credential-helper)
- [Claude Desktop on 3P: configuration reference](https://claude.com/docs/third-party/claude-desktop/configuration)
- [Claude Desktop on 3P: user identity and local data](https://claude.com/docs/third-party/claude-desktop/data-storage)
- [Claude apps gateway](https://code.claude.com/docs/en/claude-apps-gateway)

Claude Code itself documents the passthrough this repo uses: with only `ANTHROPIC_BASE_URL` set, "a saved claude.ai login remains the active credential, so its usage limits and billing apply" ([Subscriptions and gateways](https://code.claude.com/docs/en/llm-gateway#subscriptions-and-gateways)).

## Not covered yet

Open questions and gaps, not tested here:

- **Claude desktop app and Cowork.** This client can't route them: the app ignores `ANTHROPIC_BASE_URL` from settings (finding 16). See [Claude desktop app and Cowork](#claude-desktop-app-and-cowork) for the documented route, which wasn't run here. Cowork itself wasn't run.
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
- **Gateway API keys** instead of a JWT (see [Without a JWT](#without-a-jwt-gateway-api-keys)): service and user keys, a revoked key's 401, and per-user attribution of user keys.
- **Also untested:**
  - 403 and 407 with a stored login;
  - on macOS: the live scenarios other than `stored_login_proxy` (the harness reads the stored login from the login Keychain and passes the real `HOME` to Claude Code for them), `claude -p` while signed out, and device code expiry.
- **Protecting the JWT and the refresh token at rest.** In file mode the JWT sits in the settings file; `mode: proxy` (1.4.0) keeps it in memory only. With a stored login through it (`stored_login_proxy`, 1.4.0, against the mock), a refused or missing JWT fails in one attempt and the login isn't rotated. Not yet run: the proxy against the real gateway. The refresh token is in the OS credential store since 1.3.0 (the file is the fallback). Options not built yet:
  - Claude Code permission rules that deny reading the files;
  - sender-constrained tokens, if the gateway ever supports them.

  Claude Code has no documented helper that supplies headers for model requests (as of 2.1.286). `apiKeyHelper` doesn't fit, since its value replaces the Anthropic login, and `proxyAuthHelper` doesn't reach the gateway (finding 11).
- **Token lifetime guidance.** The broker default is 1 h, renewed 5 min before expiry. A shorter JWT narrows the window for a stolen token or an offboarded user, because a Mode A JWT can't be revoked before it expires. A longer one means fewer IdP and broker calls and fewer renewals at prompt time. There's no recommendation yet. Also untested: how renewals behave across sleep, and the gateway's clock-skew tolerance on `exp`.

## License

MIT; see [LICENSE](LICENSE).
