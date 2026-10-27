# aigw-claude-code-native-login

Claude Code CLI users who sign in with their own Anthropic account (`claude login`, for example a Claude Enterprise seat) can still go through an AI Gateway, so the gateway sees, logs, guards and attributes every request. **This is for organizations that want to govern Claude Code use without giving up the user's own Anthropic identity:** the users' Anthropic plan stays the billing and policy anchor, and the gateway adds identity, attribution, logging and guardrails on top, with no long-lived gateway API key handed to anyone.

**Two credentials travel on every request.** Claude Code keeps sending the user's Anthropic login in `Authorization: Bearer`, and the gateway passes it through to Anthropic, which bills and limits the user as usual. The gateway identifies and attributes the person by a short-lived JWT in a second header, `x-portkey-api-key`, issued through your identity provider (IdP). That JWT is what the gateway authenticates. (A gateway API key in the same header is the alternative, with different trade-offs: [Without a JWT](#without-a-jwt-gateway-api-keys).)

This repository ships a small client, `aigw-claude-auth` (one Python file, standard library only), that gets that JWT from your IdP, directly or through a token broker, and keeps it fresh. It also makes gateway auth failures fail fast: without it, a gateway 401 sends a logged-in Claude Code into its own Anthropic OAuth refresh-and-retry loop for several minutes. It runs in one of two modes, set by `mode` in its config. **File mode** (the default) writes the JWT into Claude Code's `settings.json` and renews it from hooks and an optional background daemon. **Proxy mode** runs a small local proxy on `127.0.0.1` that adds the JWT to every request and keeps it in memory, so no token sits in a settings file; a background service keeps the proxy running. Pick one under "Choose a mode" in [1.3 Client, per user](#13-client-per-user). (These are not Portkey's "Mode A" and "Mode B", which describe what the JWT carries: see [What you need](#what-you-need).)

**Two ways to deploy it, from the same model.**

1. **Pilot or per-user (the supported baseline).** Set up the gateway, register an IdP app, install the client for each user, who signs in once. Start at [What you need](#what-you-need), then [1. Build](#1-build).
2. **Fleet (pilot / administrator preview).** Distribute the same model centrally, with managed settings and packages. Read [docs/fleet-deployment.md](docs/fleet-deployment.md) first: it says what is and isn't ready.

How it works today: [docs/architecture.md](docs/architecture.md). What has been tested, on which versions: [docs/support-matrix.md](docs/support-matrix.md).

> **Disclaimer:** This is a simple, art-of-the-possible example. It is **not** an official Palo Alto Networks, Portkey or Anthropic project, it is **not** a recommended or supported production design, and it comes with **no support**. Use it at your own risk, under the [MIT License](LICENSE).

![How it fits together: the client keeps a gateway JWT in Claude Code's settings; every request carries the user's Anthropic login and the JWT; the gateway checks the JWT and forwards the login to Anthropic](docs/flow.svg)

Shown with Entra ID and a token broker, as tested: Entra ID can't add Portkey's claims to its tokens, so the broker exchanges the IdP token for a JWT that carries them (Mode A). If your IdP can add the claims itself (Mode A), or you use its standard token as it is (Mode B), there is no broker and the client puts the IdP's own token into the header. What "Mode A" and "Mode B" mean is under [What you need](#what-you-need).

| Piece                                    | What it does                                                                                                                                     | Where                                                              |
| ---------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------ |
| Gateway passthrough config               | Sends the request to Anthropic with the caller's own `Authorization` and `anthropic-beta` headers instead of a provider key                      | [gateway/passthrough-config.json](gateway/passthrough-config.json) |
| Gateway JWT auth                         | The gateway accepts a JWT in one of Portkey's [two ways](https://portkey.ai/docs/aigw/product/enterprise-offering/org-management/jwt): "Mode A", where you control the issuer and add Portkey's claims (from your IdP, or through a broker); "Mode B", a standard IdP token you can't change (hybrid gateway only) | Your gateway (prerequisite)                                        |
| `aigw-claude-auth`                       | Signs in to the IdP once, then keeps a valid JWT in `env.ANTHROPIC_CUSTOM_HEADERS` of Claude Code's settings                                     | [client/aigw_claude_auth.py](client/aigw_claude_auth.py)           |
| Precheck hook (UserPromptSubmit)         | Before each prompt: renews an expired JWT and waits for Claude Code to reload it, or blocks the prompt with a sign-in message                    | `aigw-claude-auth hook precheck`                                   |
| StopFailure hook                         | After a turn failed on a gateway auth error: renews the JWT and notifies the user, so the retry works                                            | `aigw-claude-auth hook stop-failure`                               |
| LB guard (optional, file mode, hybrid gateway only) | File mode: answers "no usable JWT" with 498 at the load balancer, which Claude Code shows at once. Proxy mode does this itself                                                           | [gateway/alb-guard-ingress.yaml](gateway/alb-guard-ingress.yaml)   |

## Without a JWT: gateway API keys

A JWT isn't the only way to authenticate to the gateway. The gateway's own API keys go in the same header, `x-portkey-api-key`, and the rest of the layout stays as it is: Claude Code's Anthropic login in `Authorization`, and the passthrough config forwarding it.

- **AI Gateway service API keys:** one key per workspace, team or machine. The gateway knows the key, not the person.
- **AI Gateway user API keys:** one key per user, so requests are attributed to the person. This needs the SCM tenant onboarded with the customer's directory through Cloud Identity Engine (CIE), so the gateway knows the users.

Set it once, in `env.ANTHROPIC_CUSTOM_HEADERS` of Claude Code's settings (`x-portkey-api-key: <key>`), with the passthrough config bound to the key (`defaults.config_id` set to the config's UUID; a slug is refused). A workspace default doesn't reach service keys on a hybrid gateway, so bind it to the key. No client, broker or IdP sign-in is needed. The trade-offs, compared with the JWT:
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
3. **The sentinel (file mode).** When the client can't get a JWT and the current one is unusable, it writes `x-portkey-api-key: expired` instead of an old or empty value. With the optional LB guard (also file mode), that request gets a 498 at once, also on machines where the hooks are off. In proxy mode there is no sentinel: the local proxy holds the JWT and answers 498 itself when it has none.
4. **The StopFailure hook** handles the rest: the gateway refused a JWT that still looked valid (revoked, or the signing key rotated). By then Claude Code has already failed the turn, so the hook renews the JWT and tells the user to retry.

## What you need

- **An AI Gateway that accepts a JWT** in `x-portkey-api-key` (for gateway API keys instead, see [Without a JWT](#without-a-jwt-gateway-api-keys)), in one of two ways:
  - **"Mode A": you control the JWT issuer** ([Portkey's JWT modes](https://portkey.ai/docs/aigw/product/enterprise-offering/org-management/jwt)). The JWT carries Portkey's own claims (`portkey_oid`, `portkey_workspace`, a nested `defaults` object, and `usage_limits` / `rate_limits` if you want them per user) and is signed by a key the gateway trusts. Your IdP can issue it directly if it can add custom claims, including nested JSON (Keycloak can, finding 18). An IdP that can't gets them from a broker that exchanges the IdP token for a JWT that has them. A broker is a way to reach Mode A, not a mode of its own. It is needed for: Entra ID (see article `aigw-entra-jwt-broker`), and Okta for the nested `defaults` (its claim expressions can't nest; Portkey's [JWT authentication with Okta](https://portkey.ai/docs/aigw/product/enterprise-offering/org-management/jwt/okta#jwt-authentication-with-okta) adds `defaults` through a token inline hook instead; finding 21);
  - **"Mode B": a standard IdP token whose schema you can't change** (Okta, Auth0, Entra ID, Cognito). The gateway fills in what the token lacks from its own settings: the organization (`ORGANISATIONS_TO_SYNC`, a single org), the workspace (a workspace allowlist or the org default), scopes (`JWT_LOCAL_AUTH_DEFAULT_SCOPES`, if the IdP doesn't issue them) and limits (workspace policies). It attributes the request to a user by `email_id`, `sub` or `uid`. Point the org's JWKS URL at the IdP. Hybrid gateway only: the SaaS gateway takes Mode A only, because it needs `portkey_oid` and `portkey_workspace` in the token.
- **The passthrough config** ([gateway/passthrough-config.json](gateway/passthrough-config.json)), as the config the users' requests get. Either:
  - bind it to the credential: named in the JWT's claims, or bound to the service or user API key. Different users or groups in one workspace can then get different configs, and Claude Code's settings (or the MDM or Claude Enterprise policy that manages them) need to know nothing about configs or workspaces;
  - or make it the workspace default: the workspace's `defaults.user_api_key_config`, the only supported workspace-level config default. That's simpler, but then every JWT request in the workspace that doesn't name a config gets that one. On a hybrid gateway it doesn't apply to service API keys.

  In the JWT, the hybrid gateway reads `defaults.config_slug` and ignores `defaults.config_id`; the SaaS gateway reads `defaults.config_id`, as a slug or a UUID (separate lab tests, 2026-10-01; SaaS not run by this article). Write both claims; the broker `aigw-entra-jwt-broker` does, with `config_id` falling back to the slug. A wrong claim fails open on hybrid (HTTP 200, no config). The config's `api_key` is a placeholder. `forward_headers` sends the caller's `authorization` and `anthropic-beta` to Anthropic, so Anthropic sees the user's own login.
- **An IdP public client** (no secret) for the client to sign in with. There are two ways to sign in, and the app has to allow the one your users' machines can use:
  - **Authorization code with PKCE**, in a browser on the same machine. The client opens the IdP's sign-in page and receives the answer on a loopback address, `http://127.0.0.1:<port>/`. Use it on a desktop or laptop with a browser: macOS, Windows, a Linux desktop. The app needs that redirect URI registered (Entra: platform "Mobile and desktop applications" with `http://127.0.0.1`, which accepts any port; Okta and others match the exact URI and port, so also set `redirect_port`). Without it, Entra's sign-in fails with `AADSTS500113` (no reply address registered). It does not suit a headless host, an ssh session or a container: the browser is somewhere else and the loopback port can't be reached. `login --pkce-print` with an `ssh -L` forward, or `login --paste`, can work around that;
  - **Device authorization grant** (device code). The client prints a URL and a short code, and the user signs in on any device that has a browser, so the machine running the client needs none. Use it on headless machines, ssh sessions, containers and CLI-only environments. It needs no redirect URI, but the app must allow the grant (Entra: "Allow public client flows"; Okta: the Device Authorization grant type). Some IdPs or policies refuse it; then fall back to PKCE;
  - **Which one is used:** the client decides by itself. It tries PKCE where it can reach a browser on this machine, the device code over ssh, in a container or with no display, and it remembers what worked last. `login --device`, `--pkce`, `--pkce-print` and `--paste` force a method. [Sign-in method](#sign-in-method) has the exact order;
  - either way, `offline_access` granted, so the IdP issues a refresh token;
  - with a broker, permission for its API scope (Entra: `api://<broker app>/access_as_user`).
- **Okta specifics** (finding 21; Portkey's setup: [JWT authentication with Okta](https://portkey.ai/docs/aigw/product/enterprise-offering/org-management/jwt/okta#jwt-authentication-with-okta)):
  - a custom authorization server (`https://<org>.okta.com/oauth2/default` or your own); the gateway's JWKS URL is `<issuer>/v1/keys` and must start with the token's `iss`;
  - an OIDC **Native Application** with the grant types Authorization Code, Refresh Token and Device Authorization, sign-in redirect URI exactly `http://127.0.0.1:<port>/` with the same port in the client's `redirect_port` (Okta matches exactly), no custom-scheme redirect; the server's access policy rule must allow the same grant types;
  - the claims on the **access token** (Include in token type: Access Token; Include in: Any scope): `portkey_oid`, `portkey_workspace`, and `scopes` = `access.scope` (the gateway reads `scope` or `scopes`, Okta writes `scp`). A literal value needs double quotes (`"my-workspace"`): unquoted, it's an expression, and a failing expression drops the claim without an error;
  - a custom scope `completions.write` (User consent: Implicit) on the authorization server, as in Portkey's setup, requested by the client: `"scope": "openid offline_access completions.write"`. Seen 2026-10-26: Okta then lists it in both `scp` and `scopes`. The hybrid gateway doesn't require it: a token without it got the same results (finding 22);
  - `defaults` only through a token inline hook or a broker; check the token with `aigw-claude-auth inspect`. For mapping Okta groups to workspaces, defaults and limits, see the design's [Mapping IdP groups to gateway workspaces](docs/design-v2.md#mapping-idp-groups-to-gateway-workspaces-mode-a): the broker is the recommended route; the Okta-native route uses a reference hook that lives in [its own repository](https://github.com/thresh97/idp-okta-webhook-custom-claims) and is not production-ready (offline tests only); see [gateway/okta.md](gateway/okta.md). Put every Mode A claim in the hook: it fails open.
- **Users with an Anthropic login** in Claude Code (`claude`, then `/login`).
- **Python 3.8+** on the users' machines: macOS, Linux or native Windows (`py -3` from python.org). No packages.
- **Optional, for the LB guard (file mode only):** an AWS ALB in front of a hybrid gateway. Any L7 load balancer that can match headers and return a fixed response works the same way. With the SaaS gateway there's no load balancer of yours in front of it, and an L4/TLS passthrough load balancer can't match headers; in both cases rely on the hooks alone (a refused or missing JWT is then the gateway's 401).

## 1. Build

### 1.1 Gateway

1. Create the passthrough config from [gateway/passthrough-config.json](gateway/passthrough-config.json) in the users' workspace, and make it the config their requests get: bound to the credential (the JWT's `defaults.config_slug` on a hybrid gateway or `defaults.config_id` on SaaS, or the API key), or as the workspace default `defaults.user_api_key_config` (JWT requests only; see What you need).
2. Check that the gateway's JWT validation (JWKS URL, issuer, audience) accepts your IdP's or broker's tokens. The JWKS URL setting is per org and takes a comma-separated list, so one gateway can trust a broker and an IdP at once (operator's statement; with both listed, Okta's JWT is accepted, finding 22). Without `defaults` in the JWT, set the passthrough as the workspace's default config ("default config for user API keys"); a per-request `x-portkey-config` is refused when the org blocks inline config (finding 22).

### 1.2 Optional, file mode: answer token problems at the load balancer

This is extra configuration for **file mode**. There Claude Code itself sends the JWT, or the sentinel `expired` when none can be had, so a load balancer in front of the gateway can recognize "no usable JWT" and answer with a 498 that Claude Code shows at once.

**Proxy mode doesn't need it.** The local proxy adds the JWT to every request, writes no sentinel, answers 498 itself when it has no JWT (and sends nothing upstream), and also turns a gateway 401 into a 498 after one renew-and-retry, which a load balancer cannot do. A proxy-mode client never sends the sentinel or a request without the header, so rules 1 and 3 below never match its traffic: the guard is inert for it and rule 2 forwards its requests. That comes from reading the rules and the proxy's behavior (finding 13), not from a run of the two together. If one gateway serves both kinds of client, the guard still protects the file-mode ones.

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

# 2. Configure (see "Client reference" below; the example is Entra ID through a broker, which supplies the Mode A claims).
#    For proxy mode copy client/config.proxy.example.json instead: it has mode, proxy_listen and gateway_url set (see "Choose a mode").
#    Desktop notifications are on by default ("notify": "auto"); set "notify" to "off" or a command to change that.
cp client/config.example.json ~/.config/aigw-claude-auth/config.json && ${EDITOR:-vi} ~/.config/aigw-claude-auth/config.json

# 3. Sign in to the IdP: browser flow on a desktop, device code over ssh or without a display (--device forces it).
#    Install works before this step; a signed-out install says to sign in next.
aigw-claude-auth login

# 4. Point Claude Code at the gateway and add the hooks (edits ~/.claude/settings.json, or $CLAUDE_CONFIG_DIR/settings.json).
#    File mode: `--base-url https://<gateway host>`. Proxy mode: no arguments (see "Choose a mode" below).
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

**Choose a mode.** The `mode` setting in `config.json` decides how Claude Code gets the JWT. `install` reads it and does the right thing; the command is the same in both modes.

*File mode (`"mode": "file"`, the default).* The JWT is written into `~/.claude/settings.json`. No background process is needed: the hooks renew the JWT before a prompt that needs it, which can add a pause of about 3 s. The daemon (step 5) is optional.

```bash
# config.json: "mode": "file", "gateway_url": "https://<gateway host>"
aigw-claude-auth login
aigw-claude-auth install --base-url https://<gateway host>
```

*Proxy mode (`"mode": "proxy"`).* A local proxy on loopback keeps the JWT in memory, injects it into each request, and turns a gateway refusal into a 498 after one renew-and-retry. Nothing sensitive is left in `settings.json` except a per-user secret for the proxy. The daemon has to be running, because the proxy is what renews the JWT.

```bash
# config.json: start from client/config.proxy.example.json ("mode": "proxy", "proxy_listen": "127.0.0.1:18787", "gateway_url": "https://<gateway host>")
cp client/config.proxy.example.json ~/.config/aigw-claude-auth/config.json && chmod 600 ~/.config/aigw-claude-auth/config.json   # then edit the <placeholders>
aigw-claude-auth login
aigw-claude-auth install          # no --base-url: the address comes from proxy_listen
aigw-claude-auth daemon           # or the launchd / systemd / Task Scheduler entry from step 5
```

`install` writes `ANTHROPIC_BASE_URL=http://127.0.0.1:18787` and the `x-aigw-local` secret, removes the JWT line, and installs the daemon as a per-user service: a launchd agent on macOS (`~/Library/LaunchAgents/aigw-claude-auth.plist`), a systemd user unit on Linux (`~/.config/systemd/user/aigw-claude-auth.service`), or a Task Scheduler task on Windows. If it can't, `install` prints a warning with the reason and still exits 0, and you start the daemon by hand (`aigw-claude-auth daemon`). Use `--no-service` to skip the service. Linux needs a systemd user session. **When to add `--linger`.** By default the proxy stops when your last login session ends, because systemd stops the user manager with it. That is right for a desktop, where Claude Code ends with your session too. Add `install --linger` (it runs `loginctl enable-linger`) when Claude Code can outlive your login: an SSH-only or headless machine, or a `tmux` or `screen` session you disconnect from. With lingering the proxy keeps running after logout and starts at boot, so it is off by default: it lets your processes run without a login. Whether a user may do this without `sudo` is up to the system's polkit policy: it may ask for an admin password on a real terminal, and in a test container with no terminal it was refused (`Could not enable linger: No such device or address`). When it is refused, `install` still succeeds and prints the `sudo loginctl enable-linger $USER` to run instead. Undo it with `loginctl disable-linger`. `doctor` warns (`proxy-linger`) when the proxy runs as a systemd user unit, lingering is off, and the session looks like SSH or headless; on a desktop it only notes that this is fine. **What a local process can do to the proxy.** The proxy listens on loopback only, and every request needs the per-user secret. Connections that have not presented it are on a clock: a new connection has 10 seconds to send a request with the secret, there are at most 64 such connections at a time (when that budget is full the oldest is dropped, so a real client connecting now always gets in), and all connections together are capped at 512 or the process's open-file limit minus 64, whichever is lower. The proxy raises its own open-file limit to 4096 when it starts, because a macOS launch agent starts at 256. A connection that has presented the secret may sit idle for 5 minutes. A request body over `proxy_max_body_mb` is answered 413 before it is read. Requests with the wrong secret are counted, but only the first 20 in any 10 seconds are kept in `requests` and the log, so a flood cannot bury them. `status` shows a `connections` row when the proxy has dropped any connection that never presented the secret. These limits protect availability against another process on the same machine. They do not make proxy mode safe for several users at once, which stays unsupported.

**Changing `config.json` while the proxy runs.** The proxy looks at the file every 2 seconds, and every `status`, `renew` and `login` call looks first. It compares the file's content (a hash), not its timestamp or size, so an edit made with `rsync -t`, `cp -p` or `touch -r` is noticed too. The keys that say where the JWT comes from (`issuer`, `client_id`, `scope`, `broker_url`, `idp_token`, `token_command`, `refresh_before`, the timeouts, `proxy_log_requests` and the sign-in keys) are applied in place, with no restart and no dropped connection. `mode`, `proxy_listen`, `gateway_url`, `header`, `sentinel` and `secret_store` are not: a restart ends the streaming responses of a live Claude Code session, so the proxy never restarts itself. It keeps running on the old values and `status` and `doctor` (`proxy-config`) say which keys wait for a restart and how to restart. A file that does not load changes nothing: the proxy keeps the old settings and logs why, and fixing the file is picked up by itself. While it is broken every command fails on it except `doctor` and `status`: `doctor` shows the parse error, and `status` says the file does not load and still reports what the running proxy holds. If you move to another IdP, `status` says to run `login`: a refresh token is bound to the issuer and client that produced it, and the client refuses to send it to a different one instead of letting the new IdP reject and delete it. A service installed by `install` is removed by the teardown in section 4. `doctor` lists anything still wrong. Switching modes: change `mode`, run `install` again, and it removes the other mode's entries. To check the Linux path in a throwaway container (systemd user unit, restart after a kill, the request log), run `packaging/linux/smoke-proxy-systemd.sh --client client/aigw_claude_auth.py`; it needs Docker and uses a fake JWT and a mock gateway.

**Fleet packages.** To roll this out to many machines, see [docs/fleet-deployment.md](docs/fleet-deployment.md): packages for macOS, Linux and Windows built from one fleet file, in pilot status, with the supported OS and mode matrix and the shortcomings first.

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

It's optional. Without it, the precheck hook renews before the prompt that needs it, at the cost of a pause of about 3 s. To check it's working: `systemctl --user status aigw-claude-auth` or `launchctl print gui/$(id -u)/aigw-claude-auth | head`, and `aigw-claude-auth status` shows a new fingerprint and expiry after each renewal. On macOS and Linux, `install` (proxy mode) runs the daemon under the newest Python 3.8+ it finds in this order: Homebrew (`/opt/homebrew/bin/python3`, `/usr/local/bin/python3`), python.org, the Command Line Tools (`/usr/bin/python3`), then the Python that ran `install` (not from a virtualenv). Ties go to Homebrew. The chosen path is in the agent's `ProgramArguments`, and `install` prints it. To use another interpreter, edit the plist or the unit.

**Trial install (your everyday Claude Code untouched).** Claude Code re-reads its settings about a second after they change. So `install` on `~/.claude/settings.json` reroutes every running Claude Code session, including an agent doing the install. To try it first, use a separate Claude Code config dir. That dir needs its own `/login`:

```bash
export CLAUDE_CONFIG_DIR=~/.claude-aigw
claude                                                   # /login once, then exit
aigw-claude-auth install --base-url https://<gateway host>   # edits only ~/.claude-aigw/settings.json
CLAUDE_CONFIG_DIR=~/.claude-aigw claude                  # a session through the gateway
```

For the daemon, set the same `CLAUDE_CONFIG_DIR` in the unit (`Environment=`) or the plist (`EnvironmentVariables`). The hooks need nothing: they inherit the environment of the Claude Code that runs them, `CLAUDE_CONFIG_DIR` included. To go live later, run `install` again without `CLAUDE_CONFIG_DIR`.

**Fleet rollout (managed settings).** IT can ship the hooks and `ANTHROPIC_BASE_URL` in Claude Code's managed settings, without the packages. The steps and the constraints (never `ANTHROPIC_CUSTOM_HEADERS`; `allowManagedHooksOnly`; a writable `settings.json`) are in [docs/fleet-deployment.md](docs/fleet-deployment.md#managed-settings-without-the-packages).

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

`repro/run.sh` tests the whole design (how to run it: [Re-run](docs/evidence/rerun.md)). The offline scenarios run the real Claude Code against a mock gateway and a fake IdP, so they need no accounts. The live ones use your gateway, IdP and Anthropic login.

| Scenario | Shows | Needs |
|---|---|---|
| `unit` | The client's 30 unit tests: settings edits, refresh, sentinel, device and PKCE sign-in, hooks, daemon | Python |
| `headers` | `install`; Claude Code sends both credentials; a running session picks up a renewed JWT | Claude Code |
| `errors` | How Claude Code treats 401 (gateway and Anthropic), 403, 407 and 498 with an env-token login | Claude Code |
| `precheck` | Renew before the request; no-op while valid; why `hook_wait` matters; block when no JWT can be had (signed out, IdP hanging); the device code sign-in offered in the block message and the resent prompt going through; the LB guard path with blocking off | Claude Code |
| `stopfailure` | Renew and notify after a refused JWT; Anthropic-side failures left alone | Claude Code |
| `proxy` | The client's local proxy (`mode: proxy`, 1.4.0; [design-v2](docs/design-v2.md)) in front of the mock: per-user secret header required and stripped, renew and retry once on a gateway 401, header injected, client value stripped, SSE streamed, a gateway 401 turned into 498 (one attempt), an Anthropic 401 passed through, no token fails closed; which Unix socket base URLs Claude Code accepts | Claude Code |
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
loginctl disable-linger          # Linux, only if you ran `install --linger` and nothing else needs lingering
```

Then:
1. In `~/.claude/settings.json`, remove `ANTHROPIC_BASE_URL`, the `x-portkey-api-key` line (file mode) and the `x-aigw-local` line (proxy mode) in `ANTHROPIC_CUSTOM_HEADERS`, and the two hook entries whose command contains `aigw-claude-auth`. Leave other lines in that header alone.
2. Delete `~/.config/aigw-claude-auth` and `~/.local/bin/aigw-claude-auth` (Windows: `%APPDATA%\aigw-claude-auth` and `%USERPROFILE%\.local\bin\aigw-claude-auth.py`).

On the gateway side, remove the passthrough config and the LB rules if nothing else uses them.

## Client reference

Usage: `aigw-claude-auth <command>`. Global options: `--config FILE`, `--state-dir DIR`, `--settings FILE`, `--version`.

| Command | What it does |
|---|---|
| `login [--device \| --pkce \| --pkce-print \| --paste] [--no-browser]` | Sign in to the IdP, then write a JWT. `--pkce` opens a browser here; `--pkce-print` (or `--pkce --no-browser`) prints the URL, and that browser must reach `127.0.0.1:<redirect_port>` on this host (for example `ssh -L <port>:127.0.0.1:<port> <host>`); `--paste` prints the URL, you sign in in any browser and paste the `http://127.0.0.1:...` address you end up on (no listener, no device grant); `--device` uses a device code. With no flag, see [Sign-in method](#sign-in-method) |
| `install [--base-url URL] [--no-hooks] [--no-service] [--linger] [--hook-command CMD] [--print]` | Add `ANTHROPIC_BASE_URL` and the hooks to the settings file (or print the snippet), then `sync`. Proxy mode also installs the daemon as a per-user service (launchd agent, systemd user unit or Task Scheduler task) unless `--no-service`, `--no-hooks` or a fleet config says not to; a failure is a warning with the reason, and `install` still exits 0. `--linger` (Linux) also enables lingering so the proxy survives logout: use it on SSH-only or headless machines or with tmux/screen, not on a desktop. On Windows the hooks are in exec form; `--hook-command` is still a shell string |
| `sync [--force] [--quiet]` | Make sure the settings hold a JWT valid for more than `refresh_before` seconds |
| `daemon [--max-sleep 60]` | Run `sync` ahead of every expiry. It naps at most `--max-sleep` seconds, so it catches up within a minute after a laptop wakes. On failures it backs off from 30 s to 5 min |
| `token [--force]` | Print a valid JWT on stdout (for curl and scripts); also updates the settings |
| `status [--offline]` | In proxy mode a `config` row appears when the running proxy and the file differ: `status` compares a short fingerprint of each of the proxy's settings (no values) with the file it just read, so timestamps play no part. A `connections` row appears when the proxy has dropped connections that never presented the secret. Works when `config.json` does not load, then it reports that and what the proxy holds, and exits 1. Settings file, token source, sign-in state, where the refresh token lives (never its value), JWT fingerprint, expiry, and who the JWT is for: `iss`, `sub`, `email` (the `email_id` or `email` claim), `portkey_oid`, `portkey_workspace`, `config_slug` (`defaults.config_slug`) and `scope`. It then names the JWKS that publishes the signing key (the broker's `<origin>/.well-known/jwks.json`, or the IdP's `jwks_uri` when there is no broker) and says whether it lists the JWT's `kid`. That is one short request; `--offline` skips it. The client does not verify the signature: the gateway does, against the JWKS URL in its org settings, which the client cannot read |
| `requests [-n N \| --count N] [--json]` | Proxy mode: the proxy's last N requests (default 20; it keeps `proxy_log_requests`, in memory, lost on restart). Each shows time, method, path, status, latency and the note (`local-secret`, `gateway-401->498`, ...), then the headers Claude Code sent (`authorization`, `anthropic-beta`, `user-agent`, ...), the `x-portkey-api-key` the proxy injected, and the reply's `request-id` and `retry-after` when it has them (they show whether the gateway or Anthropic answered a 429 or 401). Credentials are partly masked: the scheme, 4 characters at each end and the length. The proxy's own `x-aigw-local` secret is never kept. A healthy proxy writes nothing to its log file for a request that succeeds, so this is where to look |
| `proxy [--max-sleep SECONDS] [--access-log FILE]` | Run the local proxy in the foreground (proxy mode; `daemon` runs it in the background under the single-instance lock). The launchd agent (`KeepAlive`), systemd unit (`Restart=on-failure`) and Task Scheduler task (restart on failure) restart it after a crash |
| `inspect [--live] [--fresh] [--show-claims] [--debug on\|off]` | Decode the JWT: header, times, Mode A claims, verdicts against the config, its source. Prints a `PROBLEM` line and exits 1 for `alg: none`, expired, not yet valid, no `exp`, issuer mismatch (Mode B), opaque token or the sentinel. Never prints the token or signature; redacts `sub`, email and groups unless `--show-claims`. `--fresh` mints a token without writing it. `--debug on` logs a summary at each renewal for 24 h |
| `doctor [--json]` | Read every config source (helper config, user settings, the managed file and `managed-settings.d/`, the macOS managed preferences, the Windows `HKLM`/`HKCU` policy, `AIGW_*` keys in managed `env`) and list findings as Error, Warning or Info, each with a fix. Exits 1 on any Error. Works with a broken config. Server-managed settings show as unknown |
| `hook precheck`, `hook stop-failure` | The two Claude Code hooks. They read the hook payload on stdin and always exit 0 |
| `hook-login-wait [--method device \| pkce \| pkce-print]` | Internal: the precheck's background sign-in. It reads the device authorization response on stdin, waits for the user, writes the JWT, notifies and exits |
| `logout` | Forget the refresh token, write the sentinel |
| `task install \| remove \| print [--name NAME]` | Windows: register or remove a Task Scheduler task that runs `daemon` at log on (current user, one instance, restart on failure, `pythonw.exe`). `print` shows the task XML and registers nothing, on any OS |

**Files and locking:**
- `~/.config/aigw-claude-auth/config.json` (Windows: `%APPDATA%\aigw-claude-auth\config.json`) holds your config. The refresh token is in the OS credential store (macOS Keychain, Linux Secret Service through `secret-tool`, Windows Credential Manager; service `aigw-claude-auth`, account `state-<hash of the state dir>`) unless `secret_store` is `file` or no store works; then `state.json` holds it. `state.json` (mode 600) also holds the discovered endpoints, the last sign-in method and learned refusals, never the JWT. A token found in `state.json` moves to the store on the next run. Limits: on macOS a secret over about 3900 characters stays in the file (`security -i` line limit); on Linux the store needs `secret-tool` and a session bus; on Windows an ssh or service session has no credential store (error 1312), so the file is used there, and values over 2560 bytes are split across several credentials (finding 20). Override the directory with `AIGW_CLAUDE_AUTH_DIR`. Mode 600 means nothing on Windows; the folder relies on the profile's default user-only permissions.
- While a sign-in started by the precheck is pending, `hook-login.json` (mode 600) next to `state.json` holds its user code, URL, expiry and the waiting process's pid. The device code itself is passed to that process on stdin and never written. The process logs to `hook-login.log` there. `status` shows a pending sign-in.
- The settings file is the first of: `--settings`, `AIGW_CLAUDE_SETTINGS`, `$CLAUDE_CONFIG_DIR/settings.json`, `~/.claude/settings.json`.
- Every write is atomic (temp file, fsync, rename, mode 600).
- A lock serializes the daemon and the hooks. The interactive part of `login` runs outside it, so a slow sign-in doesn't stall the hooks.

**Config keys.** `config.json` is checked against one schema when it is loaded: unknown keys (with a "did you mean"), the JSON type of every value, ranges, URLs (`http://` or `https://` with a host), the header name, the sentinel, a loopback `redirect_uri`, and the cross-field rules (a `client_id` needs an `issuer` or `token_endpoint`; a `redirect_uri` without `{port}` needs a fixed `redirect_port`). Every problem is listed at once, and `doctor` shows the same list (finding `config-invalid`), so a hand-edit never turns into a `TypeError` in a daemon or a hook. Whether a value works (reachable URL, the IdP accepting the scope) is for `doctor` and the live checks, not the schema.

| Key | Default | Meaning |
|---|---|---|
| `issuer` | | OIDC issuer; endpoints come from its discovery document |
| `token_endpoint` | | The IdP's token endpoint, when you don't want discovery from `issuer`. Overrides what discovery finds |
| `device_authorization_endpoint` | | The IdP's device authorization endpoint, to override discovery |
| `authorization_endpoint` | | The IdP's authorization endpoint (browser sign-in), to override discovery |
| `token_endpoint`, `device_authorization_endpoint`, `authorization_endpoint` | | Set explicitly to override discovery |
| `client_id` | | The IdP public client |
| `scope` | `openid offline_access` | Add the gateway's or broker's scope. `offline_access` is what gets a refresh token |
| `idp_token` | `access_token` | Which IdP token to use: `access_token` or `id_token` |
| `broker_url` | | Full exchange URL. A broker turns an IdP token that can't carry Portkey's claims (Entra ID, for one) into a JWT that does (Mode A). The IdP token is sent as `Authorization: Bearer`, and the response's `token` (or `access_token`) is the gateway JWT. Empty: the IdP token itself is the JWT: Mode A if your IdP adds Portkey's claims itself, Mode B if it is a standard token the gateway handles with its own settings |
| `token_command` | | Instead of an IdP: a command that prints a JWT, for example a corporate token tool. `login` doesn't apply then |
| `header` | `x-portkey-api-key` | The header the gateway reads the JWT from |
| `sentinel` | `expired` | File mode: written when no usable JWT can be had. Must match the LB rule, and can't be empty. Proxy mode writes none |
| `refresh_before` | `300` | Renew when fewer seconds than this are left |
| `hook_wait` | `3` | Seconds the precheck hook waits after a write, so the request carries the new value |
| `block_on_failure` | `true` | When there's no usable JWT, the precheck blocks the prompt. With `false` the prompt goes out with the sentinel, for setups that rely on the LB guard (never with the SaaS gateway, where the sentinel gets a 401 and the OAuth loop) |
| `hook_login` | `auto` | When signed out, what the precheck does: `auto` uses the same choice as `login` (see [Sign-in method](#sign-in-method)), preferring the last method that worked, and puts a device code or a sign-in URL into the block message; `device` always uses a device code; `off` only says to run `aigw-claude-auth login`. `AIGW_HOOK_LOGIN` (`auto`, `device`, `off`) overrides it: set `off` in CI and for `claude -p` |
| `login_method` | `auto` | `auto`, `device`, `pkce`, `pkce-print` or `pkce-paste`. Overridden by `login` flags and `AIGW_LOGIN_METHOD` |
| `device_unavailable_ttl` | `86400` | Seconds to remember that the IdP refused the device grant or the loopback redirect |
| `secret_store` | `auto` | `auto`: refresh token in the OS credential store, the file if none works; `file`: `state.json` only |
| `redirect_uri` | `http://127.0.0.1:{port}/` | The browser sign-in's loopback redirect. Must be an `http://` loopback address and use only `{port}` as a placeholder. Without `{port}` it needs a fixed `redirect_port` (Okta matches the registered URI exactly, so register this one) |
| `redirect_port` | `0` | The port the loopback listener binds. `0` is any free port (fine for Entra ID and Keycloak, which accept any loopback port); set it when the IdP pins one, and forward it with `ssh -L` from a remote host |
| `mode` | `file` | `file`: the JWT is written into `settings.json`. `proxy`: a local proxy (run by `daemon`, or `proxy` in the foreground) keeps the JWT in memory, injects it, and turns a gateway refusal into 498 after one renew-and-retry; `install` then writes `ANTHROPIC_BASE_URL=http://<proxy_listen>` and the per-user secret header, no JWT |
| `proxy_listen` | `127.0.0.1:18787` | The proxy's address. Loopback only; non-loopback addresses are refused. Every request must carry the per-user secret in `x-aigw-local` (written by `install` into `ANTHROPIC_CUSTOM_HEADERS`, kept in the state dir with mode 600, stripped before forwarding), so other local users and web pages can't use the proxy |
| `gateway_url` | | Proxy mode: the gateway the proxy forwards to (required) |
| `proxy_log_requests` | `100` | Proxy mode: how many recent requests the proxy keeps in memory for `requests`, 0 to 10000 (0 keeps none) |
| `proxy_max_body_mb` | `64` | Proxy mode: the largest request body the proxy accepts, 1 to 1024. A bigger one gets a 413 `request_too_large` before its body is read. The API's own limits are 32 MB (Messages, Token Counting), 256 MB (Message Batches) and 500 MB (Files), so raise this only if you send batches or files through the proxy. Applied without a restart |
| `fleet` | `false` | Set by the fleet packages: at login the fleet moves a personal install of the user aside, and `doctor` reports one that is left ([packaging/README.md](packaging/README.md)) |
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

## Re-run and evidence

`repro/run.py` reruns the tests: the offline scenarios take about 10 minutes and need only Python and Claude Code; the live ones need your
gateway and IdP and ask before they touch a login. How to run them and how to read the result: [docs/evidence/rerun.md](docs/evidence/rerun.md).

The claims this design rests on are numbered findings, each with the versions, environment, date, method and the command that reproduces it:
[docs/evidence/findings.md](docs/evidence/findings.md) (index and run log in [docs/evidence/](docs/evidence/README.md)). What has been tested on which
Claude Code, OS, gateway and IdP, and what to rerun for a newer one: [docs/support-matrix.md](docs/support-matrix.md).

## Known limitations

Ranked by what they would cost you. The full list, with what was and wasn't run, is [docs/evidence/limitations.md](docs/evidence/limitations.md).

1. **The SaaS AI Gateway has not been run.** It is reported to take Mode A only, with `defaults.config_id`, and it has no load balancer of yours for the guard, so there it is hooks only. Everything here was run against a hybrid gateway.
2. **Fleet packaging is a pilot.** Unsigned packages, no bundled interpreter for Windows, no upgrade or rollback policy, one user at a time in proxy mode. See [docs/fleet-deployment.md](docs/fleet-deployment.md).
3. **Windows has no live run.** The offline scenarios pass on Windows 11; a real IdP, the Task Scheduler task at a real log on, permissions on `%APPDATA%\aigw-claude-auth` and a locked-down corporate image weren't.
4. **The Claude desktop app and Cowork can't be routed by this client**: the app ignores `ANTHROPIC_BASE_URL` from settings (finding 16). [The documented route](docs/evidence/desktop-and-cowork.md) wasn't run.
5. **Only Entra ID (with the broker), Keycloak and Okta (by hand) have been exercised.** Ping hasn't. Okta has no scenario, and a full browser sign-in against it isn't recorded.
6. **Sign-in method detection ran on mocked signals only** for real `ssh -L`, dev containers and WSL2.
7. **No token lifetime guidance yet.** A Mode A JWT can't be revoked before it expires, so lifetime is the offboarding window.

## Private (not published)

- `aigw-config-selection`: which config the gateway applies (JWT claims, API key and workspace defaults) on SaaS and hybrid, tracked by release. Article under development.

## License

MIT; see [LICENSE](LICENSE).
