# The Claude desktop app behind the gateway, with the user's own Anthropic token

> **Not a product, not official, no warranty, no support.** Art-of-the-possible example for learning and enablement, not endorsed by Palo Alto Networks, Portkey, Anthropic, Microsoft, Okta or any other vendor named. Use at your own risk; see the [README](../README.md).

**Status (2026-10-27): observed on one macOS machine with one Claude Pro account; not verified anywhere else, and not in the [support matrix](support-matrix.md).** Everything below is marked *documented* (read in a vendor document), *observed* (seen in a run or a log on that machine) or *not verified*. Read Anthropic's terms for subscription tokens before relying on this; this page does not interpret them.

The README covers Claude Code in a terminal or IDE. This page covers the Claude desktop app (Chat, Cowork and Code tabs). It does not honour `ANTHROPIC_BASE_URL` in `settings.json` (finding 16, [desktop-and-cowork.md](evidence/desktop-and-cowork.md)), so the CLI recipe does not carry over. The route that does exist is the app's own third-party (3P) gateway mode.

## The problem, and the design

*Documented:* in 3P mode the app sends **one** credential to the gateway (a bearer, or `x-api-key`) and never sends the user's Claude account credentials to the provider. The CLI recipe in this repository needs two: the user's Anthropic token (so Anthropic bills and limits the person) and a gateway JWT (so the gateway knows the person). The client's [proxy mode](../README.md) supplies the second one:

```
Claude desktop app (3P gateway mode, base URL http://127.0.0.1:18787)
   Authorization: Bearer <the user's own Anthropic token>        <- the app's one credential
   x-aigw-local:  <the proxy's per-user secret>                   <- a custom header, so only this app may use the proxy
        |
aigw-claude-auth proxy  (127.0.0.1, in memory)
   adds  x-portkey-api-key: <the user's gateway JWT>             <- minted from the IdP, renewed ahead of expiry
        |
the gateway (passthrough config: forwards Authorization, anthropic-beta, anthropic-version)
        |
Anthropic  (sees the user's own token: per-user attribution, the user's plan limits)
```

| Who | Holds | Never holds |
|---|---|---|
| The app | the user's Anthropic token, the proxy secret | the gateway JWT |
| The proxy | the gateway JWT (memory only), the IdP refresh token (credential store) | a provider key |
| The gateway | sees both in transit, logs and guards the request | a shared Anthropic key |
| Anthropic | the request, billed to the user's plan | the gateway JWT (not forwarded) |

This is *not* "the gateway never sees the token": it passes the user's Anthropic token through. What it removes is a shared provider key at the gateway. The app's own SSO option (`inferenceGatewayOidc`, *documented*) would use the single credential slot for the IdP token, which leaves nowhere to carry the user's Anthropic token; the proxy keeps the SSO in the client instead.

## The token

*Documented:* `claude setup-token` prints a one-year token that authenticates with the user's Claude subscription (a Pro, Max, Team or Enterprise plan), can only make model requests, and is meant for Claude Code (`CLAUDE_CODE_OAUTH_TOKEN`).
*Observed:* Anthropic accepted it from the desktop app's Claude Code engine and from the CLI, and **refused it from a raw `curl` and from the app's own launch probe** (HTTP 429, `rate_limit_error`, message `Error`, no rate-limit headers), with the same token and model. The difference between the accepted and refused requests was the request itself (the Claude Code beta flag and system prompt), not the token or the gateway. This repository does not reproduce Claude Code's request shape from another client, and neither should you.
*Observed:* a Console API key (`sk-ant-api…`) works as a bearer through the same gateway, but it is billed per token to the Console organization, not to a subscription.

## Set it up

1. **Install the client in proxy mode** and sign in ([README](../README.md)). Note the proxy's secret: it is the file `proxy-secret` in the client's config directory (`~/.config/aigw-claude-auth/` on macOS and Linux). Copy it without printing it, for example `pbcopy < ~/.config/aigw-claude-auth/proxy-secret` on macOS.
2. **Mint the user's token** in a terminal: `claude setup-token`. Store it where you store credentials. Do not paste it into a chat, a ticket or a log.
3. **Configure the app.** *Documented:* open the menu **Help, Troubleshooting, Enable Developer Mode**, then **Developer, Configure Third-Party Inference**.
   - Provider **Gateway**, base URL `http://127.0.0.1:18787` (the proxy's address; the app accepted a loopback address here, *observed*).
   - Custom header `x-aigw-local` with the proxy secret as its value.
   - Credential kind **static**, value the setup token (or a **helper script** that prints it, see [Troubleshooting](#troubleshooting): the path must be absolute and outside macOS-protected folders).
   - Apply, then fully quit and relaunch the app.
4. **Gateway side.** The gateway must authenticate the JWT in `x-portkey-api-key` and forward `Authorization`, `anthropic-beta` and `anthropic-version` to Anthropic: [gateway/passthrough-config.json](../gateway/passthrough-config.json). *Observed:* a passthrough config that lists only those headers discards `x-api-key` and replaces it with the config's placeholder, so a credential sent in `x-api-key` fails with `401 invalid x-api-key`; keep the app's scheme at the default **bearer**.
5. **Check it.** Send a Code prompt, then `aigw-claude-auth requests --json` and look at each row's `status`, `path` and `in["user-agent"]`. You want `POST /v1/messages` rows from `claude-cli/… (external, claude-desktop-3p …)` with status 200. Rows from the `Electron` user agent that return 429 are the app's own probe (below); they are not a failure.

## What was observed

- The app's Claude Code engine (user agent `claude-cli/2.1.308 (external, claude-desktop-3p, agent-sdk/0.3.308)`, app build `Claude/3.6556.2`) sent `POST /v1/messages` and `/v1/messages/count_tokens` through the proxy and the gateway to Anthropic with status 200.
- **The credential was identified, not assumed.** With the app pointed at a logging mock gateway, every request (the launch probe, the model list, the engine) carried one credential of class `sk-ant-oat`, and `sha256("Bearer " + token)` truncated to eight hex characters matched the token file. A deliberately wrong reference file printed no match, so the comparison discriminates. The same check on a mock is the way to rerun this: note the hash, point the app at any server that logs a hash of the `Authorization` header, send a prompt, compare. Never log the token itself.
- The app also sends `anthropic-beta: oauth-2025-04-20` on its own probe and model-list calls, and the engine adds the Claude Code beta flags on real requests.

## Troubleshooting

**Where to look**

| What | Where |
|---|---|
| The app's log | macOS `~/Library/Logs/Claude-3p/main.log`; Windows `%LOCALAPPDATA%\Claude-3p\Logs\main.log` (*documented*). Lines about this feature start with `[custom-3p]`. `grep '\[custom-3p\]' main.log \| tail -20` |
| The app's diagnostic report | **Help, Troubleshooting, Generate Diagnostic Report, Export to file** (*documented*): `managed-config.txt` (where the configuration came from, secrets redacted), `provider-status.txt`, `deployment-mode.txt` |
| The proxy's recent requests | `aigw-claude-auth requests` (or `--json`): time, method, path, status, latency, the note (`local-secret`, `gateway-401->498`, …), the headers the app sent (credentials partly masked), the `x-portkey-api-key` the proxy injected, and the reply's `request-id` and `retry-after`, which show whether the gateway or Anthropic answered a 429 or 401. In memory only; lost on restart |
| The proxy's service log | macOS `~/Library/Logs/aigw-claude-auth.log`; Linux `journalctl --user -u aigw-claude-auth`; Windows `%LOCALAPPDATA%\aigw-claude-auth\logs\daemon.log` |
| The client's own checks | `aigw-claude-auth status` and `aigw-claude-auth doctor` |
| A background sign-in | `hook-login.log` in the client's config directory |
| The gateway and Anthropic | the response headers `x-portkey-trace-id` (gateway log) and `request-id` (Anthropic) for a failing call |

**Symptoms**

| Symptom | Cause | Look at | Fix |
|---|---|---|---|
| **"Couldn't load your organization's model list."** with a helper script as the credential | *Observed:* macOS blocked the helper. `main.log`: `helper blocked by macOS TCC … Operation not permitted`, then `credential helper failed (reason=tcc-denied)` and an empty model picker | `main.log` | Macs protect `~/Documents`, `~/Desktop` and `~/Downloads` from processes the app starts. Put the helper, and everything it runs, elsewhere (for example `~/.local/bin`). A test in Terminal proves nothing, because Terminal has the access |
| The same message, with a path like `~/bin/helper` | *Observed:* the app does not expand `~` | `main.log` (`running helper { helperPath: … }`) | Use the absolute path |
| The same message, or an empty model list, with a static credential | the model list call returned an error | `main.log`: `Gateway /v1/models non-OK { status: … }` | `498` goes to the next row; `401` is the gateway rejecting the JWT or the credential (run `aigw-claude-auth status`) |
| `498 proxy_auth_error … request not authorized. Run aigw-claude-auth install …` | *Observed:* the request reached the proxy without the right `x-aigw-local` header | `main.log`, `aigw-claude-auth requests` (note: `local-secret`) | The app's custom header must equal the contents of the `proxy-secret` file. Run `aigw-claude-auth doctor`; if the file's contents have changed since you configured the app, update the app |
| "Your connection works, but the provider rejected a test request", `HTTP 429`, `probedModel: …`, at launch and in the settings window | *Observed:* the app's own connection probe, a bare one-token request without Claude Code's request shape. Anthropic refuses that for a subscription token | `aigw-claude-auth requests --json`: `Electron` rows 429, `claude-desktop-3p` rows 200 | Nothing, if real prompts work. It is a warning, not an outage |
| `401 invalid x-api-key` through the gateway | *Observed:* the credential travels in `x-api-key` and a header-limiting passthrough config replaced it | the gateway config's `forward_headers` | Send the credential as a bearer (the app's default scheme) |
| `429 rate_limit_error` / `Error` from your own script with the setup token | *Observed:* subscription tokens are accepted only for Claude Code's requests | | Test with the app or the CLI, not `curl`. Use a Console key if you need a scripted client |
| A device-code prompt where you expected a browser sign-in | `hook_login` is `device` in `config.json`, or the remembered method is `device` | `config.json`, `state.json` (`last_login_method`), `hook-login.log` | Set `hook_login` to `auto` and run `aigw-claude-auth login --pkce` once ([README, sign-in methods](../README.md)) |
| Nothing reaches the proxy at all | wrong base URL, the configuration not applied, or the proxy not running | `aigw-claude-auth status`; the proxy's service log; the diagnostic report | The settings window is read-only when a managed profile exists; quit and relaunch the app after changes |
| Launch is fine but a session stalls after an hour | the gateway JWT or a cached helper credential expired | `requests` (a `498` or `401` row), the service log | `aigw-claude-auth renew`; check the helper's cache time (`inferenceCredentialHelperTtlSec`, 3600 by default, *documented*) |

## Limits and what is not verified

- One machine (macOS), one account (Pro), one app build. Windows, Linux, Team and Enterprise seats, other builds: not verified.
- One user per machine: the proxy has one fixed port ([architecture](architecture.md)).
- Signing out of the app: *not verified*. The documentation describes no user-facing sign-out in 3P mode; a session ends when the credential stops working. To cut a user off, revoke at the IdP (no new gateway JWT), at the gateway, and at Anthropic (the one-year token).
- A one-year token is a long-lived credential. Where it lives is up to you: a credential store, or a secrets manager read by a helper script.
- This does not use the app's own SSO sign-in (Microsoft Entra ID, Okta or another OIDC provider). That option is *documented* and works for per-user gateway identity, but then the gateway, not the user, holds the provider credential.

Related: [README](../README.md), [architecture](architecture.md), [findings](evidence/findings.md), [Claude desktop app and Cowork](evidence/desktop-and-cowork.md).
