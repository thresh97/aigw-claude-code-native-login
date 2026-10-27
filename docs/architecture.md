# Architecture (current)

This is the source of truth for how the client works today: the two credentials, the two client modes, the defaults, the platforms
and what lives in this repository. For the reasoning behind the design see [design-v2.md](design-v2.md) (a historical record, not a
specification). For the evidence behind a claim see [evidence](evidence/README.md); for what has been run on which versions, the
[support matrix](support-matrix.md).

## What it is for

Organizations that want to govern Claude Code CLI use through an AI Gateway, with the gateway adding attribution, logging and policy,
while each user keeps their own Anthropic login and Anthropic keeps billing and limiting that login. The gateway never holds an
Anthropic key for the user. No long-lived gateway API key is handed out either: the gateway identifies the person by a short-lived JWT.

## Two credentials on every request

| | Anthropic login | Gateway JWT |
|---|---|---|
| Whose | The user's Claude account (`claude login`) | The gateway's: names the user, the org, the workspace and, optionally, the config |
| Header | `Authorization: Bearer ...`, sent by Claude Code as it always does | `x-portkey-api-key` by default (the config key `header`) |
| Lifetime | Managed by Claude Code (OAuth refresh) | About an hour; this client renews it |
| Used by | Anthropic, through the gateway's passthrough config | The gateway, to authenticate and attribute the request |

The JWT's claims are Portkey's own ([JWT modes](https://portkey.ai/docs/aigw/product/enterprise-offering/org-management/jwt)). In
**Mode A** you control the issuer and add the gateway's claims, from the IdP if it can add custom claims or from a token broker if it
cannot. In **Mode B** the JWT is a standard IdP token whose schema you cannot change, and the gateway fills in organization,
workspace and limits from its own settings (hybrid gateway only). These are about the token and are independent of the client modes below.

## The hard problem, and how the client answers it

Claude Code cannot tell a gateway 401 from an Anthropic 401. A 401 from the gateway sends a logged-in Claude Code into its OAuth
refresh-and-retry loop for minutes. So the client's job is to make that 401 rare and to turn "no usable JWT" into something else:
a 498 (the gateway's load balancer or this client's proxy answers it) that Claude Code shows at once, or a blocked prompt (a hook).

## Two client modes (`mode` in `config.json`)

| | File mode (default) | Proxy mode |
|---|---|---|
| Where the JWT lives | `env.ANTHROPIC_CUSTOM_HEADERS` in Claude Code's `settings.json` | In the memory of a local proxy only |
| What `install` writes | The gateway URL as `ANTHROPIC_BASE_URL`, the JWT line, two hooks | `ANTHROPIC_BASE_URL=http://127.0.0.1:18787`, a per-user secret line (`x-aigw-local`), two hooks; no JWT |
| Who renews | An optional background daemon, and the `UserPromptSubmit` hook before a prompt that needs it | The proxy, ahead of every expiry; the hook asks it |
| No usable JWT | The hook blocks the prompt; the sentinel `expired` is sent; an optional load balancer rule answers it with 498 | The proxy answers 498 itself and sends nothing upstream |
| Gateway refuses the JWT | The `StopFailure` hook renews and tells the user to retry | One renew-and-retry in the proxy, then 498 |
| Background service | Optional (launchd, systemd user unit, Task Scheduler task) | Required; `install` sets it up, `--linger` keeps it past logout on Linux |
| Load balancer guard | Optional extra ([gateway/alb-guard-ingress.yaml](../gateway/alb-guard-ingress.yaml)) | Not needed; inert for a proxy's traffic |
| Several users at once on one machine | Supported per user | Not supported (one fixed port) |

The proxy listens on `127.0.0.1:18787` only. Every request needs the per-user secret, which is checked in constant time and removed
before forwarding. A connection that has not presented the secret gets 10 seconds and one of 64 slots; a request body over
`proxy_max_body_mb` (64) gets a 413; the last requests are kept, with credentials partly masked, for `requests`. It follows
`config.json` while running (applies the IdP and broker keys, reports the others as "restart needed").

## Sign-in and credentials at rest

- **Sign-in:** authorization code with PKCE in a browser on the same machine, or the device authorization grant anywhere else. The
  client chooses by itself and remembers what worked. A public client; there is no client secret.
- **Refresh token:** in the OS credential store (macOS Keychain, Secret Service, Windows Credential Manager), else in `state.json`
  (mode 600). It is bound to the issuer and client that produced it and is never sent to another IdP.
- **JWT:** minted from the IdP token, directly or through a broker (`broker_url`), or from any command (`token_command`).
- **Files:** `~/.config/aigw-claude-auth/` (Windows: `%APPDATA%\aigw-claude-auth\`): `config.json`, `state.json`, the proxy secret,
  `proxy.json`. Claude Code's `settings.json` (`~/.claude/`, or `$CLAUDE_CONFIG_DIR`) holds only what `install` adds.

## Defaults

`mode` file · `proxy_listen` 127.0.0.1:18787 · `header` x-portkey-api-key · `sentinel` expired · `refresh_before` 300 s ·
`hook_wait` 3 s · `http_timeout` 30 s · `hook_http_timeout` 5 s · `secret_store` auto · `login_method` auto · `hook_login` auto ·
`proxy_log_requests` 100 · `proxy_max_body_mb` 64. The full list, with what each key may hold, is the README's config table and
`SCHEMA` in the client; `config.json` is validated against it when loaded and `doctor` reports the same problems.

## Platforms

macOS, Linux and native Windows, Python 3.8 or later, standard library only; the client is one file you copy. Which versions have
actually been run is in the [support matrix](support-matrix.md). The proxy's service is a launchd agent on macOS, a systemd user
unit on Linux and a Task Scheduler task on Windows.

## What lives where

| Path | What | Status |
|---|---|---|
| `client/` | `aigw_claude_auth.py` and its tests, example configs, service templates | Supported core |
| `gateway/` | The passthrough config, the load balancer rules (file mode) and a short Okta page | Examples |
| `repro/` | The reproducibility harness: fake IdP, mock gateway, scenarios, `WINDOWS.md` | Test kit |
| `packaging/` | Fleet packages (macOS `.pkg`, `.deb`, `.rpm`, a Windows installer), the Linux systemd smoke test | Pilot / administrator preview: see the [fleet guide](fleet-deployment.md) |
| `docs/` | This page, the support matrix, the evidence, the fleet guide, the historical design | Documentation |
| `tools/` | The release gate | Maintainer tool |

Two things that used to live here are separate, independently owned repositories with their own lifecycle: the Okta token inline hook
([idp-okta-webhook-custom-claims](https://github.com/thresh97/idp-okta-webhook-custom-claims)) and the Azure Windows test VM ([azure-win-vm-ssh](https://github.com/thresh97/azure-win-vm-ssh)).
This repository keeps only a short [Okta page](../gateway/okta.md) and the portable Windows test protocol (`repro/WINDOWS.md`), and links to them.

## Where to read next

| To | Read |
|---|---|
| Set it up for one user, or understand the commands and config | [README](../README.md) |
| Roll it out to a fleet | [fleet-deployment.md](fleet-deployment.md) |
| Know what was tested, and on what | [support-matrix.md](support-matrix.md) |
| Check a claim, or rerun the evidence | [evidence/](evidence/README.md) |
| Understand why it is built this way | [design-v2.md](design-v2.md) (history) |
| Change the code or release | [AGENTS.md](../AGENTS.md), `tools/release_check.py` |
