# Support matrix and compatibility policy

Last reviewed: 2026-10-26 · Current client: 1.10.0 (`client/aigw_claude_auth.py`, `VERSION`)

The client depends on Claude Code behavior that nobody promises to keep: how soon `settings.json` is re-read, what a hook may
return, how managed and user settings merge, and which response statuses make Claude Code retry. This page says what has been run,
on which versions, at which level, and what to rerun before calling a newer version supported. It is a compatibility statement,
not a guarantee. Anything not in a table below is untested.

**Test levels.** *Offline*: the repro scenarios against a mock gateway and a fake IdP, with a real Claude Code where the scenario
needs one. *Live*: a real gateway and IdP with a real Claude Code (`gateway`, `stored_login`, `live_login`, `client_live`; these touch
a real login, so a person approves each run). *Manual*: done by hand and written down. *Emulated pilot*: a real privileged install of
a fleet package on a disposable machine, no IdP sign-in. *Unit*: `client/test_aigw_claude_auth.py` and the other suites (no Claude Code).

## Client versions

| Client | Status | What is covered |
|---|---|---|
| `1.10.x` (current) | Unit and smoke tested; configs checked by hand | Everything in 1.9.x, plus the config schema: `config.json` is validated against `SCHEMA` at load time (types, ranges, URLs, header and sentinel, loopback `redirect_uri`, a `client_id` needs an `issuer` or `token_endpoint`) and `doctor` shows the same problems. Unit suite on macOS 26.6 and Ubuntu 26.04 LTS; the systemd smoke test (50 checks). The two configs in real use (Entra ID and the broker on macOS; Okta, a fixed redirect port and a Lambda broker on Ubuntu) load and pass `doctor` with the new schema. **A stricter config can reject a file that 1.9.x accepted:** run `doctor` after upgrading. **Not rerun on 1.10.x:** the live scenarios, `managed`, Windows. |
| `1.9.x` | Unit and smoke tested; manual on macOS | Unit suite on macOS 26.6 (Python 3.13) and Ubuntu 26.04 LTS (Python 3.14, non-root). `packaging/linux/smoke-proxy-systemd.sh` on Ubuntu 26.04 with systemd as PID 1. Manual: this macOS machine's own Claude Code 2.1.308 session through the 1.9.0 proxy to the gateway (2026-10-26). **Not rerun on 1.9.x:** the live scenarios, the `managed` scenario, Windows. |
| `1.8.x` | Unit and smoke tested; Okta by hand | As 1.9.x. Manual, Ubuntu 26.04 container with an Okta Integrator org and a Lambda broker (2026-10-26): device code sign-in, the broker exchange, and a request through the proxy that the gateway accepted (it reached Anthropic, which rejected a deliberately invalid login). **No Claude Code prompt with Okta was recorded.** |
| `1.5.x` to `1.7.x` | Unit and smoke tested; manual on Linux | Service install for the proxy (launchd, systemd, Task Scheduler), `--linger`, the request log. Manual (1.6.0): Claude Code 2.1.311 in an Ubuntu 26.04 container through the proxy with Entra ID and the broker; several prompts answered (2026-10-26). |
| `1.4.x` | Offline and live | `mode: proxy` (1.4.0): `proxy` scenario on macOS and the Windows 11 VM, `stored_login_proxy` on macOS. Okta against the hybrid gateway: `gateway` and `client_live` (finding 22). Fleet packaging: emulated pilots on Linux, Windows and macOS, and one live fleet run on macOS (1.4.1). |
| `1.3.x` | Offline, live and manual | Credential store, sign-in selection, `doctor`, `inspect`: `managed` scenario (19 cases) on macOS, `keycloak` against Keycloak 26.4.7, Okta by hand. |
| `1.2.x` | Offline | Native Windows: the offline scenarios on the Windows 11 VM and macOS. |
| `1.0.x`, `1.1.x` | Offline and live | The original file-mode client with Entra ID and a broker, on Linux and macOS. |

## Claude Code versions

| Claude Code | Where it ran | Client versions it was exercised with | Level |
|---|---|---|---|
| `2.1.286` | Linux, Python 3.10 to 3.12 | 1.0.0, 1.1.0 | Offline, live |
| `2.1.308` | macOS 26.6, Python 3.13 | 1.0.x to 1.4.1 (most findings), and 1.9.0 manually | Offline, live, `managed`, manual |
| `2.1.310` | Windows 11 24H2 VM, Python 3.13 | 1.2.0 to 1.4.0 | Offline, emulated pilot, `winprobe` |
| `2.1.311` | Ubuntu 26.04 container, Python 3.14 | 1.6.0 | Manual, one proxied session |
| anything newer | | | **Untested.** See the policy below. |

## Operating systems and Python

| Platform | Python | Covered |
|---|---|---|
| macOS 26.6 (Apple silicon) | 3.13 (Homebrew); the system 3.9 is only a candidate for the service interpreter | Everything except Windows-only paths |
| Ubuntu 26.04.1 LTS (aarch64) | 3.14 | Unit suite as a non-root user; the systemd service path; a Claude Code session |
| Linux, earlier | 3.10 to 3.12 | The original 2026-10-24 findings, client 1.0.0 and 1.1.0 |
| Debian 12, Rocky 9 (containers) | the system Python | Fleet `.deb` and `.rpm` install, remove, first run |
| Windows 11 24H2 | 3.13, installed for all users | Offline scenarios, emulated pilot (file and proxy mode). `managed` is not ported |

Python 3.8 is the declared floor. The lowest version in the record above is 3.10. A 3.8 or 3.9 run has not been recorded.

## Gateways and identity providers

| | Status |
|---|---|
| Hybrid AI Gateway (`gateway_enterprise` 2.29.0), behind an AWS ALB with the guard rules | Tested, live. Mode A with Entra ID and a broker; Okta JWTs accepted when the gateway's JWKS list holds the broker's and Okta's keys (finding 22) |
| SaaS AI Gateway | **Not run here.** Reported as Mode A only, with `defaults.config_id` |
| Entra ID, with the token broker | Device code, PKCE (browser), refresh, broker exchange: tested live |
| Okta (Integrator org), custom authorization server | Device code, refresh rotation and replay, claims, `client_live` against the hybrid gateway. Browser PKCE: Okta's authorize endpoint accepts the registered loopback redirect, but a full browser sign-in has not been recorded |
| Keycloak 26.4.7 (Docker) | Device code, PKCE, `offline_access`, Mode A claims from mappers and Mode B (the `keycloak` scenario) |
| Ping and others | Untested |

## What to do with a newer Claude Code (or gateway)

A version newer than the newest row above is untested, not unsupported. To call it supported:

1. Run the offline scenarios (`repro/run.py unit headers errors precheck stopfailure proxy`). A `CHANGED` result means Claude Code or the
   gateway now behaves differently: read the scenario's finding in the README before touching the client.
2. Run `managed` (a person runs it; it writes the machine-wide managed-settings file) if managed settings, hooks or `allowedProviders` matter to you.
3. Run `stored_login`, `live_login` and `client_live` against your gateway and IdP (a person approves; they refresh the stored login).
4. Re-read the authoritative pages below and record anything that changed.
5. Add a row here with the versions, the date and the level, and move the `Last reviewed` date.

The release gate (`python3 tools/release_check.py`) refuses a release whose current client version has no row in the table above.

## Keeping the claims honest

Every behavior claim in this repository is one of three kinds, and the third is the weakest:

- **Authoritative:** stated in the vendor's documentation. Cite the page.
- **Observed:** a test or a run showed it. Keep the component versions, the environment, the date and the command that reproduces it
  (each finding in the README names its scenario).
- **Inferred:** read from code or reasoned, not run. Say so where it is used.

Documentation is a source of behavior the project would otherwise learn by experiment, so it is re-read on a schedule, not only when
something breaks. At each Claude Code upgrade, and at least monthly, re-read these and note any change next to the finding it affects:

| Page | Why it matters here | Last read |
|---|---|---|
| [Settings](https://code.claude.com/docs/en/settings) and the settings reference | The settings file model and precedence the client writes into | not in the 2026-10-26 pass |
| [Managed settings](https://code.claude.com/docs/en/managed-settings) | Drop-ins, `allowedProviders`, what a managed `env` replaces (finding 11) | not in the 2026-10-26 pass |
| [Hooks](https://code.claude.com/docs/en/hooks) | Timeouts, the exec form, `StopFailure` | not in the 2026-10-26 pass |
| [LLM gateway](https://code.claude.com/docs/en/llm-gateway) and [connect](https://code.claude.com/docs/en/llm-gateway-connect) | What `ANTHROPIC_BASE_URL` does with a saved claude.ai login | 2026-10-26 (the gateway page) |
| [Authentication](https://code.claude.com/docs/en/authentication) | The login the client must not disturb | not in the 2026-10-26 pass |
| [Setup](https://code.claude.com/docs/en/setup) | Install methods and update behavior | 2026-10-26 |
| [Errors](https://platform.claude.com/docs/en/api/errors) | Status codes and the request size limits the proxy's body cap follows | 2026-10-26 |

The Portkey side has its own pages: [JWT authentication](https://portkey.ai/docs/aigw/product/enterprise-offering/org-management/jwt)
and [JWT with Okta](https://portkey.ai/docs/aigw/product/enterprise-offering/org-management/jwt/okta). Where the observed behavior of the
gateway differs from them (for example the config-selection claims), the README says which one it is relying on.
