# Roadmap (draft)

**Status: planning notes, not commitments.** Written 2026-10-27. Nothing here is built; each claim about the gateway is either marked as
read from a document or measured elsewhere, and is to be re-tested here before it goes into the [findings](evidence/findings.md).
Everything about the gateway is verified by test and documented before it is relied on; until then it is a lead.

## Questions this plan answers

1. How fast can a user be cut off (the kill switch)?
2. How short can the gateway JWT live?
3. Can a call already in flight be interrupted?
4. Where should credentials live when there is no OS credential store, or no IdP?
5. What changes when the second credential is cloud auth (Vertex, AWS) and not an Anthropic login?

## Revocation: what each option can and cannot do

| Mechanism | Latency | Interrupts a call in flight? |
|---|---|---|
| IdP revoke (no new JWT can be minted) | up to one JWT lifetime | no |
| Gateway JWT guardrail with `introspectEndpoint` and `introspectCacheMaxAge` | up to the cache window | no (checked when a request starts, as far as known) |
| Bring-your-own webhook guardrail reading a blocklist | the next request, if the list is not cached long | no, unless output guardrails run on streams (unknown) |
| This client's local proxy drops its own connections (proxy mode only) | as fast as the proxy learns of the kill | yes: it owns the client and upstream sockets |
| Someone stops the Claude Code process | immediate | yes, but not remote |

Exposure is bounded by one request's duration, so blocking the next request is enough for most threat models. Cutting a stream matters for
long agentic calls and for cost, and only proxy mode can do it. A check inside the client is advisory against a hostile user (they can run
`curl`, or patch the client), so the gateway has to be the enforcement point.

## What earlier tests already show

From [aigw-mcp-jwt-validation](https://github.com/thresh97/aigw-mcp-jwt-validation) (hybrid gateway 2.27.0, Keycloak, 2026-10-14; this is the MCP
integration's `jwt_validation`, not the LLM request path):

- With `introspectCacheMaxAge: 30`, a revoked token was accepted at 0, 11 and 21 seconds and rejected from 32 seconds. The cache window is the revocation latency.
- The gateway posts the introspection request form-encoded (as RFC 7662 specifies). The introspecting client must be in the token's `aud`, or every token reads `Token is not active`.
- `jwt_validation` has `maxTokenAge` (an `iat` check) and `claimValues`. Gateway authentication does not check `aud`.

From [aigw-byo-guardrail](https://github.com/thresh97/aigw-byo-guardrail) (SaaS 2026-10-13, hybrid 2.27.0 and 2.29.0):

- A webhook sees a client header only if it is listed in `forwardHeaders`, and the control plane refuses `authorization`, `x-portkey-api-key`,
  `x-portkey-metadata`, `x-portkey-config`, `x-api-key` and `cookie` (error AB01; seen on the MCP guardrail, not separately shown for the LLM path).
  So a webhook probably cannot be handed the gateway JWT.
- The payload's `metadata` is the client's own `x-portkey-metadata`, passed as sent. No verified user identity reaches the webhook.
- `failOnError: true` fails closed (446) when the webhook errors; `false` skips every rule. A webhook timeout is untested. A denied client sees only "Webhook request failed".

## The signed revocation list

An unauthenticated HTTPS file that lists currently rejected subjects, signed, so any consumer can verify it without trusting the transport.

- **Format:** a JWS signed RS256 (the client is standard-library only, and RSA verification is one modular exponentiation plus a padding check).
  Payload: `iat`, `exp`, a monotonic `seq`, and opaque subject IDs (the JWT `sub`; no email addresses, because the list is public).
  A consumer rejects a stale `exp` or a lower `seq`, so a replayed old list cannot un-revoke anyone.
- **Size:** entries only have to live for one JWT lifetime plus clock skew, so the list stays tiny. The publisher is a script that signs and uploads a static file.
- **Client consumer (proxy mode):** a poll thread in the proxy with the public keys pinned in `config.json` (two, for rotation). On a hit it
  drops the JWT, stops renewing, closes the upstream sockets and answers 498 "access revoked", where a gateway refusal could send Claude Code into its 401 retry loop.
  `status` and `doctor` show the list's age. If the list cannot be fetched for longer than a set staleness, fail closed (operator option).
- **Gateway consumer:** the open problem. A webhook that keys on `sub` has no trustworthy `sub` (see above). Options to test:
  1. the JWT's metadata claims arriving as the payload `metadata`, set by the gateway and not the client;
  2. enforce at the introspection endpoint: the gateway sends the token there, the endpoint consults the list and answers `active: false`;
  3. enforce at your own load balancer or a proxy in front of the gateway, which sees the JWT;
  4. client-side only (advisory).

  The leaning is option 2, with the proxy for the clean cut-off. Option 2 is measured only on the MCP path so far.

  A webhook that receives no verified claims may be a dead end for this, which does not mean it should not be investigated. The better outcome would be
  a **feature request**: pass the verified JWT claims (all, or a named list as `include_claims` does for MCP identity forwarding) to webhook
  guardrails, which would make a webhook a general policy enforcement point, with a deny reason the client can see and a defined timeout behavior.

## Phases

### Phase 0: tests on the gateway (records in the evidence area, no client change)

1. Revocation latency through introspection with `introspectCacheMaxAge` at 0 and 300, on the LLM path (Okta or Keycloak; Entra is believed to lack RFC 7662).
2. Introspection failure modes: endpoint down (open or closed), and `active: false` (which status the client sees; a 401 triggers Claude Code's refresh loop).
3. How the JWT guardrail combines with organization-level JWT (Mode A) authentication.
4. Whether a webhook guardrail on the LLM path can see anything the gateway vouches for (the JWT's metadata claims, option 1 above), and its added latency and failure behavior.
5. Mid-request expiry: does a long stream survive its JWT expiring, and what does the next request get.
6. Whether the gateway can block by a stable claim (`sub`, key or workspace) without a webhook. A question for Portkey.

### Phase 1: decide the model

Recommended JWT lifetime and `refresh_before` per mode (file mode longer, proxy mode shorter); the kill-switch levels and the latency of each;
then update [architecture](architecture.md) and the [support matrix](support-matrix.md) after reruns.

### Phase 1b: the signed list

Build the format, the signing script and the proxy consumer; choose the gateway consumer from Phase 0. Open decision: fail open or closed when the list is unreachable (default proposed: closed after two lifetimes of staleness).

### Phase 2: credential storage

Documentation and scripts, no client change: per-user gateway keys fetched through the existing `token_command`. One worked example for each of
CyberArk Conjur, AWS Secrets Manager, Google Cloud Secret Manager and Azure Key Vault (and, if wanted, Vault or OpenBao). All are in scope from the start.

These are examples to copy, not a supported integration, so they are kept cheap to maintain:

- each example is a short script with its tool and API versions, and the date it was last run, stated in one table, so a version bump is one edit and one rerun;
- the examples use each provider's own CLI or plain HTTP, so the client stays standard-library only;
- there is no continuous version tracking: an example is rerun when someone bumps its row, and the table says how old each row is.

A shared key plus a user header (attribution by assertion, not proof) is a demo mode and is written up as one.

### Phase 3: Vertex and AWS

Read Claude Code's provider documentation first. Establish who renews the cloud bearer and whether the gateway JWT rides alongside it. Run on a real setup before writing anything.

### Phase 4: housekeeping

The two extracted repositories are private and linked from public pages (publish them or change the links); rebuild the two historical PNG diagrams as SVG;
update `ARTICLE.md`'s versions only after reruns.
