# Okta with the AI Gateway

Okta works as the IdP for this client. This page says what has been shown, what route to take for the gateway's claims, and where the
Okta-specific service now lives.

## What has been shown

- **Sign-in, refresh and claims, by hand** (client 1.3.0, an Okta Integrator org, a custom authorization server, a Native app): device code,
  PKCE support in discovery, refresh rotation and replay, the access token's claims, and what Okta drops or flattens
  ([finding 21](../docs/evidence/findings.md#finding-21)).
- **An Okta JWT against the hybrid gateway** ([finding 22](../docs/evidence/findings.md#finding-22)): accepted when the org's JWKS URL
  list holds Okta's keys, and `client_live` passed with Okta and Claude Code 2.1.308.
- Not shown: a full browser (PKCE) sign-in against Okta, the in-session sign-in from the first prompt against Okta, and Ping. See the
  [support matrix](../docs/support-matrix.md).

The app and authorization-server settings that mattered (grant types, the exact loopback redirect URI, the access policy, the custom scope and
claims) are under "Okta specifics" in the [README](../README.md#what-you-need).

## Which route for Portkey's claims

Okta claim expressions cannot produce a nested object, so a claim named `defaults.config_slug` arrives as a flat key with a dot, which the
gateway does not read. Two ways to get the nested claims Mode A needs:

1. **A token broker (recommended).** It exchanges the Okta token for a Portkey-signed Mode A JWT. It needs no Okta-side service, covers
   other IdPs too, and is the route the client's `broker_url` is built for. Mapping Okta groups to workspaces, defaults and limits is
   described in the design record's [mapping section](../docs/design-v2.md#mapping-idp-groups-to-gateway-workspaces-mode-a).
2. **An Okta token inline hook.** Okta calls an HTTPS service while minting the token and that service adds the claims. A reference
   implementation exists in its own repository,
   [idp-okta-webhook-custom-claims](https://github.com/thresh97/idp-okta-webhook-custom-claims). **It is not production-ready:** no real Okta
   organization has exercised it, it sits synchronously on the sign-in path with a 3 second budget, and when it is down or slow Okta still issues the token but without the claims, which the gateway refuses. If you
   use it, put every Mode A claim in the hook, never half in claim expressions: a hook failure then yields a token without the required claims,
   which the gateway refuses.

Choose the hook only if you want Okta to be the only token issuer and the gateway to trust Okta's keys directly, and you are prepared to run
it as a service.
