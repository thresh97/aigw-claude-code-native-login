# Okta token inline hook for Portkey Mode A claims

`okta_token_hook.py` is a reference Okta [token inline hook](https://developer.okta.com/docs/reference/token-hook/):
Okta calls it while minting an access token, and it answers with the Portkey AI Gateway "Mode A" claims for the
user's Okta group (`portkey_oid`, `portkey_workspace`, a nested `defaults`, `usage_limits`, `rate_limits`, and
optionally `email_id`). Python 3.8+, standard library only, one file.

Why a hook: Okta claim expressions can't produce nested objects (a claim named `defaults.config_slug` arrives as a
flat key with a dot; README finding 21). A hook's patch `value` can be any JSON, so `defaults` and `usage_limits`
arrive as a real object and array. This follows Portkey's own
[JWT authentication with Okta](https://portkey.ai/docs/aigw/product/enterprise-offering/org-management/jwt/okta)
setup, which adds `defaults` with a hook, and extends it with a group-to-workspace mapping.

Nothing here was run against a real Okta org. The tests are offline, with payloads shaped from the docs.

## Fail open, so set it up fail closed

Okta calls the hook with a 3 s timeout and no retries. On timeout or error, **Okta issues the original token**
(fails open). So:

> **Put every Mode A claim (`portkey_oid`, `portkey_workspace`, `defaults`, limits) only in the hook. Do not
> also set any of them as Okta claims (claim expressions).**

Then a hook that is down, slow or erroring yields a token without `portkey_oid`/`portkey_workspace`, and the gateway
rejects it. The same holds for a user in no mapped group: the hook returns no commands. If you also kept
`portkey_workspace` as an Okta claim, a failed hook would issue a token that works with the wrong or default
settings. Keep only non-Portkey claims (e.g. `scopes` = `access.scope`, README "Okta specifics") in Okta itself.
Alert on 401/5xx and on hook failures in the Okta System Log.

## Mapping file

`mapping.example.json` (placeholders only). An ordered list; the **first rule whose `group` the user has wins**;
an optional `"default"` rule (a rule without `group`) applies to everyone else, `null`/absent means no commands.

```json
{"rules": [{"group": "aigw-eng", "email_id_from_login": true,
            "claims": {"portkey_oid": "...", "portkey_workspace": "...",
                       "defaults": {"config_id": "...", "config_slug": "...", "metadata": {}},
                       "usage_limits": [{"id": "...", "type": "cost", "credit_limit": 100, "status": "active"}],
                       "rate_limits": "passed through as written"}}],
 "default": null}
```

- Each key in `claims` becomes `{"op":"add","path":"/claims/<key>","value":<as written>}` in one
  `com.okta.access.patch` command.
- `email_id_from_login: true` adds `email_id` from the user's login (gateway identity precedence is `email_id`, then
  `sub`, then `uid`). Omit it to let the gateway use `sub`.
- The mapping can't set `iss sub aud exp iat nbf jti scp cid uid ver` (load fails).
- Loaded at start; reloaded when the file's mtime changes (checked per request, one `stat`) and on SIGHUP. A bad
  file on reload is logged and the previous mapping stays.
- No network I/O per request.

## Run

```
export OKTA_HOOK_SECRET='<the exact header value Okta will send>'   # or --secret-file
python3 okta_token_hook.py --mapping mapping.json --listen 127.0.0.1 --port 8080
```

Flags: `--auth-header` (default `Authorization`), `--secret-env`, `--secret-file`, `--tls-cert/--tls-key`,
`GET /healthz`. The secret is compared in constant time with the whole header value; a mismatch is a 401, and the
secret is never logged. Bodies over 256 KiB get 413; malformed or unexpected bodies get `200 {}` and a log line.
One log line per request: `user=<10 hex of sha256 of the Okta user id> rule=<group> claims=<names>`.

**TLS:** Okta only calls HTTPS endpoints on the internet. Run the hook behind a TLS-terminating reverse proxy
(nginx, Caddy, an ALB/API gateway forwarding to it) or, for a test, a tunnel (ngrok, cloudflared) pointed at
`127.0.0.1:8080`. Okta's own guide uses ngrok. Restrict the proxy to the hook path. `--tls-cert/--tls-key` serve TLS
directly if you prefer. Keep it up in more than one place: a 3 s timeout means a cold start can lock users out
(fail closed, which is the intent).

## Okta Admin Console steps

1. **Workflow > Inline Hooks > Add Inline Hook > Token.** Name it; URL `https://<hook host>/`; Authentication field
   `Authorization`; Authentication secret = the value in `OKTA_HOOK_SECRET` (Okta sends it as is, so
   `Basic ...` works as well as any opaque string). Save. (Okta also supports OAuth 2.0 client auth for hooks; not
   implemented here.)
2. **Security > API > Authorization Servers > `<your server>` > Claims > Add Claim** (only if you need groups,
   see below): name `groups`, Include in token type **Access Token**, Value type **Groups**, filter **Starts with**
   `aigw-`, Include in **Any scope**.
3. **Security > API > Authorization Servers > `<your server>` > Access Policies >** the policy and its rule used by
   the client app > edit the rule > **Use this inline hook** > pick the hook > **Update Rule**.
4. Remove any `portkey_oid`, `portkey_workspace`, `defaults.*` claims from the server's Claims tab (fail closed).
   Keep `scopes` = `access.scope` and the `completions.write` scope as in the repo README.
5. Create Okta groups `aigw-eng`, `aigw-research`, assign users (and the app) to them.

## Where the hook reads groups

Okta's docs I could read don't show groups in the hook request. The hook looks in `data.access.claims.groups`
(the Groups-type claim from step 2: **the recommended, documented-by-construction route**) and falls back to
`data.context.user.groups` (a guess). Use Token Preview or the System Log to see the real payload for your org.

## Verify

- **Token Preview** (Authorization Server > Token Preview): pick the client, user, grant type, scopes; the preview
  runs the hook (the payload can differ from a real sign-in). Check `defaults` decodes as an object.
- **Real token:** `aigw-claude-auth login` then `aigw-claude-auth inspect`. It shows `defaults.*` nested, and flags a
  flat `defaults.*` key (the Okta claim-expression mistake).
- Hook logs: the matched rule and claim names per request. Okta System Log: `inline_hook.executed`/failed events.
- Fail-closed check: stop the hook, sign in again, `inspect` should show no `portkey_oid`/`portkey_workspace`; the
  gateway should answer 401/403.

## Confirmed vs unconfirmed

Confirmed from docs (the Okta reference page rendered empty to my fetcher, so these come from Okta's token-hook
guide, Okta Developer Forum posts and Portkey's Okta page):
- HTTPS POST to your endpoint, Basic or configured-header auth ([guide](https://developer.okta.com/docs/guides/token-inline-hook/nodejs/main/)); 3 s timeout, no retries, and on timeout or error "The Okta process flow continues with the original token returned" ([inline hooks concepts](https://developer.okta.com/docs/concepts/inline-hooks/)).
- Request has `data.context` (`request`, `protocol`, `policy`, `user`) and `data.access.claims` / `.token.lifetime` /
  `.scopes` (a [forum post](https://devforum.okta.com/t/inline-token-hook-issue/23559) quoting an event).
- Response `com.okta.access.patch` with `add` on `/claims/<name>`, object value ([Portkey Okta page](https://portkey.ai/docs/aigw/product/enterprise-offering/org-management/jwt/okta)).

Unconfirmed (treat as such):
- Groups in the request body, and `data.context.user.profile.login`: guessed; use the groups claim.
- Whether Okta's reserved-claims list rejects any claim we set (the hook's own forbidden list is conservative).
- Whether the hook fires on **refresh-token grants** (the forum/support material suggests the request can carry
  a `/token` refresh request, but I did not confirm it fires or that the groups claim is present then). If it
  doesn't fire, refreshed tokens would keep the old claims or lose them: test a refresh and `inspect`.
- Array values in an `add` patch are expected to work like objects; not verified.

## Open questions

- Refresh grants (above). The client refreshes silently; a refreshed token without the Portkey claims fails closed.
- `usage_limits`: does the gateway count per JWT or per user? A new token each hour could reset a per-JWT counter.
- `defaults.config_slug` vs `config_id`: Portkey's SaaS docs name `config_id`; this repo's README says the hybrid
  gateway reads `config_slug`. The example sets both; keep the one your gateway type uses.
- `rate_limits` shape is undocumented; the mapping passes it through.

## Compared with the broker

This hook is Okta-only, needs an internet-facing HTTPS endpoint Okta can reach in 3 s, and its failure mode
(fail open) has to be designed around. The token broker (`aigw-entra-jwt-broker` in the article, IdP-neutral) exchanges
any IdP token for a Portkey-signed Mode A JWT, so it needs none of that and also covers Entra ID. Choose this hook
when you want Okta to be the only token issuer and the gateway to trust Okta's JWKS directly.
