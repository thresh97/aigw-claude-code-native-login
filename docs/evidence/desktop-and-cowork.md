# Claude desktop app and Cowork

**See also [docs/desktop.md](../desktop.md)**, which describes the 3P gateway route with the proxy and the user's own token as observed on one machine, with troubleshooting and log locations.

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
