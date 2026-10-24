---
id: aigw-claude-code-native-login
title: Claude Code with its own Anthropic login behind the AI Gateway: gateway JWT in a second header, refresh, and failing fast instead of a multi-minute OAuth loop
area: aigw
type: guide            # guide | behavior | capability | limitation | workaround | position
status: verified          # verified | reported | stale | superseded | retracted
visibility: internal      # internal | public
verified: 2026-10-24      # YYYY-MM-DD: date of the newest private evidence folder; empty if never tested
versions:                 # component: version, as confirmed by that evidence
  claude-code: 2.1.286 (Linux), 2.1.308 (macOS)
  aigw-claude-auth: 1.0.0
  aigw-gateway: 2.29.0
source:                   # required when status is reported: where the claim came from
related: [aigw-entra-jwt-broker]               # other article IDs
supersedes: []
superseded_by:
tags: [claude-code, anthropic, oauth, jwt, mode-a, mode-b, passthrough, forward-headers, hooks, alb, entra, device-code, pkce]
internal_refs: []         # public only, recorded exceptions with `why`: README → Private references
---
Metadata for this article, read by `kb`, Obsidian Dataview and agents. The content is in [README.md](README.md).
