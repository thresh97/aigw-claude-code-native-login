# HANDOFF: trial install and macOS test on a personal Mac

For a coding agent (Codex, Claude Code or similar) working on the operator's Mac. Read README.md and AGENTS.md first. This file is temporary: it goes away once the macOS results are in the article.

## Goal

1. Install `aigw-claude-auth` on this Mac as a **trial**, without touching the operator's everyday Claude Code.
2. Test the paths that were never run on macOS: browser (PKCE) and device sign-in against the real IdP, the launchd agent, Notification Center, and the hooks on macOS.
3. Run the repro (`repro/run.sh`) on macOS.
4. Write a report the operator can send back. Results go into the article's private evidence, not into this repo.

Everything in the article so far was verified on Linux with Claude Code 2.1.286 (README, Findings).

## Inputs from the operator (not in git)

The operator sends these separately. Never commit them, and never print the password or any token:

- `config.json` for the client: `issuer`, `client_id`, `scope`, `idp_token`, `broker_url`, `notify`.
- The gateway URL (`https://<gateway host>`).
- An IdP test user and password, for the sign-in prompts in a browser or on the device code page.
- The operator's own Anthropic login, done by the operator in step 2 (`/login`).

The gateway sits behind a load balancer with a source-IP allow-list. If requests time out instead of getting an HTTP answer, this Mac's address isn't on the list. Stop and tell the operator.

## Rules

- **Don't touch `~/.claude`.** Every Claude Code run in this test uses `CLAUDE_CONFIG_DIR=~/.claude-aigw`. Pass `--settings`/`CLAUDE_CONFIG_DIR` explicitly, and never run `aigw-claude-auth install` without `CLAUDE_CONFIG_DIR` set. If you are a Claude Code agent yourself, your own settings must stay as they are: rerouting them would reroute you.
- **Secrets.** No tokens, refresh tokens, passwords or JWTs in output, logs, the report or git. `aigw-claude-auth status` prints fingerprints only; use it instead of reading `settings.json` or `state.json`. When you must look at the settings, print the keys only (`python3 -c 'import json;print(list(json.load(open(...))["env"]))'`).
- **No lab facts in git.** The gateway URL, tenant and client IDs and the test user stay out of tracked files; `repro/env` and `repro/results/` are gitignored. Don't commit or push anything unless the operator asks.
- **Report what you observe**, with the command and the relevant output (masked). If a step fails, record the failure and move on to the next step where possible.

## Steps

Mark each step in the report as `ok`, `differs` (with what happened) or `skipped` (with why).

### 0. Preflight

```bash
sw_vers; python3 --version; claude --version; bash --version | head -1
brew install bash                 # repro/run.sh needs bash 4+; macOS ships 3.2
curl -s -o /dev/null -w '%{http_code}\n' --max-time 10 https://<gateway host>/v1/messages   # any code = reachable; 000 = blocked
```

### 1. Offline repro (no accounts needed)

```bash
cp repro/env.example repro/env
$(brew --prefix)/bin/bash repro/run.sh check
for s in unit headers errors precheck stopfailure; do $(brew --prefix)/bin/bash repro/run.sh $s; done
```

Expected: `PASS` for each. Linux-only assumptions in the scripts count as findings too; report them with the error, and don't patch around them silently.

### 2. Trial install

Follow README "1.3 Client, per user" and "Trial install":

```bash
mkdir -p ~/.local/bin ~/.config/aigw-claude-auth
cp client/aigw_claude_auth.py ~/.local/bin/aigw-claude-auth && chmod +x ~/.local/bin/aigw-claude-auth
cp <config.json from the operator> ~/.config/aigw-claude-auth/config.json
export CLAUDE_CONFIG_DIR=~/.claude-aigw
claude          # the OPERATOR runs this and does /login with their Anthropic account, then exits
```

### 3. Sign-in paths (each followed by `aigw-claude-auth status` → `signed in    yes`)

1. `aigw-claude-auth login`: on a Mac desktop the default is PKCE; a browser opens on the IdP. The operator signs in as the test user.
2. `aigw-claude-auth logout`, then `aigw-claude-auth login --device`: the code and URL are printed; the operator enters them.
3. `aigw-claude-auth logout`, then `aigw-claude-auth login --pkce --no-browser`: the URL is printed; open it by hand.

Record per path: worked or not, any IdP prompt (consent, MFA registration) and the error text if any.

### 4. Gateway and a real turn

```bash
aigw-claude-auth install --base-url https://<gateway host>       # CLAUDE_CONFIG_DIR still set
aigw-claude-auth status
# README "2. Quick check" curl: expect 401 "anthropic error: OAuth access token is invalid."
claude -p "Reply with exactly: OK" < /dev/null                    # expect OK
```

### 5. launchd agent

Install the plist per README 1.3, with `CLAUDE_CONFIG_DIR` (`$HOME/.claude-aigw`) added to its `EnvironmentVariables`. Then:

- `launchctl print gui/$(id -u)/aigw-claude-auth | head -20`: running.
- `~/Library/Logs/aigw-claude-auth.log`: no errors.
- See a renewal happen. Note the expiry in `status`. If it's far away, temporarily set `refresh_before` in `config.json` to (JWT lifetime − 120) and restart the agent. Within about 3 minutes, `status` should show a new fingerprint and expiry. Restore `refresh_before`, then restart the agent again.

### 6. Hooks in an interactive session

Run `CLAUDE_CONFIG_DIR=~/.claude-aigw claude` in a terminal. Stop the launchd agent for 6a to 6c (`launchctl bootout ...`) so it can't repair things behind the test's back. To edit the header, rewrite only the `x-portkey-api-key` line in `env.ANTHROPIC_CUSTOM_HEADERS` of `~/.claude-aigw/settings.json` with a small Python snippet. Don't print the file.

- **6a. Precheck renews.** Set the header value to `expired`, then send a prompt. Expect a normal answer after a pause of about 3 s, and a new fingerprint in `status`.
- **6b. Precheck blocks.** Run `aigw-claude-auth logout`, then send a prompt. Expect "UserPromptSubmit operation blocked by hook" with the sign-in message, and no request sent. Run `aigw-claude-auth login` again.
- **6c. Sentinel and load balancer.** Set `"block_on_failure": false` in `config.json`, run `logout`, then send a prompt. Expect an immediate 498 with "AI gateway token expired and could not be refreshed...". Then restore `block_on_failure`, `login` again, and set the header to a fresh JWT with `aigw-claude-auth sync --force`.
- **6d. StopFailure and Notification Center.** Flip one character in the middle of the JWT's last segment, then send a prompt. Expect retrying for about 4 minutes (Claude Code's OAuth loop on a gateway 401, see the README), then an auth error. After that, a macOS notification saying "AI gateway token renewed; retry your prompt.", and a new fingerprint in `status`. The next prompt works. If no notification shows, check System Settings → Notifications for Script Editor or osascript.

### 7. Live repro on macOS (optional; rotates the Anthropic login in `~/.claude-aigw`)

In `repro/env`, set `CLAUDE_BIN` (blank is fine), `LOGIN_CONFIG_DIR=~/.claude-aigw`, `GATEWAY_URL`, and `LB_GUARD=on`. Then:

```bash
$(brew --prefix)/bin/bash repro/run.sh check
for s in gateway live_login client_live stored_login; do $(brew --prefix)/bin/bash repro/run.sh $s --yes; done
```

Known risk: on macOS, Claude Code may keep a stored login in the Keychain instead of `<config dir>/.credentials.json`. The harness reads that file to check rotation and expiry. If `check` reports no stored login, or the `*_login_*` observations come out `missing`, report it: it's a finding about macOS, not a reason to patch the harness on the spot.

### 8. Leave or remove

Ask the operator. To remove: README "4. Teardown", plus `rm -r ~/.claude-aigw` (after the operator agrees). If the trial stays, keep the launchd agent and stay in the trial config dir.

## Next round (not now): Claude desktop app and Cowork

After the CLI path works on macOS, the operator wants to test the Claude desktop app (its Claude Code) and Cowork, as far as they allow. Open questions to answer then, not assumptions:

- Does the app's Claude Code read `settings.json` `env` (`ANTHROPIC_BASE_URL`, `ANTHROPIC_CUSTOM_HEADERS`) and run the hooks (UserPromptSubmit, StopFailure)?
- Which config dir does it use? A GUI app doesn't inherit the shell's `CLAUDE_CONFIG_DIR`, so the trial dir may not apply; testing may need `launchctl setenv` or the real `~/.claude` (operator's call).
- Where does it keep the Anthropic login (Keychain?), and does a gateway 401 cause the same retry loop there?
- How does a hook's block message show up in the app (matters for an in-hook device sign-in prompt)?
- Cowork: does it allow a custom base URL, headers or hooks at all, or does it bypass them?

## Report

Write `~/aigw-claude-code-native-login-macos-report.md`, outside the repo:

- Mac model and chip, macOS version, Python, Claude Code and client versions (`aigw-claude-auth --version`).
- Steps 0 to 8, each as `ok`, `differs` or `skipped`, with the command and the masked output.
- Anything in README or AGENTS.md that was wrong, missing or unclear for macOS.

Then pack the results and give both files to the operator:

```bash
tar czf ~/aigw-macos-results.tgz -C repro results
```

Scan the tarball for tokens first: `grep -rE 'eyJ[A-Za-z0-9_-]{10,}\.|sk-ant-[A-Za-z0-9_-]{20,}' repro/results` must find nothing. The operator brings both files back to the article's private evidence.
