# HANDOFF: macOS round 2, the precheck's sign-in (aigw-claude-auth 1.1.0)

For a coding agent (Codex, Claude Code or similar) working on the operator's Mac. Read README.md and AGENTS.md first. This file is temporary: it goes away once the macOS results are in the article.

## Where things stand

Round 1 on this Mac (2026-10-24) left a **trial install** in place: client 1.0.0 at `~/.local/bin/aigw-claude-auth`, config in `~/.config/aigw-claude-auth/`, Claude Code config dir `~/.claude-aigw` (the operator's own `/login` there, gateway settings and hooks installed), and the launchd agent `aigw-claude-auth` running with `CLAUDE_CONFIG_DIR=$HOME/.claude-aigw`. Round 1 results: offline repro PASS on Claude Code 2.1.308; device code sign-in ok; hooks ok; Notification Center ok with `notify: auto`. Browser (PKCE) sign-in failed with `AADSTS500113` until the lab's Entra app got the `http://127.0.0.1` redirect URI. Since that fix the operator has run the plain browser `aigw-claude-auth login` successfully.

New in 1.1.0: when the user is signed out, the **precheck hook starts a device code sign-in** in the background. It blocks the prompt with "AI gateway sign-in needed: open <URL> and enter the code <CODE> ..., then send your prompt again." Once the user has signed in, a detached process writes the JWT and sends a notification, and the resent prompt goes through. See README "Why the extra parts are needed" (item 2) and Findings row 10. So far it has been tested only against the fake IdP.

## Rules

- **Don't touch `~/.claude`.** Every Claude Code run here uses `CLAUDE_CONFIG_DIR=~/.claude-aigw`. If you are a Claude Code agent yourself, your own settings must stay as they are: rerouting them would reroute you.
- **Secrets.** No tokens, refresh tokens, passwords or JWTs in output, logs, the report or git. Use `aigw-claude-auth status` (fingerprints only) instead of reading `settings.json` or `state.json`. When you must look at the settings, print the keys only. The user code and URL in a block message are fine to report: they're single-use and useless after the sign-in.
- **No lab facts in git.** Gateway URL, tenant and client IDs and the test user stay out of tracked files. Don't commit or push unless the operator asks.
- **Run the repro outside your sandbox.** It listens on 127.0.0.1; in round 1 a sandbox turned every scenario into `ERROR` (`PermissionError: [Errno 1]`).
- **Report what you observe**, with the command and the masked output. If a step fails, record it and move on where possible.

## Steps

Mark each step in the report as `ok`, `differs` (with what happened) or `skipped` (with why).

### 0. Update

```bash
git pull
sw_vers; claude --version; python3 --version
cp client/aigw_claude_auth.py ~/.local/bin/aigw-claude-auth && chmod +x ~/.local/bin/aigw-claude-auth
aigw-claude-auth --version                                  # 1.1.0
launchctl kickstart -k gui/$(id -u)/aigw-claude-auth        # restart the agent on the new code
export CLAUDE_CONFIG_DIR=~/.claude-aigw
aigw-claude-auth status                                     # signed in yes, a JWT fingerprint
```

### 1. Offline repro

```bash
for s in unit headers errors precheck stopfailure; do $(brew --prefix)/bin/bash repro/run.sh $s; done
```

Expect `PASS` for each. `precheck` now has a `hooklogin` case (45 observations).

### 2. Browser sign-in, for the record

The operator says the plain `aigw-claude-auth login` (browser) works now. Confirm and record:
1. `aigw-claude-auth logout`, then `aigw-claude-auth login`: a browser opens on Entra, the operator signs in, and the terminal reports a new JWT. Then `status` shows `signed in    yes`.
2. `aigw-claude-auth logout`, then `aigw-claude-auth login --pkce --no-browser`: open the printed URL by hand. Same result.

Record any Entra prompt (account picker, consent) and the time it took.

### 3. The precheck's sign-in, live against Entra (the main test)

Stop the launchd agent first, so it can't interfere: `launchctl bootout gui/$(id -u)/aigw-claude-auth`. For 3b, set `"notify": "auto"` in `~/.config/aigw-claude-auth/config.json` if it's `off` (note the original value, restore it in 3g).

- **3a. Blocked with a code.** Run `aigw-claude-auth logout`. In a terminal, run `CLAUDE_CONFIG_DIR=~/.claude-aigw claude` and send a prompt. Expect at once: "UserPromptSubmit operation blocked by hook: AI gateway sign-in needed: open https://... and enter the code ... (within N min), then send your prompt again. Or run `aigw-claude-auth login` in a terminal." Record the exact text (the code may stay in), and how Claude Code displays it. In another terminal, `aigw-claude-auth status` should show a `pending` row with the same code. Check `~/.config/aigw-claude-auth/hook-login.json` holds no device code: `python3 -c 'import json;print(sorted(json.load(open("'$HOME'/.config/aigw-claude-auth/hook-login.json"))))'` should list `expires_at, pid, prompt, uri, user_code` only.
- **3b. Too early.** Send another prompt before signing in. Expect the same code, not a new one.
- **3c. Sign in.** The operator opens the URL (any browser, the phone works too), enters the code and signs in as the test user. Expect within seconds: a macOS notification "Signed in to the AI gateway; send your prompt again.", `status` showing `signed in    yes` and no `pending` row, and `~/.config/aigw-claude-auth/hook-login.log` ending with that message (no tokens in it).
- **3d. Resend.** Send the prompt again in the same session. Expect a normal answer with no block.
- **3e. Refused at Entra.** `logout`, prompt (new code), and at Entra cancel or decline instead of signing in. Expect a notification and a log line with the error, e.g. "AI gateway sign-in: device sign-in failed: ...". The next prompt gets a new code. Record the exact error text.
- **3f. Switched off.** Set `"hook_login": "off"`, then `logout` and prompt. Expect the old message only: "AI gateway: not signed in to the gateway: run `aigw-claude-auth login`", with no code and no `hook-login.json`. Set it back to `"device"`.
- **3g. Back to normal.** Run `aigw-claude-auth login`, restore `notify`, and restart the agent: `launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/aigw-claude-auth.plist`.
- **Optional 3h. Non-interactive.** Signed out, run `CLAUDE_CONFIG_DIR=~/.claude-aigw claude -p "Reply with exactly: OK" < /dev/null`. Record what is printed and the exit code. Then sign in using that code (or `login`).
- **Optional 3i. Code expiry.** Signed out, prompt, and don't sign in. After the code's lifetime (about 15 min with Entra), prompt again. Expect a new code.

### 4. Leave the trial as it was

Signed in, agent running, `notify` and `hook_login` as before, `~/.claude` untouched.

## Next round (not now): Claude desktop app and Cowork

After the CLI path works on macOS, the operator wants to test the Claude desktop app (its Claude Code) and Cowork, as far as they allow. Open questions to answer then, not assumptions:

- Does the app's Claude Code read `settings.json` `env` (`ANTHROPIC_BASE_URL`, `ANTHROPIC_CUSTOM_HEADERS`) and run the hooks (UserPromptSubmit, StopFailure)?
- Which config dir does it use? A GUI app doesn't inherit the shell's `CLAUDE_CONFIG_DIR`, so the trial dir may not apply; testing may need `launchctl setenv` or the real `~/.claude` (operator's call).
- Where does it keep the Anthropic login (Keychain?), and does a gateway 401 cause the same retry loop there?
- How does a hook's block message show up in the app? That decides whether the precheck's sign-in message works there.
- Cowork: does it allow a custom base URL, headers or hooks at all, or does it bypass them?

## Report

Write `~/aigw-claude-code-native-login-macos-report-2.md`, outside the repo:

- macOS, Claude Code, Python and client versions.
- Steps 0 to 4, each `ok`, `differs` or `skipped`, with the command and the masked output. For 3a to 3f, the exact messages.
- Anything in README or AGENTS.md that was wrong, missing or unclear.

Then pack the results:

```bash
grep -rE 'eyJ[A-Za-z0-9_-]{10,}\.|sk-ant-[A-Za-z0-9_-]{20,}' repro/results ~/.config/aigw-claude-auth/hook-login.log   # must find nothing
tar czf ~/aigw-macos-results-2.tgz -C repro results
cp ~/.config/aigw-claude-auth/hook-login.log ~/aigw-hook-login.log
```

The operator brings the three files back to the article's private evidence.
