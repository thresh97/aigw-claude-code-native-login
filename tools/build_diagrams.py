#!/usr/bin/env python3
"""Builds the two architecture diagrams, docs/flow-file-mode.svg and docs/flow-proxy-mode.svg.

    python3 tools/build_diagrams.py            # write both
    python3 tools/build_diagrams.py --check    # exit 1 if the committed files differ from what this would write
    python3 tools/render_svg.py docs/flow-proxy-mode.svg   # a PNG to look at (macOS)

The SVG files are the product and stay plain text (GitHub renders them). This script is the source: the parts the two diagrams share (the IdP,
the broker, the credentials callout, the gateway, Anthropic) are written once, and each mode adds its own machine and data path. To change a
box, a label or a color, change it here and rerun; the release gate fails if the committed SVGs are not what this writes.

Conventions (keep them, so a new diagram looks like these):
  canvas      1180 x 640, white rounded frame, Helvetica/Arial; text sizes 14 (box title), 12 (inner title), 11, 10 (body), 9 (arrow label)
  columns     machine 25..470 | identity 540..1155 | data path 540..1155 along y 400..560
  roles       amber  = the client            (#d97706 line, #fffbeb fill, #92400e / #78350f text)
              orange = Claude Code           (#ea580c, #fff7ed)
              blue   = identity (IdP, broker) (#3b82f6, #eff6ff) and the sign-in arrows
              purple = the gateway and the gateway JWT (#7c3aed, #faf5ff)
              green  = Anthropic             (#16a34a, #f0fdf4)
              slate  = infrastructure and notes (#64748b / #94a3b8, #f1f5f9)
              red    = refusals (498)        (#dc2626, dashed)
  arrows      one marker per color (arrow, arrow-blue, ...); dashed = optional or out of band; a numbered circle is one step
  numbering   1 sign in, 2 broker exchange, 3 the client prepares Claude Code, 4 the request, 5 on to the gateway, 6 on to Anthropic
  neutrality  name no single IdP: the diagrams are the same for Okta, Entra ID and Keycloak
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

AMBER, ORANGE, BLUE, PURPLE, GREEN, SLATE, RED = "#d97706", "#ea580c", "#3b82f6", "#7c3aed", "#16a34a", "#64748b", "#dc2626"
MARKERS = {"arrow": "#64748b", "arrow-blue": "#2563eb", "arrow-amber": "#d97706", "arrow-purple": "#7c3aed", "arrow-green": "#16a34a", "arrow-red": "#dc2626"}


# ---------------------------------------------------------------------------------------------- primitives

def section(title):
    return ["", "  <!-- " + "=" * 62 + " -->", "  <!-- " + title.ljust(62) + " -->", "  <!-- " + "=" * 62 + " -->"]


def rect(x, y, w, h, fill, stroke, sw, rx=10, dash=None):
    d = f' stroke-dasharray="{dash}"' if dash else ""
    return f'  <rect x="{x}" y="{y}" width="{w}" height="{h}" rx="{rx}" ry="{rx}" fill="{fill}" stroke="{stroke}" stroke-width="{sw}"{d} />'


def text(x, y, s, size=10, fill="#475569", weight=None, family=None, extra=""):
    w = f' font-weight="{weight}"' if weight else ""
    f = f' font-family="{family}"' if family else ""
    return f'  <text x="{x}" y="{y}" font-size="{size}"{w}{f} fill="{fill}"{extra}>{s}</text>'


def line(x1, y1, x2, y2, color, sw, marker, dash=None):
    d = f' stroke-dasharray="{dash}"' if dash else ""
    return f'  <line x1="{x1}" y1="{y1}" x2="{x2}" y2="{y2}" stroke="{color}" stroke-width="{sw}"{d} marker-end="url(#{marker})" />'


def path(d, color, sw, marker, dash=None):
    ds = f' stroke-dasharray="{dash}"' if dash else ""
    return f'  <path d="{d}" fill="none" stroke="{color}" stroke-width="{sw}"{ds} marker-end="url(#{marker})" />'


def step(cx, cy, n, color, r=10):
    return [f'  <circle cx="{cx}" cy="{cy}" r="{r}" fill="{color}" />', text(cx - 3.5, cy + 4, n, 11, "#ffffff", "700")]


def lines_of(items):
    """Flatten nested lists of lines (a step() is two lines)."""
    out = []
    for part in items:
        out += lines_of(part) if isinstance(part, list) else [part]
    return out


# ---------------------------------------------------------------------------------------------- shared parts

def head():
    out = ['<svg viewBox="0 0 1180 640" width="1180" height="640" xmlns="http://www.w3.org/2000/svg" font-family="Helvetica, Arial, sans-serif">', "  <defs>"]
    for mid, fill in MARKERS.items():
        out += [f'    <marker id="{mid}" viewBox="0 0 10 10" refX="7" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">',
                f'      <path d="M 0 1.5 L 8 5 L 0 8.5 z" fill="{fill}" />', "    </marker>"]
    out += ["  </defs>", "", "  <!-- Canvas frame -->", rect(5, 5, 1170, 630, "#ffffff", "#e2e8f0", 1.5, rx=16)]
    return out


def identity():
    """Step 1 (sign in), step 2 (broker exchange). The broker is optional and the IdP is not named."""
    return lines_of([
        section("IDENTITY: the IdP and the optional token broker (blue)"),
        rect(540, 45, 250, 120, "#eff6ff", BLUE, 2),
        text(555, 72, "Identity provider (IdP)", 14, "#1e40af", "700"),
        text(555, 92, "Public client, no secret:"),
        text(555, 108, "• browser sign-in (PKCE, http://127.0.0.1)"),
        text(555, 124, "• device code (ssh, no display, the hook)"),
        text(555, 145, "Refresh token → access tokens", 10, "#2563eb", "600"),
        "",
        rect(850, 45, 305, 120, "#eff6ff", BLUE, 2),
        text(865, 72, "Token broker (optional)", 14, "#1e40af", "700"),
        text(865, 92, "Adds Portkey's claims when the IdP can't (Mode A)"),
        text(865, 108, "• IdP access token in, gateway JWT out (1 h)"),
        text(865, 124, "• IdP groups → workspace and config"),
        text(865, 145, "Publishes /.well-known/jwks.json", 10, "#2563eb", "600"),
    ])


def sign_in_arrows(exchange_label):
    return lines_of([
        "", "  <!-- Step 1: client <-> IdP -->",
        line(450, 85, 532, 85, "#2563eb", 1.8, "arrow-blue"),
        line(540, 120, 458, 120, "#2563eb", 1.8, "arrow-blue"),
        step(495, 70, "1", "#2563eb"),
        text(479, 104, "sign in", 9), text(479, 138, "tokens", 9),
        "", "  <!-- Step 2: client -> broker -->",
        path("M 450 190 L 1100 190 L 1100 173", "#2563eb", 1.8, "arrow-blue"),
        step(580, 190, "2", "#2563eb"),
        text(598, 208, exchange_label, 10, "#1e40af", "600"),
    ])


def credentials_callout():
    return lines_of([
        section("REQUEST HEADERS CALLOUT (step 4)"),
        rect(540, 232, 380, 150, "#f5f3ff", "#ddd6fe", 1.2, rx=8),
        step(562, 256, "4", PURPLE, r=11),
        text(582, 260, "TWO CREDENTIALS ON EVERY REQUEST", 11, "#6b21a8", "700"),
        text(560, 284, '<tspan font-family="monospace" fill="#c2410c">Authorization</tspan>: the user\'s Anthropic login,', 10, "#334155"),
        text(572, 299, "checked by Anthropic (their own seat)", 10, "#334155"),
        text(560, 320, '<tspan font-family="monospace" fill="#7c3aed">x-portkey-api-key</tspan>: the gateway JWT,', 10, "#334155"),
        text(572, 335, "checked by the gateway (who, which workspace)", 10, "#334155"),
        text(560, 356, "No Anthropic key at the gateway: the passthrough", 10, "#64748b"),
        text(560, 371, "config forwards the user's own login", 10, "#64748b"),
    ])


def gateway_and_anthropic():
    return lines_of([
        "", "  <!-- Gateway (purple) -->",
        rect(765, 400, 210, 160, "#faf5ff", PURPLE, 2),
        text(780, 426, "Portkey AI Gateway", 14, "#6b21a8", "700"),
        text(780, 445, "JWT auth (Mode A or B)", 10, "#7c3aed"),
        text(780, 466, "• verifies the JWT (JWKS)", 10, "#334155"),
        text(780, 482, "• passthrough config from", 10, "#334155"),
        text(790, 497, "JWT or workspace default", 10, "#334155"),
        text(780, 513, "• forward_headers:", 10, "#334155"),
        text(790, 528, "authorization,", 10, "#334155", family="monospace"),
        text(790, 543, "anthropic-beta", 10, "#334155", family="monospace"),
        "", "  <!-- Anthropic (green) -->",
        rect(1015, 420, 140, 120, "#f0fdf4", GREEN, 2),
        text(1030, 447, "Anthropic API", 14, "#15803d", "700"),
        text(1030, 468, "Checks the user's", 10, "#166534"),
        text(1030, 483, "own login", 10, "#166534"),
        text(1030, 504, "Its refusals come", 10, "#166534"),
        text(1030, 519, "back as 401 with", 10, "#166534"),
        text(1030, 534, '"provider"', 10, "#166534", family="monospace"),
    ])


def gateway_to_anthropic_and_jwks():
    return lines_of([
        "", "  <!-- Step 6: gateway -> Anthropic -->",
        line(975, 455, 1007, 455, GREEN, 2, "arrow-green"),
        step(993, 439, "6", GREEN),
        "", "  <!-- JWKS: gateway -> broker (dashed, out of band) -->",
        line(950, 400, 950, 173, "#64748b", 1.8, "arrow", dash="5 5"),
        text(958, 372, "JWKS (cached)", 9, "#475569", "600"),
    ])


def footer(first_line):
    return ["", "  <!-- Footer -->",
            text(25, 605, f'<tspan font-weight="700">Gateway refuses the JWT (401 "Portkey Error")</tspan>{first_line}'),
            text(25, 621, '<tspan font-weight="700">Anthropic refuses the login (401 "anthropic error", "provider")</tspan>: left to Claude Code (/login).')]


# ---------------------------------------------------------------------------------------------- file mode

def file_mode():
    out = head()
    out += section("USER'S MACHINE (container)")
    out += [rect(25, 25, 445, 555, "#f8fafc", "#94a3b8", 1.5, rx=12, dash="6 4"),
            text(45, 48, "USER'S MACHINE (macOS / Linux / Windows) · FILE MODE", 12, "#475569", "700"),
            "", "  <!-- Client (yellow) -->",
            rect(60, 62, 390, 148, "#fffbeb", AMBER, 2),
            text(75, 88, "aigw-claude-auth (one Python file)", 14, "#92400e", "700"),
            text(75, 108, "• daemon (launchd / systemd / Task Scheduler): renews the JWT before it expires", 10, "#78350f"),
            text(75, 125, "• precheck hook: renews before the turn, or blocks it;", 10, "#78350f"),
            text(85, 140, "signed out → starts a device code sign-in, code in the message", 10, "#78350f"),
            text(75, 157, "• StopFailure hook: gateway refused the JWT → renew + notify", 10, "#78350f"),
            text(75, 174, '• no usable JWT → writes the sentinel "expired" (guard: 498)', 10, "#78350f"),
            text(75, 194, "state.json: IdP refresh token only (mode 600)", 10, "#b45309", "600"),
            "", "  <!-- settings.json (white inner) -->",
            rect(60, 262, 390, 92, "#ffffff", "#cbd5e1", 1.5, rx=8),
            text(75, 285, "Claude Code settings.json", 12, "#0f172a", "700"),
            text(75, 304, "ANTHROPIC_BASE_URL       = https://&lt;gateway&gt;", 10, "#334155", family="monospace"),
            text(75, 320, "ANTHROPIC_CUSTOM_HEADERS = x-portkey-api-key: &lt;JWT&gt;", 10, "#7c3aed", family="monospace"),
            text(75, 336, "hooks: UserPromptSubmit, StopFailure", 10, "#334155", family="monospace"),
            "", "  <!-- Claude Code (orange) -->",
            rect(60, 406, 390, 150, "#fff7ed", ORANGE, 2),
            text(75, 432, "Claude Code", 14, "#9a3412", "700"),
            text(75, 451, "The user's own Anthropic login (/login), unchanged", 11, "#7c2d12"),
            text(75, 472, "Authorization: Bearer &lt;Anthropic login&gt;", 10, "#c2410c", family="monospace"),
            text(75, 488, "x-portkey-api-key: &lt;gateway JWT&gt;", 10, "#7c3aed", family="monospace"),
            text(75, 510, "• picks up a rewritten settings file about 1 s later", 10, "#475569"),
            text(75, 526, "• a gateway 401 looks like its own expired login:", 10, "#475569"),
            text(85, 541, "13 OAuth refresh-and-retry attempts over about 4 min", 10, "#475569"),
            "", "  <!-- Step 3: client writes JWT into settings.json -->",
            line(255, 210, 255, 254, AMBER, 1.8, "arrow-amber"),
            step(277, 232, "3", AMBER),
            text(295, 236, "writes the JWT", 10, "#92400e", "600"),
            "", "  <!-- settings.json -> Claude Code -->",
            line(255, 354, 255, 398, "#64748b", 1.8, "arrow"),
            text(270, 381, "reads", 10, "#64748b"),
            "", "  <!-- Claude Code runs the hooks (left rail, up) -->",
            path("M 60 480 L 42 480 L 42 136 L 52 136", AMBER, 1.5, "arrow-amber", dash="4 3"),
            text(37, 330, "runs the hooks", 10, "#b45309", "600", extra=' transform="rotate(-90 37 330)" text-anchor="middle"')]
    out += identity()
    out += sign_in_arrows("POST /token/exchange (Bearer IdP token) → gateway JWT")
    out += credentials_callout()
    out += section("DATA PATH: ALB guard -> gateway -> Anthropic")
    out += ["  <!-- ALB guard (slate, dashed = optional) -->",
            rect(540, 400, 175, 160, "#f1f5f9", SLATE, 2, dash="6 4"),
            text(555, 426, "ALB guard", 14, "#334155", "700"),
            text(555, 443, "optional, hybrid only", 10, "#64748b", "600"),
            text(555, 456, "file mode only", 10, "#64748b", "600"),
            text(555, 476, "Sentinel, or no", 10, "#475569"),
            text(555, 491, "x-portkey-api-key:", 10, "#475569"),
            text(555, 506, "498, before the gateway", 10, "#dc2626", "600"),
            text(555, 525, "Claude Code fails at", 10, "#475569"),
            text(555, 540, "once, login untouched", 10, "#475569")]
    out += gateway_and_anthropic()
    out += ["", "  <!-- Step 4: Claude Code -> ALB guard -->",
            line(450, 455, 532, 455, PURPLE, 2.5, "arrow-purple"),
            step(491, 439, "4", PURPLE),
            "", "  <!-- 498 back to Claude Code -->",
            line(540, 520, 458, 520, RED, 1.8, "arrow-red", dash="5 4"),
            text(478, 512, "498", 10, "#dc2626", "700"),
            "", "  <!-- Step 5: ALB -> gateway -->",
            line(715, 455, 757, 455, PURPLE, 2.5, "arrow-purple"),
            step(738, 439, "5", PURPLE)]
    out += gateway_to_anthropic_and_jwks()
    out += footer(": Claude Code retries for minutes, then the StopFailure hook renews the JWT and notifies; resend the prompt.")
    out += ["</svg>", ""]
    return "\n".join(lines_of(out))


# ---------------------------------------------------------------------------------------------- proxy mode

def proxy_mode():
    out = head()
    out += section("USER'S MACHINE (container)")
    out += [rect(25, 25, 445, 559, "#f8fafc", "#94a3b8", 1.5, rx=12, dash="6 4"),
            text(45, 48, "USER'S MACHINE (macOS / Linux / Windows) · PROXY MODE", 12, "#475569", "700"),
            "", "  <!-- Client (yellow) -->",
            rect(60, 62, 390, 134, "#fffbeb", AMBER, 2),
            text(75, 88, "aigw-claude-auth (one Python file)", 14, "#92400e", "700"),
            text(75, 108, "• login: browser or device-code sign-in, keeps the refresh token", 10, "#78350f"),
            text(75, 124, "• precheck hook: no JWT → blocks the turn;", 10, "#78350f"),
            text(85, 139, "signed out → starts a device code sign-in, code in the message", 10, "#78350f"),
            text(75, 156, "• StopFailure hook: gateway refused the JWT → renew + notify", 10, "#78350f"),
            text(75, 180, "state.json: IdP refresh token only (mode 600); no JWT on disk", 10, "#b45309", "600"),
            "", "  <!-- settings.json (white inner) -->",
            rect(60, 222, 390, 78, "#ffffff", "#cbd5e1", 1.5, rx=8),
            text(75, 244, "Claude Code settings.json", 12, "#0f172a", "700"),
            text(75, 262, "ANTHROPIC_BASE_URL       = http://127.0.0.1:18787", 10, "#334155", family="monospace"),
            text(75, 277, "ANTHROPIC_CUSTOM_HEADERS = x-aigw-local: &lt;secret&gt;", 10, "#b45309", family="monospace"),
            text(75, 292, "hooks: UserPromptSubmit, StopFailure", 10, "#334155", family="monospace"),
            "", "  <!-- Claude Code (orange) -->",
            rect(60, 326, 390, 132, "#fff7ed", ORANGE, 2),
            text(75, 352, "Claude Code", 14, "#9a3412", "700"),
            text(75, 371, "The user's own Anthropic login (/login), unchanged", 11, "#7c2d12"),
            text(75, 392, "Authorization: Bearer &lt;Anthropic login&gt;", 10, "#c2410c", family="monospace"),
            text(75, 408, "x-aigw-local: &lt;per-user secret&gt;", 10, "#b45309", family="monospace"),
            text(75, 430, "• sends to the local proxy, never straight to the gateway", 10, "#475569"),
            text(75, 446, "• a gateway refusal comes back as a 498, at once", 10, "#475569"),
            "", "  <!-- Local proxy = the daemon (yellow) -->",
            rect(60, 484, 390, 82, "#fffbeb", AMBER, 2),
            text(75, 507, "Local proxy (the daemon), 127.0.0.1:18787", 14, "#92400e", "700"),
            text(75, 525, "• checks the secret, then adds x-portkey-api-key: &lt;JWT&gt;", 10, "#78350f"),
            text(75, 540, "• keeps the JWT in memory only; renews it before it expires", 10, "#78350f"),
            text(75, 555, "• gateway 401 → renew, retry once, else answer 498 itself", 10, "#78350f"),
            "", "  <!-- Step 3: client writes the proxy address and the secret into settings.json -->",
            line(255, 196, 255, 214, AMBER, 1.8, "arrow-amber"),
            step(277, 205, "3", AMBER),
            text(293, 209, "writes the address + secret", 10, "#92400e", "600"),
            "", "  <!-- settings.json -> Claude Code -->",
            line(255, 300, 255, 318, "#64748b", 1.8, "arrow"),
            text(270, 314, "reads", 10, "#64748b"),
            "", "  <!-- Step 4: Claude Code -> the local proxy -->",
            line(255, 458, 255, 476, PURPLE, 2.5, "arrow-purple"),
            step(277, 467, "4", PURPLE),
            text(293, 471, "to the proxy", 10, "#6b21a8", "600"),
            "", "  <!-- 498 back to Claude Code -->",
            line(425, 484, 425, 464, RED, 1.8, "arrow-red", dash="5 4"),
            text(433, 479, "498", 10, "#dc2626", "700"),
            "", "  <!-- Claude Code runs the hooks (left rail, up) -->",
            path("M 60 392 L 42 392 L 42 132 L 52 132", AMBER, 1.5, "arrow-amber", dash="4 3"),
            text(37, 262, "runs the hooks", 10, "#b45309", "600", extra=' transform="rotate(-90 37 262)" text-anchor="middle"')]
    out += identity()
    out += sign_in_arrows("the proxy renews: POST /token/exchange (Bearer IdP token) → gateway JWT")
    out += credentials_callout()
    out += section("DATA PATH: local proxy -> gateway -> Anthropic")
    out += ["  <!-- Note: no load balancer rule needed -->",
            rect(540, 398, 195, 100, "#f8fafc", "#cbd5e1", 1.2, rx=8),
            text(555, 420, "NO LOAD BALANCER RULE", 11, "#334155", "700"),
            text(555, 438, "The proxy answers 498 itself:", 10, "#475569"),
            text(555, 452, "no JWT, or the gateway refuses", 10, "#475569"),
            text(555, 466, "it after one renew and retry.", 10, "#475569"),
            text(555, 484, "Claude Code never sees the 401.", 10, "#64748b")]
    out += gateway_and_anthropic()
    out += ["", "  <!-- Step 5: local proxy -> gateway (the JWT is added here) -->",
            line(450, 525, 757, 525, PURPLE, 2.5, "arrow-purple"),
            step(490, 509, "5", PURPLE),
            text(506, 513, "adds x-portkey-api-key", 10, "#6b21a8", "600")]
    out += gateway_to_anthropic_and_jwks()
    out += footer(": the proxy renews and retries once, then answers 498; Claude Code never sees the 401 and the login is untouched.")
    out += ["</svg>", ""]
    return "\n".join(lines_of(out))


# ---------------------------------------------------------------------------------------------- output

def build_all():
    return {"docs/flow-file-mode.svg": file_mode(), "docs/flow-proxy-mode.svg": proxy_mode()}


def stale(root=ROOT):
    """The committed diagrams that differ from what this script writes."""
    out = []
    for rel, svg in build_all().items():
        p = root / rel
        if not p.exists() or p.read_text(encoding="utf-8") != svg:
            out.append(rel)
    return out


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if "--check" in argv:
        bad = stale()
        for rel in bad:
            print(f"out of date: {rel} (run python3 tools/build_diagrams.py)")
        return 1 if bad else 0
    for rel, svg in build_all().items():
        (ROOT / rel).write_text(svg, encoding="utf-8")
        print("wrote", rel)
    return 0


if __name__ == "__main__":
    sys.exit(main())
