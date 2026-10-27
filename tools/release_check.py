#!/usr/bin/env python3
"""Release gate: the things that must agree before a client release, checked mechanically.

    python3 tools/release_check.py            # every check; exit 1 if any fails
    python3 -m unittest tools/test_release_check.py

What it compares (AGENTS.md says "keep these in step"; this makes it a check, not a memory):
  config     DEFAULTS, SCHEMA, the README config table and the example configs list the same keys
  commands   the argparse commands and flags and the README client reference agree
  help       the top-level --help still explains both client modes and Mode A / Mode B
  versions   VERSION is a version; the fleet packages take it from the client; no reader-facing header hard-codes another
  fleet      the example fleet profile renders for every OS and its client config passes the client's own validation
  links      every relative Markdown link points at a file, and every #anchor at a heading that exists
  matrix     docs/support-matrix.md has a row for this client version and a review date that is not in the future
  guard      the 498 text matches in the client, the mock gateway and the load balancer rules
  informational (never fails): the version ARTICLE.md says the evidence was gathered on

Standard library only. Each check takes what it reads as arguments, so the tests can feed it broken input.
"""
import argparse
import datetime
import importlib.util
import json
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
VERSION_RE = re.compile(r"^\d+\.\d+\.\d+$")


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


def load_client(root=ROOT):
    return load_module("aigw_claude_auth_gate", root / "client" / "aigw_claude_auth.py")


# ------------------------------------------------------------------------------------------------- Markdown helpers

def strip_code(text):
    """The text without fenced code blocks and inline code spans, so examples are not read as links or headings."""
    text = re.sub(r"^(```|~~~).*?^\1[^\n]*$", "", text, flags=re.S | re.M)
    return re.sub(r"`[^`\n]*`", "", text)


def slugify(heading):
    """The anchor GitHub gives a heading."""
    text = re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", heading)             # a link keeps its text
    text = re.sub(r"[`*_~]", lambda m: "_" if m.group(0) == "_" else "", text)
    text = text.strip().lower()
    text = re.sub(r"[^\w\s-]", "", text, flags=re.UNICODE)
    return re.sub(r"\s", "-", text)


def heading_anchors(md_text):
    seen, out = {}, set()
    for line in re.sub(r"^(```|~~~).*?^\1[^\n]*$", "", md_text, flags=re.S | re.M).splitlines():
        m = re.match(r"^#{1,6}\s+(.*?)\s*#*\s*$", line)
        if m:
            slug = slugify(m.group(1))
            n = seen.get(slug, 0)
            seen[slug] = n + 1
            out.add(slug if n == 0 else f"{slug}-{n}")
    return out


def table_rows(md_text, start_marker, end_marker):
    """The cells of each table row between two markers, split on unescaped pipes."""
    i = md_text.index(start_marker)
    j = md_text.find(end_marker, i + len(start_marker))
    block = md_text[i:j if j != -1 else len(md_text)]
    rows = []
    for line in block.splitlines():
        line = line.strip()
        if line.startswith("|") and line.endswith("|") and not re.match(r"^\|[-\s|:]+\|$", line):
            rows.append([c.strip() for c in re.split(r"(?<!\\)\|", line[1:-1])])
    return rows


# ------------------------------------------------------------------------------------------------- checks

def config_problems(client, readme_text, example_dir):
    out = []
    if set(client.SCHEMA) != set(client.DEFAULTS):
        out.append(f"SCHEMA and DEFAULTS differ: {sorted(set(client.SCHEMA) ^ set(client.DEFAULTS))}")
    rows = table_rows(readme_text, "**Config keys.**", "\n## ")
    listed = {m.group(1) for r in rows if (m := re.match(r"^`([a-z_]+)`$", r[0]))}
    for k in sorted(set(client.DEFAULTS) - listed):
        out.append(f"config key {k!r} is in DEFAULTS but not in the README config table")
    for k in sorted(listed - set(client.DEFAULTS)):
        out.append(f"config key {k!r} is in the README config table but not in DEFAULTS")
    for p in sorted(Path(example_dir).glob("config*.example.json")):
        extra = set(json.loads(p.read_text())) - set(client.DEFAULTS)
        if extra:
            out.append(f"{p.name} has keys the client does not know: {sorted(extra)}")
    return out


def command_problems(parser, readme_text):
    out = []
    sub = next(a for a in parser._actions if a.__class__.__name__ == "_SubParsersAction")
    rows = table_rows(readme_text, "## Client reference", "**Config keys.**")
    documented = {}                                                    # command -> the whole row text
    for r in rows:
        if len(r) < 2:
            continue
        names = {c.split()[0] for c in re.findall(r"`([^`]+)`", r[0])}
        for n in names:
            documented[n] = r[0] + " " + r[1]
    for name in sorted(set(sub.choices) - set(documented)):
        out.append(f"command {name!r} is in the argument parser but not in the README client reference")
    for name in sorted(set(documented) - set(sub.choices)):
        out.append(f"command {name!r} is in the README client reference but not in the argument parser")
    for name, sp in sub.choices.items():
        if name not in documented:
            continue
        flags = {o for a in sp._actions for o in a.option_strings if o.startswith("--") and o != "--help"}
        for f in sorted(f for f in flags if f not in documented[name]):
            out.append(f"{name} {f} is in the argument parser but not in its README row")
    for r in rows:
        if len(r) < 2:
            continue
        for c in re.findall(r"`([^`]+)`", r[0]):
            name = c.split()[0]
            if name in sub.choices:
                known = {o for a in sub.choices[name]._actions for o in a.option_strings}
                for f in sorted(set(re.findall(r"--[a-z][a-z-]*", c)) - known):
                    out.append(f"README documents {name} {f}, which the argument parser does not have")
    return out


def help_problems(parser):
    text = parser.format_help()
    return [f"top-level --help does not mention {w!r}" for w in ("file", "proxy", "Mode A", "Mode B", "portkey.ai/docs") if w not in text]


def version_problems(client, root, build=None):
    out = []
    if not VERSION_RE.match(client.VERSION):
        out.append(f"VERSION {client.VERSION!r} is not major.minor.patch")
    pk = root / "packaging" / "README.md"
    if pk.exists():
        title = pk.read_text().splitlines()[0]
        if re.search(r"\(client \d", title):
            out.append(f"packaging/README.md hard-codes a client version in its title ({title!r}); the packages take it from the client's VERSION")
    if build is not None and build.package_version() != client.VERSION:
        out.append(f"the fleet packages would carry version {build.package_version()}, not the client's {client.VERSION}")
    return out


def fleet_problems(client, root, build):
    out = []
    fleet = json.loads((root / "packaging" / "fleet.example.json").read_text())

    def fill(v):
        if isinstance(v, dict):
            return {k: fill(x) for k, x in v.items()}
        return re.sub(r"<[^<>]+>", "example.com", v) if isinstance(v, str) else v
    fleet = fill(fleet)
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "fleet.json"
        p.write_text(json.dumps(fleet))
        try:
            loaded = build.load_fleet(p)
        except Exception as e:
            return [f"packaging/fleet.example.json (placeholders filled in) does not load: {e}"]
    for osname in ("macos", "linux", "windows"):
        try:
            build.render(loaded, osname)
        except Exception as e:
            out.append(f"the example fleet profile does not render for {osname}: {e}")
    try:
        cfg = build.client_config(loaded, client)
        bad = client.config_problems(dict(client.DEFAULTS, **cfg))
        out += [f"the fleet's client config fails the schema: {m}" for _, m in bad]
    except Exception as e:
        out.append(f"the fleet's client config is refused by the client: {e}")
    return out


def link_problems(files):
    """files: {relative path (posix): text}. Every relative link must reach a file, and every #anchor a heading."""
    out, anchors = [], {}

    def anchors_of(rel):
        if rel not in anchors:
            anchors[rel] = heading_anchors(files[rel]) if rel in files else None
        return anchors[rel]
    for rel, text in sorted(files.items()):
        for m in re.finditer(r"!?\[[^\]]*\]\(([^)\s]+)(?:\s+\"[^\"]*\")?\)", strip_code(text)):
            target = m.group(1)
            if re.match(r"^[a-z][a-z0-9+.-]*:", target, re.I) or target.startswith("//"):
                continue                                                 # http:, https:, mailto: ...
            path, _, frag = target.partition("#")
            dest = rel if not path else (Path(rel).parent / path).as_posix()
            dest = re.sub(r"(^|/)(?:\./)", r"\1", dest)
            parts = []
            for seg in dest.split("/"):
                if seg == "..":
                    if parts:
                        parts.pop()
                elif seg not in ("", "."):
                    parts.append(seg)
            dest = "/".join(parts)
            known = dest in files or any(f.startswith(dest.rstrip("/") + "/") for f in files) or (ROOT / dest).exists()
            if not known:
                out.append(f"{rel}: link to {target!r} does not reach a file")
            elif frag and dest.endswith(".md"):
                a = anchors_of(dest)
                if a is not None and frag.lower() not in a:
                    out.append(f"{rel}: link to {target!r}: no heading gives the anchor #{frag}")
    return out


def matrix_problems(client, matrix_text, today=None):
    if matrix_text is None:
        return ["docs/support-matrix.md is missing"]
    out = []
    today = today or datetime.date.today()
    m = re.search(r"Last reviewed:\s*(\d{4}-\d{2}-\d{2})", matrix_text)
    if not m:
        out.append("docs/support-matrix.md has no 'Last reviewed: YYYY-MM-DD' line")
    elif datetime.date.fromisoformat(m.group(1)) > today:
        out.append(f"docs/support-matrix.md says it was reviewed on {m.group(1)}, which is in the future")
    major_minor = ".".join(client.VERSION.split(".")[:2])
    if not re.search(rf"\|\s*`?{re.escape(major_minor)}\.[0-9x]+`?", matrix_text) and f"{major_minor}.x" not in matrix_text:
        out.append(f"docs/support-matrix.md has no row for client {major_minor}.x (the current version is {client.VERSION})")
    return out


def guard_problems(root):
    name = "client.test_aigw_claude_auth.ProxyRefusalTests.test_the_498_text_matches_the_lb_guard_everywhere"
    result = unittest.TestResult()
    old = sys.path[:]
    sys.path.insert(0, str(root))
    try:
        unittest.defaultTestLoader.loadTestsFromName(name).run(result)
    finally:
        sys.path[:] = old
    return [f"498 text mismatch: {t.id()}: {tb.strip().splitlines()[-1]}" for t, tb in result.failures + result.errors]


def article_note(root, client):
    p = root / "ARTICLE.md"
    if not p.exists():
        return None
    m = re.search(r"^\s+aigw-claude-auth:\s*([\d.]+)", p.read_text(), re.M)
    if m and m.group(1) != client.VERSION:
        return f"ARTICLE.md says the evidence was gathered on client {m.group(1)}; the current client is {client.VERSION}. Update `versions:` and `verified:` only after rerunning what changed."
    return None


# ------------------------------------------------------------------------------------------------- run

def markdown_files(root):
    out = {}
    tracked = subprocess.run(["git", "ls-files", "*.md"], cwd=root, capture_output=True, text=True)
    names = tracked.stdout.split() if tracked.returncode == 0 and tracked.stdout.strip() else \
        [p.relative_to(root).as_posix() for p in root.rglob("*.md") if ".git" not in p.parts]
    for n in names:
        if (root / n).exists() and "repro/results" not in n:
            out[n] = (root / n).read_text(encoding="utf-8")
    return out


def run_all(root=ROOT, only=None):
    """{check name: [problems]} and a list of informational notes."""
    client = load_client(root)
    readme = (root / "README.md").read_text(encoding="utf-8")
    files = markdown_files(root)
    build = load_module("aigw_build_gate", root / "packaging" / "build.py")
    matrix = (root / "docs" / "support-matrix.md")
    checks = {
        "config": lambda: config_problems(client, readme, root / "client"),
        "commands": lambda: command_problems(client.build_parser(), readme),
        "help": lambda: help_problems(client.build_parser()),
        "versions": lambda: version_problems(client, root, build),
        "fleet": lambda: fleet_problems(client, root, build),
        "links": lambda: link_problems(files),
        "matrix": lambda: matrix_problems(client, matrix.read_text(encoding="utf-8") if matrix.exists() else None),
        "guard": lambda: guard_problems(root),
    }
    results = {name: fn() for name, fn in checks.items() if only is None or name in only}
    note = article_note(root, client)
    return results, [note] if note else []


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--only", nargs="*", help="run only these checks")
    a = ap.parse_args(argv)
    results, notes = run_all(only=a.only)
    bad = 0
    for name, problems in results.items():
        print(("FAIL " if problems else "ok   ") + name)
        for p in problems:
            print("       - " + p)
        bad += bool(problems)
    for n in notes:
        print("note " + n)
    print(f"\n{len(results) - bad} of {len(results)} checks pass")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
