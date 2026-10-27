#!/usr/bin/env python3
"""Render an SVG to a PNG to look at. macOS only (Quick Look); elsewhere use rsvg-convert, inkscape or a browser.

    python3 tools/render_svg.py docs/flow-proxy-mode.svg [out.png]

Quick Look crops a wide SVG, so this renders a square-padded copy: the same drawing in the top-left of a square canvas. The PNG is for
reviewing a diagram while building it, not for publishing (the SVG is the product).
"""
import re
import subprocess
import sys
import tempfile
from pathlib import Path


def render(svg_path, out_path=None):
    svg = Path(svg_path).read_text(encoding="utf-8")
    m = re.search(r'<svg viewBox="0 0 (\d+) (\d+)" width="\d+" height="\d+"', svg)
    if not m:
        raise SystemExit("expected a root element like <svg viewBox=\"0 0 W H\" width=\"W\" height=\"H\" ...")
    w = int(m.group(1))
    square = svg.replace(m.group(0), f'<svg viewBox="0 0 {w} {w}" width="{w}" height="{w}"', 1)
    with tempfile.TemporaryDirectory() as d:
        src = Path(d) / Path(svg_path).name
        src.write_text(square, encoding="utf-8")
        r = subprocess.run(["qlmanage", "-t", "-s", str(w), "-o", d, str(src)], capture_output=True, text=True)
        png = Path(d) / (src.name + ".png")
        if r.returncode != 0 or not png.exists():
            raise SystemExit("qlmanage could not render it (macOS only). Try rsvg-convert, inkscape or a browser.")
        dest = Path(out_path) if out_path else Path(tempfile.gettempdir()) / (Path(svg_path).stem + ".png")
        dest.write_bytes(png.read_bytes())
    return dest


if __name__ == "__main__":
    if len(sys.argv) < 2:
        raise SystemExit(__doc__)
    print(render(sys.argv[1], sys.argv[2] if len(sys.argv) > 2 else None))
