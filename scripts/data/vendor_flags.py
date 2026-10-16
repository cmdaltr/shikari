#!/usr/bin/env python3
"""
Vendor the flag of every country on the Cyber Powers map (static/images/world_equal_earth.svg,
data-iso) from flag-icons (MIT, 4x3 SVGs) into static/vendor/flag-icons/, with its licence.
Flags render as images, so they work where flag emoji don't (Windows shows "GB").
Somaliland and Northern Cyprus have no ISO code, so no flag-icons file: theirs are drawn here,
on the same 640x480 canvas.

Usage:
    python3 scripts/data/vendor_flags.py

Standard library only. Run again after the map changes.
"""

import math
import re
import sys
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MAP = ROOT / "static" / "images" / "world_equal_earth.svg"
OUT = ROOT / "static" / "vendor" / "flag-icons"
VERSION = "7.6.0"
BASE = f"https://cdn.jsdelivr.net/npm/flag-icons@{VERSION}"


def star(cx: float, cy: float, r: float, rotate: float = -90) -> str:
    """A five-pointed star's points, the first pointing `rotate` degrees from east."""
    points = []
    for i in range(10):
        radius = r if i % 2 == 0 else r * 0.382
        angle = math.radians(rotate + i * 36)
        points.append(f"{cx + radius * math.cos(angle):.1f},{cy + radius * math.sin(angle):.1f}")
    return " ".join(points)


# Green, white and red bands; the Shahada on the green, a black star on the white
SOMALILAND = f"""<svg xmlns="http://www.w3.org/2000/svg" id="flag-somaliland" viewBox="0 0 640 480">
  <path fill="#009639" d="M0 0h640v160H0z"/>
  <path fill="#fff" d="M0 160h640v160H0z"/>
  <path fill="#de2010" d="M0 320h640v160H0z"/>
  <text x="320" y="100" fill="#fff" font-family="Arial, sans-serif" font-size="52" font-weight="700" text-anchor="middle"
        direction="rtl">لا إله إلا الله محمد رسول الله</text>
  <polygon fill="#000" points="{star(320, 242, 62)}"/>
</svg>
"""

# White, a red band near the top and bottom, a red crescent and star between them
NORTHERN_CYPRUS = f"""<svg xmlns="http://www.w3.org/2000/svg" id="flag-northern-cyprus" viewBox="0 0 640 480">
  <path fill="#fff" d="M0 0h640v480H0z"/>
  <path fill="#e30a17" d="M0 40h640v36H0zm0 364h640v36H0z"/>
  <mask id="nc-crescent"><rect width="640" height="480" fill="#fff"/><circle cx="296" cy="240" r="76" fill="#000"/></mask>
  <circle cx="268" cy="240" r="96" fill="#e30a17" mask="url(#nc-crescent)"/>
  <polygon fill="#e30a17" points="{star(380, 240, 52, 180)}"/>
</svg>
"""
OWN = {"somaliland.svg": SOMALILAND, "northern-cyprus.svg": NORTHERN_CYPRUS}


def main() -> int:
    codes = sorted({c.lower() for c in re.findall(r'data-iso="([A-Z]{2})"', MAP.read_text(encoding="utf-8"))})
    flags = OUT / "4x3"
    flags.mkdir(parents=True, exist_ok=True)
    for old in flags.glob("*.svg"):
        old.unlink()
    total = 0
    for code in codes:
        with urllib.request.urlopen(f"{BASE}/flags/4x3/{code}.svg", timeout=60) as res:
            data = res.read()
        (flags / f"{code}.svg").write_bytes(data)
        total += len(data)
    for name, svg in OWN.items():
        (flags / name).write_text(svg, encoding="utf-8")
    with urllib.request.urlopen(f"{BASE}/LICENSE", timeout=60) as res:
        (OUT / "LICENSE").write_bytes(res.read())
    (OUT / "VERSION").write_text(f"flag-icons {VERSION} (4x3), plus somaliland.svg and northern-cyprus.svg drawn by "
                                 f"scripts/data/vendor_flags.py\n", encoding="utf-8")
    print(f"{len(codes)} flags ({total // 1024} KB) and {len(OWN)} drawn, in {OUT.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
