#!/usr/bin/env python3
"""
Build the desktop app icons from archer.png: archer.png and archer-<size>.png (Linux),
archer.ico (Windows) and, on macOS (needs iconutil), archer.icns. The outputs are committed; rerun after changing the art.

    .venv/bin/python desktop/make_icons.py
"""

import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from PIL import Image, ImageDraw

ROOT = Path(__file__).resolve().parent.parent
SOURCE = ROOT / "archer.png"
OUT = ROOT / "desktop" / "icons"

SIZE = 1024
PAD = 100           # transparent margin around the rounded square (macOS leaves the corners clear)
RADIUS = 186        # corner radius of the square, ~22.5% of its side, as macOS icons use
BG = (233, 221, 190, 255)  # parchment: a warm cream, clearly not white against the Dock
FIGURE = 0.70       # the archer's height as a fraction of the square


def master():
    """The archer centred on an opaque light rounded square. Opaque, not transparent:
    a transparent icon shows see-through in the Dock once the app sets it at runtime."""
    art = Image.open(SOURCE).convert("RGBA")
    # The source has faint stray pixels around the figure; crop to what's actually visible
    art = art.crop(art.getchannel("A").point(lambda a: 255 if a > 64 else 0).getbbox())

    canvas = Image.new("RGBA", (SIZE, SIZE), (0, 0, 0, 0))
    draw = ImageDraw.Draw(canvas)
    draw.rounded_rectangle([PAD, PAD, SIZE - PAD, SIZE - PAD], radius=RADIUS, fill=BG)

    fit = int((SIZE - 2 * PAD) * FIGURE)
    art.thumbnail((fit, fit), Image.LANCZOS)
    canvas.alpha_composite(art, ((SIZE - art.width) // 2, (SIZE - art.height) // 2))
    return canvas


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    icon = master()
    icon.resize((512, 512), Image.LANCZOS).save(OUT / "archer.png")
    # Briefcase's Linux build takes one PNG per size, named <icon>-<size>.png
    for size in (16, 32, 64, 128, 256, 512):
        icon.resize((size, size), Image.LANCZOS).save(OUT / f"archer-{size}.png")
    icon.save(OUT / "archer.ico", sizes=[(s, s) for s in (16, 24, 32, 48, 64, 128, 256)])
    print(f"wrote {OUT / 'archer.png'}, {OUT / 'archer.ico'}")

    if not shutil.which("iconutil"):
        print("iconutil not found (macOS only); archer.icns left as it is")
        return 0
    with tempfile.TemporaryDirectory() as tmp:
        iconset = Path(tmp) / "Archer.iconset"
        iconset.mkdir()
        for size in (16, 32, 128, 256, 512):
            icon.resize((size, size), Image.LANCZOS).save(iconset / f"icon_{size}x{size}.png")
            icon.resize((size * 2, size * 2), Image.LANCZOS).save(iconset / f"icon_{size}x{size}@2x.png")
        subprocess.run(["iconutil", "-c", "icns", str(iconset), "-o", str(OUT / "archer.icns")], check=True)
    print(f"wrote {OUT / 'archer.icns'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
