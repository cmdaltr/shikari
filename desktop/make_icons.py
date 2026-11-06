#!/usr/bin/env python3
"""
Build the desktop app icons from the Bateleur hexagon: shikari.png and shikari-<size>.png (Linux),
shikari.ico (Windows) and, on macOS (needs iconutil), shikari.icns. The outputs are committed; rerun after changing the art.

The master is the hexagon brand mark (static/images/shikari/shikari-bateleur-hexagon.png). The
rounded-square alternate (shikari-bateleur.png in the repo root) is there if the hexagon's
transparent surround reads badly in the Dock: point SOURCE at it instead and rerun.

    .venv/bin/python desktop/make_icons.py
"""

import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from PIL import Image

ROOT = Path(__file__).resolve().parent.parent
SOURCE = ROOT / "static" / "images" / "shikari" / "shikari-bateleur-hexagon.png"
OUT = ROOT / "desktop" / "icons"

SIZE = 1024


def master():
    """The Bateleur app icon, finished art with its corners already transparent, exactly as macOS
    wants. Used as-is, only normalised to a square SIZE canvas."""
    art = Image.open(SOURCE).convert("RGBA")
    if art.size != (SIZE, SIZE):
        art = art.resize((SIZE, SIZE), Image.LANCZOS)
    return art


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    icon = master()
    icon.resize((512, 512), Image.LANCZOS).save(OUT / "shikari.png")
    # Briefcase's Linux build takes one PNG per size, named <icon>-<size>.png
    for size in (16, 32, 64, 128, 256, 512):
        icon.resize((size, size), Image.LANCZOS).save(OUT / f"shikari-{size}.png")
    icon.save(OUT / "shikari.ico", sizes=[(s, s) for s in (16, 24, 32, 48, 64, 128, 256)])
    print(f"wrote {OUT / 'shikari.png'}, {OUT / 'shikari.ico'}")

    if not shutil.which("iconutil"):
        print("iconutil not found (macOS only); shikari.icns left as it is")
        return 0
    with tempfile.TemporaryDirectory() as tmp:
        iconset = Path(tmp) / "Shikari.iconset"
        iconset.mkdir()
        for size in (16, 32, 128, 256, 512):
            icon.resize((size, size), Image.LANCZOS).save(iconset / f"icon_{size}x{size}.png")
            icon.resize((size * 2, size * 2), Image.LANCZOS).save(iconset / f"icon_{size}x{size}@2x.png")
        subprocess.run(["iconutil", "-c", "icns", str(iconset), "-o", str(OUT / "shikari.icns")], check=True)
    print(f"wrote {OUT / 'shikari.icns'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
