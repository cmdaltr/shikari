"""Regenerate the full SHIKARI brand asset set from the two-tone-K wordmark and the three bird poses.

Writes straight into static/images/shikari/ (the live asset locations). The hero IS the lockup card:
six images shikari-lockup-{perched,profile,screech}-{light,dark} (light = lightcard, dark = navy
darkcard). perched is the home/auth hero; the top-nav banner uses the perched eagle too.

    python scripts/brand/build_assets.py            # write to static/images/shikari/
    python scripts/brand/build_assets.py --out DIR   # write to DIR instead (preview without touching repo)

Needs: pillow, numpy, shapely, plus the Rajdhani fonts under scripts/brand/fonts/.
"""
import argparse
import sys
from pathlib import Path

import numpy as np
from PIL import Image

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
sys.path.insert(0, str(HERE))

import wordmark as WM          # noqa: E402
import make_icons as MK        # noqa: E402
import lockup as LK            # noqa: E402

TTF = HERE / "fonts" / "Rajdhani-SemiBold.ttf"
ASSETS = REPO / "static" / "images" / "shikari"

DARK_INK = (26, 32, 40, 255)
WHITE = (255, 255, 255, 255)

BIRDS = LK.BIRDS

# The canonical hero/lockup set is named by pose label; each label maps to a bird cutout. The home
# page and auth splashes use "perched"; profile and screech are the alternates.
POSES = {"perched": "branch", "profile": "profile", "screech": "screech"}
NAV_POSE = "branch"   # bird shown in the compact top-nav banner (the perched eagle)


def tight(img):
    bb = Image.fromarray(np.array(img)[:, :, 3]).getbbox()
    return img.crop(bb)


def wordmark(ink, width):
    wm = tight(WM.render(TTF, 560, bg=None, letter=ink))
    s = width / wm.width
    return wm.resize((round(wm.width * s), round(wm.height * s)))


def banner(ink, bird_h=560, gap=80, pad=30):
    """Compact nav lockup: perched eagle left, two-tone-K word right, no tagline."""
    wm = wordmark(ink, 1200)
    bird = tight(Image.open(BIRDS[NAV_POSE]).convert("RGBA"))
    s = bird_h / bird.height
    bird = bird.resize((round(bird.width * s), round(bird.height * s)))
    H = max(bird.height, wm.height) + 2 * pad
    W = bird.width + gap + wm.width + 2 * pad
    c = Image.new("RGBA", (W, H), (0, 0, 0, 0))
    c.alpha_composite(bird, (pad, (H - bird.height) // 2))
    c.alpha_composite(wm, (pad + bird.width + gap, (H - wm.height) // 2))
    return c


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=str(ASSETS), help="output directory (default: live asset dir)")
    out = Path(ap.parse_args().out)
    out.mkdir(parents=True, exist_ok=True)

    # the hero IS the lockup card: six images, one per pose x theme (light = lightcard, dark = darkcard)
    for label, pose in POSES.items():
        LK.build("lightcard", pose).save(out / f"shikari-lockup-{label}-light.png")
        LK.build("darkcard", pose).save(out / f"shikari-lockup-{label}-dark.png")

    # nav banner (perched eagle + word, no tagline)
    banner(DARK_INK).save(out / "shikari-wordmark-light.png")
    banner(WHITE).save(out / "shikari-wordmark-dark.png")

    # video master: horizontal perched-eagle + two-tone-K word, NO tagline, dark ink, transparent.
    # The video card() adds the tagline itself, so this must not carry one.
    wm = wordmark(DARK_INK, 2400)
    bird = tight(Image.open(BIRDS["branch"]).convert("RGBA"))
    bh = int(wm.height * 2.4)
    s = bh / bird.height
    bird = bird.resize((round(bird.width * s), round(bird.height * s)))
    gap, pad = 150, 60
    Wm = bird.width + gap + wm.width + 2 * pad
    Hm = max(bird.height, wm.height) + 2 * pad
    master = Image.new("RGBA", (Wm, Hm), (0, 0, 0, 0))
    master.alpha_composite(bird, (pad, (Hm - bird.height) // 2))
    master.alpha_composite(wm, (pad + bird.width + gap, (Hm - wm.height) // 2))
    master.save(out / "shikari-lockup.png")

    # hexagon + favicons
    MK.build(1197).save(out / "shikari-hexagon.png")
    MK.on_navy(MK.build(180), 180).save(out / "shikari-apple-touch-icon.png")
    MK.on_navy(MK.build(180), 180).save(out / "shikari-apple-touch-icon-precomposed.png")
    MK.build(32).save(out / "shikari-favicon-32.png")
    MK.build(16).save(out / "shikari-favicon-16.png")
    MK.build(48).save(out / "shikari-favicon.ico", sizes=[(16, 16), (32, 32), (48, 48)])

    print("built assets in", out)
    for f in sorted(p.name for p in out.glob("shikari-*")):
        print("  ", f)


if __name__ == "__main__":
    main()
