"""Render the SHIKARI wordmark with the two-tone K (gold stem+arm, red leg).

Raster approach: draw the whole word white, draw the K alone to get its exact mask at the
same position, split that mask into gold/arm+stem and red/leg along the arm's lower edge,
then paint those two colours over the white K.
"""
from pathlib import Path

import numpy as np
from PIL import Image, ImageDraw, ImageFont

HERE = Path(__file__).resolve().parent
TTF_SEMIBOLD = HERE / "fonts" / "Rajdhani-SemiBold.ttf"
TTF_BOLD = HERE / "fonts" / "Rajdhani-Bold.ttf"

GOLD = (245, 158, 11, 255)   # #F59E0B
RED = (223, 81, 78, 255)     # #DF514E

WORD = "SHIKARI"


def k_split(kmask):
    """kmask: HxW uint8 alpha of the K glyph. Return (gold_bool, red_bool) over filled pixels."""
    a = kmask > 32
    ys, xs = np.where(a)
    x0, x1, y0, y1 = xs.min(), xs.max(), ys.min(), ys.max()
    H = y1 - y0 + 1

    # stem_right: in the lower part of the glyph (clearly below the arm/leg junction) each row is
    # stem | gap | leg. Take the right edge of the first (stem) run, median across those rows.
    stem_rights = []
    for y in range(y0 + int(H * 0.55), y1 - int(H * 0.08)):
        row = np.where(a[y])[0]
        if row.size == 0:
            continue
        brk = np.where(np.diff(row) > 1)[0]
        if brk.size == 0:
            continue  # no gap -> stem and leg still joined, skip
        stem_rights.append(row[brk[0]])
    stem_right = int(np.median(stem_rights)) if stem_rights else x0 + int((x1 - x0) * 0.42)

    # Divide collinear with the top-right stroke: fit a single straight line to the ARM's lower edge,
    # then cut the K with it. Everything right of the stem and below that line is the leg (red); the
    # stem, the arm, and the junction above the line stay gold. One halfplane cut -> one clean diagonal,
    # the whole leg red, no gold sliver along the leg's top.
    arm_x, arm_y = [], []
    for x in range(stem_right + 1, x1 + 1):
        col = np.where(a[:, x])[0]
        if col.size == 0:
            continue
        brk = np.where(np.diff(col) > 1)[0]
        if brk.size == 0:
            continue  # arm and leg still joined at this column -> edge ill-defined, skip
        upper = col[:brk[0] + 1]        # the arm run
        arm_x.append(x)
        arm_y.append(upper.max())       # bottom of the arm at this column
    arm_x = np.array(arm_x, float)
    arm_y = np.array(arm_y, float)
    m, c = np.polyfit(arm_x, arm_y, 1)   # y = m x + c  (arm lower edge, = the divide)

    X = np.arange(kmask.shape[1])[None, :]
    Y = np.arange(kmask.shape[0])[:, None]
    line_y = m * X + c
    red = a & (X >= stem_right) & (Y > line_y)
    gold = a & ~red
    return gold, red


def render(ttf, size, bg=None, letter=(255, 255, 255, 255), pad=40, track=0):
    font = ImageFont.truetype(str(ttf), size)
    # layout width with optional tracking
    tmp = Image.new("RGBA", (10, 10)); td = ImageDraw.Draw(tmp)
    widths = [td.textlength(ch, font=font) for ch in WORD]
    total = sum(widths) + track * (len(WORD) - 1)
    asc, desc = font.getmetrics()
    Wc = int(total) + 2 * pad
    Hc = asc + desc + 2 * pad
    img = Image.new("RGBA", (Wc, Hc), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    # draw each glyph at tracked positions, white
    x = pad
    kx = None
    for ch, w in zip(WORD, widths):
        d.text((x, pad), ch, font=font, fill=letter)
        if ch == "K" and kx is None:
            kx = x
        x += w + track
    # K-only mask at same position
    kimg = Image.new("RGBA", (Wc, Hc), (0, 0, 0, 0))
    ImageDraw.Draw(kimg).text((kx, pad), "K", font=font, fill=(255, 255, 255, 255))
    kmask = np.array(kimg)[:, :, 3]
    gold, red = k_split(kmask)
    arr = np.array(img)
    arr[gold] = GOLD
    arr[red] = RED
    out = Image.fromarray(arr)
    if bg is not None:
        base = Image.new("RGBA", out.size, bg)
        base.alpha_composite(out)
        out = base
    return out


if __name__ == "__main__":
    navy = (19, 30, 45, 255)
    for wname, ttf in [("bold", TTF_BOLD), ("semibold", TTF_SEMIBOLD)]:
        out = render(ttf, 600, bg=navy, letter=(255, 255, 255, 255))
        out.convert("RGB").save(HERE / f"wm-{wname}-navy.png")
        print("wrote", wname, out.size)
