"""Compose the SHIKARI lockup in three versions: lightcard, darkcard, and dark (transparent).

[perched eagle]  SHIKARI
                 ---------------------------------
                 AUTOMATED MULTI-VENDOR THREAT HUNTING & DETECTION SUITE
"""
from pathlib import Path

import numpy as np
from PIL import Image, ImageDraw, ImageFont

import wordmark as WM

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
TTF = HERE / "fonts" / "Rajdhani-SemiBold.ttf"
BIRDS = {
    "branch":  REPO / "static" / "images" / "shikari" / "shikari-bateleur-perched.png",
    "profile": REPO / "static" / "images" / "bateleur" / "_src" / "bateleur-profile.png",
    "screech": REPO / "static" / "images" / "bateleur" / "_src" / "bateleur-screech.png",
}
TAGLINE = "AUTOMATED MULTI-VENDOR THREAT HUNTING & DETECTION SUITE"

THEMES = {
    "lightcard": dict(card=(236, 238, 241, 255), border=(205, 210, 217, 255),
                      ink=(26, 32, 40, 255), tag=(96, 104, 117, 255), rule=(198, 204, 212, 255)),
    "darkcard":  dict(card=(19, 30, 45, 255), border=(236, 239, 243, 255),
                      ink=(255, 255, 255, 255), tag=(150, 176, 206, 255), rule=(74, 92, 116, 255)),
    "dark":      dict(card=None, border=None,
                      ink=(255, 255, 255, 255), tag=(150, 176, 206, 255), rule=(74, 92, 116, 255)),
}


def tight(img):
    bb = Image.fromarray(np.array(img)[:, :, 3]).getbbox()
    return img.crop(bb)


def tracked(word, font, track):
    tmp = ImageDraw.Draw(Image.new("RGBA", (4, 4)))
    w = sum(tmp.textlength(c, font=font) for c in word) + track * (len(word) - 1)
    asc, desc = font.getmetrics()
    img = Image.new("RGBA", (int(w) + 4, asc + desc + 4), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    x = 2
    for c in word:
        d.text((x, 2), c, font=font, fill=(255, 255, 255, 255))
        x += tmp.textlength(c, font=font) + track
    return tight(img)


def tint(mask_img, colour):
    a = np.array(mask_img)
    out = np.zeros_like(a)
    out[:, :, 0], out[:, :, 1], out[:, :, 2] = colour[0], colour[1], colour[2]
    out[:, :, 3] = a[:, :, 3]
    return Image.fromarray(out)


def build(version, pose="branch"):
    t = THEMES[version]
    CW, CH = 2600, 820
    M = 70
    canvas = Image.new("RGBA", (CW, CH), (0, 0, 0, 0))
    d = ImageDraw.Draw(canvas)
    radius = 54
    if t["card"] is not None:
        d.rounded_rectangle([4, 4, CW - 4, CH - 4], radius=radius, fill=t["card"])
        bw = 7
        d.rounded_rectangle([4 + bw // 2, 4 + bw // 2, CW - 4 - bw // 2, CH - 4 - bw // 2],
                            radius=radius, outline=t["border"], width=bw)

    # bird, always on the left. Fit into a left box (max height, max width), preserving aspect so a
    # wide screech or a square head sits in the same column as the tall perched eagle.
    bird = tight(Image.open(BIRDS[pose]).convert("RGBA"))
    box_h = int(CH * 0.82)
    box_w = int(CW * 0.20)
    bscale = min(box_h / bird.height, box_w / bird.width)
    bird = bird.resize((round(bird.width * bscale), round(bird.height * bscale)))
    bx = M + 40
    if pose == "branch":
        by = CH - bird.height - int(CH * 0.07)      # stands on its branch at the base
    else:
        by = (CH - bird.height) // 2                 # head / screech centred in the column
    canvas.alpha_composite(bird, (bx, by))

    # wordmark (two-tone K), to the right of the bird
    wm = tight(WM.render(TTF, 520, bg=None, letter=t["ink"]))
    block_x = M + 40 + int(CW * 0.20) + int(CW * 0.045)   # after the left column, fixed across poses
    avail_w = CW - block_x - M - 30
    # scale wordmark to a target width within available space
    target_w = min(avail_w, int(CW * 0.60))
    s = target_w / wm.width
    wm = wm.resize((round(wm.width * s), round(wm.height * s)))
    # vertical block: wordmark, rule, tagline — centred in the card
    tag_font = ImageFont.truetype(str(TTF), 112)
    tagimg = tint(tracked(TAGLINE, tag_font, 10), t["tag"])
    tag_target_w = wm.width
    ts = tag_target_w / tagimg.width
    tagimg = tagimg.resize((round(tagimg.width * ts), round(tagimg.height * ts)))
    gap1, gap2 = 46, 40
    rule_h = 4
    block_h = wm.height + gap1 + rule_h + gap2 + tagimg.height
    top = (CH - block_h) // 2
    canvas.alpha_composite(wm, (block_x, top))
    ry = top + wm.height + gap1
    d.rectangle([block_x, ry, block_x + wm.width, ry + rule_h], fill=t["rule"])
    canvas.alpha_composite(tagimg, (block_x, ry + rule_h + gap2))
    return canvas


if __name__ == "__main__":
    for v in ("lightcard", "darkcard", "dark"):
        img = build(v)
        img.save(HERE / f"lockup-{v}.png")
        if v == "dark":
            bg = Image.new("RGBA", img.size, (17, 24, 33, 255)); bg.alpha_composite(img)
            bg.convert("RGB").save(HERE / "lockup-dark-preview.png")
        print("built", v, img.size)
