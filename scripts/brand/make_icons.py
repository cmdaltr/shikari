"""Rebuild the hexagon icon: profile head on a white interior, a thin white hexagonal band, and a
rounded gold hexagon ring. Derives the favicon/apple-touch sizes from the same build.
"""
import math
from pathlib import Path

import numpy as np
from PIL import Image, ImageDraw
from shapely.geometry import Polygon

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
HEAD_SRC = REPO / "static" / "images" / "bateleur" / "_src" / "bateleur-profile.png"

NAVY = (11, 22, 32, 255)
FACE = (255, 255, 255, 255)
GOLD = (245, 158, 11, 255)

F = dict(zoom=0.72, fx=0.58, fy=0.45)   # framing b (Ben's pick)


def tight(img):
    a = np.array(img)[:, :, 3]
    bb = Image.fromarray(a).getbbox()
    return img.crop(bb)


def hexagon(cx, cy, R):
    # pointy-top hexagon: vertices at 90,150,210,270,330,30 degrees
    pts = [(cx + R * math.cos(math.radians(d)), cy - R * math.sin(math.radians(d)))
           for d in (90, 150, 210, 270, 330, 30)]
    return Polygon(pts)


def rounded_hex(cx, cy, R, cr):
    hp = hexagon(cx, cy, R)
    return hp.buffer(-cr, join_style=1).buffer(cr, join_style=1)


def poly_mask(poly, size):
    """Binary mask (L) of a shapely polygon rasterised at `size`."""
    m = Image.new("L", (size, size), 0)
    d = ImageDraw.Draw(m)
    if poly.geom_type == "Polygon":
        d.polygon(list(poly.exterior.coords), fill=255)
    return m


def build(S):
    ss = 4
    W = S * ss
    cx = cy = W / 2
    R = W * 0.47
    stroke = W * 0.06
    band = W * 0.045
    cr = W * 0.085

    canvas = Image.new("RGBA", (W, W), (0, 0, 0, 0))

    gold_hex = rounded_hex(cx, cy, R, cr)
    white_hex = rounded_hex(cx, cy, R * 0.985 - stroke, cr)
    head_hex = rounded_hex(cx, cy, R * 0.985 - stroke - band, cr)

    # gold ring
    g = Image.new("RGBA", (W, W), (0, 0, 0, 0))
    g.paste(Image.new("RGBA", (W, W), GOLD), (0, 0), poly_mask(gold_hex, W))
    canvas.alpha_composite(g)
    # white interior
    wf = Image.new("RGBA", (W, W), (0, 0, 0, 0))
    wf.paste(Image.new("RGBA", (W, W), FACE), (0, 0), poly_mask(white_hex, W))
    canvas.alpha_composite(wf)

    # head, clipped to the head hexagon (leaves the white band between head and gold ring)
    head = tight(Image.open(HEAD_SRC).convert("RGBA"))
    hh_target = int(W * F["zoom"])
    scale = hh_target / head.height
    head = head.resize((round(head.width * scale), round(head.height * scale)))
    hw, hgt = head.size
    hx = int(cx - F["fx"] * hw)
    hy = int(cy - F["fy"] * hgt)
    head_layer = Image.new("RGBA", (W, W), (0, 0, 0, 0))
    head_layer.alpha_composite(head, (hx, hy))
    hmask = poly_mask(head_hex, W)
    # keep head only inside the head hexagon
    ha = np.array(head_layer)
    ha[:, :, 3] = (ha[:, :, 3].astype(int) * (np.array(hmask) // 255)).astype("uint8")
    canvas.alpha_composite(Image.fromarray(ha))

    return canvas.resize((S, S), Image.LANCZOS)


def on_navy(img, S):
    base = Image.new("RGBA", (S, S), NAVY)
    base.alpha_composite(img)
    return base.convert("RGB")


if __name__ == "__main__":
    master = build(1197)
    master.save(HERE / "hexagon.png")
    on_navy(build(512), 512).save(HERE / "hexagon-on-navy.png")
    prev = Image.new("RGB", (512, 512), (244, 245, 247)); prev.paste(build(512), (0, 0), build(512))
    prev.save(HERE / "hexagon-on-light.png")
    print("hexagon built", master.size)
