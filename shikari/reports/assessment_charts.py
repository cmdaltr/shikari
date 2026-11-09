"""
Figures for the assessment report (#42), drawn with Pillow so the report needs no plotting
library. Each function returns PNG bytes, drawn at twice the size it's shown for print.

Calibri is used where the machine has it (Office on macOS and Windows) or Carlito, its
metric-compatible twin on Linux; otherwise Pillow's own font.
"""

import io
import os
import sys
from functools import lru_cache
from typing import Dict, List, Optional, Sequence, Tuple

from PIL import Image, ImageDraw, ImageFilter, ImageFont

from shikari import paths

# Brand: the wordmark's ink and its K's gold and red, and the bateleur's own colours
# (sampled from shikari-bateleur-perched.png): face, chestnut mantle, wing grey, bark.
INK = (26, 32, 40)          # #1a2028
GOLD = (245, 158, 11)       # #f59e0b
RED = (223, 81, 78)         # #df514e
FACE = (240, 116, 112)      # #f07470
CHESTNUT = (143, 87, 66)    # #8f5742
MAHOGANY = (82, 38, 9)      # #522609
WING = (179, 162, 155)      # #b3a29b
BARK = (119, 100, 88)       # #776458
SLATE = (91, 98, 112)
MIST = (240, 237, 235)      # the wing grey, faded to paper
WHITE = (255, 255, 255)

# Outcomes in the brand's colours: warm (the K's red and gold) where the defence missed,
# the bird's dark plumage where it held.
BLUE_OUTCOMES = [
    ("prevented", "Prevented", INK),
    ("alerted", "Alerted", BARK),
    ("logged", "Logged", GOLD),
    ("not_logged", "Not logged", RED),
    ("not_assessed", "Not assessed", (214, 206, 202)),
]
RED_OUTCOMES = [
    ("executed", "Executed", RED),
    ("failed", "Failed", GOLD),
    ("blocked", "Blocked", INK),
    ("not_run", "Not run", (214, 206, 202)),
]
RATINGS = [("Critical", MAHOGANY), ("High", RED), ("Medium", GOLD), ("Low", WING)]
BLUE_COLOUR = {k: c for k, _, c in BLUE_OUTCOMES}
RATING_COLOUR = dict(RATINGS)

IMAGES = paths.ROOT / "static" / "images" / "shikari"
EAGLE = IMAGES / "shikari-bateleur-perched.png"
WORDMARK = IMAGES / "shikari-wordmark-light.png"

_FONT_DIRS = [
    "/Applications/Microsoft Word.app/Contents/Resources/DFonts",
    "/Applications/Microsoft Excel.app/Contents/Resources/DFonts",
    "/Applications/Microsoft PowerPoint.app/Contents/Resources/DFonts",
    "/Applications/Microsoft Outlook.app/Contents/Resources/DFonts",
    "/Library/Fonts", os.path.expanduser("~/Library/Fonts"),
    os.path.join(os.environ.get("WINDIR", r"C:\Windows"), "Fonts"),
    "/usr/share/fonts/truetype/crosextra", "/usr/share/fonts/crosextra", "/usr/share/fonts/truetype/carlito",
    "/usr/share/fonts/carlito", os.path.expanduser("~/.local/share/fonts"),
]
_FONT_FILES = {  # style -> candidates: Calibri (Office) first, then Carlito
    "regular": ["Calibri.ttf", "calibri.ttf", "Carlito-Regular.ttf"],
    "bold": ["Calibrib.ttf", "calibrib.ttf", "Carlito-Bold.ttf"],
    "italic": ["Calibrii.ttf", "calibrii.ttf", "Carlito-Italic.ttf"],
    "bolditalic": ["Calibriz.ttf", "calibriz.ttf", "Carlito-BoldItalic.ttf"],
}


@lru_cache(maxsize=None)
def font_path(style: str = "regular") -> Optional[str]:
    """The Calibri (or Carlito) file for a style, or None when the machine has neither."""
    for d in _FONT_DIRS:
        for name in _FONT_FILES[style]:
            p = os.path.join(d, name)
            if os.path.isfile(p):
                return p
    return None


@lru_cache(maxsize=None)
def _font(size: int, bold: bool = False) -> ImageFont.FreeTypeFont:
    path = font_path("bold" if bold else "regular")
    if path:
        return ImageFont.truetype(path, size)
    return ImageFont.load_default(size=size)


def _png(img: Image.Image) -> bytes:
    buf = io.BytesIO()
    img.save(buf, "PNG", optimize=True)
    return buf.getvalue()


def _text_w(draw: ImageDraw.ImageDraw, text: str, font) -> int:
    return int(draw.textlength(text, font=font))


def _ideal_ink(rgb: Tuple[int, int, int]) -> Tuple[int, int, int]:
    """White or ink, whichever reads on the fill."""
    r, g, b = rgb
    return INK if (0.299 * r + 0.587 * g + 0.114 * b) > 150 else WHITE


# ── The title page ────────────────────────────────────────────────────────────

def title_background(width_px: int = 1654, height_px: int = 2339) -> bytes:
    """A4 portrait at 200 dpi: the bateleur on its branch filling the page, faded into the
    paper towards the top left where the title sits, and running off the right and bottom edges."""
    page = Image.new("RGB", (width_px, height_px), WHITE)

    # A soft wash from white (top left) to the lockup's grey panel (bottom right).
    down = Image.linear_gradient("L").resize((width_px, height_px))
    across = Image.linear_gradient("L").rotate(90).transpose(Image.FLIP_LEFT_RIGHT).resize((width_px, height_px))
    wash = Image.blend(down, across, 0.5)
    page = Image.composite(Image.new("RGB", page.size, MIST), page, wash)

    eagle = Image.open(EAGLE).convert("RGBA")
    scale = (height_px * 1.02) / eagle.height
    eagle = eagle.resize((int(eagle.width * scale), int(eagle.height * scale)), Image.LANCZOS)
    x = width_px - int(eagle.width * 0.70)      # its tail and wing past the right edge
    y = height_px - int(eagle.height * 0.94)    # the branch runs off the bottom

    alpha = eagle.getchannel("A")
    # Fade: strongest at the bird's head and talons (right), into the paper on the left.
    ramp = Image.linear_gradient("L").rotate(90).resize(eagle.size)            # 255 left -> 0 right
    ramp = ramp.point(lambda v: int(255 - v * 0.80))                          # 51 left -> 255 right
    fade = Image.eval(Image.composite(ramp, Image.new("L", eagle.size, 0), alpha), lambda v: int(v * 0.50))
    eagle.putalpha(fade)
    page.paste(eagle, (x, y), eagle)

    # A white veil behind the title block keeps the type on clean paper.
    veil = Image.new("L", page.size, 0)
    ImageDraw.Draw(veil).rectangle([0, 0, int(width_px * 0.62), height_px], fill=150)
    veil = veil.filter(ImageFilter.GaussianBlur(width_px // 12))
    page = Image.composite(Image.new("RGB", page.size, WHITE), page, veil)

    # The K's gold and red as a spine down the left edge.
    d = ImageDraw.Draw(page)
    spine = int(width_px * 0.018)
    d.rectangle([0, 0, spine, int(height_px * 0.62)], fill=GOLD)
    d.rectangle([0, int(height_px * 0.62), spine, height_px], fill=RED)
    return _png(page)


def wordmark(with_eagle: bool = True, height_px: int = 160) -> bytes:
    """The SHIKARI wordmark, with or without its bird, cropped tight on a transparent ground."""
    img = Image.open(WORDMARK).convert("RGBA")
    if not with_eagle:
        img = img.crop((int(img.width * 0.27), 0, img.width, img.height))
    img = img.crop(img.getbbox())
    scale = height_px / img.height
    return _png(img.resize((int(img.width * scale), height_px), Image.LANCZOS))


# ── Charts ────────────────────────────────────────────────────────────────────

def scorecard(tiles: Sequence[Tuple[str, str, Tuple[int, int, int]]], width: int = 1800) -> bytes:
    """Headline numbers as coloured tiles: [(value, label, colour), ...]."""
    n = max(len(tiles), 1)
    gap, h = 28, 300
    tw = (width - gap * (n - 1)) // n
    img = Image.new("RGB", (width, h), WHITE)
    d = ImageDraw.Draw(img)
    for i, (value, label, colour) in enumerate(tiles):
        x0 = i * (tw + gap)
        d.rounded_rectangle([x0, 0, x0 + tw, h], radius=26, fill=colour)
        ink = _ideal_ink(colour)
        vf, lf = _font(120, True), _font(40)
        d.text((x0 + tw / 2, 125), value, font=vf, fill=ink, anchor="mm")
        d.text((x0 + tw / 2, 238), label, font=lf, fill=ink, anchor="mm")
    return _png(img)


def outcome_bars(counts: Dict[str, int], scheme=BLUE_OUTCOMES, title: str = "", width: int = 1800) -> bytes:
    """Horizontal bars, one per outcome, in the scheme's colours, with the count on each."""
    row, top, left = 120, 110 if title else 30, 380
    img = Image.new("RGB", (width, top + row * len(scheme) + 30), WHITE)
    d = ImageDraw.Draw(img)
    if title:
        d.text((0, 20), title, font=_font(54, True), fill=INK)
    peak = max([counts.get(k, 0) for k, _, _ in scheme] + [1])
    span = width - left - 140
    for i, (key, label, colour) in enumerate(scheme):
        y = top + i * row
        d.text((left - 30, y + row / 2 - 8), label, font=_font(46), fill=INK, anchor="rm")
        n = counts.get(key, 0)
        w = max(int(span * n / peak), 10 if n else 0)
        d.rectangle([left, y + 20, left + span, y + row - 30], fill=MIST)
        if w:
            d.rectangle([left, y + 20, left + w, y + row - 30], fill=colour)
        d.text((left + w + 22, y + row / 2 - 8), str(n), font=_font(48, True), fill=INK, anchor="lm")
    return _png(img)


def donut(counts: Dict[str, int], scheme=RED_OUTCOMES, centre_label: str = "", width: int = 1800) -> bytes:
    """A ring of the scheme's outcomes with the total in the middle and a legend beside it."""
    h = 900
    img = Image.new("RGB", (width, h), WHITE)
    d = ImageDraw.Draw(img)
    total = sum(counts.get(k, 0) for k, _, _ in scheme)
    box = [60, 60, 60 + h - 120, h - 60]
    if total:
        start = -90.0
        for key, _, colour in scheme:
            n = counts.get(key, 0)
            if n:
                sweep = 360.0 * n / total
                d.pieslice(box, start, start + sweep, fill=colour)
                start += sweep
    else:
        d.ellipse(box, fill=MIST)
    inset = 190
    d.ellipse([box[0] + inset, box[1] + inset, box[2] - inset, box[3] - inset], fill=WHITE)
    cx, cy = (box[0] + box[2]) / 2, (box[1] + box[3]) / 2
    d.text((cx, cy - 30), str(total), font=_font(150, True), fill=INK, anchor="mm")
    d.text((cx, cy + 80), centre_label, font=_font(44), fill=SLATE, anchor="mm")
    lx, ly = box[2] + 120, 200
    size = 52
    # Shrink the legend until its longest label and count fit beside the ring.
    while size > 30 and max(_text_w(d, label, _font(size)) + _text_w(d, f"{counts.get(k, 0)}  (100%)", _font(size, True))
                            for k, label, _ in scheme) > width - 40 - (lx + 90) - 30:
        size -= 2
    for key, label, colour in scheme:
        n = counts.get(key, 0)
        pct = f"{100 * n / total:.0f}%" if total else "0%"
        d.rounded_rectangle([lx, ly, lx + 60, ly + 60], radius=10, fill=colour)
        d.text((lx + 90, ly + 30), f"{label}", font=_font(size), fill=INK, anchor="lm")
        d.text((width - 40, ly + 30), f"{n}  ({pct})", font=_font(size, True), fill=INK, anchor="rm")
        ly += 130
    return _png(img)


def tactic_stack(by_tactic: Dict[str, Dict[str, int]], width: int = 1800) -> bytes:
    """One bar per tactic, split by blue outcome: where in the kill chain the defence held."""
    tactics = list(by_tactic)
    row, top, left, legend = 96, 20, 520, 120
    img = Image.new("RGB", (width, top + row * max(len(tactics), 1) + legend), WHITE)
    d = ImageDraw.Draw(img)
    peak = max([sum(v.values()) for v in by_tactic.values()] + [1])
    span = width - left - 120
    for i, tactic in enumerate(tactics):
        y = top + i * row
        d.text((left - 26, y + row / 2), tactic, font=_font(42), fill=INK, anchor="rm")
        x = left
        for key, _, colour in BLUE_OUTCOMES:
            n = by_tactic[tactic].get(key, 0)
            if n:
                w = int(span * n / peak)
                d.rectangle([x, y + 14, x + w, y + row - 14], fill=colour)
                if w > 50:
                    d.text((x + w / 2, y + row / 2), str(n), font=_font(38, True), fill=_ideal_ink(colour), anchor="mm")
                x += w
        d.text((x + 16, y + row / 2), str(sum(by_tactic[tactic].values())), font=_font(40, True),
               fill=SLATE, anchor="lm")
    _legend(d, BLUE_OUTCOMES, top + row * max(len(tactics), 1) + 40, width)
    return _png(img)


def _legend(d: ImageDraw.ImageDraw, scheme, y: int, width: int) -> None:
    f = _font(40)
    items = [(label, colour) for _, label, colour in scheme]
    total = sum(70 + _text_w(d, label, f) + 50 for label, _ in items)
    x = max((width - total) // 2, 0)
    for label, colour in items:
        d.rounded_rectangle([x, y, x + 46, y + 46], radius=8, fill=colour)
        d.text((x + 62, y + 23), label, font=f, fill=INK, anchor="lm")
        x += 70 + _text_w(d, label, f) + 50


def coverage_matrix(columns: Dict[str, List[Tuple[str, str]]], width: int = 1800) -> bytes:
    """An ATT&CK-style matrix of the techniques tested: a column per tactic, each technique a
    cell coloured by its blue outcome. columns: {tactic: [(technique ID, blue outcome), ...]}."""
    tactics = list(columns) or ["No techniques"]
    cols = len(tactics)
    gap, head, cell = 14, 150, 78
    cw = (width - gap * (cols - 1)) // cols
    rows = max([len(v) for v in columns.values()] + [1])
    img = Image.new("RGB", (width, head + rows * (cell + 10) + 140), WHITE)
    d = ImageDraw.Draw(img)
    hf = _font(30 if cw < 220 else 36, True)
    cf = _font(34 if cw < 220 else 40, True)
    for c, tactic in enumerate(tactics):
        x = c * (cw + gap)
        d.rectangle([x, 0, x + cw, head - 16], fill=INK)
        _wrap_centred(d, tactic, hf, (x, 0, x + cw, head - 16), WHITE)
        for r, (tid, blue) in enumerate(columns.get(tactic, [])):
            y = head + r * (cell + 10)
            colour = BLUE_COLOUR.get(blue, BLUE_COLOUR["not_assessed"])
            d.rounded_rectangle([x, y, x + cw, y + cell], radius=10, fill=colour)
            d.text((x + cw / 2, y + cell / 2), tid, font=cf, fill=_ideal_ink(colour), anchor="mm")
    _legend(d, BLUE_OUTCOMES, head + rows * (cell + 10) + 50, width)
    return _png(img)


def _wrap_centred(d, text: str, font, box, fill) -> None:
    x0, y0, x1, y1 = box
    words, lines, line = text.split(), [], ""
    for w in words:
        trial = (line + " " + w).strip()
        if _text_w(d, trial, font) <= (x1 - x0) - 16 or not line:
            line = trial
        else:
            lines.append(line)
            line = w
    lines.append(line)
    lh = font.size * 1.15
    y = (y0 + y1) / 2 - lh * (len(lines) - 1) / 2
    for ln in lines:
        d.text(((x0 + x1) / 2, y), ln, font=font, fill=fill, anchor="mm")
        y += lh


def risk_heatmap(cells: Dict[Tuple[int, int], int], width: int = 1800) -> bytes:
    """Likelihood (rows, 3 high at the top) by impact (columns), each cell the number of
    findings at that rating, shaded by the rating it produces."""
    labels = {1: "Low", 2: "Medium", 3: "High"}
    left, top, size = 330, 40, 400
    img = Image.new("RGB", (width, top + size * 3 + 260), WHITE)
    d = ImageDraw.Draw(img)
    x_off = (width - left - size * 3) // 2 + left - 120
    for li in (3, 2, 1):
        for ii in (1, 2, 3):
            x = x_off + (ii - 1) * size
            y = top + (3 - li) * size
            rating = rating_for(li * ii)
            colour = RATING_COLOUR[rating]
            n = cells.get((li, ii), 0)
            fill = colour if n else tuple(int(c + (255 - c) * 0.72) for c in colour)
            d.rectangle([x + 6, y + 6, x + size - 6, y + size - 6], fill=fill)
            d.text((x + size / 2, y + size / 2 - 30), str(n), font=_font(130, True),
                   fill=WHITE if n else SLATE, anchor="mm")
            d.text((x + size / 2, y + size / 2 + 90), rating, font=_font(40), fill=WHITE if n else SLATE, anchor="mm")
        d.text((x_off - 30, top + (3 - li) * size + size / 2), labels[li], font=_font(46), fill=INK, anchor="rm")
    for ii in (1, 2, 3):
        d.text((x_off + (ii - 0.5) * size, top + 3 * size + 50), labels[ii], font=_font(46), fill=INK, anchor="mm")
    d.text((x_off + 1.5 * size, top + 3 * size + 150), "Impact (what the defence saw)", font=_font(48, True),
           fill=INK, anchor="mm")
    lab = Image.new("RGBA", (size * 3, 90), (255, 255, 255, 0))
    ImageDraw.Draw(lab).text((size * 1.5, 45), "Likelihood (what the attack did)", font=_font(48, True),
                             fill=INK, anchor="mm")
    lab = lab.rotate(90, expand=True)
    img.paste(lab, (x_off - 260, top), lab)
    return _png(img)


def rating_for(score: int) -> str:
    """Likelihood x impact (each 1-3) as a rating."""
    if score >= 9:
        return "Critical"
    if score >= 6:
        return "High"
    if score >= 3:
        return "Medium"
    return "Low"


def readiness(with_detections: int, without: int, width: int = 1800) -> bytes:
    """Gaps split by whether deploying a library detection would close them."""
    return donut({"ready": with_detections, "none": without},
                 scheme=[("ready", "Ready to deploy", CHESTNUT),
                         ("none", "Needs logging or a detection", WING)],
                 centre_label="gaps", width=width)


if __name__ == "__main__":  # python -m shikari.reports.assessment_charts: which font the report will use
    print(font_path("regular") or "no Calibri or Carlito: falling back", file=sys.stdout)
