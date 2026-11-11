"""
Report branding — a Pro feature.

An install can dress the three report products (the adversary-emulation assessment, the
campaign-intelligence report and the detection/hunt report) in its own identity: up to
three logos and a three-colour chrome palette, held install-wide under ``data/branding/``
and threaded into the report shells from here.

The override is chrome only. It drives the cover lead, the running header, the section and
heading rules, the table-header fill and the accent. Severity and risk-rating colours
(Critical / High / Medium / Low) and the bateleur are left alone — a "Critical" badge
recoloured to a house teal stops reading as critical, and that costs the reader more than
the branding gains. Shikari keeps a co-brand line on the cover and the back cover, so a
report never hides where it came from.

Storage is a folder, not a table: a single install-wide profile (self-hosted, one
consultancy), the logos are files anyway, and it keeps the branding out of the database
that lives in OneDrive. ``profile.json`` holds the palette and the flags; ``logo-1.png`` …
``logo-3.png`` hold the marks.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from shikari import paths
from shikari.reports import assessment_charts as charts

RGB = Tuple[int, int, int]

BRANDING_DIR = paths.DATA / "branding"
PROFILE = BRANDING_DIR / "profile.json"
MAX_LOGOS = 3

# The palette slots a profile can set, each mapped to the Shikari role it replaces, with the
# default (the current Shikari look) alongside. Order is the order the settings form shows them.
SLOTS: Tuple[Tuple[str, str, RGB], ...] = (
    ("primary", "Accent — header and section rules, labels, callouts", charts.GOLD),
    ("secondary", "Secondary — the cover title underline", charts.RED),
    ("heading", "Headings — sub-headings and the 'prepared for' line", charts.CHESTNUT),
    ("dark", "Dark — table headers, the cover title, body text", charts.INK),
)
_DEFAULTS: Dict[str, RGB] = {name: rgb for name, _, rgb in SLOTS}


def hex_to_rgb(value: str) -> Optional[RGB]:
    """'#1a2028' or '1a2028' -> (26, 32, 40); None when it isn't a 6-digit hex colour."""
    h = (value or "").strip().lstrip("#")
    if len(h) != 6:
        return None
    try:
        return tuple(int(h[i:i + 2], 16) for i in (0, 2, 4))  # type: ignore[return-value]
    except ValueError:
        return None


def rgb_to_hex(rgb: RGB) -> str:
    return "#%02x%02x%02x" % tuple(rgb)


@dataclass(frozen=True)
class ReportTheme:
    """One install's report identity. Defaults are the Shikari look, so an unbranded install
    and ``DEFAULT`` render byte-for-byte as before."""

    primary: RGB = charts.GOLD
    secondary: RGB = charts.RED
    heading: RGB = charts.CHESTNUT
    dark: RGB = charts.INK
    logos: Tuple[bytes, ...] = ()          # 0–3 logo PNGs, lead-to-trail
    org_name: str = ""
    show_shikari: bool = True              # co-brand: keep the Shikari line and back cover
    custom: bool = False                   # False = the stock Shikari look (fast path)

    def brand_assets(self) -> Dict[str, bytes]:
        """The cover background, the cover/header lead mark, and the Shikari wordmark for the
        co-brand line and back cover. A stock theme returns the bateleur cover and the Shikari
        wordmark unchanged; a custom one returns a clean themed panel and the logo strip (or the
        Shikari wordmark when colours changed but no logo was uploaded)."""
        shikari_mark = charts.wordmark(True, 300)
        if not self.custom:
            return {"background": charts.title_background(), "lead": shikari_mark,
                    "shikari": shikari_mark}
        lead = logo_strip(self.logos, height_px=300) if self.logos else shikari_mark
        return {"background": themed_background(self.primary, self.secondary, self.dark),
                "lead": lead, "shikari": shikari_mark}


DEFAULT = ReportTheme()


# ── Drawn assets for a custom theme ─────────────────────────────────────────────

def logo_strip(logos: Tuple[bytes, ...], height_px: int = 300, gap_px: int = 60) -> bytes:
    """Up to three logos in a row, normalised to one height, on a transparent ground. Placement
    code reads the aspect from the bytes, so the same strip serves the tall cover and the short
    header."""
    from PIL import Image

    imgs = []
    for data in logos[:MAX_LOGOS]:
        try:
            img = Image.open(_io(data)).convert("RGBA")
        except Exception:
            continue
        img = img.crop(img.getbbox() or (0, 0, img.width, img.height))
        scale = height_px / img.height
        imgs.append(img.resize((max(1, int(img.width * scale)), height_px), Image.LANCZOS))
    if not imgs:
        return charts.wordmark(True, height_px)
    width = sum(i.width for i in imgs) + gap_px * (len(imgs) - 1)
    strip = Image.new("RGBA", (width, height_px), (0, 0, 0, 0))
    x = 0
    for i, img in enumerate(imgs):
        strip.alpha_composite(img, (x, 0))
        x += img.width + gap_px
    return charts._png(strip)


def themed_background(primary: RGB, secondary: RGB, dark: RGB,
                      width_px: int = 1654, height_px: int = 2339) -> bytes:
    """A clean A4 cover panel in the theme's colours: a pale wash on paper, a two-tone spine down
    the left edge (primary over secondary) and a thin dark rule along the foot. No bird — a custom
    report leads with the customer's own mark, not Shikari's."""
    from PIL import Image, ImageDraw

    page = Image.new("RGB", (width_px, height_px), charts.WHITE)
    # A faint diagonal wash towards the bottom-right, tinted by the accent so the paper isn't flat.
    down = Image.linear_gradient("L").resize((width_px, height_px))
    across = Image.linear_gradient("L").rotate(90).transpose(Image.FLIP_LEFT_RIGHT).resize((width_px, height_px))
    wash = Image.blend(down, across, 0.5).point(lambda v: int(v * 0.14))
    tint = tuple(int(c + (255 - c) * 0.80) for c in primary)   # the accent, lifted close to paper
    page = Image.composite(Image.new("RGB", page.size, tint), page, wash)

    d = ImageDraw.Draw(page)
    spine = int(width_px * 0.018)
    d.rectangle([0, 0, spine, int(height_px * 0.62)], fill=primary)
    d.rectangle([0, int(height_px * 0.62), spine, height_px], fill=secondary)
    foot = int(height_px * 0.965)
    d.rectangle([spine, foot, width_px, foot + max(3, int(height_px * 0.0016))], fill=dark)
    return charts._png(page)


def _io(data: bytes):
    import io
    return io.BytesIO(data)


# ── Storage: one install-wide profile under data/branding/ ──────────────────────

def _logo_path(index: int):
    return BRANDING_DIR / f"logo-{index + 1}.png"


def load_profile() -> dict:
    """The stored profile, or {} when the install has none."""
    try:
        return json.loads(PROFILE.read_text("utf-8"))
    except (OSError, ValueError):
        return {}


def logo_bytes() -> List[bytes]:
    """The uploaded logos, lead-to-trail, skipping any slot with no file."""
    out: List[bytes] = []
    for i in range(MAX_LOGOS):
        p = _logo_path(i)
        if p.exists():
            try:
                out.append(p.read_bytes())
            except OSError:
                pass
    return out


def active_theme() -> ReportTheme:
    """The theme every report wears: the stored profile when branding is enabled, else the stock
    Shikari look. Cheap enough to read on each render (a small JSON file and up to three PNGs)."""
    prof = load_profile()
    if not prof.get("enabled"):
        return DEFAULT
    # Report branding is a commercial feature: without a valid licence, reports stay stock
    # however the profile is set. The check is here, at the point of use, so it can't be
    # sidestepped by editing the stored files.
    from shikari import licensing
    if not licensing.has_feature(licensing.FEATURE_REPORT_BRANDING):
        return DEFAULT
    colours = prof.get("colours", {})
    resolved = {name: (hex_to_rgb(colours.get(name, "")) or default) for name, _, default in SLOTS}
    return ReportTheme(
        logos=tuple(logo_bytes()),
        org_name=(prof.get("org_name") or "").strip(),
        show_shikari=bool(prof.get("show_shikari", True)),
        custom=True,
        **resolved,
    )


def theme_for_assessment(brand_id: Optional[str]) -> ReportTheme:
    """The theme an assessment's reports wear. With the ``brand-library`` licence (Services) and a
    brand named on the assessment, its reports use that client brand; otherwise they fall back to
    the installation brand (``active_theme``), then to the stock Shikari look. The licence is checked
    here, at the render, so a saved choice can't get around it, and losing the licence loses the use
    of the brand, not the choice."""
    from shikari import licensing
    if brand_id and licensing.has_feature(licensing.FEATURE_BRAND_LIBRARY):
        from shikari.reports import brand_library
        brand = brand_library.get_brand(brand_id)
        if brand is not None:
            return brand_library.theme_for(brand)
    return active_theme()


def save_profile(colours: Dict[str, str], org_name: str, show_shikari: bool, enabled: bool) -> dict:
    """Write the palette and flags. Colours are kept as hex; anything unparseable falls back to the
    Shikari default for that slot so a report can't end up with a broken colour."""
    BRANDING_DIR.mkdir(parents=True, exist_ok=True)
    clean = {name: rgb_to_hex(hex_to_rgb(colours.get(name, "")) or default)
             for name, _, default in SLOTS}
    profile = {"enabled": bool(enabled), "org_name": (org_name or "").strip(),
               "show_shikari": bool(show_shikari), "colours": clean}
    PROFILE.write_text(json.dumps(profile, indent=2), "utf-8")
    return profile


def save_logo(index: int, data: bytes) -> None:
    """Store an uploaded logo (0-based slot), normalised to PNG with transparency preserved."""
    if not 0 <= index < MAX_LOGOS:
        raise ValueError("logo slot out of range")
    from PIL import Image

    img = Image.open(_io(data)).convert("RGBA")
    BRANDING_DIR.mkdir(parents=True, exist_ok=True)
    img.save(_logo_path(index), "PNG", optimize=True)


def remove_logo(index: int) -> None:
    _logo_path(index).unlink(missing_ok=True)


def clear() -> None:
    """Drop the whole profile and every logo — back to the stock look."""
    PROFILE.unlink(missing_ok=True)
    for i in range(MAX_LOGOS):
        remove_logo(i)
