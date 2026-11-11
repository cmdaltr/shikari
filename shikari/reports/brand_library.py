"""
The brand library — a Services feature (`brand-library`).

Report branding (Pro) dresses every report in one identity, the installation's own (``theme.py``).
A consultancy running Shikari for several clients needs more than one: a brand per client, picked
for the engagement the report comes from. This module keeps that library, and an assessment names
the brand its reports should wear (``Assessment.brand``). ostraka attaches a brand to an incident;
Shikari's engagement is the assessment.

Choosing and using a client brand is gated by ``brand-library`` at the point the report is drawn
(``theme.theme_for_assessment``), never when the choice is saved. Without the licence an assessment
keeps its stored choice, but its reports fall back to the installation brand, then to Shikari's own
style — nothing is lost, it just isn't used.

Storage mirrors the installation brand: a folder, not a table, under ``data/branding/library/``.
``brands.json`` is the index (id, name, palette, flags); each brand's logos are PNGs in its own
folder. Uploaded logos follow ostraka's rule — PNG or JPEG only, refused above a pixel limit before
the pixels are decoded, and always redrawn as a fresh PNG so nothing but the image survives.
"""

from __future__ import annotations

import json
import time
import uuid
from typing import Dict, List, Optional

from shikari.reports import theme as theme_mod

LIBRARY_DIR = theme_mod.BRANDING_DIR / "library"
INDEX = LIBRARY_DIR / "brands.json"
MAX_LOGOS = theme_mod.MAX_LOGOS

# Logo rules, matching ostraka's clean_logo so a brand looks the same wherever it was made.
UPLOAD_LIMIT = 2 * 1024 * 1024    # 2 MB of upload
MAX_EDGE = 4096                   # refused before decoding: a decompression-bomb guard
RENDER_EDGE = 1200                # a logo is redrawn down to this longest side


class LogoProblem(ValueError):
    """An uploaded logo that can't be used, with a reason to show the admin."""


def clean_logo(data: bytes) -> bytes:
    """A logo redrawn as a fresh PNG: PNG or JPEG only, under 2 MB, not a decompression bomb, and
    scaled so its longest side is at most RENDER_EDGE. Raises LogoProblem. Nothing of the original
    file survives the redraw — no metadata, no trailing bytes, no embedded payload."""
    from PIL import Image, UnidentifiedImageError

    if len(data) > UPLOAD_LIMIT:
        raise LogoProblem("That logo is over 2 MB. Give a smaller file.")
    try:
        img = Image.open(theme_mod._io(data))
    except (UnidentifiedImageError, OSError) as exc:
        raise LogoProblem("A logo must be a PNG or JPEG.") from exc
    if img.format not in ("PNG", "JPEG"):
        raise LogoProblem("A logo must be a PNG or JPEG.")
    if max(img.size) > MAX_EDGE:  # img.size is read from the header, before the pixels are decoded
        raise LogoProblem(f"That logo is too large: keep its longest side under {MAX_EDGE} pixels.")
    img = img.convert("RGBA")
    if max(img.size) > RENDER_EDGE:
        img.thumbnail((RENDER_EDGE, RENDER_EDGE), Image.LANCZOS)
    clean = Image.new("RGBA", img.size, (0, 0, 0, 0))
    clean.alpha_composite(img)
    return theme_mod.charts._png(clean)


# ── Storage: the index and each brand's folder under data/branding/library/ ─────

def _load() -> List[dict]:
    try:
        rows = json.loads(INDEX.read_text("utf-8"))
        return rows if isinstance(rows, list) else []
    except (OSError, ValueError):
        return []


def _save(rows: List[dict]) -> None:
    LIBRARY_DIR.mkdir(parents=True, exist_ok=True)
    INDEX.write_text(json.dumps(rows, indent=2), "utf-8")


def _brand_dir(brand_id: str):
    return LIBRARY_DIR / brand_id


def _logo_path(brand_id: str, index: int):
    return _brand_dir(brand_id) / f"logo-{index + 1}.png"


def _clean_colours(colours: Dict[str, str]) -> Dict[str, str]:
    """Hex per slot, with the Shikari default for anything missing or unparseable (as theme does)."""
    return {name: theme_mod.rgb_to_hex(theme_mod.hex_to_rgb(colours.get(name, "")) or default)
            for name, _, default in theme_mod.SLOTS}


def list_brands() -> List[dict]:
    """Every brand in the library, each with whether it carries any logo, newest name first."""
    out = []
    for row in sorted(_load(), key=lambda r: (r.get("name") or "").lower()):
        out.append({**row, "has_logo": any(_logo_path(row["id"], i).exists() for i in range(MAX_LOGOS))})
    return out


def get_brand(brand_id: Optional[str]) -> Optional[dict]:
    if not brand_id:
        return None
    return next((r for r in _load() if r.get("id") == brand_id), None)


def create_brand(name: str, colours: Dict[str, str], show_shikari: bool = True) -> dict:
    now = time.time()
    brand = {"id": f"brand_{uuid.uuid4().hex[:12]}", "name": (name or "").strip() or "Untitled brand",
             "colours": _clean_colours(colours), "show_shikari": bool(show_shikari),
             "created_at": now, "updated_at": now}
    rows = _load()
    rows.append(brand)
    _save(rows)
    return brand


def update_brand(brand_id: str, *, name: Optional[str] = None, colours: Optional[Dict[str, str]] = None,
                 show_shikari: Optional[bool] = None) -> Optional[dict]:
    rows = _load()
    for row in rows:
        if row.get("id") == brand_id:
            if name is not None:
                row["name"] = name.strip() or row["name"]
            if colours is not None:
                row["colours"] = _clean_colours(colours)
            if show_shikari is not None:
                row["show_shikari"] = bool(show_shikari)
            row["updated_at"] = time.time()
            _save(rows)
            return row
    return None


def delete_brand(brand_id: str) -> bool:
    """Drop a brand and its logos. Assessments that named it keep the name but fall back when drawn."""
    rows = _load()
    kept = [r for r in rows if r.get("id") != brand_id]
    if len(kept) == len(rows):
        return False
    for i in range(MAX_LOGOS):
        _logo_path(brand_id, i).unlink(missing_ok=True)
    try:
        _brand_dir(brand_id).rmdir()
    except OSError:
        pass
    _save(kept)
    return True


def save_logo(brand_id: str, index: int, data: bytes) -> None:
    """Store a cleaned logo in a brand's slot (0-based). Raises LogoProblem on a bad image."""
    if not 0 <= index < MAX_LOGOS:
        raise ValueError("logo slot out of range")
    if get_brand(brand_id) is None:
        raise ValueError("no such brand")
    cleaned = clean_logo(data)
    _brand_dir(brand_id).mkdir(parents=True, exist_ok=True)
    _logo_path(brand_id, index).write_bytes(cleaned)


def remove_logo(brand_id: str, index: int) -> None:
    if 0 <= index < MAX_LOGOS:
        _logo_path(brand_id, index).unlink(missing_ok=True)


def logo_bytes(brand_id: str) -> List[bytes]:
    out: List[bytes] = []
    for i in range(MAX_LOGOS):
        p = _logo_path(brand_id, i)
        if p.exists():
            try:
                out.append(p.read_bytes())
            except OSError:
                pass
    return out


def theme_for(brand: dict) -> theme_mod.ReportTheme:
    """A client brand as a report theme. Same shape as the installation brand, so the report shells
    don't care which one they're wearing."""
    colours = brand.get("colours", {})
    resolved = {name: (theme_mod.hex_to_rgb(colours.get(name, "")) or default)
                for name, _, default in theme_mod.SLOTS}
    return theme_mod.ReportTheme(
        logos=tuple(logo_bytes(brand["id"])),
        org_name=(brand.get("name") or "").strip(),
        show_shikari=bool(brand.get("show_shikari", True)),
        custom=True,
        **resolved,
    )
