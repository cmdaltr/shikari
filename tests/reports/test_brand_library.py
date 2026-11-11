"""
The brand library (a Services feature): logo cleaning, the store, and which brand an assessment's
report wears. The licence itself is tested in tests/test_licensing.py; here we check the gate at the
render — a client brand under Services, the installation brand under Pro.
"""

import io
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from shikari import licensing
from shikari.reports import brand_library as lib
from shikari.reports import theme


@pytest.fixture
def store(tmp_path, monkeypatch):
    """Point both the installation brand and the client-brand library at a temp dir."""
    branding = tmp_path / "branding"
    monkeypatch.setattr(theme, "BRANDING_DIR", branding)
    monkeypatch.setattr(theme, "PROFILE", branding / "profile.json")
    monkeypatch.setattr(lib, "LIBRARY_DIR", branding / "library")
    monkeypatch.setattr(lib, "INDEX", branding / "library" / "brands.json")
    return branding


def _png(size=(400, 120), mode="RGBA", fmt="PNG", **save) -> bytes:
    from PIL import Image

    buf = io.BytesIO()
    Image.new(mode, size, (10, 20, 30) if mode == "RGB" else (10, 20, 30, 255)).save(buf, fmt, **save)
    return buf.getvalue()


# ── logo cleaning, ostraka's rule ──

def test_a_logo_is_redrawn_as_a_clean_png():
    from PIL import Image, PngImagePlugin

    info = PngImagePlugin.PngInfo()
    info.add_text("Comment", "secret")
    img = Image.open(io.BytesIO(lib.clean_logo(_png(pnginfo=info) + b"trailing bytes")))
    assert img.format == "PNG" and img.size == (400, 120) and "Comment" not in img.info


def test_a_big_logo_is_scaled_down():
    img = __import__("PIL.Image", fromlist=["open"]).open(io.BytesIO(lib.clean_logo(_png((3000, 1000), "RGB", "JPEG"))))
    assert img.format == "PNG" and max(img.size) == lib.RENDER_EDGE


@pytest.mark.parametrize("data, why", [
    (b'<svg xmlns="http://www.w3.org/2000/svg"><script/></svg>', "PNG or JPEG"),
    (_png(fmt="GIF", mode="RGB"), "PNG or JPEG"),
    (_png((5000, 5000), "RGB", "JPEG"), "too large"),
    (b"\x89PNG" + b"0" * (3 * 1024 * 1024), "over 2 MB"),
])
def test_a_bad_logo_is_refused(data, why):
    with pytest.raises(lib.LogoProblem, match=why):
        lib.clean_logo(data)


# ── the store ──

def test_brands_are_created_listed_and_deleted(store):
    a = lib.create_brand("Client A", {"primary": "#007a74"})
    b = lib.create_brand("Client B", {"primary": "#b23a48"})
    assert {r["name"] for r in lib.list_brands()} == {"Client A", "Client B"}
    assert lib.get_brand(a["id"])["colours"]["primary"] == "#007a74"
    lib.save_logo(a["id"], 0, _png())
    assert next(r for r in lib.list_brands() if r["id"] == a["id"])["has_logo"]
    assert lib.delete_brand(b["id"]) and lib.get_brand(b["id"]) is None


# ── the gate at the render ──

def test_an_assessment_uses_its_client_brand_under_services_and_falls_back_under_pro(store, monkeypatch):
    # The installation brand (report-branding), enabled.
    theme.save_profile({"primary": "#101010"}, org_name="Installation Co", show_shikari=True, enabled=True)
    brand = lib.create_brand("Client A", {"primary": "#007a74"})

    # Services: brand-library and report-branding. The assessment's own brand is used.
    monkeypatch.setattr(licensing, "has_feature",
                        lambda f: f in (licensing.FEATURE_BRAND_LIBRARY, licensing.FEATURE_REPORT_BRANDING))
    th = theme.theme_for_assessment(brand["id"])
    assert th.custom and th.org_name == "Client A" and th.primary == (0, 122, 116)

    # Pro: report-branding only. The client brand is kept on the assessment but not used; the report
    # falls back to the installation brand.
    monkeypatch.setattr(licensing, "has_feature", lambda f: f == licensing.FEATURE_REPORT_BRANDING)
    th = theme.theme_for_assessment(brand["id"])
    assert th.custom and th.org_name == "Installation Co" and th.primary == (16, 16, 16)

    # No brand named: the installation brand, on any edition.
    assert theme.theme_for_assessment(None).org_name == "Installation Co"


def test_without_report_branding_an_assessment_report_is_stock(store, monkeypatch):
    theme.save_profile({"primary": "#101010"}, org_name="Installation Co", show_shikari=True, enabled=True)
    brand = lib.create_brand("Client A", {"primary": "#007a74"})
    monkeypatch.setattr(licensing, "has_feature", lambda f: False)   # Free
    assert theme.theme_for_assessment(brand["id"]).custom is False
