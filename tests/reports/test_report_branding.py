"""
Report branding: the theme model, its install-wide profile, the licence-gated activation, and the
response-actions indicator-shape fix. The licence mechanism itself is tested in tests/test_licensing.py.
"""

import io
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from shikari import licensing
from shikari.reports import branded, response_actions, theme


# a 1x1 PNG, so logo tests don't need an asset on disk
_PNG_1x1 = (
    b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00"
    b"\x1f\x15\xc4\x89\x00\x00\x00\nIDATx\x9cc\xf8\x0f\x00\x01\x01\x01\x00\x1b\xb6\xee\x56"
    b"\x00\x00\x00\x00IEND\xaeB`\x82"
)


@pytest.fixture
def branding_dir(tmp_path, monkeypatch):
    """Point the theme's install-wide storage at a temp dir."""
    d = tmp_path / "branding"
    monkeypatch.setattr(theme, "BRANDING_DIR", d)
    monkeypatch.setattr(theme, "PROFILE", d / "profile.json")
    return d


# ── theme / palette ──

def test_hex_roundtrip():
    assert theme.hex_to_rgb("#1a2028") == (26, 32, 40)
    assert theme.hex_to_rgb("1a2028") == (26, 32, 40)
    assert theme.hex_to_rgb("nope") is None
    assert theme.rgb_to_hex((26, 32, 40)) == "#1a2028"


def test_profile_roundtrip_and_bad_colour_falls_back(branding_dir):
    saved = theme.save_profile(
        {"primary": "#007a74", "secondary": "not-a-colour", "heading": "#50505a", "dark": "#101e28"},
        org_name="  Acme  ", show_shikari=False, enabled=True)
    assert saved["org_name"] == "Acme"
    assert saved["enabled"] is True and saved["show_shikari"] is False
    assert saved["colours"]["primary"] == "#007a74"
    assert saved["colours"]["secondary"] == theme.rgb_to_hex(theme.charts.RED)
    assert theme.load_profile()["colours"]["heading"] == "#50505a"


def test_active_theme_is_gated_by_the_licence(branding_dir, monkeypatch):
    theme.save_profile({"primary": "#007a74", "secondary": "#14283c", "heading": "#50505a",
                        "dark": "#101e28"}, "Acme", True, True)

    monkeypatch.setattr(licensing, "has_feature", lambda f: False)
    assert theme.active_theme().custom is False          # enabled, but unlicensed -> stock

    monkeypatch.setattr(licensing, "has_feature", lambda f: True)
    th = theme.active_theme()
    assert th.custom is True and th.primary == (0, 122, 116)


def test_active_theme_off_when_disabled(branding_dir, monkeypatch):
    monkeypatch.setattr(licensing, "has_feature", lambda f: True)
    theme.save_profile({}, "", True, enabled=False)
    assert theme.active_theme().custom is False


def test_logo_strip_composes(branding_dir):
    strip = theme.logo_strip((_PNG_1x1, _PNG_1x1), height_px=40)
    from PIL import Image
    img = Image.open(io.BytesIO(strip))
    assert img.height == 40 and img.width >= 40  # two logos side by side


def test_custom_render_differs_from_stock():
    cover = branded.Cover(kind="Assessment", title="Acme", date="11 November 2026", tlp="TLP:GREEN")
    blocks = [("section", "Summary"), ("para", "Body."),
              ("table", (["A", "B"], [["1", "2"]], [6.0, 6.0], {}), "", False)]
    stock = branded.render(cover, blocks, "docx", theme=theme.DEFAULT)
    custom = branded.render(cover, blocks, "docx",
                            theme=theme.ReportTheme(primary=(0, 122, 116), dark=(16, 30, 40), custom=True))
    assert stock[:2] == b"PK" and custom[:2] == b"PK"
    assert stock != custom


# ── the response-actions indicator-shape fix ──

@pytest.mark.parametrize("indicators", [None, ["whoami", "net.exe"], {"cmd": ["a"], "sw": ["b"]},
                                        "single", {"cmd": "not-a-list"}])
def test_response_actions_accepts_any_indicator_shape(indicators):
    g = response_actions.ResponseActionsGenerator()
    out = g.generate_response_actions("OS Credential Dumping", "T1003", "Credential Access",
                                      "desc", indicators=indicators)
    assert out["priority"] and out["response_actions"]
