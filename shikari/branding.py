"""
Brand layer.

Shikari is the product. Its name, wordmark, favicon and accent live here once and are
exposed to every template as the ``brand`` global, so no template hard-codes the product
name: they read ``brand.name``, ``brand.banner`` and so on. The edition is still selected
from the ``SHIKARI_EDITION`` environment variable, leaving room for a future paid tier;
for now there is a single edition and anything unset/unknown resolves to it.

Assets: a compact head + wordmark lockup (``banner``, used in the top nav on every page),
the bateleur flying over the word (``hero``, used on the home page and the auth splashes),
and a hexagon favicon/app-icon set. Each wordmark has a light and a dark variant, swapped
by theme in the markup.
"""

from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Brand:
    """One edition's identity. Paths are relative to the static/ mount."""

    key: str          # edition id, matches SHIKARI_EDITION
    name: str         # product name shown in the UI and <title>
    tagline: str      # one-line descriptor
    banner: str       # compact wordmark, top nav on every page (static/-relative)
    banner_dark: str  # banner variant for dark mode (swapped by theme in the markup)
    hero: str         # lockup for the home page + auth splashes
    hero_dark: str    # hero variant for dark mode
    favicon: str      # .ico under static/
    icon_32: str      # 32px png under static/
    apple_icon: str   # 180px touch icon under static/
    accent: str       # primary accent colour (hex) — drives the UI --accent token
    accent_hover: str # darker accent for hover/active states (--accent-hover)
    vendor: str       # the company behind the edition
    url: str          # canonical site / handle


_SHIKARI = Brand(
    key="shikari",
    name="Shikari",
    tagline="Automated multi-SIEM detection generation",
    # Nav banner = compact head + word lockup. Hero = bateleur flying over the word (home + auth).
    # Light = black letters, gold "A"; dark = gold letters, black "A".
    banner="images/shikari/shikari-wordmark-light.png",
    banner_dark="images/shikari/shikari-wordmark-dark.png",
    hero="images/shikari/shikari-hero-light.png",
    hero_dark="images/shikari/shikari-hero-dark.png",
    favicon="images/shikari/shikari-favicon.ico",
    icon_32="images/shikari/shikari-favicon-32.png",
    apple_icon="images/shikari/shikari-apple-touch-icon.png",
    accent="#C9A227",   # Shikari gold — matches the wordmark; the bird's red face is the lone warm accent
    accent_hover="#A8851F",
    vendor="cmdaltr",
    url="https://github.com/cmdaltr/shikari",
)

_EDITIONS = {_SHIKARI.key: _SHIKARI}

_DEFAULT = "shikari"


def active_brand() -> Brand:
    """The brand this build wears, from SHIKARI_EDITION; unknown/unset resolves to Shikari."""
    return _EDITIONS.get(os.getenv("SHIKARI_EDITION", _DEFAULT).strip().lower(), _SHIKARI)
