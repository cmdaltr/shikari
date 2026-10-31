"""
Brand/edition layer.

Archer ships as a free community edition and a paid edition (Arcarius) built from the
same codebase. Which brand a running build wears — its name, wordmark, favicon and
accent — is decided once here from the ARCHER_EDITION environment variable and exposed
to every template as the ``brand`` global. Switching edition is an env/config change at
launch, not a code change, so no template hard-codes the product name: they read
``brand.name``, ``brand.banner`` and so on.

The commercial edition is the OffSec/Kali model — same engine, different wearer. Its
own assets (wordmark banner, and later its favicons) ship with that build; until they
exist the edition still runs, it just points at asset paths the build is expected to
supply.
"""

from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Brand:
    """One edition's identity. Paths are relative to the static/ mount."""

    key: str          # edition id, matches ARCHER_EDITION
    name: str         # product name shown in the UI and <title>
    tagline: str      # one-line descriptor
    banner: str       # wordmark/banner image under static/
    favicon: str      # .ico under static/
    icon_32: str      # 32px png under static/
    apple_icon: str   # 180px touch icon under static/
    accent: str       # primary accent colour (hex)
    vendor: str       # the company behind the edition
    url: str          # canonical site / handle


# The shared favicons are name-agnostic, so the commercial edition reuses them until it
# ships its own set; only the visible wordmark (banner), name and accent differ today.
_SHARED_FAVICON = "favicon.ico"
_SHARED_ICON_32 = "favicon-32.png"
_SHARED_APPLE_ICON = "apple-touch-icon.png"

_ARCHER = Brand(
    key="archer",
    name="Archer",
    tagline="Automated multi-SIEM detection generation",
    banner="images/archer_banner.png",
    favicon=_SHARED_FAVICON,
    icon_32=_SHARED_ICON_32,
    apple_icon=_SHARED_APPLE_ICON,
    accent="#C53030",
    vendor="cmdaltr",
    url="https://github.com/cmdaltr/archer",
)

_ARCARIUS = Brand(
    key="arcarius",
    name="Arcarius",
    tagline="Automated multi-SIEM detection generation",
    banner="images/arcarius_banner.png",   # supplied by the commercial build
    favicon=_SHARED_FAVICON,
    icon_32=_SHARED_ICON_32,
    apple_icon=_SHARED_APPLE_ICON,
    accent="#00D4AA",
    vendor="cmdaltr",
    url="https://github.com/cmdaltr/archer",
)

_EDITIONS = {b.key: b for b in (_ARCHER, _ARCARIUS)}

# Default is the free community edition; the commercial build sets ARCHER_EDITION=arcarius.
_DEFAULT = "archer"


def active_brand() -> Brand:
    """The brand this build wears, from ARCHER_EDITION; unknown/unset falls back to Archer."""
    return _EDITIONS.get(os.getenv("ARCHER_EDITION", _DEFAULT).strip().lower(), _ARCHER)
