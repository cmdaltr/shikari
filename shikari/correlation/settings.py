"""
Correlation settings an admin saves on the Profile page (Correlation Parameters).

Kept in data/correlation_settings.json, not in the source: saving used to rewrite config.py and
engine.py, which dirtied the git checkout homelab pulls from, and two of the three values it wrote
were no longer read by anything.

    threshold   minimum relevance score (0-1); CORRELATION_MIN_RELEVANCE, or a hunt's own
                threshold, overrides it for a run
    per_vendor  most technique pairs kept per vendor; Google SecOps, the primary platform, keeps
                at least engine.CORRELATION_CAP's 100
    tech_freq   most other techniques one technique is paired with, per vendor
"""

import json
from typing import Dict

from shikari import paths

DEFAULTS = {"threshold": 0.4, "per_vendor": 60, "tech_freq": 20}
LIMITS = {"threshold": (0.0, 1.0), "per_vendor": (1, 500), "tech_freq": (1, 100)}


def _path():
    return paths.DATA / "correlation_settings.json"


def load() -> Dict:
    """The saved settings over the defaults; a missing or damaged file gives the defaults"""
    try:
        saved = json.loads(_path().read_text())
    except (OSError, ValueError):
        saved = {}
    settings = dict(DEFAULTS)
    for key, default in DEFAULTS.items():
        try:
            value = type(default)(saved[key])
        except (KeyError, TypeError, ValueError):
            continue
        low, high = LIMITS[key]
        if low <= value <= high:
            settings[key] = value
    return settings


def save(changes: Dict) -> Dict:
    """Merge the given settings into the saved ones; a key left out keeps its value.

    Raises ValueError, naming the setting, for an unknown key or a value out of range.
    """
    settings = load()
    for key, value in changes.items():
        if key not in DEFAULTS:
            raise ValueError(f"Unknown setting: {key}")
        try:
            value = type(DEFAULTS[key])(value)
        except (TypeError, ValueError):
            raise ValueError(f"{key} must be a number") from None
        low, high = LIMITS[key]
        if not low <= value <= high:
            raise ValueError(f"{key} must be between {low:g} and {high:g}")
        settings[key] = value
    path = _path()
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(settings, indent=2))
    tmp.replace(path)
    return settings
