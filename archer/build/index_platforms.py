"""
Which platforms each Splunk index serves. Index names are organisation-specific, so none
are written into the code: they come from bespoke/mappings/sources/platforms.json
(gitignored), which lists each platform's indexes per SIEM:

    {"Windows": {"Splunk": ["<windows index>", ...], "MDE": [...], ...}, "AWS": {...}, ...}

With no file every lookup is empty and callers fall back to the index name itself.
"""

import json
import os
from typing import Dict, Set

_PATH = os.path.join(os.path.dirname(__file__), "..", "..", "bespoke", "mappings", "sources", "platforms.json")
_cache: Dict = {"mtime": None, "by_index": {}}

# Platforms whose logs are cloud API activity: they apply whatever the OS of a technique
CLOUD_NATIVE = {"AWS", "Azure", "Azure AD", "GCP", "Identity Provider"}


def _by_index() -> Dict[str, Set[str]]:
    try:
        mtime = os.path.getmtime(_PATH)
    except OSError:
        return {}
    if _cache["mtime"] != mtime:
        by_index: Dict[str, Set[str]] = {}
        try:
            with open(_PATH, encoding="utf-8") as fh:
                for platform, siems in (json.load(fh) or {}).items():
                    for index in (siems or {}).get("Splunk", []) or []:
                        by_index.setdefault(index, set()).add(platform)
        except (OSError, ValueError):
            by_index = {}
        _cache.update(mtime=mtime, by_index=by_index)
    return _cache["by_index"]


def platforms_of(index: str) -> Set[str]:
    """The platforms platforms.json files this Splunk index under (empty if unknown)."""
    return set(_by_index().get((index or "").replace("index=", "").strip(), set()))


def indexes_for(*platforms: str) -> Set[str]:
    """Every Splunk index platforms.json files under any of these platforms."""
    wanted = set(platforms)
    return {i for i, p in _by_index().items() if p & wanted}


def is_cloud_native(index: str) -> bool:
    """Cloud API logs (CloudTrail, Activity Log, Entra ID, GCP audit) and nothing else."""
    found = platforms_of(index)
    return bool(found) and found <= CLOUD_NATIVE
