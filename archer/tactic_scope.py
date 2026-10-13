"""
The ATT&CK tactics Archer works with. Reconnaissance and Resource Development happen on
the adversary's side, before the target's estate: no log source sees them, so Archer
leaves them out everywhere (matrix, coverage, mappings, detections, flows, reports).
"""

from typing import Iterable, List

EXCLUDED = ("reconnaissance", "resource development")
EXCLUDED_IDS = ("TA0043", "TA0042")


def _key(tactic) -> str:
    return " ".join(str(tactic).replace("-", " ").replace("_", " ").lower().split())


def excluded(tactic) -> bool:
    return _key(tactic) in EXCLUDED or str(tactic).upper() in EXCLUDED_IDS


def keep(tactics: Iterable) -> List:
    """tactics without the excluded ones, order kept."""
    return [t for t in tactics or [] if not excluded(t)]
