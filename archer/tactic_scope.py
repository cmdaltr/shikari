"""
Reconnaissance and Resource Development: shown everywhere (matrix, coverage, flows,
briefings, the Manual), because groups use them and leaving them out made groups look as
if they skipped those stages. Detections are another matter. Most of these techniques
happen on the adversary's side: ATT&CK's analytics for them need domain registration,
passive DNS, certificate or malware data, not the target's logs. Those are "intel only":
never written as a detection and never counted as a coverage gap.

The exceptions are the ones the target's own telemetry sees (ATT&CK v20 analytics on
network traffic or application logs): scanning, phishing for information, searching the
victim's own websites and gathering identity information. Those are written and counted
like any other technique.
"""

from typing import Iterable

PRE_COMPROMISE = ("reconnaissance", "resource development")
PRE_COMPROMISE_IDS = ("TA0043", "TA0042")

# Pre-compromise techniques (and their sub-techniques) a log source on the estate sees
DETECTABLE = ("T1595", "T1598", "T1594", "T1589")


def _key(tactic) -> str:
    return " ".join(str(tactic).replace("-", " ").replace("_", " ").lower().split())


def pre_compromise(tactic) -> bool:
    """Reconnaissance or Resource Development, by name, shortname or ID."""
    return _key(tactic) in PRE_COMPROMISE or str(tactic).upper() in PRE_COMPROMISE_IDS


def intel_only(technique_id, tactics: Iterable) -> bool:
    """A technique only in pre-compromise tactics that the estate's logs can't see."""
    tactics = [t for t in tactics or [] if t]
    if not tactics or not all(pre_compromise(t) for t in tactics):
        return False
    return str(technique_id or "").upper().split(".")[0] not in DETECTABLE
