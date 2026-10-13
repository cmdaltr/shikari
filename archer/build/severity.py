"""
A detection's severity, from where its technique sits in the kill chain (contract rubric
R04.3): the later the stage, the more an alert there means damage is already under way.
Credential access, lateral movement and impact are never Low; delivery alone is never
Critical. A technique listed under several tactics takes the most severe. No AI.

The same rating goes in the YAML's severity field and, upper-cased, in a YARA-L rule's
meta.severity, so the two always agree (validator YL-16).
"""

from typing import Iterable, Union

RATINGS = ("Low", "Medium", "High", "Critical")

BY_TACTIC = {
    "discovery": "Low",
    "initial access": "Medium",
    "execution": "Medium",
    "persistence": "Medium",
    "defense evasion": "Medium",
    "stealth": "Medium",
    "collection": "Medium",
    "privilege escalation": "High",
    "credential access": "High",
    "lateral movement": "High",
    "command and control": "High",
    "exfiltration": "High",
    "defense impairment": "High",
    "impact": "Critical",
    # An IOC sweep matches a known-bad indicator, whatever the stage
    "ioc sweep": "High",
}
DEFAULT = "Medium"

# YARA-L outcome $risk_score for each rating
RISK_SCORE = {"Low": 25, "Medium": 50, "High": 75, "Critical": 90}


def _key(tactic: str) -> str:
    return " ".join(str(tactic).replace("-", " ").replace("_", " ").lower().split())


def rate(tactics: Union[str, Iterable[str], None]) -> str:
    """Low, Medium, High or Critical for a technique's tactics."""
    if isinstance(tactics, str):
        tactics = [tactics]
    found = [BY_TACTIC[_key(t)] for t in tactics or [] if _key(t) in BY_TACTIC]
    return max(found, key=RATINGS.index) if found else DEFAULT
