"""
Export threat-library test cases as a MACATable library TOML (#24 / MACAT interop).

MACAT (macat.io) runs ATT&CK-tagged procedures on a lab host and pushes results to VECTR — the same
VECTR that assessments are modelled on. This writes Archer's test cases as a MACATable **library**
file so MACAT can hold them: one `[[lib_procedures]]` per test case, tagged with the technique, tactic
and attributing group, with the matching Atomic Red Team GUID noted so MACAT can pair it with the ART
procedure it already syncs.

Archer's test cases are intelligence (technique, procedure text, indicators), not runnable commands, so
the export carries no `procedure_steps` — the executable steps come from the Atomic in MACAT. Format per
https://docs.macat.io/schemas/macatable-library.schema.json (top-level `version`, required
`lib_procedures`; each procedure requires `id` and `name`; unknown fields are rejected). No AI.
"""

import re
import uuid
from typing import Dict, List

# A fixed namespace so a test case's signature always maps to the same procedure id.
_NS = uuid.UUID("a7c3e1b2-1d4e-4c2a-9f6b-0a9c3e1b2d4e")


def _esc(s: str) -> str:
    return (str(s or "").replace("\\", "\\\\").replace('"', '\\"')
            .replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t"))


def _str(key: str, value) -> str:
    return f'{key} = "{_esc(value)}"\n'


def _arr(key: str, values) -> str:
    inner = ", ".join(f'"{_esc(v)}"' for v in values)
    return f"{key} = [{inner}]\n"


def _tactic_slug(tactic: str) -> str:
    """ATT&CK tactic display name -> MACAT/ATT&CK shortname, e.g. 'Privilege Escalation' -> 'privilege-escalation'."""
    return re.sub(r"[^a-z0-9]+", "-", (tactic or "").strip().lower()).strip("-")


def _ref(technique_id: str, n: int) -> str:
    """Snake_case ref matching ^[a-z][a-z0-9_]*$, unique within the file."""
    base = re.sub(r"[^a-z0-9]+", "_", (technique_id or "proc").lower()).strip("_") or "proc"
    if not base[0].isalpha():
        base = "t_" + base
    return f"{base}_{n}"


def _procedure(case: Dict, n: int) -> str:
    tactics = [t.strip() for t in (case.get("tactic") or "").split(",") if t.strip()]
    slugs = [s for s in (_tactic_slug(t) for t in tactics) if s]
    pid = str(uuid.uuid5(_NS, case.get("signature") or f"{case.get('technique_id')}-{n}"))

    name = case.get("technique_name") or case.get("technique_id") or "Procedure"
    desc_bits = [case.get("procedure") or ""]
    if case.get("atomic_guid"):
        desc_bits.append(f"Atomic Red Team test: {case['atomic_guid']}")
    if case.get("group_name"):
        desc_bits.append(f"Attributed to {case['group_name']} (via Archer).")
    description = " ".join(b for b in desc_bits if b).strip()

    tags = ["archer"]
    if case.get("group_name"):
        tags.append(case["group_name"])
    if case.get("atomic_guid"):
        tags.append(f"atomic:{case['atomic_guid']}")

    out = ["[[lib_procedures]]\n", _str("id", pid), _str("name", name),
           _str("ref", _ref(case.get("technique_id"), n))]
    if description:
        out.append(_str("description", description))
    if case.get("technique_id"):
        out.append(_str("primary_technique", case["technique_id"]))
    if slugs:
        out.append(_str("primary_tactic", slugs[0]))
        out.append(_arr("mitre_tactics_ref", slugs))
    out.append(_str("src_type", "art" if case.get("atomic_guid") else "macat"))
    out.append(_arr("possible_defenses", ["edr", "siem"]))
    out.append(_arr("tags", tags))
    return "".join(out)


def test_cases_to_macatable(cases: List[Dict]) -> str:
    """A MACATable library TOML for a list of test-case dicts (technique_id, technique_name, tactic,
    procedure, indicators, atomic_guid, group_name, signature)."""
    parts = ["# MACATable library exported from Archer (threat library)\n",
             "# Procedure metadata mapped to ATT&CK; link the runnable Atomic in MACAT.\n",
             "version = 1\n\n"]
    for i, case in enumerate(cases):
        parts.append(_procedure(case, i))
        parts.append("\n")
    return "".join(parts).rstrip("\n") + "\n"
