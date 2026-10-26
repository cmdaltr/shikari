"""
Build threat-library test cases from MITRESaw procedures (#24).

A test case is one procedure for a technique, drawn from a set of groups (those a company profile
ranks, or a group you name). Prevalence is how many of those groups use the technique, so the list
sorts by what the most ranked adversaries actually do. The matching Atomic Red Team test is attached
where the local atomics are configured. No AI, nothing is executed here.
"""

import csv
import hashlib
import json
import os
from typing import Dict, List, Optional

from archer.config import DATA_DIR

_CSV = os.path.join(DATA_DIR, "mitre_procedures.csv")


def _signature(technique_id: str, procedure: str) -> str:
    return hashlib.sha1(f"{technique_id}|{procedure}".encode("utf-8")).hexdigest()


def _indicators(evidence: str) -> Dict[str, List[str]]:
    try:
        data = json.loads(evidence) if evidence else {}
        return {k: v for k, v in data.items() if isinstance(v, list) and v}
    except (ValueError, TypeError):
        return {}


def build_test_cases(groups: List[str], csv_path: Optional[str] = None) -> List[Dict]:
    """Candidate test cases for a set of groups, most prevalent technique first.

    One per distinct (technique, procedure). prevalence = how many of `groups` attribute the
    technique. Returns [] if the CSV is missing or the groups aren't in it."""
    path = csv_path or _CSV
    if not os.path.exists(path):
        return []
    wanted = {g.strip().lower() for g in groups if g and g.strip()}
    if not wanted:
        return []

    # How many of the chosen groups use each technique (prevalence), and the procedures seen.
    tech_groups: Dict[str, set] = {}
    cases: Dict[str, Dict] = {}
    with open(path, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            gname = (row.get("group_sw_name") or row.get("group_name") or "").strip().lower()
            if gname not in wanted:
                continue
            tid = (row.get("technique_id") or "").strip()
            if not tid:
                continue
            tech_groups.setdefault(tid, set()).add(gname)
            proc = (row.get("procedure_example") or "").strip()
            sig = _signature(tid, proc)
            if sig not in cases:
                cases[sig] = {
                    "signature": sig,
                    "technique_id": tid,
                    "technique_name": row.get("technique_name") or tid,
                    "tactic": row.get("tactic") or "",
                    "group_name": row.get("group_sw_name") or row.get("group_name") or "",
                    "procedure": proc,
                    "indicators": _indicators(row.get("evidence", "")),
                    "detectable_via": (row.get("detectable_via") or "").strip(),
                }

    atomics = atomic_index()
    out = []
    for case in cases.values():
        case["prevalence"] = len(tech_groups.get(case["technique_id"], ()))
        case["atomic_guid"] = (atomics.get(case["technique_id"]) or [None])[0]
        out.append(case)
    out.sort(key=lambda c: (-c["prevalence"], c["technique_id"]))
    return out


_ATOMIC_CACHE: Optional[Dict[str, List[str]]] = None


def atomic_index() -> Dict[str, List[str]]:
    """{technique_id: [atomic GUIDs]} from a local Atomic Red Team checkout, or {} if not configured.

    Reads the atomics' index only; it never runs a test (running is stage 2/3 of #22)."""
    global _ATOMIC_CACHE
    if _ATOMIC_CACHE is not None:
        return _ATOMIC_CACHE

    from archer.config import EmulationConfig

    index: Dict[str, List[str]] = {}
    root = getattr(EmulationConfig, "atomic_path", None)
    atomics_dir = os.path.join(root, "atomics") if root else None
    if atomics_dir and os.path.isdir(atomics_dir):
        try:
            import yaml
        except ImportError:
            yaml = None
        for tid in os.listdir(atomics_dir):
            yml = os.path.join(atomics_dir, tid, f"{tid}.yaml")
            if not (tid.startswith("T") and os.path.exists(yml)):
                continue
            if yaml is None:
                index[tid] = []
                continue
            try:
                with open(yml, encoding="utf-8") as fh:
                    doc = yaml.safe_load(fh) or {}
                guids = [t.get("auto_generated_guid") for t in doc.get("atomic_tests", [])
                         if t.get("auto_generated_guid")]
                index[tid] = guids
            except (OSError, ValueError):
                index[tid] = []
    _ATOMIC_CACHE = index
    return index
