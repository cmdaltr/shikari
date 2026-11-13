"""
Coverage gaps between SIEMs: the techniques the detection library covers in some of the user's
SIEMs but not all of them, and which SIEMs lack each one. Techniques no SIEM covers are the
matrix's job; this is the parity view for anyone running more than one SIEM.

Reads the saved detections (not the reference queries, the examples Shikari learns from), with the
same per-file SIEM attribution as cloud coverage. A technique counts only by its
own ID: a sub-technique's detection doesn't cover its parent here, or a parent would look covered
in a SIEM that only detects one narrow sub-technique of it.
"""

import os
from typing import Dict, Iterable, List, Optional, Set

from shikari.build.cloud_coverage import _TID, siem_of

# Profile's SIEM ids (app.SIEM_PLATFORMS) to the names siem_of gives
SIEM_NAMES = {"secops": "SecOps", "mde": "Defender XDR", "splunk": "Splunk", "elastic": "Elastic"}
ORDER = ("secops", "mde", "splunk", "elastic")


def siem_index(generate_dir: str) -> Dict[str, Set[str]]:
    """{technique ID: {SIEM names}} from the detection files' text."""
    index: Dict[str, Set[str]] = {}
    if not os.path.isdir(generate_dir):
        return index
    for name in os.listdir(generate_dir):
        if not name.endswith((".yaml", ".yml")):
            continue
        try:
            with open(os.path.join(generate_dir, name), encoding="utf-8", errors="replace") as fh:
                text = fh.read()
        except OSError:
            continue
        m = _TID.search(text)
        if m:
            index.setdefault(m.group(1).upper(), set()).add(siem_of(name, text))
    return index


def siem_gaps(generate_dir: str, attack: Dict[str, Dict], siems: Optional[Iterable[str]] = None) -> Dict:
    """{siems: [{id, label}], summary: {id: missing count}, techniques: [{technique_id, name, tactics,
    coverage: {id: bool}}]} for the given Profile SIEM ids (none: all four)."""
    chosen: List[str] = [s for s in ORDER if s in set(siems or ORDER)] or list(ORDER)
    index = siem_index(generate_dir)
    rows = []
    for tid in sorted(index):
        obj = attack.get(tid)
        if obj is None:
            continue
        have = {s: SIEM_NAMES[s] in index[tid] for s in chosen}
        if any(have.values()) and not all(have.values()):
            rows.append({
                "technique_id": tid, "name": obj.get("name"),
                "tactics": [p["phase_name"] for p in obj.get("kill_chain_phases", []) if p.get("kill_chain_name") == "mitre-attack"],
                "coverage": have,
            })
    return {"siems": [{"id": s, "label": SIEM_NAMES[s]} for s in chosen],
            "summary": {s: sum(not r["coverage"][s] for r in rows) for s in chosen},
            "techniques": rows}
