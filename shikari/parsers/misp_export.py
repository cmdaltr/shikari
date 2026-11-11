"""
Export a run as a MISP event (#19).

A run becomes a single MISP event: the group as a threat-actor galaxy, each technique as a
mitre-attack-pattern galaxy cluster (and a tag, so simple parsers pick it up too), and the
detections' IOCs as attributes typed by kind. MISP carries intel, not detection logic, so the
queries themselves aren't embedded — the event summarises what the run is about. The event is
assembled by `samarkand.misp.event`, the suite's shared builder (plain JSON, no pymisp); which IOCs
go in, as which types and categories, is Shikari's. No AI.

The inverse of ``shikari.parsers.misp_import`` — a run exported here re-imports to the same
techniques and IOCs.
"""

import json
from datetime import date
from typing import Dict, List

from samarkand import misp

# IOC kind → (MISP attribute type, category). The import side (_ATTR_KIND) maps these back.
_KIND_ATTR = {
    "ip": ("ip-dst", "Network activity"),
    "domain": ("domain", "Network activity"),
    "file": ("filename", "Payload delivery"),
    "reg": ("regkey", "Persistence mechanism"),
    "sw": ("windows-service-name", "Artifacts dropped"),
}


def _attributes(indicators: Dict[str, List[str]], seen: set) -> List[misp.Attribute]:
    attrs: List[misp.Attribute] = []
    for kind, values in (indicators or {}).items():
        for value in values or []:
            value = str(value).strip()
            if not value or (kind, value) in seen:
                continue
            seen.add((kind, value))
            if kind == "hash":
                atype, category = misp.hash_type(value), "Payload delivery"
            elif kind in _KIND_ATTR:
                atype, category = _KIND_ATTR[kind]
            else:
                continue  # cmd and anything else: no faithful MISP type, left out
            attrs.append(misp.Attribute(atype, category, value,
                                        to_ids=kind in ("ip", "domain", "hash", "file"), comment="Shikari"))
    return attrs


def run_to_misp(group_name: str, detections: List[Dict], description: str = "") -> str:
    """detections: dicts with name, technique_id, query, siem, indicators. Returns a MISP event (JSON)."""
    techniques: List[tuple] = []
    attributes: List[misp.Attribute] = []
    seen_ioc: set = set()

    for det in detections:
        tid = str(det.get("technique_id") or "").strip()
        if tid and tid not in [t for t, _ in techniques]:
            techniques.append((tid, det.get("technique_name") or tid))
        attributes.extend(_attributes(det.get("indicators") or {}, seen_ioc))
    if description:
        attributes.insert(0, misp.Attribute("comment", "External analysis", description[:2000], comment="Shikari"))

    n, t = len(detections), len(techniques)
    info = (f"Shikari run: {group_name}" if group_name else "Shikari run") + \
           f" — {t} technique{'' if t == 1 else 's'}, {n} detection{'' if n == 1 else 's'}"
    event = misp.event(
        info=info,
        date=date.today().isoformat(),
        analysis="2",          # completed
        threat_level_id="2",   # medium
        distribution=0,        # your org only
        attributes=attributes,
        techniques=techniques,
        threat_actor=group_name,
    )
    return json.dumps(event, indent=2)
