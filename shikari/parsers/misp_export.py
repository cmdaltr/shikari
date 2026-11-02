"""
Export a run as a MISP event (#19).

A run becomes a single MISP event: the group as a threat-actor galaxy, each technique as a
mitre-attack-pattern galaxy cluster (and a tag, so simple parsers pick it up too), and the
detections' IOCs as attributes typed by kind. MISP carries intel, not detection logic, so the
queries themselves aren't embedded — the event summarises what the run is about. Built as plain
JSON, no pymisp dependency. No AI.

The inverse of ``shikari.parsers.misp_import`` — a run exported here re-imports to the same
techniques and IOCs.
"""

import json
from collections import defaultdict
from datetime import date
from typing import Dict, List

# IOC kind → (MISP attribute type, category). The import side (_ATTR_KIND) maps these back.
_KIND_ATTR = {
    "ip": ("ip-dst", "Network activity"),
    "domain": ("domain", "Network activity"),
    "file": ("filename", "Payload delivery"),
    "reg": ("regkey", "Persistence mechanism"),
    "sw": ("windows-service-name", "Artifacts dropped"),
}
_HASH_TYPE = {32: "md5", 40: "sha1", 64: "sha256", 128: "sha512"}


def _hash_type(value: str) -> str:
    v = value.strip()
    return _HASH_TYPE.get(len(v), "sha256") if all(c in "0123456789abcdefABCDEF" for c in v) else "sha256"


def _attributes(indicators: Dict[str, List[str]], seen: set) -> List[Dict]:
    attrs: List[Dict] = []
    for kind, values in (indicators or {}).items():
        for value in values or []:
            value = str(value).strip()
            if not value or (kind, value) in seen:
                continue
            seen.add((kind, value))
            if kind == "hash":
                atype, category = _hash_type(value), "Payload delivery"
            elif kind in _KIND_ATTR:
                atype, category = _KIND_ATTR[kind]
            else:
                continue  # cmd and anything else: no faithful MISP type, left out
            attrs.append({"type": atype, "category": category, "value": value,
                          "to_ids": kind in ("ip", "domain", "hash", "file"), "comment": "Shikari"})
    return attrs


def run_to_misp(group_name: str, detections: List[Dict], description: str = "") -> str:
    """detections: dicts with name, technique_id, query, siem, indicators. Returns a MISP event (JSON)."""
    techniques: List[str] = []
    tech_names: Dict[str, str] = {}
    attributes: List[Dict] = []
    seen_ioc: set = set()

    for det in detections:
        tid = str(det.get("technique_id") or "").strip()
        if tid and tid not in techniques:
            techniques.append(tid)
            tech_names[tid] = det.get("technique_name") or tid
        attributes.extend(_attributes(det.get("indicators") or {}, seen_ioc))

    tags: List[Dict] = []
    ap_clusters: List[Dict] = []
    for tid in techniques:
        label = tech_names[tid] if tech_names[tid] != tid else tid
        value = f"{label} - {tid}" if label != tid else tid
        tags.append({"name": f'misp-galaxy:mitre-attack-pattern="{value}"'})
        ap_clusters.append({"type": "mitre-attack-pattern", "value": value,
                            "meta": {"external_id": [tid]}})

    galaxies: List[Dict] = []
    if ap_clusters:
        galaxies.append({"type": "mitre-attack-pattern", "name": "Attack Pattern",
                         "GalaxyCluster": ap_clusters})
    if group_name:
        galaxies.append({"type": "threat-actor", "name": "Threat Actor",
                         "GalaxyCluster": [{"type": "threat-actor", "value": group_name}]})
        tags.append({"name": f'misp-galaxy:threat-actor="{group_name}"'})

    n = len(detections)
    info = (f"Shikari run: {group_name}" if group_name else "Shikari run") + \
           f" — {len(techniques)} technique{'' if len(techniques) == 1 else 's'}, {n} detection{'' if n == 1 else 's'}"
    event = {
        "info": info,
        "date": date.today().isoformat(),
        "analysis": "2",          # completed
        "threat_level_id": "2",   # medium
        "distribution": "0",      # your org only
        "Attribute": attributes,
        "Tag": tags,
        "Galaxy": galaxies,
    }
    if description:
        event["Attribute"].insert(0, {"type": "comment", "category": "External analysis",
                                      "value": description[:2000], "comment": "Shikari"})
    return json.dumps({"Event": event}, indent=2)
