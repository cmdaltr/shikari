"""
Kill-chain view of an actor's attack flow for the results page.

One node per distinct technique, placed in the lane of its primary tactic, with
the vendors that have a detection for it. Edges are the correlations Shikari built
(technique A observed before technique B on the same host), so the diagram shows
the detection chains that exist, not every theoretically possible route.
Techniques ATT&CK attributes to the group that have no detection are included
as gaps. Reconnaissance and Resource Development are left out: that activity
happens on the adversary's side, before the intrusion, where no log source looks.
"""

import csv
import os
import re
import uuid
from datetime import datetime, timezone
from functools import lru_cache
from typing import Dict, Iterable, List, Optional


from shikari import yaml_cache
from shikari.tactic_scope import intel_only
from shikari import paths as shikari_paths

# ATT&CK enterprise kill-chain order. v18 split Defense Evasion into Stealth and
# Defense Impairment; older detections still carry Defense Evasion.
TACTIC_ORDER = [
    "Reconnaissance", "Resource Development", "Initial Access", "Execution", "Persistence",
    "Privilege Escalation", "Defense Evasion", "Stealth", "Defense Impairment", "Credential Access",
    "Discovery", "Lateral Movement", "Collection", "Command and Control", "Exfiltration", "Impact",
]
_TACTIC_KEY = {t.lower(): t for t in TACTIC_ORDER}

# Display order and names; SecOps is the primary platform
VENDORS = [("googlesecops", "Google SecOps"), ("mde", "Defender XDR"), ("splunk", "Splunk"), ("elastic", "Elastic")]
_CONNECTOR_VENDOR = {"GoogleSecOps": "googlesecops", "MicrosoftThreatProtection": "mde",
                     "Splunk": "splunk", "Elastic": "elastic", "ElasticSecurity": "elastic"}

_TID = re.compile(r"^T\d{4}(?:\.\d{3})?$")
_PROCEDURES_CSV = str(shikari_paths.DATA / "mitre_procedures.csv")


def canonical_tactic(name: str) -> Optional[str]:
    """'Command And Control' -> 'Command and Control'; unknown names pass through title-cased."""
    if not name:
        return None
    return _TACTIC_KEY.get(name.strip().lower(), name.strip().title())


def _lane_index(tactic: str) -> int:
    return TACTIC_ORDER.index(tactic) if tactic in TACTIC_ORDER else len(TACTIC_ORDER)


@lru_cache(maxsize=4096)
def _read_detection(path: str, mtime: float) -> Optional[Dict]:
    try:
        data = yaml_cache.load(path) or {}
    except Exception:
        return None
    tid = str(data.get("technique_id") or "").upper()
    if not _TID.match(tid):
        return None
    connectors = data.get("requiredDataConnectors") or [{}]
    connector = connectors[0].get("connectorId", "") if isinstance(connectors[0], dict) else ""
    return {
        "id": tid,
        "name": data.get("name") or tid,
        "tactics": [t for t in (canonical_tactic(x) for x in data.get("tactics") or []) if t],
        "vendor": _CONNECTOR_VENDOR.get(connector),
    }


def read_detection(path: str) -> Optional[Dict]:
    try:
        return _read_detection(path, os.path.getmtime(path))
    except OSError:
        return None


@lru_cache(maxsize=8)
def _attributed_rows(csv_path: str, mtime: float) -> Dict[str, List[Dict]]:
    by_group: Dict[str, List[Dict]] = {}
    with open(csv_path, newline="", encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            # MITRESaw's 12-column CSV uses group_sw_name; the older 9-column one, group_name
            name = row.get("group_sw_name") or row.get("group_name") or ""
            by_group.setdefault(name.lower(), []).append(row)
    return by_group


def attributed_techniques(group_name: str, csv_path: str = _PROCEDURES_CSV) -> List[Dict]:
    """Techniques ATT&CK attributes to the group (MITRESaw's procedures CSV), one per ID."""
    try:
        rows = _attributed_rows(os.path.abspath(csv_path), os.path.getmtime(csv_path))
    except OSError:
        return []
    seen: Dict[str, Dict] = {}
    for row in rows.get(group_name.lower(), []):
        tid = row.get("technique_id", "").upper()
        if not _TID.match(tid):
            continue
        entry = seen.setdefault(tid, {"id": tid, "name": row.get("technique_name") or tid, "tactics": []})
        tactic = canonical_tactic(row.get("tactic", ""))
        if tactic and tactic not in entry["tactics"]:
            entry["tactics"].append(tactic)
    return list(seen.values())


def current_tactics(bundle) -> Dict[str, List[str]]:
    """Technique ID -> tactics from the loaded ATT&CK bundle (kill-chain phases), so stale CSV tactics can be corrected."""
    key = id(bundle)
    if _TACTICS_CACHE.get("key") != key:
        lookup: Dict[str, List[str]] = {}
        objects = bundle.get("objects", []) if isinstance(bundle, dict) else getattr(bundle, "objects", []) or []
        for obj in objects:
            obj = obj if isinstance(obj, dict) else dict(obj)
            if obj.get("type") != "attack-pattern" or obj.get("revoked") or obj.get("x_mitre_deprecated"):
                continue
            tid = next((r.get("external_id") for r in obj.get("external_references", [])
                        if r.get("source_name") == "mitre-attack"), None)
            phases = [canonical_tactic(p["phase_name"].replace("-", " ")) for p in obj.get("kill_chain_phases", [])
                      if p.get("kill_chain_name") == "mitre-attack"]
            if tid and phases:
                lookup[tid.upper()] = phases
        _TACTICS_CACHE.update(key=key, lookup=lookup)
    return _TACTICS_CACHE["lookup"]


_TACTICS_CACHE: Dict = {}


def via_parent(tid: str, attributed_ids) -> bool:
    """A sub-technique the run built from its attributed parent, not attributed itself."""
    return "." in tid and tid not in attributed_ids and tid.split(".")[0] in attributed_ids


def build_flow_view(detection_paths: Dict[str, Iterable[str]], correlations: List[Dict],
                    attributed: Optional[List[Dict]] = None,
                    tactic_lookup: Optional[Dict[str, List[str]]] = None) -> Dict:
    """
    Lanes, nodes and edges for the results-page attack flow.

    detection_paths: vendor -> detection YAML paths shown on the results page
    correlations:    the group's vendor_correlations (from data/correlate/<group>.json)
    attributed:      ATT&CK techniques for the group (attributed_techniques()), for gaps.
                     A built sub-technique ATT&CK doesn't attribute, whose parent it does,
                     is via_parent: the run expands attributed parents into their
                     sub-techniques (shikari.mitre.retrieve). It's extra coverage, never a gap.
    tactic_lookup:   current tactics per technique (current_tactics()); overrides the
                     procedures CSV, which can predate the loaded ATT&CK version
    """
    nodes: Dict[str, Dict] = {}

    def node(tid: str, name: str, tactics: List[str]) -> Dict:
        n = nodes.get(tid)
        if n is None:
            n = nodes[tid] = {"id": tid, "name": name, "tactics": [], "vendors": {},
                              "attributed": False, "url": "https://attack.mitre.org/techniques/"
                              + tid.replace(".", "/") + "/"}
        for t in tactics:
            if t not in n["tactics"]:
                n["tactics"].append(t)
        return n

    for vendor, paths in detection_paths.items():
        for path in paths:
            det = read_detection(path)
            if not det:
                continue
            n = node(det["id"], det["name"], det["tactics"])
            v = det["vendor"] or vendor
            n["vendors"][v] = n["vendors"].get(v, 0) + 1

    for tech in attributed or []:
        if tactic_lookup and tech["id"] not in tactic_lookup:
            continue  # revoked or deprecated since the CSV was generated
        tactics = (tactic_lookup or {}).get(tech["id"]) or tech["tactics"]
        node(tech["id"], tech["name"], tactics)["attributed"] = True

    # Edges: correlation A -> B. Merged correlations chain A to every technique involved.
    by_name = {n["name"].lower(): tid for tid, n in nodes.items()}
    edges: Dict[tuple, Dict] = {}
    for corr in correlations or []:
        if corr.get("chain"):
            continue  # all on one host in any order: no A -> B, and its pairs are edges already
        vendor = corr.get("vendor", "")
        a = read_detection(corr.get("a", ""))
        b = read_detection(corr.get("b", ""))
        if not a:
            continue
        targets = {b["id"]} if b else set()
        for name in corr.get("techniques_involved") or []:
            tid = by_name.get(str(name).lower())
            if tid:
                targets.add(tid)
        for tid in targets - {a["id"]}:
            if a["id"] not in nodes or tid not in nodes:
                continue
            e = edges.setdefault((a["id"], tid), {"from": a["id"], "to": tid, "vendors": [], "relevance": 0.0})
            if vendor and vendor not in e["vendors"]:
                e["vendors"].append(vendor)
            e["relevance"] = max(e["relevance"], float(corr.get("relevance_score") or 0))

    attributed_ids = {tid for tid, n in nodes.items() if n["attributed"]}
    for n in nodes.values():
        n["via_parent"] = via_parent(n["id"], attributed_ids)
        # Primary tactic: the detection's first tactic; it decides the lane
        n["tactic"] = n["tactics"][0] if n["tactics"] else "Unknown"
        n["detected"] = bool(n["vendors"])
        # Adversary-side Reconnaissance/Resource Development: not a gap (shikari.tactic_scope)
        n["intel_only"] = not n["detected"] and intel_only(n["id"], n["tactics"])
        n["degree"] = sum(1 for e in edges.values() if n["id"] in (e["from"], e["to"]))

    lanes = []
    for tactic in sorted({n["tactic"] for n in nodes.values()}, key=lambda t: (_lane_index(t), t)):
        members = sorted((n for n in nodes.values() if n["tactic"] == tactic),
                         key=lambda n: (not n["detected"], -n["degree"], n["id"]))
        lanes.append({"tactic": tactic, "nodes": members})

    vendor_names = dict(VENDORS)
    present = {v for n in nodes.values() for v in n["vendors"]}
    return {
        "lanes": lanes,
        "edges": sorted(edges.values(), key=lambda e: -e["relevance"]),
        "vendors": [{"key": k, "name": vendor_names[k]} for k, _ in VENDORS if k in present],
        "stats": {
            "techniques": len(nodes),
            "detected": sum(1 for n in nodes.values() if n["detected"]),
            "gaps": sum(1 for n in nodes.values() if n["attributed"] and not n["detected"] and not n["intel_only"]),
            "attributed": len(attributed_ids),
            "via_parent": sum(1 for n in nodes.values() if n["via_parent"]),
            "intel_only": sum(1 for n in nodes.values() if n["intel_only"]),
            "edges": len(edges),
            "tactics": len(lanes),
        },
    }


def arrange(view: Dict, state: Dict) -> List[Dict]:
    """
    The view's lanes after drag and drop: a technique moved to another tactic's lane
    sits there (its ATT&CK tactics stay in "tactics"), touched lanes keep the order
    the user gave, and lanes follow lane_order, then the kill chain.
    """
    arrangement = state.get("arrangement") or {}
    placed = {tid: lane for lane, tids in arrangement.items() for tid in tids}
    nodes = {n["id"]: (lane["tactic"], n) for lane in view["lanes"] for n in lane["nodes"]}
    names = list(dict.fromkeys([l["tactic"] for l in view["lanes"]] + list(arrangement)))
    members: Dict[str, List[Dict]] = {name: [] for name in names}
    for lane, tids in arrangement.items():
        members[lane] = [dict(nodes[t][1], tactic=lane) for t in tids if t in nodes]
    for lane in view["lanes"]:
        members[lane["tactic"]] += [n for n in lane["nodes"] if n["id"] not in placed]
    order = [l for l in state.get("lane_order") or [] if l in members]
    order += sorted((l for l in names if l not in order), key=lambda t: (_lane_index(t), t))
    return [{"tactic": name, "nodes": members[name]} for name in order if members[name]]


def apply_edits(view: Dict, state: Dict) -> Dict:
    """
    The view as the results page shows it after the user's edits (state as
    flow_layouts.clean_state returns it): SIEM filters, Hide Undetected, hidden
    techniques, removed and drawn links, and techniques and lanes moved by drag and
    drop. Free positions, orientation and direction are layout only. The Links toggle
    is display only too, so links are kept.
    """
    present = [v["key"] for v in view["vendors"]]
    vendors = set(state["vendors"]) if "vendors" in state else set(present)
    removed = set(state.get("removed", []))
    unlinked = set(state.get("unlinked", []))
    show_gaps = state.get("gaps", True)

    lanes, kept = [], {}
    for lane in arrange(view, state):
        members = []
        for n in lane["nodes"]:
            cov = {v: c for v, c in n["vendors"].items() if v in vendors}
            if n["id"] in removed or (not cov and not show_gaps):
                continue
            kept[n["id"]] = dict(n, vendors=cov, detected=bool(cov))
            members.append(kept[n["id"]])
        if members:
            lanes.append(dict(lane, nodes=members))
    edges = []
    for e in view["edges"]:
        evs = [v for v in e["vendors"] if v in vendors]
        if evs and e["from"] in kept and e["to"] in kept and f"{e['from']}>{e['to']}" not in unlinked:
            edges.append(dict(e, vendors=evs))
    # Links the user drew: an analyst's sequence, not a detection correlation
    existing = {(e["from"], e["to"]) for e in edges}
    for key in state.get("linked", []):
        a, b = key.split(">")
        if a in kept and b in kept and (a, b) not in existing and key not in unlinked:
            edges.append({"from": a, "to": b, "vendors": [], "relevance": 0.0, "manual": True})
    for n in kept.values():
        n["degree"] = sum(1 for e in edges if n["id"] in (e["from"], e["to"]))
    return dict(view, lanes=lanes, edges=edges,
                vendors=[v for v in view["vendors"] if v["key"] in vendors], edited=True)


# ── Attack Flow 2.x export (CTID Attack Flow Builder) ───────────────────────

AF_EXTENSION = "extension-definition--fb9c968a-745b-4ade-9b25-c324172197f4"
_AF_CREATOR = "identity--fb9c968a-745b-4ade-9b25-c324172197f4"
_NS = uuid.UUID("3c9a6d2e-6f9b-4d55-9a3c-2a6b8f0e4d11")


def _stix_id(kind: str, *parts: str) -> str:
    return f"{kind}--{uuid.uuid5(_NS, '|'.join(parts))}"


def to_attack_flow_bundle(view: Dict, group_name: str) -> Dict:
    """
    The correlated techniques as an Attack Flow 2.x STIX bundle: one attack-action per
    technique that takes part in a correlation, effect_refs following the correlations.
    IDs are deterministic per group and technique, so re-exports diff cleanly.
    """
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    ext = {AF_EXTENSION: {"extension_type": "new-sdo"}}
    author = _stix_id("identity", "shikari")
    nodes = {n["id"]: n for lane in view["lanes"] for n in lane["nodes"]}
    linked = [tid for tid in nodes if any(tid in (e["from"], e["to"]) for e in view["edges"])]
    action_id = {tid: _stix_id("attack-action", group_name, tid) for tid in linked}

    actions = []
    for tid in linked:
        n = nodes[tid]
        coverage = ", ".join(f"{dict(VENDORS).get(v, v)} ({c})" for v, c in n["vendors"].items()) or "none"
        actions.append({
            "type": "attack-action", "spec_version": "2.1", "id": action_id[tid],
            "created": now, "modified": now, "extensions": ext,
            "name": n["name"], "technique_id": tid,
            "description": (f"{n['tactic']} (moved; ATT&CK: {' / '.join(n['tactics'])})" if n.get("tactic") and n["tactics"]
                            and n["tactic"] not in n["tactics"] else ' / '.join(n['tactics']))
                           + f". Shikari detections: {coverage}.",
            "effect_refs": [action_id[e["to"]] for e in view["edges"] if e["from"] == tid],
        })

    targets = {e["to"] for e in view["edges"]}
    starts = [action_id[t] for t in linked if t not in targets]
    if linked and not starts:  # every action has a predecessor (cycle): start from the busiest
        starts = [action_id[max(linked, key=lambda t: nodes[t]["degree"])]]

    flow = {
        "type": "attack-flow", "spec_version": "2.1", "id": _stix_id("attack-flow", group_name),
        "created": now, "modified": now, "created_by_ref": author, "extensions": ext,
        "name": f"{group_name}: correlated techniques" + (" (edited)" if view.get("edited") else ""),
        "description": (f"Techniques Shikari correlated for {group_name}: each arrow is a detection "
                        "correlation (first technique seen before the second on the same host)"
                        + ("; arrows the analyst drew are included." if any(e.get("manual") for e in view["edges"])
                           else ".")),
        "scope": "threat-actor", "start_refs": starts,
    }
    return {
        "type": "bundle", "id": _stix_id("bundle", group_name, now),
        "objects": [
            {"type": "extension-definition", "id": AF_EXTENSION, "spec_version": "2.1",
             "created": "2022-08-02T19:34:35.143Z", "modified": "2022-08-02T19:34:35.143Z",
             "name": "Attack Flow", "description": "Extends STIX 2.1 with features to create Attack Flows.",
             "created_by_ref": _AF_CREATOR,
             "schema": "https://center-for-threat-informed-defense.github.io/attack-flow/stix/attack-flow-schema-2.0.0.json",
             "version": "2.0.0", "extension_types": ["new-sdo"]},
            {"type": "identity", "spec_version": "2.1", "id": author, "created": now, "modified": now,
             "name": "Shikari", "identity_class": "system"},
            flow,
            *actions,
        ],
    }
