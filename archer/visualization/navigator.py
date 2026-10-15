"""
The ATT&CK Enterprise matrix, for the Coverage page's Navigator-style view: every tactic
in the matrix's own order, each with every technique ATT&CK files under it and their
sub-techniques. Built from the STIX bundle Archer loads at startup, so it follows
ATT&CK's own changes (v18 split Defense Evasion into Stealth and Defense Impairment).
Revoked and deprecated techniques are left out. No coverage here: the page colours
each cell from the reference coverage map (archer.build.references).
"""

import os
import re
from typing import Dict, List

_cache: Dict[int, List[Dict]] = {}
_index_cache: Dict[int, Dict[str, Dict]] = {}


def _get(obj, key, default=None):
    getter = getattr(obj, "get", None)
    return getter(key, default) if getter else getattr(obj, key, default)


def _attack_id(obj) -> str:
    for ref in _get(obj, "external_references", []) or []:
        if _get(ref, "source_name") == "mitre-attack":
            return _get(ref, "external_id") or ""
    return ""


def matrix(bundle) -> List[Dict]:
    """[{tactic, shortname, techniques: [{id, name, subs: [{id, name}]}]}], in matrix order."""
    if bundle is None:
        return []
    key = id(bundle)
    if key in _cache:
        return _cache[key]

    objects = list(_get(bundle, "objects", []) or [])
    tactics = {_get(o, "id"): o for o in objects if _get(o, "type") == "x-mitre-tactic"}
    order = []
    for o in objects:
        if _get(o, "type") == "x-mitre-matrix" and _attack_id(o) == "enterprise-attack":
            order = [tactics[r] for r in _get(o, "tactic_refs", []) or [] if r in tactics]
            break
    if not order:
        order = list(tactics.values())

    parents: Dict[str, Dict] = {}
    subs: Dict[str, List[Dict]] = {}
    phases: Dict[str, List[str]] = {}
    for o in objects:
        if (_get(o, "type") != "attack-pattern" or _get(o, "revoked") or _get(o, "x_mitre_deprecated")):
            continue
        tid = _attack_id(o)
        if not tid:
            continue
        entry = {"id": tid, "name": _get(o, "name", tid)}
        if "." in tid:
            subs.setdefault(tid.split(".")[0], []).append(entry)
            continue
        parents[tid] = entry
        phases[tid] = [_get(p, "phase_name") for p in _get(o, "kill_chain_phases", []) or []
                       if _get(p, "kill_chain_name") == "mitre-attack"]

    result = []
    for t in order:
        short = _get(t, "x_mitre_shortname")
        techniques = sorted(
            ({**parents[tid], "subs": sorted(subs.get(tid, []), key=lambda s: s["id"])}
             for tid in parents if short in phases[tid]),
            key=lambda e: e["name"].lower())
        result.append({"tactic": _get(t, "name"), "shortname": short, "techniques": techniques})
    _cache.clear()
    _cache[key] = result
    return result


def technique_index(bundle) -> Dict[str, Dict]:
    """{technique ID: {name, tactics}} for every current technique and sub-technique, with
    tactics as display names in matrix order. What a detection's mapping defaults to."""
    if bundle is None:
        return {}
    key = id(bundle)
    if key in _index_cache:
        return _index_cache[key]
    names = {c["shortname"]: c["tactic"] for c in matrix(bundle)}
    order = list(names)
    index = {}
    for o in _get(bundle, "objects", []) or []:
        if (_get(o, "type") != "attack-pattern" or _get(o, "revoked") or _get(o, "x_mitre_deprecated")):
            continue
        tid = _attack_id(o)
        if not tid:
            continue
        phases = [_get(p, "phase_name") for p in _get(o, "kill_chain_phases", []) or []
                  if _get(p, "kill_chain_name") == "mitre-attack"]
        tactics = [names[s] for s in sorted(set(phases) & set(order), key=order.index)]
        if tactics:
            index[tid] = {"name": _get(o, "name", tid), "tactics": tactics}
    _index_cache.clear()
    _index_cache[key] = index
    return index


# ── Your detections, for the matrix's "My detections" layer ──────────────────
# Placed by the mapping in force (archer.build.attack_mapping), so a technique moved to
# another tactic by hand shows there. Read with regexes, not a YAML parse: it runs over
# every detection on each Coverage load.

_VENDORS = (("GoogleSecOps", "Google SecOps"), ("MicrosoftThreatProtection", "MDE"),
            ("Splunk", "Splunk"), ("Elastic", "Elastic"))
_TID = re.compile(r"^technique_id: *(\S+)", re.M)
_TACTICS = re.compile(r"^tactics:\n((?:  - .*\n?)+)", re.M)
_CONNECTOR = re.compile(r"connectorId: *(\S+)")
_detections_cache: Dict[str, object] = {}


def _detection_stamp(directory: str):
    entries = [e for e in os.scandir(directory) if e.name.endswith(".yaml")] if os.path.isdir(directory) else []
    return directory, len(entries), max((e.stat().st_mtime for e in entries), default=0)


def detection_files_for(directory: str, technique_id: str) -> List[str]:
    """Detection files mapped to technique_id."""
    pattern = re.compile(rf"^technique_id: *{re.escape(technique_id)}\s*$", re.M)
    out = []
    for entry in sorted(os.scandir(directory), key=lambda e: e.name) if os.path.isdir(directory) else []:
        if entry.name.endswith(".yaml"):
            try:
                with open(entry.path, encoding="utf-8") as fh:
                    if pattern.search(fh.read()):
                        out.append(entry.name)
            except OSError:
                pass
    return out


def detections_by_tactic(directory: str) -> Dict[str, Dict[str, Dict]]:
    """{tactic: {technique ID: {count, vendors, changed}}} over every detection file."""
    stamp = _detection_stamp(directory)
    if _detections_cache.get("stamp") == stamp:
        return _detections_cache["result"]
    result: Dict[str, Dict[str, Dict]] = {}
    for entry in sorted(os.scandir(directory), key=lambda e: e.name) if stamp[1] else []:
        if not entry.name.endswith(".yaml"):
            continue
        try:
            with open(entry.path, encoding="utf-8") as fh:
                text = fh.read()
        except OSError:
            continue
        tid, tactics = _TID.search(text), _TACTICS.search(text)
        if not tid or not tactics:
            continue
        connector = (_CONNECTOR.search(text) or [None, ""])[1]
        vendor = next((name for key, name in _VENDORS if key.lower() in connector.lower()), None)
        changed = bool(re.search(r"^attack_override:", text, re.M))
        for tactic in [t[4:].strip() for t in tactics.group(1).splitlines() if t.strip()]:
            stat = result.setdefault(tactic, {}).setdefault(tid.group(1), {"count": 0, "vendors": [], "changed": False})
            stat["count"] += 1
            stat["changed"] = stat["changed"] or changed
            if vendor and vendor not in stat["vendors"]:
                stat["vendors"].append(vendor)
    _detections_cache.update(stamp=stamp, result=result)
    return result


_legacy_cache: Dict[int, Dict[str, Dict]] = {}


def legacy(bundle) -> Dict[str, Dict]:
    """{technique ID: {name, status, by, by_name, by_tactics}} for every technique ATT&CK
    has revoked or deprecated. status is "revoked" or "deprecated"; by is the replacement
    ATT&CK names (revoked-by), or "" when it names none (deprecated techniques never do).
    Detections can outlive the ATT&CK version they were built from."""
    if bundle is None:
        return {}
    key = id(bundle)
    if key in _legacy_cache:
        return _legacy_cache[key]
    objects = list(_get(bundle, "objects", []) or [])
    ids = {_get(o, "id"): _attack_id(o) for o in objects if _get(o, "type") == "attack-pattern"}
    by = {_get(r, "source_ref"): ids.get(_get(r, "target_ref"), "") for r in objects
          if _get(r, "type") == "relationship" and _get(r, "relationship_type") == "revoked-by"}
    index = technique_index(bundle)
    result = {}
    for o in objects:
        tid = ids.get(_get(o, "id")) if _get(o, "type") == "attack-pattern" else None
        if not tid or tid in index or not (_get(o, "revoked") or _get(o, "x_mitre_deprecated")):
            continue
        new = by.get(_get(o, "id"), "")
        new = new if new in index else ""
        result[tid] = {"name": _get(o, "name", ""), "status": "revoked" if _get(o, "revoked") else "deprecated",
                       "by": new, "by_name": index.get(new, {}).get("name", ""),
                       "by_tactics": index.get(new, {}).get("tactics", [])}
    _legacy_cache.clear()
    _legacy_cache[key] = result
    return result
