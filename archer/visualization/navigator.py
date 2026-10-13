"""
The ATT&CK Enterprise matrix, for the Coverage page's Navigator-style view: every tactic
in the matrix's own order, each with every technique ATT&CK files under it and their
sub-techniques. Built from the STIX bundle Archer loads at startup, so it follows
ATT&CK's own changes (v18 split Defense Evasion into Stealth and Defense Impairment).
Revoked and deprecated techniques are left out. No coverage here: the page colours
each cell from the reference coverage map (archer.build.references).
"""

from typing import Dict, List

_cache: Dict[int, List[Dict]] = {}


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
