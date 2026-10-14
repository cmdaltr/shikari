"""
What changed in ATT&CK since the procedures CSV was built, and which groups that touches.

ATT&CK's minor releases now carry content (v19.2 added groups and software), and most of
what a release touches is a patch: a new `modified` stamp or spec version, nothing the
CSV shows. So each object is fingerprinted on the fields the CSV is built from, and only
groups whose procedures could differ are collected again:

  - the group itself (name, description, aliases) changed, arrived or went
  - a "uses" / "attributed-to" relationship on any of its paths changed: its own
    techniques, its campaigns' and its software's
  - one of its campaigns or software changed (the name labels the procedure)
  - one of its techniques changed (name, description, tactics, platforms, data sources)

The index this compares against is saved beside the CSV after every build
(mitre_procedures.meta.json). Revoked and deprecated objects count as gone.
"""
from __future__ import annotations

import hashlib
import json
from typing import Dict, Iterable, List, Optional, Set, Tuple

# The fields the CSV is built from, per object type; anything else is a patch
_FIELDS = {
    "intrusion-set": ("name", "description", "aliases"),
    "attack-pattern": ("name", "description", "kill_chain_phases", "x_mitre_platforms",
                       "x_mitre_data_sources", "x_mitre_detection", "x_mitre_is_subtechnique"),
    "malware": ("name",),
    "tool": ("name",),
    "campaign": ("name",),
    "relationship": ("relationship_type", "source_ref", "target_ref", "description"),
}
_RELATIONSHIPS = ("uses", "attributed-to")
_SOFTWARE = ("malware", "tool")

# index: STIX id -> [type, ATT&CK id, fingerprint, source_ref, target_ref, retired]
Index = Dict[str, list]


def _attack_id(obj: dict) -> str:
    for ref in obj.get("external_references", []) or []:
        if ref.get("source_name") == "mitre-attack" and ref.get("external_id"):
            return ref["external_id"]
    return ""


def build_index(objects: Iterable[dict]) -> Index:
    """Fingerprint every object the procedures CSV draws on."""
    index: Index = {}
    for o in objects:
        t = o.get("type", "")
        if t not in _FIELDS or (t == "relationship" and o.get("relationship_type") not in _RELATIONSHIPS):
            continue
        retired = bool(o.get("revoked") or o.get("x_mitre_deprecated"))
        body = json.dumps([o.get(f) for f in _FIELDS[t]] + [retired], sort_keys=True, default=str)
        fp = hashlib.sha1(body.encode("utf-8")).hexdigest()[:16]
        index[o["id"]] = [t, _attack_id(o), fp, o.get("source_ref", ""), o.get("target_ref", ""), retired]
    return index


class _Graph:
    """Who reaches what in one index: groups by ATT&CK ID, everything else by STIX id."""

    def __init__(self, index: Index):
        live = {k: v for k, v in index.items() if not v[5]}
        self.groups = {k: v[1] for k, v in live.items() if v[0] == "intrusion-set" and v[1].startswith("G")}
        self.campaign_groups: Dict[str, Set[str]] = {}
        self.software_groups: Dict[str, Set[str]] = {}
        uses: List[Tuple[str, str]] = []
        for v in live.values():
            if v[0] != "relationship":
                continue
            src, tgt = v[3], v[4]
            if src in live and tgt in live and live[src][0] == "campaign" and tgt in self.groups:
                self.campaign_groups.setdefault(src, set()).add(self.groups[tgt])
            elif src in self.groups and tgt in live and live[tgt][0] in _SOFTWARE:
                self.software_groups.setdefault(tgt, set()).add(self.groups[src])
            elif tgt in live and live[tgt][0] == "attack-pattern":
                uses.append((src, tgt))
        self.technique_groups: Dict[str, Set[str]] = {}
        for src, tech in uses:
            self.technique_groups.setdefault(tech, set()).update(self.groups_of(src))

    def groups_of(self, stix_id: str) -> Set[str]:
        """The groups an object belongs to: a group itself, or a campaign's or software's groups."""
        if stix_id in self.groups:
            return {self.groups[stix_id]}
        return self.campaign_groups.get(stix_id, set()) | self.software_groups.get(stix_id, set())


def groups_in(index: Index) -> List[str]:
    """The current groups' ATT&CK IDs."""
    return list(_Graph(index).groups.values())


def plan(old: Optional[Index], new: Index,
         csv_links: Optional[Dict[str, Set[str]]] = None) -> Optional[Dict[str, List[str]]]:
    """Groups to collect again (run) and groups whose rows go (drop), or None when there's
    nothing to compare with and it has to be a full collection. csv_links (group -> its
    techniques in the current CSV) catches links the old index alone wouldn't."""
    if not old:
        return None
    before, after = _Graph(old), _Graph(new)
    csv_links = csv_links or {}
    by_technique: Dict[str, Set[str]] = {}
    attack_ids = {v[1]: k for k, v in list(old.items()) + list(new.items()) if v[0] == "attack-pattern" and v[1]}
    for group, techniques in csv_links.items():
        for tid in techniques:
            if tid in attack_ids:
                by_technique.setdefault(attack_ids[tid], set()).add(group)

    affected: Set[str] = set()
    for stix_id in set(old) | set(new):
        o, n = old.get(stix_id), new.get(stix_id)
        if o and n and o[2] == n[2]:
            continue
        kind = (n or o)[0]
        if kind == "intrusion-set":
            affected |= {e[1] for e in (o, n) if e and e[1].startswith("G")}
        elif kind == "relationship":
            for e in (o, n):
                if e:
                    for end in (e[3], e[4]):
                        affected |= before.groups_of(end) | after.groups_of(end)
        elif kind == "attack-pattern":
            affected |= (before.technique_groups.get(stix_id, set()) | after.technique_groups.get(stix_id, set())
                         | by_technique.get(stix_id, set()))
        else:  # campaign or software
            affected |= before.groups_of(stix_id) | after.groups_of(stix_id)

    live = set(after.groups.values())
    gone = (affected | set(before.groups.values()) | set(csv_links)) - live
    return {"run": sorted(affected & live), "drop": sorted(gone)}
