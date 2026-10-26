"""
Export a run as a STIX 2.1 bundle (#19).

A run becomes: an identity (Archer), an intrusion-set for the group, an attack-pattern per
technique (with its ATT&CK external reference), the detections as x-archer-detection custom
objects carrying the SIEM and query, and indicators built from each detection's IOCs — tied
together with relationships. No AI.
"""

from typing import Dict, List, Optional

import stix2
from stix2 import v21
from stix2.properties import ListProperty, ReferenceProperty, StringProperty

ARCHER_IDENTITY_NAME = "Archer"
_ATTACK_URL = "https://attack.mitre.org/techniques/"

# IOC kind → the STIX observable path a pattern comparison uses
_PATTERN_PATH = {
    "ip": "ipv4-addr:value", "domain": "domain-name:value", "hash": "file:hashes.'SHA-256'",
    "file": "file:name", "cmd": "process:command_line", "reg": "windows-registry-key:key",
    "sw": "process:name",
}


@stix2.CustomObject("x-archer-detection", [
    ("name", StringProperty(required=True)),
    ("siem", StringProperty()),
    ("query", StringProperty()),
    ("technique_id", StringProperty()),
    ("created_by_ref", ReferenceProperty(valid_types="identity")),
    ("object_marking_refs", ListProperty(ReferenceProperty(valid_types="marking-definition"))),
])
class ArcherDetection:
    """A generated Archer detection, carried in the bundle alongside the standard objects."""


def _escape(value: str) -> str:
    return str(value).replace("\\", "\\\\").replace("'", "\\'")


def _pattern_for(indicators: Dict[str, List[str]]) -> Optional[str]:
    """A STIX 2.1 pattern OR-ing a few of a detection's IOCs, or None when there are none."""
    parts = []
    for kind, path in _PATTERN_PATH.items():
        for value in (indicators.get(kind) or [])[:5]:
            value = str(value).strip()
            if value:
                parts.append(f"[{path} = '{_escape(value)}']")
    return " OR ".join(parts) if parts else None


def run_to_stix(group_name: str, detections: List[Dict], description: str = "") -> str:
    """detections: dicts with name, technique_id, query, siem, indicators. Returns the serialized
    STIX 2.1 bundle (JSON)."""
    identity = v21.Identity(name=ARCHER_IDENTITY_NAME, identity_class="system",
                            description="Archer — automated multi-SIEM detection generation")
    objects = [identity]
    created_by = identity.id

    intrusion = None
    if group_name:
        intrusion = v21.IntrusionSet(name=group_name, description=description or None, created_by_ref=created_by)
        objects.append(intrusion)

    attack_patterns: Dict[str, object] = {}
    for det in detections:
        tid = str(det.get("technique_id") or "").strip()
        if tid and tid not in attack_patterns:
            ap = v21.AttackPattern(
                name=det.get("technique_name") or tid,
                created_by_ref=created_by,
                external_references=[{"source_name": "mitre-attack", "external_id": tid,
                                      "url": f"{_ATTACK_URL}{tid.replace('.', '/')}/"}],
            )
            attack_patterns[tid] = ap
            objects.append(ap)
            if intrusion is not None:
                objects.append(v21.Relationship(relationship_type="uses", source_ref=intrusion.id,
                                                target_ref=ap.id, created_by_ref=created_by))

    for det in detections:
        tid = str(det.get("technique_id") or "").strip()
        ap = attack_patterns.get(tid)
        detection = ArcherDetection(
            name=det.get("name") or det.get("query_name") or "detection",
            siem=det.get("siem") or det.get("connector") or "",
            query=det.get("query") or "",
            technique_id=tid,
            created_by_ref=created_by,
        )
        objects.append(detection)
        if ap is not None:
            # source_ref is our custom x-archer-detection object, so allow_custom is required
            objects.append(v21.Relationship(relationship_type="detects", source_ref=detection.id,
                                            target_ref=ap.id, created_by_ref=created_by, allow_custom=True))
        pattern = _pattern_for(det.get("indicators") or {})
        if pattern:
            indicator = v21.Indicator(name=f"IOCs for {det.get('name') or tid}", pattern=pattern,
                                      pattern_type="stix", created_by_ref=created_by)
            objects.append(indicator)
            if ap is not None:
                objects.append(v21.Relationship(relationship_type="indicates", source_ref=indicator.id,
                                                target_ref=ap.id, created_by_ref=created_by))

    return stix2.Bundle(objects=objects, allow_custom=True).serialize()
