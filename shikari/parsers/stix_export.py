"""
Export a run as a STIX 2.1 bundle (#19).

A run becomes: an identity (Shikari), the TLP 2.0 marking it's shared under, an intrusion-set for the
group, an attack-pattern per technique (with its ATT&CK external reference), an indicator per IOC
with its cyber observables, the detections as x-shikari-detection custom objects carrying the SIEM
and query, and a report referencing them all, tied together with `uses`, `detects` and `indicates`
relationships. No AI.

The standard objects come from `samarkand.stix.bundle()`, the suite's shared builder: hand-written
JSON with stable ids (UUIDv5 under Shikari's own namespace, so exporting a run again gives the same
ids and a newer `modified`) and the TLP marking on every object. The intrusion-set and the
detections are Shikari's own, added to the same objects list.
"""

import json
import string
import uuid
from datetime import datetime, timezone
from typing import Dict, List, Optional

from samarkand import stix
from samarkand.stix import Kind

# Shikari's STIX namespace: never change it, or every exported id changes with it
NAMESPACE = uuid.UUID("ad90fcf4-f2c8-4490-bf60-9d46f7697c62")
SHIKARI_IDENTITY_NAME = "Shikari"
DETECTION_TYPE = "x-shikari-detection"
DEFAULT_TLP = "amber"  # as Shikari's reports: AMBER unless given

# IOC kind → samarkand's neutral kind (hashes by their length). evt has no STIX observable.
_KINDS = {
    "ip": Kind.IP_ADDRESS, "domain": Kind.DOMAIN, "file": Kind.FILE_NAME, "cmd": Kind.PROCESS_COMMAND,
    "reg": Kind.REGISTRY_KEY, "sw": Kind.PROCESS_NAME,
}
_HASHES = {32: Kind.FILE_HASH_MD5, 40: Kind.FILE_HASH_SHA1, 64: Kind.FILE_HASH_SHA256,
           128: Kind.FILE_HASH_SHA512}


def _kind(kind: str, value: str) -> Optional[Kind]:
    if kind == "hash":
        hexadecimal = all(c in string.hexdigits for c in value)
        return _HASHES.get(len(value), Kind.FILE_HASH_SHA256) if hexadecimal else Kind.FILE_HASH_SHA256
    return _KINDS.get(kind)


def run_to_stix(group_name: str, detections: List[Dict], description: str = "", *,
                tlp: str = DEFAULT_TLP, now: Optional[datetime] = None) -> str:
    """detections: dicts with name, technique_id, query, siem, indicators. Returns the serialized
    STIX 2.1 bundle (JSON), every object marked with `tlp`."""
    now = now or datetime.now(timezone.utc)
    key = group_name or "run"

    techniques: Dict[str, str] = {}
    iocs: Dict[tuple, List[str]] = {}  # (kind, value) → the techniques it indicates
    for det in detections:
        tid = str(det.get("technique_id") or "").strip()
        if tid and tid not in techniques:
            techniques[tid] = det.get("technique_name") or ""
        for ioc_kind, values in (det.get("indicators") or {}).items():
            for value in values or []:
                value = str(value).strip()
                kind = _kind(ioc_kind, value) if value else None
                if kind is None:
                    continue
                linked = iocs.setdefault((kind, value), [])
                if tid and tid not in linked:
                    linked.append(tid)

    bundle = stix.bundle(stix.Export(
        namespace=NAMESPACE, key=key, producer=SHIKARI_IDENTITY_NAME, tlp=tlp, created=now,
        name=f"Shikari run: {group_name}" if group_name else "Shikari run", description=description,
        techniques=tuple(stix.ExportTechnique(tid, name) for tid, name in techniques.items()),
        indicators=tuple(stix.ExportIndicator(key=f"{kind.value}|{value}", kind=kind, value=value,
                                              techniques=tuple(linked))
                         for (kind, value), linked in iocs.items()),
    ), now)

    objects = bundle["objects"]
    report = objects.pop()  # bundle() puts the report last; Shikari's objects go before it
    identity = objects[0]["id"]
    props = stix.common(identity, now, now, tlp)
    patterns = {o["external_references"][0]["external_id"]: o["id"]
                for o in objects if o["type"] == "attack-pattern"}

    own: List[Dict] = []
    if group_name:
        intrusion = {"type": "intrusion-set", "id": stix.object_id(NAMESPACE, "intrusion-set", key), **props,
                     "name": group_name, **({"description": description} if description else {})}
        own.append(intrusion)
        for tid, pattern in patterns.items():
            own.append(stix.relationship_object(stix.object_id(NAMESPACE, "relationship", key, "uses", tid),
                                                props, "uses", intrusion["id"], pattern))
    seen: Dict[tuple, int] = {}
    for det in detections:
        tid = str(det.get("technique_id") or "").strip()
        name = det.get("name") or det.get("query_name") or "detection"
        siem = det.get("siem") or det.get("connector") or ""
        n = seen[(name, siem, tid)] = seen.get((name, siem, tid), 0) + 1
        detection = {"type": DETECTION_TYPE,
                     "id": stix.object_id(NAMESPACE, DETECTION_TYPE, key, name, siem, tid, n), **props,
                     "name": name, "siem": siem, "query": det.get("query") or "", "technique_id": tid}
        own.append(detection)
        if tid in patterns:
            own.append(stix.relationship_object(
                stix.object_id(NAMESPACE, "relationship", key, "detects", detection["id"]),
                props, "detects", detection["id"], patterns[tid]))

    objects.extend(own)
    report["object_refs"] = report["object_refs"] + [o["id"] for o in own]
    objects.append(report)
    return json.dumps(bundle, indent=2)
