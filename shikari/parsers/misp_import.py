"""
Import a MISP event as an Analyse input (#19).

MISP event JSON (the standard export: {"Event": {...}} or a bare event) → the blog_analyzer
extraction shape. The event is read by `samarkand.misp.parse`, the suite's shared reader (plain
JSON, no pymisp); this module maps its attributes to Shikari's IOC kinds by type, MITRE galaxies and
tags to ATT&CK techniques, and a threat-actor galaxy to the group name. No AI.
"""

import json
import re
from collections import defaultdict
from typing import Dict, List, Union
from urllib.parse import urlparse

from samarkand import misp

_TID = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")

# MISP attribute type → Shikari IOC kind (cmd, reg, evt, sw, ip, domain, hash, file)
_ATTR_KIND = {
    "ip-src": "ip", "ip-dst": "ip", "ip": "ip",
    "domain": "domain", "hostname": "domain", "domain|ip": "domain",
    "url": "domain", "uri": "domain", "link": "domain",
    "md5": "hash", "sha1": "hash", "sha256": "hash", "sha512": "hash",
    "imphash": "hash", "authentihash": "hash", "ssdeep": "hash",
    "filename": "file", "filepath": "file",
    "regkey": "reg", "regkey|value": "reg",
    "windows-service-name": "sw", "windows-service-displayname": "sw", "mutex": "sw",
    "command": "cmd", "windows-scheduled-task": "cmd",
}


def _host(value: str) -> str:
    if "://" in value:
        return (urlparse(value).netloc or value).split("@")[-1].split(":")[0]
    return value


def _add(iocs, kind, value):
    value = (value or "").strip()
    if value and value not in iocs[kind]:
        iocs[kind].append(value)


def _attribute(iocs: Dict[str, List[str]], attr: misp.ParsedAttribute):
    # Composite types (filename|md5, domain|ip, regkey|value) carry both halves in `parts`
    if attr.composite:
        left, right = attr.parts
        if attr.type == "domain|ip":
            _add(iocs, "domain", left.value), _add(iocs, "ip", right.value)
        elif attr.type.startswith("filename|"):
            _add(iocs, "file", left.value), _add(iocs, "hash", right.value)
        elif attr.type == "regkey|value":
            _add(iocs, "reg", left.value)
        return
    kind = _ATTR_KIND.get(attr.type)
    if kind:
        _add(iocs, kind, _host(attr.value) if kind == "domain" and "://" in attr.value else attr.value)


def parse_misp_event(data: Union[str, bytes, dict]) -> Dict:
    """A MISP event (JSON) → the blog_analyzer extraction shape."""
    try:
        event = misp.parse(data)
    except misp.NotAnEvent:
        return {"success": False, "error": "Not a MISP event"}

    iocs: Dict[str, List[str]] = defaultdict(list)
    for attr in event.attributes:  # top level, then inside objects
        _attribute(iocs, attr)
    # Techniques from any tag naming mitre or attack-pattern, and from attack-pattern galaxies
    techniques = [tid for tag in event.tags if "mitre" in tag.lower() or "attack-pattern" in tag.lower()
                  for tid in _TID.findall(tag)]
    techniques += [tid for cluster in event.attack_patterns
                   for tid in _TID.findall(cluster.value + " " + json.dumps(cluster.meta))]
    group_name = event.threat_actors[0].split(" - ")[0] if event.threat_actors else ""

    return {
        "success": True,
        "group_name": group_name,
        "group_desc": event.info[:500],
        "title": event.info or group_name,
        "techniques": sorted(set(techniques)),
        "tactics": [],
        "procedures": [],
        "iocs": {k: v for k, v in iocs.items() if v},
        "ioc_mentions": {},
        "source": "misp",
    }
