"""
Import a MISP event as an Analyse input (#19).

MISP event JSON (the standard export: {"Event": {...}} or a bare event) → the blog_analyzer
extraction shape. Attributes map to IOCs by type, MITRE galaxies/tags to ATT&CK techniques, and
a threat-actor galaxy or the event tags to the group name. Parsed directly from the JSON — no
pymisp dependency. No AI.
"""

import json
import re
from collections import defaultdict
from typing import Dict, List, Union
from urllib.parse import urlparse

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


def _attribute(iocs: Dict[str, List[str]], attr: Dict):
    atype = str(attr.get("type", ""))
    value = str(attr.get("value", "")).strip()
    if not value:
        return
    # Composite types (filename|md5, domain|ip, regkey|value) carry two values split by | —
    # handled before the simple-kind lookup, since the composite type isn't in _ATTR_KIND.
    if "|" in atype and "|" in value:
        left, right = value.split("|", 1)
        if atype == "domain|ip":
            _add(iocs, "domain", left), _add(iocs, "ip", right)
        elif atype.startswith("filename|"):
            _add(iocs, "file", left), _add(iocs, "hash", right)
        elif atype == "regkey|value":
            _add(iocs, "reg", left)
        return
    kind = _ATTR_KIND.get(atype)
    if not kind:
        return
    _add(iocs, kind, _host(value) if kind == "domain" and ("://" in value) else value)


def _techniques_from_tags(tags: List, out: List[str]):
    for tag in tags or []:
        name = tag.get("name", "") if isinstance(tag, dict) else str(tag)
        if "mitre" in name.lower() or "attack-pattern" in name.lower():
            for tid in _TID.findall(name):
                if tid not in out:
                    out.append(tid)


def parse_misp_event(data: Union[str, bytes, dict]) -> Dict:
    """A MISP event (JSON) → the blog_analyzer extraction shape."""
    if isinstance(data, (str, bytes)):
        data = json.loads(data)
    event = data.get("Event", data) if isinstance(data, dict) else {}
    if not isinstance(event, dict):
        return {"success": False, "error": "Not a MISP event"}

    iocs: Dict[str, List[str]] = defaultdict(list)
    techniques: List[str] = []
    group_name = ""

    # Attributes (top level and inside objects)
    for attr in event.get("Attribute", []) or []:
        _attribute(iocs, attr)
    for obj in event.get("Object", []) or []:
        for attr in obj.get("Attribute", []) or []:
            _attribute(iocs, attr)

    # Techniques and threat actor from galaxies and tags
    _techniques_from_tags(event.get("Tag"), techniques)
    for galaxy in event.get("Galaxy", []) or []:
        gtype = str(galaxy.get("type", ""))
        for cluster in galaxy.get("GalaxyCluster", []) or []:
            value = str(cluster.get("value", ""))
            if "mitre-attack-pattern" in gtype or "attack-pattern" in gtype:
                for tid in _TID.findall(value + " " + json.dumps(cluster.get("meta", {}))):
                    if tid not in techniques:
                        techniques.append(tid)
            elif "threat-actor" in gtype or "intrusion-set" in gtype:
                group_name = group_name or value.split(" - ")[0]

    info = str(event.get("info", ""))
    return {
        "success": True,
        "group_name": group_name,
        "group_desc": info[:500],
        "title": info or group_name,
        "techniques": sorted(set(techniques)),
        "tactics": [],
        "procedures": [],
        "iocs": {k: v for k, v in iocs.items() if v},
        "ioc_mentions": {},
        "source": "misp",
    }
