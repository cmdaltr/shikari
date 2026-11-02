"""
Import a STIX 2.1 bundle as an Analyse input (#19).

attack-pattern objects → ATT&CK technique IDs, indicator patterns and cyber-observables → IOCs,
intrusion-set / threat-actor → the group name, report → the title. The result is the same
extraction shape blog_analyzer produces, so it flows through the existing generation pipeline.

Parsed from the raw JSON rather than through python-stix2's strict loader: MISP- and vendor-
exported bundles carry custom properties and objects that the strict loader rejects. No AI.
"""

import json
import re
from collections import defaultdict
from typing import Dict, List, Optional, Union
from urllib.parse import urlparse

_TID = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")
# objtype(:path)? = 'value'  — the comparisons inside a STIX pattern
_PATTERN_CMP = re.compile(r"([a-z0-9][a-z0-9-]*)(?::([^\s=<>!]+))?\s*(?:=|LIKE|MATCHES)\s*'([^']*)'", re.IGNORECASE)

# IOC kinds Shikari uses: cmd, reg, evt, sw, ip, domain, hash, file
_OBS_KIND = {
    "ipv4-addr": "ip", "ipv6-addr": "ip",
    "domain-name": "domain", "url": "domain",
    "windows-registry-key": "reg",
    "process": "cmd",
    "software": "sw",
}


def _host(value: str) -> str:
    """A URL's host, or the value unchanged when it's already a bare domain/IP."""
    if "://" in value:
        netloc = urlparse(value).netloc or value
        return netloc.split("@")[-1].split(":")[0]
    return value


def _add(iocs: Dict[str, List[str]], kind: str, value: str):
    value = (value or "").strip()
    if value and value not in iocs[kind]:
        iocs[kind].append(value)


def _ioc_from_observable(iocs: Dict[str, List[str]], obj: Dict):
    """A STIX cyber-observable (SCO) object → an IOC."""
    t = obj.get("type")
    if t in ("ipv4-addr", "ipv6-addr") and obj.get("value"):
        _add(iocs, "ip", obj["value"])
    elif t == "domain-name" and obj.get("value"):
        _add(iocs, "domain", obj["value"])
    elif t == "url" and obj.get("value"):
        _add(iocs, "domain", _host(obj["value"]))
    elif t == "file":
        for h in (obj.get("hashes") or {}).values():
            _add(iocs, "hash", h)
        if obj.get("name"):
            _add(iocs, "file", obj["name"])
    elif t == "process" and obj.get("command_line"):
        _add(iocs, "cmd", obj["command_line"])
    elif t == "windows-registry-key" and obj.get("key"):
        _add(iocs, "reg", obj["key"])


def _ioc_from_pattern(iocs: Dict[str, List[str]], pattern: str):
    """A STIX indicator pattern string → IOCs, by the observable type each comparison names."""
    for objtype, path, value in _PATTERN_CMP.findall(pattern or ""):
        objtype = objtype.lower()
        value = value.strip()
        if not value:
            continue
        if objtype in ("ipv4-addr", "ipv6-addr"):
            _add(iocs, "ip", value)
        elif objtype == "domain-name":
            _add(iocs, "domain", value)
        elif objtype == "url":
            _add(iocs, "domain", _host(value))
        elif objtype == "file":
            _add(iocs, "hash" if "hashes" in (path or "").lower() else "file", value)
        elif objtype == "process":
            _add(iocs, "cmd" if "command_line" in (path or "") else "sw", value)
        elif objtype == "windows-registry-key":
            _add(iocs, "reg", value)
        elif objtype in ("software",):
            _add(iocs, "sw", value)


def _techniques_from_attack_pattern(obj: Dict) -> List[str]:
    out = []
    for ref in obj.get("external_references") or []:
        if str(ref.get("source_name", "")).lower() in ("mitre-attack", "mitre attack"):
            ext = str(ref.get("external_id") or "")
            if _TID.fullmatch(ext):
                out.append(ext)
    # Fall back to a T-code in the name/description
    if not out:
        out += _TID.findall(obj.get("name", "") + " " + (obj.get("description") or ""))
    return out


def parse_stix_bundle(data: Union[str, bytes, dict]) -> Dict:
    """A STIX 2.1 bundle (or a bare list of objects) → the blog_analyzer extraction shape."""
    if isinstance(data, (str, bytes)):
        data = json.loads(data)
    objects = data.get("objects") if isinstance(data, dict) else data
    if not isinstance(objects, list):
        return {"success": False, "error": "Not a STIX bundle (no 'objects' list)"}

    iocs: Dict[str, List[str]] = defaultdict(list)
    techniques: List[str] = []
    group_name = ""
    title = ""
    description = ""

    for obj in objects:
        if not isinstance(obj, dict):
            continue
        t = obj.get("type")
        if t == "attack-pattern":
            for tid in _techniques_from_attack_pattern(obj):
                if tid not in techniques:
                    techniques.append(tid)
        elif t == "indicator":
            _ioc_from_pattern(iocs, obj.get("pattern", ""))
            # An indicator may also reference a technique in a kill_chain or name
            for tid in _TID.findall(obj.get("name", "")):
                if tid not in techniques:
                    techniques.append(tid)
        elif t in ("intrusion-set", "threat-actor"):
            group_name = group_name or obj.get("name", "")
            description = description or (obj.get("description") or "")
        elif t == "report":
            title = title or obj.get("name", "")
            description = description or (obj.get("description") or "")
        elif t in _OBS_KIND or t == "file":
            _ioc_from_observable(iocs, obj)

    return {
        "success": True,
        "group_name": group_name,
        "group_desc": description[:500],
        "title": title or group_name,
        "techniques": sorted(set(techniques)),
        "tactics": [],
        "procedures": [],
        "iocs": {k: v for k, v in iocs.items() if v},
        "ioc_mentions": {},
        "source": "stix",
    }
