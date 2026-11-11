"""
Import a STIX 2.1 bundle as an Analyse input (#19).

attack-pattern objects → ATT&CK technique IDs, indicator patterns and cyber-observables → IOCs,
intrusion-set / threat-actor → the group name, report → the title. The result is the same
extraction shape blog_analyzer produces, so it flows through the existing generation pipeline.

The bundle is read by `samarkand.stix.parse`, the suite's shared reader (raw JSON, not python-stix2's
strict loader, so MISP- and vendor-exported bundles with custom properties import cleanly); this
module maps its neutral indicators to Shikari's IOC kinds. Escaped quotes and backslashes in pattern
strings are undone (`'it\\'s.exe'` reads as it's.exe), and of two objects with one id (a newer
version) only the last is read. No AI.
"""

from collections import defaultdict
from typing import Dict, List, Optional, Tuple, Union
from urllib.parse import urlparse

from samarkand import stix


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


def _kind(item: stix.Indicator) -> Optional[Tuple[str, str]]:
    """A value read from a bundle → (Shikari IOC kind, value), or None for one Shikari doesn't use.
    IOC kinds: cmd, reg, evt, sw, ip, domain, hash, file."""
    t, path = item.stix_type, item.stix_path
    if t in ("ipv4-addr", "ipv6-addr"):
        return "ip", item.value
    if t == "domain-name":
        return "domain", item.value
    if t == "url":
        return "domain", _host(item.value)
    if t == "windows-registry-key":
        return "reg", item.value
    if item.object_type == "indicator":
        # A pattern comparison, by the observable type and property it names
        if t == "file":
            return ("hash" if "hashes" in path.lower() else "file"), item.value
        if t == "process":
            return ("cmd" if "command_line" in path else "sw"), item.value
        if t == "software":
            return "sw", item.value
        return None
    # A cyber-observable object
    if t == "file":
        return ("hash" if path.startswith("hashes") else "file"), item.value
    if t == "process":
        return "cmd", item.value
    return None


def parse_stix_bundle(data: Union[str, bytes, dict, list]) -> Dict:
    """A STIX 2.1 bundle (or a bare list of objects) → the blog_analyzer extraction shape."""
    try:
        parsed = stix.parse(data)
    except stix.NotABundle as exc:
        return {"success": False, "error": str(exc)}

    iocs: Dict[str, List[str]] = defaultdict(list)
    for item in parsed.indicators:
        mapped = _kind(item)
        if mapped:
            _add(iocs, *mapped)
    # Every attack-pattern in the bundle, and any T-number an indicator's name gives
    techniques = [tid for t in parsed.techniques for tid in t.ids]
    techniques += [tid for item in parsed.indicators if item.object_type == "indicator"
                   for tid in item.named_techniques]
    described = sorted([*parsed.groups, *parsed.reports], key=lambda o: o.position)
    group_name = parsed.groups[0].name if parsed.groups else ""
    title = parsed.reports[0].name if parsed.reports else ""
    description = next((o.description for o in described if o.description), "")

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
