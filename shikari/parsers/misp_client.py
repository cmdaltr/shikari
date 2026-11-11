"""
Pull events from a MISP instance (#19).

A minimal MISP client over requests — no pymisp dependency. Queries the instance's
``/events/restSearch`` with the operator's API key, reads the answer with ``samarkand.misp.events_of``
(the suite's shared reader), then hands each event to the MISP importer and merges the techniques
and IOCs, so a live MISP instance can be used as an Analyse input the same way
a TAXII collection can. The API key is used for this request only; nothing is stored. No AI.
"""

from collections import defaultdict
from typing import Dict, List
from urllib.parse import urlparse

import requests
from samarkand import misp

from shikari.parsers.misp_import import parse_misp_event


def import_events(base_url: str, api_key: str, *, last: str = "30d", limit: int = 200,
                  verify_tls: bool = True, timeout: int = 60) -> Dict:
    """Fetch recent events from a MISP instance and merge them into the extraction shape.

    base_url is the instance root (https://misp.example); /events/restSearch is appended. last limits
    to recently-published events (MISP duration syntax, e.g. 30d, 90d)."""
    root = base_url.strip().rstrip("/")
    if not root:
        return {"success": False, "error": "No MISP URL given"}
    url = root + "/events/restSearch"
    headers = {"Authorization": api_key.strip(), "Accept": "application/json",
               "Content-Type": "application/json", "User-Agent": "Shikari (MISP client)"}
    query = {"returnFormat": "json", "limit": limit, "page": 1}
    if last:
        query["last"] = last

    r = requests.post(url, json=query, headers=headers, timeout=timeout, verify=verify_tls)
    r.raise_for_status()
    events = misp.events_of(r.json())  # {"response": [...]} on current MISP, a bare list on older

    iocs: Dict[str, List[str]] = defaultdict(list)
    techniques: List[str] = []
    group_name = ""
    parsed = 0
    for wrapped in events:
        ev = wrapped.get("Event", wrapped)
        res = parse_misp_event({"Event": ev})
        if not res.get("success"):
            continue
        parsed += 1
        for tid in res.get("techniques", []):
            if tid not in techniques:
                techniques.append(tid)
        for kind, values in (res.get("iocs") or {}).items():
            for v in values:
                if v not in iocs[kind]:
                    iocs[kind].append(v)
        group_name = group_name or res.get("group_name", "")

    host = urlparse(root).netloc or root
    return {
        "success": True,
        "group_name": group_name,
        "group_desc": f"Imported from MISP instance {host}",
        "title": f"MISP: {parsed} event{'' if parsed == 1 else 's'} from {host}",
        "techniques": sorted(set(techniques)),
        "tactics": [],
        "procedures": [],
        "iocs": {k: v for k, v in iocs.items() if v},
        "ioc_mentions": {},
        "source": "misp-instance",
        "event_count": parsed,
    }
