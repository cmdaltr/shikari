"""
EVTX-to-MITRE-Attack (Michel de Crevoisier; CC0): Windows event log samples of attacks, each
.evtx filed under its tactic and technique (TA0006-Credential Access/T1003-Credential dumping/
ID4662-DCsync attack using Mimikatz.evtx). Mostly Security auditing, with Sysmon, PowerShell,
Defender and SQL Server where the attack shows there. See shikari.telemetry.datasets.
"""

import os
import re
from typing import Dict, Iterable, Optional, Tuple

from shikari.telemetry import fetch
from shikari.telemetry.datasets import PARSER_VERSION, parse, summarise

NAME = "evtx"
REPO = "mdecrevoisier/EVTX-to-MITRE-Attack"
INFO = {"name": "EVTX-to-MITRE-Attack", "url": f"https://github.com/{REPO}", "licence": "CC0-1.0",
        "note": "Maintained; Windows event log samples of attacks, mostly Security auditing, one file each"}
_TID = re.compile(r"^(T\d{4})(\.\d{3})?")


def technique(path: str) -> str:
    """T1003 from ".../T1003-Credential dumping/...", T1098 from "T1098.xxx-...": the folder's technique."""
    for part in path.split("/")[:-1]:
        m = _TID.match(part)
        if m:
            return m.group(1) + (m.group(2) or "")
    return ""


def datasets(previous: Dict[str, Dict], log=print) -> Iterable[Tuple[Dict, Optional[Dict], str]]:
    tree = fetch.tree(REPO)
    files = {t["path"]: t["sha"] for t in tree if t["type"] == "blob" and t["path"].lower().endswith(".evtx")
             and technique(t["path"])}
    log(f"EVTX-to-MITRE-Attack: {len(files)} samples")

    def one(path):
        key = f"{PARSER_VERSION}:{files[path]}"
        did = f"evtx:{path[:-5]}"
        if previous.get(did, {}).get("key") == key:
            return previous[did]["summary"], None, key
        counts, values = summarise(parse(fetch.raw(REPO, path)))
        tid = technique(path)
        title = re.sub(r"^ID\s*[\d,\-x ]+\s*-?\s*", "", os.path.basename(path)[:-5]).strip() or os.path.basename(path)
        return {"id": did, "source": NAME, "title": f"{title} ({tid})", "techniques": [tid], "platform": ["windows"],
                "tools": [], "description": "", "events": counts,
                "url": f"https://github.com/{REPO}/blob/master/{path}"}, values, key

    yield from fetch.pool(one, sorted(files), log)
