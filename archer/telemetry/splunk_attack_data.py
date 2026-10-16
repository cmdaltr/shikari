"""
Splunk attack_data (Apache-2.0): datasets recorded running Atomic Red Team and other tools in
Splunk's Attack Range, under datasets/attack_techniques/<technique>/<name>/. Each dataset's
.yml names its techniques and log files (Git LFS). Logs are read up to CAP bytes each: the
median is 10 KB, but a few captures run to hundreds of MB of background. See
archer.telemetry.datasets.
"""

import os
import re
from collections import Counter
from typing import Dict, Iterable, Optional, Tuple

import yaml

from archer.telemetry import fetch
from archer.telemetry.datasets import PARSER_VERSION, parse, summarise, unpack

NAME = "splunk"
REPO = "splunk/attack_data"
CAP = 3 * 1024 * 1024
INFO = {"name": "Splunk attack_data", "url": f"https://github.com/{REPO}", "licence": "Apache-2.0",
        "note": "Maintained; Atomic Red Team and tool runs in Splunk's Attack Range. Each log read up to 3 MB"}
_TID = re.compile(r"^T\d{4}(\.\d{3})?$")


def datasets(previous: Dict[str, Dict], log=print) -> Iterable[Tuple[Dict, Optional[Dict], str]]:
    tree = fetch.tree(REPO)
    blobs = {t["path"]: t["sha"] for t in tree if t["type"] == "blob"}
    ymls = sorted(p for p in blobs if p.startswith("datasets/attack_techniques/") and p.endswith((".yml", ".yaml")))
    log(f"Splunk attack_data: {len(ymls)} datasets")
    per_folder = Counter(os.path.dirname(p) for p in ymls)

    def one(path):
        meta = yaml.safe_load(fetch.raw(REPO, path)) or {}
        folder = os.path.dirname(path)
        logs = []
        for d in meta.get("datasets") or []:
            p = str(d.get("path") or "").lstrip("/")
            if p and p in blobs:
                logs.append((p, str(d.get("source") or "")))
        if not logs:  # older .yml files list nothing: take the folder's logs
            logs = [(p, "") for p in blobs if os.path.dirname(p) == folder and not p.endswith((".yml", ".yaml", ".md"))]
        key = f"{PARSER_VERSION}:{blobs[path]}:" + ",".join(blobs[p] for p, _ in logs)
        did = f"splunk:{folder.split('attack_techniques/', 1)[1]}"
        if per_folder[folder] > 1:  # two datasets in one folder (T1499/splunk)
            did += "/" + os.path.splitext(os.path.basename(path))[0]
        if previous.get(did, {}).get("key") == key:
            return previous[did]["summary"], None, key
        events = []
        for p, source in logs:
            default = source.split(":", 1)[1] if ":" in source else ""
            try:
                for f in unpack(fetch.lfs(REPO, p, CAP)):
                    events.extend(parse(f, default))
            except Exception as e:
                log(f"  {did}: {os.path.basename(p)}: {e}")
        counts, values = summarise(events)
        techniques = sorted({str(t).strip() for t in meta.get("mitre_technique") or [] if _TID.match(str(t).strip())})
        if not techniques:
            first = folder.split("attack_techniques/", 1)[1].split("/")[0]
            techniques = [first] if _TID.match(first) else []
        return {"id": did, "source": NAME, "title": f"{folder.split('/')[-1]} ({', '.join(techniques)})",
                "techniques": techniques, "platform": [], "tools": [folder.split("/")[-1]],
                "description": str(meta.get("description") or "")[:500], "events": counts,
                "date": str(meta.get("date") or ""), "url": f"https://github.com/{REPO}/tree/master/{folder}"}, values, key

    yield from fetch.pool(one, ymls, log)
