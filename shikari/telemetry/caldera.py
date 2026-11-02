"""
CALDERA operations (#30) as recordings: the command lines each step actually ran, collected by
shikari.lab.caldera.collect into

    data/telemetry/caldera/<operation>/manifest.json

One dataset per technique per operation, whose CommandLine values are those commands, so
shikari.telemetry.check matches detections against them like any other recording. It holds no
logs: what a SIEM recorded of the same run is still a SIEM's question. The manifests carry your
hosts' names and the steps' output, so this source is local (INFO["local"]) and never committed.
"""

import hashlib
import json
import os
from collections import defaultdict
from typing import Dict, Iterable, Optional, Tuple

from shikari.telemetry.datasets import PARSER_VERSION, summarise
from shikari import paths

NAME = "caldera"
CALDERA_DIR = str(paths.DATA / "telemetry" / "caldera")
EVENT = "CALDERA command"
INFO = {"name": "CALDERA", "url": "https://caldera.mitre.org", "licence": "Yours", "local": True,
        "note": "Commands CALDERA operations ran on your agents (shikari.lab.caldera). Never committed"}
_PLATFORM = {"darwin": "macos"}


def operations() -> Iterable[Tuple[str, Dict]]:
    for name in sorted(os.listdir(CALDERA_DIR)) if os.path.isdir(CALDERA_DIR) else []:
        path = os.path.join(CALDERA_DIR, name, "manifest.json")
        try:
            with open(path, encoding="utf-8") as fh:
                yield name, json.load(fh), path
        except (OSError, ValueError):
            continue


def datasets(previous: Dict[str, Dict], log=print) -> Iterable[Tuple[Dict, Optional[Dict], str]]:
    found = list(operations())
    log(f"CALDERA: {len(found)} operation{'' if len(found) == 1 else 's'} in {CALDERA_DIR}")
    for name, manifest, path in found:
        stamp = hashlib.sha1(f"{os.path.getsize(path)}:{os.path.getmtime(path)}".encode()).hexdigest()
        key = f"{PARSER_VERSION}:{stamp}"
        by_tid = defaultdict(list)
        for s in manifest.get("steps") or []:
            if s.get("technique_id") and s.get("command"):
                by_tid[s["technique_id"]].append(s)
        for tid, steps in sorted(by_tid.items()):
            did = f"caldera:{name}/{tid}"
            if previous.get(did, {}).get("key") == key:
                yield previous[did]["summary"], None, key
                continue
            counts, values = summarise((EVENT, {"CommandLine": s["command"]}) for s in steps)
            platforms = sorted({_PLATFORM.get(s.get("platform"), s.get("platform")) for s in steps if s.get("platform")})
            yield {"id": did, "source": NAME, "title": f"{steps[0].get('ability') or tid} ({tid})",
                   "techniques": [tid], "platform": platforms, "tools": ["CALDERA"],
                   "description": f"{name}: {len(steps)} step(s) on {', '.join(sorted({s.get('host') or s.get('paw') or '?' for s in steps}))}",
                   "events": counts, "date": str(steps[0].get("finish") or manifest.get("start") or "")[:10],
                   "url": ""}, values, key
