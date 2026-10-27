"""
Your own lab's recordings (#22): Atomic Red Team tests run by scripts/telemetry/record-atomics.ps1
on a test machine, each test's logs saved beside a manifest:

    data/telemetry/lab/<run>/manifest.json
    data/telemetry/lab/<run>/<technique>-<test>/events.xml      Windows event logs
                                              /audit.log       Linux auditd (ausearch --raw)
                                              /journal.log     Linux journal (syslog format)
                                              /es.ndjson       macOS Endpoint Security (eslogger)
                                              /unified.ndjson  macOS unified log
                                              /plists.ndjson   launch agents, daemons and login items changed
                                              /mde.json        Defender XDR rows (archer.telemetry.mde)

Copy a run's folder here from the test machine; Update on the Emulate page (or --build) reads it.
The recordings hold your hosts' and tenant's names, so they stay on this machine: data/telemetry
is gitignored and this source is local (INFO["local"]).
"""

import hashlib
import json
import os
from typing import Dict, Iterable, Optional, Tuple

from archer.telemetry.datasets import PARSER_VERSION, parse, summarise
from archer import paths

NAME = "lab"
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
LAB_DIR = str(paths.DATA / "telemetry" / "lab")
INFO = {"name": "Your lab", "url": "", "licence": "Yours", "local": True,
        "note": "Atomic Red Team tests recorded on your own machines (scripts/telemetry). Never committed"}


def runs() -> Iterable[Tuple[str, Dict]]:
    for name in sorted(os.listdir(LAB_DIR)) if os.path.isdir(LAB_DIR) else []:
        try:
            with open(os.path.join(LAB_DIR, name, "manifest.json"), encoding="utf-8") as fh:
                yield name, json.load(fh)
        except (OSError, ValueError):
            continue


def _files(run: str, test: Dict) -> list:
    folder = os.path.join(LAB_DIR, run, test.get("folder") or f"{test['technique']}-{test.get('test', 1)}")
    return sorted(os.path.join(folder, f) for f in os.listdir(folder)) if os.path.isdir(folder) else []


def datasets(previous: Dict[str, Dict], log=print) -> Iterable[Tuple[Dict, Optional[Dict], str]]:
    found = list(runs())
    log(f"Your lab: {len(found)} run{'' if len(found) == 1 else 's'} in {LAB_DIR}")
    for run, manifest in found:
        platform = str(manifest.get("platform") or "").lower()
        for test in manifest.get("tests") or []:
            if not test.get("technique"):
                continue
            files = _files(run, test)
            stamp = hashlib.sha1("".join(f"{f}:{os.path.getsize(f)}:{os.path.getmtime(f)}" for f in files).encode()).hexdigest()
            key = f"{PARSER_VERSION}:{stamp}"
            did = f"lab:{run}/{test['technique']}-{test.get('test', 1)}"
            if previous.get(did, {}).get("key") == key:
                yield previous[did]["summary"], None, key
                continue
            events = []
            for f in files:
                try:
                    with open(f, "rb") as fh:
                        events.extend(parse(fh.read()))
                except OSError as e:
                    log(f"  {did}: {os.path.basename(f)}: {e}")
            counts, values = summarise(events)
            yield {"id": did, "source": NAME, "title": f"{test.get('name') or test['technique']} ({test['technique']})",
                   "techniques": [test["technique"]], "platform": [platform] if platform else [],
                   "tools": ["Atomic Red Team"], "description": f"{run}: test {test.get('test', 1)} on {platform or 'unknown'}",
                   "events": counts, "date": str(test.get("start") or "")[:10], "url": ""}, values, key
