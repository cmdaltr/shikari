"""Security-Datasets (OTRF, formerly Mordor; MIT): the atomic datasets' host logs. See archer.telemetry.datasets."""

import re
from typing import Dict, Iterable, Optional, Tuple

import yaml

from archer.telemetry import fetch
from archer.telemetry.datasets import PARSER_VERSION, parse, summarise, unpack

NAME = "otrf"
REPO = "OTRF/Security-Datasets"
INFO = {"name": "Security-Datasets (OTRF)", "url": f"https://github.com/{REPO}", "licence": "MIT",
        "note": "Last updated March 2024; Empire, Covenant and tool runs in OTRF's lab"}


def techniques(meta: Dict) -> list:
    out = []
    for m in meta.get("attack_mappings") or []:
        tid = str(m.get("technique") or "").strip()
        sub = str(m.get("sub-technique") or "").strip()
        if tid:
            out.append(f"{tid}.{int(sub):03d}" if sub.isdigit() else tid)
    return sorted(set(out))


def datasets(previous: Dict[str, Dict], log=print) -> Iterable[Tuple[Dict, Optional[Dict], str]]:
    """(summary, values or None when unchanged, key) per atomic dataset."""
    tree = fetch.tree(REPO)
    metas = {t["path"]: t["sha"] for t in tree if re.match(r"datasets/atomic/_metadata/SD\w+-\d+\.yaml$", t["path"])}
    blobs = {t["path"]: t["sha"] for t in tree if t["path"].startswith("datasets/atomic/")}
    log(f"Security-Datasets: {len(metas)} atomic datasets")

    def one(path):
        meta = yaml.safe_load(fetch.raw(REPO, path))
        hosts = [f["link"] for f in meta.get("files") or []
                 if str(f.get("type", "")).lower() == "host" and f.get("link")]
        paths = [re.sub(r"^https://raw\.githubusercontent\.com/[^/]+/[^/]+/[^/]+/", "", h) for h in hosts]
        key = f"{PARSER_VERSION}:{metas[path]}:" + ",".join(blobs.get(p, p) for p in paths)
        did = f"otrf:{meta.get('id')}"
        if previous.get(did, {}).get("key") == key:
            return previous[did]["summary"], None, key
        events = []
        for p in paths:
            try:
                for f in unpack(fetch.raw(REPO, p)):
                    events.extend(parse(f))
            except Exception as e:
                log(f"  {meta.get('id')}: {p}: {e}")
        counts, values = summarise(events)
        tools = sorted({t.get("name") for t in (meta.get("simulation") or {}).get("tools") or [] if t.get("name")})
        return {"id": did, "source": NAME, "title": meta.get("title") or meta.get("id"),
                "techniques": techniques(meta), "platform": meta.get("platform") or [], "tools": tools,
                "description": (meta.get("description") or "")[:500], "events": counts,
                "url": f"https://github.com/{REPO}/blob/master/{path}"}, values, key

    yield from fetch.pool(one, sorted(metas), log)
