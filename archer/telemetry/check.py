"""
A detection's indicators against recorded attack telemetry (archer.telemetry.datasets).

For each indicator: the recordings of its technique whose events contain it (the event type
and field: "Sysmon 1, CommandLine"), and how many recordings of other techniques contain it
too. Found in its own technique's recordings means the detection would have matched real
events of the attack, and says which log it needs. Found in many unrelated recordings means
it also matches the lab's ordinary activity: likely noisy. Neither proves anything about
another estate; it's a cheap first look before hit counts against a real SIEM (#16).
"""

import os
from collections import Counter, defaultdict
from typing import Dict, List, Optional

from archer.build.indicator_hygiene import GAP
from archer.telemetry import datasets as ds

MIN_LEN = 3
NOISY = 5  # recordings of other techniques containing an indicator before it's called noisy
_haystack: Dict = {}


def _index() -> Optional[Dict[str, Dict[str, List[tuple]]]]:
    """{dataset: {field group: [(event type, field, lowercased values joined)]}}, built once."""
    vals = ds.values()
    if vals is None:
        return None
    if _haystack.get("for") is not vals:
        group_of = {f: g for g, fs in ds.FIELDS.items() for f in fs}
        index = {}
        for did, by_type in vals.items():
            groups = defaultdict(list)
            for etype, fields in by_type.items():
                for field, values in fields.items():
                    groups[group_of.get(field, "other")].append((etype, field, "\n".join(values).lower(), values))
            index[did] = groups
        _haystack.update({"for": vals, "index": index})
    return _haystack["index"]


def _found(indicator: str, haystack: str) -> bool:
    parts = [p for p in indicator.lower().split(GAP) if p]
    if len(parts) == 1:
        return parts[0] in haystack
    pos = 0
    for p in parts:  # in order: "C:\Users\…\AppData" matches any user's
        pos = haystack.find(p, pos)
        if pos < 0:
            return False
        pos += len(p)
    return True


def _example(indicator: str, values: List[str]) -> str:
    first = indicator.lower().split(GAP)[0]
    return next((v for v in values if first in v.lower()), "")[:240]


def indicators_of(doc: Dict) -> List[tuple]:
    """(kind, value) for a detection YAML's indicators."""
    out = []
    for kind, items in (doc.get("indicators") or {}).items():
        for v in items if isinstance(items, list) else [items]:
            v = str(v).strip()
            if len(v.replace(GAP, "")) >= MIN_LEN:
                out.append((kind, v))
    return out


def check(doc: Dict) -> Dict:
    """The detection's indicators against its technique's recordings and everyone else's."""
    tid = str(doc.get("technique_id") or "")
    own = ds.for_technique(tid) if tid else []
    result = {"technique": tid, "name": doc.get("name"), "datasets": len(own), "indicators": []}
    index = _index()
    if not own:
        return {**result, "status": "no_recordings"}
    if index is None:
        return {**result, "status": "no_values"}
    own_ids = {d["id"] for d in own}
    titles = {d["id"]: d["title"] for d in own}
    for kind, value in indicators_of(doc):
        groups = ds.KIND_FIELDS.get(kind, ("cmd", "file", "other"))
        seen, elsewhere = [], 0
        for did, by_group in index.items():
            hits = [(e, f, vals) for g in groups for e, f, text, vals in by_group.get(g, []) if _found(value, text)]
            if not hits:
                continue
            if did in own_ids:
                for etype, field, vals in hits[:3]:
                    seen.append({"dataset": did, "source": did.split(":", 1)[0], "title": titles[did], "event": etype,
                                 "label": ds.describe(etype)["label"], "field": field, "example": _example(value, vals)})
            else:
                elsewhere += 1
        result["indicators"].append({"kind": kind, "value": value, "seen": seen, "elsewhere": elsewhere,
                                     "noisy": elsewhere >= NOISY})
    any_seen = any(i["seen"] for i in result["indicators"])
    result["status"] = "seen" if any_seen else ("no_indicators" if not result["indicators"] else "not_seen")
    result["events"] = sorted({s["label"] for i in result["indicators"] for s in i["seen"]})
    described = [ds.describe(s["event"]) for i in result["indicators"] for s in i["seen"]]
    result["mde"] = sorted({d["mde"].split(" (")[0] for d in described if d.get("mde")})
    result["udm"] = sorted({d["udm"] for d in described if d.get("udm")})
    return result


def technique(tid: str) -> Dict:
    """What recorded telemetry shows for a technique: its recordings, and the event types they hold."""
    recs = ds.for_technique(tid)
    by_type: Counter = Counter()
    events: Counter = Counter()
    common = set()
    for d in recs:
        by_type.update(d["events"].keys())
        events.update(d["events"])
        common |= set(d.get("background") or [])
    rows = []
    for etype, n in by_type.most_common():
        info = ds.describe(etype)
        rows.append({"event": etype, "label": info["label"], "mde": info.get("mde", ""), "udm": info.get("udm", ""),
                     "recordings": n, "events": events[etype], "common": etype in common})
    exact = any(tid.upper() in d["techniques"] for d in recs)
    # What most of its recordings hold: Sysmon 1 is in nearly every recording because nearly
    # every attack starts processes, so how common an event type is elsewhere doesn't exclude it
    usual = [r for r in rows if r["recordings"] * 2 >= len(recs)]
    need = {"mde": Counter(r["mde"].split(" (")[0] for r in usual if r["mde"]),
            "udm": Counter(r["udm"] for r in usual if r["udm"])}
    return {"technique": tid.upper(), "exact": exact,
            "recordings": [{k: d.get(k) for k in ("id", "source", "title", "techniques", "tools", "url", "date")}
                           | {"events": sum(d["events"].values())} for d in recs],
            "event_types": rows,
            "need": {k: [{"name": n, "recordings": c} for n, c in v.most_common()] for k, v in need.items()}}


def group(group_name: str, generate_dir: str) -> Dict:
    """Every detection of a group's latest run against recorded telemetry."""
    import yaml

    from archer.build.group_files import group_yaml_files

    rows = []
    for name in group_yaml_files(group_name, generate_dir):
        try:
            with open(os.path.join(generate_dir, os.path.basename(name)), encoding="utf-8") as fh:
                doc = yaml.safe_load(fh) or {}
        except (OSError, ValueError, yaml.YAMLError):
            continue
        if not doc.get("technique_id"):
            continue
        connector = ((doc.get("requiredDataConnectors") or [{}])[0] or {}).get("connectorId", "")
        rows.append({**check(doc), "file": os.path.basename(name), "connector": connector, "group": group_name,
                     "siem": "secops" if connector == "GoogleSecOps" else "mde" if connector == "MicrosoftThreatProtection" else ""})
    counts = Counter(r["status"] for r in rows)
    return {"group": group_name, "detections": rows, "counts": dict(counts), "values": ds.values() is not None}


def _usual() -> Dict[str, Dict]:
    """{technique: {recordings, sources, usual}}: the event types in at least half its recordings."""
    recs, holding, sources = Counter(), defaultdict(Counter), defaultdict(Counter)
    for d in ds.load()["datasets"]:
        for t in d["techniques"]:
            if t == "T0000":  # Security-Datasets' placeholder for a recording with no technique
                continue
            recs[t] += 1
            sources[t][d["source"]] += 1
            holding[t].update(d["events"].keys())
    return {t: {"recordings": recs[t], "sources": dict(sources[t]),
                "usual": [e for e, n in types.most_common() if n * 2 >= recs[t]]} for t, types in holding.items()}


def overview() -> List[Dict]:
    """Every recorded technique: its recordings per source, the logs most of them hold, and those
    logs' Defender XDR tables and UDM event types."""
    rows = []
    for t, u in sorted(_usual().items()):
        infos = [ds.describe(e) for e in u["usual"]]
        rows.append({"technique": t, "recordings": u["recordings"], "sources": u["sources"],
                     "logs": [i["label"] for i in infos],
                     "mde": sorted({i["mde"].split(" (")[0] for i in infos if i.get("mde")}),
                     "udm": sorted({i["udm"] for i in infos if i.get("udm")})})
    return rows


def by_data_source() -> Dict[str, List[Dict]]:
    """For each Defender XDR table and UDM event type: the techniques at least half of whose
    recordings hold it, and the recorded logs it comes from."""
    mde, udm = defaultdict(lambda: (set(), Counter())), defaultdict(lambda: (set(), Counter()))
    for t, u in _usual().items():
        for etype in u["usual"]:
            info = ds.describe(etype)
            for m, name in ((mde, info.get("mde", "").split(" (")[0]), (udm, info.get("udm", ""))):
                if name:
                    m[name][0].add(t)
                    m[name][1][info["label"]] += 1
    # Logs by how many of the source's techniques they record
    rank = lambda m: [{"name": k, "techniques": len(v[0]), "technique_ids": sorted(v[0]), "logs": [l for l, _ in v[1].most_common()]}
                      for k, v in sorted(m.items(), key=lambda kv: (-len(kv[1][0]), kv[0]))]
    return {"mde": rank(mde), "udm": rank(udm)}


def search(text: str, limit: int = 400) -> Optional[Dict[str, List[str]]]:
    """{technique: [logs]} whose recordings hold a field value containing the text (… gaps allowed)."""
    index = _index()
    if index is None:
        return None
    text = text.strip()
    if len(text.replace(GAP, "")) < MIN_LEN:
        return {}
    techniques = {d["id"]: d["techniques"] for d in ds.load()["datasets"]}
    out = defaultdict(set)
    for did, by_group in index.items():
        for entries in by_group.values():
            for etype, _field, hay, _vals in entries:
                if _found(text, hay):
                    for t in techniques.get(did, []):
                        out[t].add(ds.describe(etype)["label"])
        if len(out) >= limit:
            break
    return {t: sorted(v) for t, v in sorted(out.items())}
