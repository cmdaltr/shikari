"""
Leads from an X-SIEM pivot's results (#46).

A playbook (shikari/correlation/cross_vendor.py) says what to run at each stage of a chain, in which
SIEM, and which keys to join on. Running it leaves the analyst with every stage's raw events. This
joins them: each event's join keys are read under its SIEM's own field names (JOIN_FIELDS) and
normalised, events are grouped by entity, and each entity's events are fitted into the playbook's
time window. One lead per entity that hit any stage, ranked by stages completed, then stages in the
chain's order, then how tightly they fall. What couldn't join is reported with the reason, so a
missing lead isn't read as a clean bill of health.

Decisions the issue left open:
- Clock skew: a fixed tolerance (TOLERANCE_SECONDS, per run) added to the window, not one measured
  per SIEM pair: the results rarely share enough events to measure it.
- Aliasing: normalised, not joined on several forms. A host is its short name in lower case
  (WS01.corp.local and ws01 are one host); a user is the account name without DOMAIN\\ or @domain.
- Where: here in Shikari, on results fetched through the query clients or uploaded as exports.

No AI and no external calls: the results are passed in.
"""

import csv
import io
import json
import re
from datetime import datetime, timezone
from typing import Dict, Iterable, List, Optional, Tuple

from shikari.correlation.cross_vendor import JOIN_FIELDS

TOLERANCE_SECONDS = 300

# Where each SIEM puts an event's time, first found wins
TIME_FIELDS = {
    "googlesecops": ["metadata.event_timestamp", "event_timestamp", "timestamp"],
    "mde": ["Timestamp", "TimeGenerated"],
    "splunk": ["_time", "time", "timestamp"],
    "elastic": ["@timestamp", "timestamp"],
}
_ANY_TIME = ["@timestamp", "Timestamp", "_time", "metadata.event_timestamp", "timestamp", "time", "TimeGenerated"]

# Other names the same entity goes by in exports and in each SIEM's raw events
_ALIASES = {
    "host": ["DeviceName", "host.name", "host.hostname", "principal.hostname", "hostname", "host", "ComputerName",
             "Computer", "dvchost", "dest_host"],
    "user": ["AccountName", "user.name", "principal.user.userid", "user", "UserName", "InitiatingProcessAccountName",
             "src_user", "suser", "duser"],
    "ip": ["RemoteIP", "source.ip", "principal.ip", "src_ip", "src", "LocalIP", "client.ip", "IPAddress"],
    "process_hash": ["SHA256", "process.hash.sha256", "target.process.file.sha256", "file_hash", "sha256",
                     "InitiatingProcessSHA256", "file.hash.sha256"],
}

# Values that say nothing about who or where
_EMPTY = {"", "-", "n/a", "na", "none", "null", "unknown", "localhost", "127.0.0.1", "::1", "system",
          "local system", "nt authority\\system", "0.0.0.0"}
_WINDOW = re.compile(r"^\s*(\d+)\s*([smhd])\s*$", re.I)


def window_seconds(window) -> int:
    """A playbook's time window ("30m", "1h", "24h", or seconds) in seconds; an hour if unreadable."""
    if isinstance(window, (int, float)) and window > 0:
        return int(window)
    m = _WINDOW.match(str(window or ""))
    if not m:
        return 3600
    return int(m.group(1)) * {"s": 1, "m": 60, "h": 3600, "d": 86400}[m.group(2).lower()]


def _lookup(row: Dict, field: str):
    """A field from a flat row ("host.name" as one key) or a nested one (host → name)."""
    if field in row:
        return row[field]
    node = row
    for part in field.split("."):
        if not isinstance(node, dict) or part not in node:
            return None
        node = node[part]
    return node


def _first(value):
    """Lists (principal.ip often is one) give their first value."""
    if isinstance(value, (list, tuple)):
        return value[0] if value else None
    return value


def normalise(entity: str, value) -> Optional[str]:
    """The form an entity is joined on, or None when the value names nobody."""
    value = _first(value)
    if value is None:
        return None
    v = str(value).strip().strip('"').lower()
    if v in _EMPTY:
        return None
    if entity == "host":
        v = v.split(".", 1)[0] if not re.fullmatch(r"[\d.]+", v) else v
    elif entity == "user":
        v = v.rsplit("\\", 1)[-1].split("@", 1)[0]
    return v if v and v not in _EMPTY else None


def _keys(row: Dict, vendor: str, keys: Iterable[str]) -> Dict[str, str]:
    """The row's normalised join keys: its SIEM's own field first, then the other names it goes by."""
    found = {}
    for entity in keys:
        fields = [JOIN_FIELDS.get(entity, {}).get(vendor)] + _ALIASES.get(entity, [])
        for field in filter(None, fields):
            value = normalise(entity, _lookup(row, field))
            if value:
                found[entity] = value
                break
    return found


def parse_time(value) -> Optional[float]:
    """Epoch seconds from the forms SIEMs write: ISO 8601 (Z, offsets, 7-digit fractions), epoch
    seconds or milliseconds, Splunk's "2026-11-09 14:02:11.000 GMT"."""
    value = _first(value)
    if value is None or value == "":
        return None
    if isinstance(value, (int, float)):
        return value / 1000 if value > 1e11 else float(value)
    s = str(value).strip()
    if re.fullmatch(r"\d+(\.\d+)?", s):
        n = float(s)
        return n / 1000 if n > 1e11 else n
    s = re.sub(r"\s+(UTC|GMT)$", "Z", s).replace(" ", "T", 1)
    s = re.sub(r"(\.\d{6})\d+", r"\1", s)  # Defender writes seven digits of fraction
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(s)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.timestamp()


def _time(row: Dict, vendor: str) -> Optional[float]:
    for field in TIME_FIELDS.get(vendor, []) + _ANY_TIME:
        t = parse_time(_lookup(row, field))
        if t is not None:
            return t
    return None


def read_export(name: str, data: bytes) -> List[Dict]:
    """Rows from an uploaded export: JSON (a list, or {"results"|"rows"|"events"|"hits": [...]}),
    JSON lines, or CSV. Raises ValueError when it's none of them."""
    text = data.decode("utf-8-sig", errors="replace").strip()
    if not text:
        return []
    if text[0] in "[{":
        try:
            doc = json.loads(text)
        except ValueError:
            doc = None
            try:
                return [json.loads(line) for line in text.splitlines() if line.strip()]
            except ValueError:
                pass
        if isinstance(doc, list):
            return [r for r in doc if isinstance(r, dict)]
        if isinstance(doc, dict):
            for key in ("results", "rows", "events", "hits", "data"):
                rows = doc.get(key)
                if isinstance(rows, dict) and isinstance(rows.get("hits"), list):  # Elasticsearch's hits.hits
                    rows = [h.get("_source", h) for h in rows["hits"]]
                if isinstance(rows, list):
                    return [r for r in rows if isinstance(r, dict)]
            return [doc]
        raise ValueError(f"{name} isn't JSON, JSON lines or CSV")
    try:
        return list(csv.DictReader(io.StringIO(text)))
    except csv.Error as e:
        raise ValueError(f"{name} isn't JSON, JSON lines or CSV ({e})") from e


def _best_run(events: List[Tuple[float, int, Dict]], span: float, stages: int) -> List[Tuple[float, int, Dict]]:
    """Of an entity's events (time, stage, event), sorted by time, those in the stretch no longer than
    `span` that hits the most stages; ties go to the stretch more in the chain's order, then the
    tighter. One event per stage: the earliest in that stretch."""
    best, best_key = [], None
    # Each stage's event positions, and a pointer to its earliest one still in the stretch: a pass
    # over thousands of an entity's events costs events × stages, not events squared
    positions: Dict[int, List[int]] = {}
    for n, ev in enumerate(events):
        positions.setdefault(ev[1], []).append(n)
    pointer = {s: 0 for s in positions}
    j = 0
    for i in range(len(events)):
        while events[i][0] - events[j][0] > span:
            j += 1
        picked = []
        for s, where in positions.items():
            while pointer[s] < len(where) and where[pointer[s]] < j:
                pointer[s] += 1
            if pointer[s] < len(where) and where[pointer[s]] <= i:
                picked.append(events[where[pointer[s]]])
        picked.sort(key=lambda e: e[1])
        key = (len(picked), _in_order(picked), -(max(e[0] for e in picked) - min(e[0] for e in picked)))
        if best_key is None or key > best_key:
            best, best_key = picked, key
    return best


def _in_order(picked: List[Tuple[float, int, Dict]]) -> int:
    """How many consecutive stages (in the chain's order) are also in time order."""
    return sum(1 for a, b in zip(picked, picked[1:]) if a[0] <= b[0])


def consolidate(playbook: Dict, results: Dict[int, Dict[str, List[Dict]]],
                tolerance: int = TOLERANCE_SECONDS) -> Dict:
    """Leads from a playbook's stage results.

    `results` maps a stage's index to {vendor: rows}. Returns {"leads", "unjoined", "summary"}:
    leads ranked strongest first, each with the stages it hit (time, SIEM, the event); unjoined the
    reasons events didn't join, per stage and SIEM."""
    stages = playbook.get("stages") or []
    keys = [k["entity"] for k in playbook.get("join_keys") or [{"entity": "host"}]]
    window = window_seconds(playbook.get("time_window"))
    span = window + max(0, int(tolerance))
    total = len(stages)

    by_entity: Dict[Tuple[str, str], List[Tuple[float, int, Dict]]] = {}
    unjoined, events_in = [], 0
    for index, by_vendor in sorted(results.items()):
        if index >= total:
            continue
        for vendor, rows in (by_vendor or {}).items():
            no_keys = no_time = 0
            for row in rows or []:
                events_in += 1
                when = _time(row, vendor)
                if when is None:
                    no_time += 1
                    continue
                found = _keys(row, vendor, keys)
                if not found:
                    no_keys += 1
                    continue
                event = {"stage": index, "vendor": vendor, "time": when, "row": row}
                for entity, value in found.items():
                    by_entity.setdefault((entity, value), []).append((when, index, event))
            label = (stages[index].get("vendors") or {}).get(vendor, {}).get("label", vendor)
            where = f"Stage {index + 1} ({stages[index].get('technique_name', '')}), {label}"
            if no_keys:
                fields = ", ".join(JOIN_FIELDS[k][vendor] for k in keys if vendor in JOIN_FIELDS.get(k, {}))
                unjoined.append({"stage": index, "vendor": vendor, "events": no_keys, "reason": "no_keys",
                                 "detail": f"{where}: {no_keys} event{'s' * (no_keys != 1)} carried none of "
                                           f"the join keys ({fields or ', '.join(keys)}). Add them to the "
                                           "query's output, or they can't be tied to anything."})
            if no_time:
                unjoined.append({"stage": index, "vendor": vendor, "events": no_time, "reason": "no_time",
                                 "detail": f"{where}: {no_time} event{'s' * (no_time != 1)} had no readable "
                                           "time, so they can't be placed in the window."})

    leads, outside = [], {}
    for (entity, value), events in by_entity.items():
        events.sort(key=lambda e: e[0])
        picked = _best_run(events, span, total)
        hit = {e[1] for e in picked}
        # Events of a stage this entity hit only outside the window: skew, or two separate episodes
        for when, stage, ev in events:
            if stage not in hit:
                outside.setdefault((stage, ev["vendor"]), set()).add(id(ev))
        times = [e[0] for e in picked]
        tightness = 1 - (max(times) - min(times)) / span if span else 1
        order = _in_order(picked) / (len(picked) - 1) if len(picked) > 1 else 1
        score = round(70 * len(picked) / total + 20 * order + 10 * tightness, 1) if total else 0
        leads.append({
            "entity": entity, "value": value, "score": score,
            "stages_hit": len(picked), "stages_total": total,
            "in_order": order == 1, "span_seconds": round(max(times) - min(times)),
            "first_seen": _iso(min(times)), "last_seen": _iso(max(times)),
            "missing": [i for i in range(total) if i not in hit],
            "hits": [{"stage": e[1], "technique_id": stages[e[1]].get("technique_id", ""),
                      "technique_name": stages[e[1]].get("technique_name", ""), "vendor": e[2]["vendor"],
                      "label": (stages[e[1]].get("vendors") or {}).get(e[2]["vendor"], {}).get("label", e[2]["vendor"]),
                      "_event": e[2],
                      "time": _iso(e[0]),
                      "events": sum(1 for x in events if x[1] == e[1]), "event": e[2]["row"]}
                     for e in picked],
        })
    # The same events can make a host lead and a user lead: keep the host's when they match exactly
    leads = _without_echoes(leads)
    # An event late for every entity it names is reported once, not once per entity
    joined = {id(h["_event"]) for lead in leads for h in lead["hits"]}
    for lead in leads:
        for h in lead["hits"]:
            del h["_event"]
    leads.sort(key=lambda l: (-l["score"], -l["stages_hit"], l["span_seconds"], l["entity"], l["value"]))
    for rank, lead in enumerate(leads, 1):
        lead["rank"] = rank

    for (stage, vendor), ids in sorted(outside.items()):
        n = len(ids - joined)
        if not n:
            continue
        label = (stages[stage].get("vendors") or {}).get(vendor, {}).get("label", vendor)
        unjoined.append({"stage": stage, "vendor": vendor, "events": n, "reason": "outside_window",
                         "detail": f"Stage {stage + 1} ({stages[stage].get('technique_name', '')}), {label}: "
                                   f"{n} event{'s' * (n != 1)} matched an entity but fell outside the "
                                   f"{playbook.get('time_window', '1h')} window (with {tolerance}s for clock "
                                   "skew) of its other stages. A SIEM's clock, or a second episode."})
    for index in range(total):
        if not any((results.get(index) or {}).values()):
            unjoined.append({"stage": index, "vendor": "", "events": 0, "reason": "no_results",
                             "detail": f"Stage {index + 1} ({stages[index].get('technique_name', '')}): no "
                                       "results, run or uploaded, so no lead can complete it."})

    return {"leads": leads, "unjoined": unjoined,
            "summary": {"events": events_in, "leads": len(leads),
                        "complete": sum(1 for l in leads if l["stages_hit"] == total),
                        "window_seconds": window, "tolerance_seconds": tolerance, "join_keys": keys}}


_ENTITY_ORDER = {"host": 0, "user": 1, "ip": 2, "process_hash": 3}


def _without_echoes(leads: List[Dict]) -> List[Dict]:
    seen, out = set(), []
    for lead in sorted(leads, key=lambda l: _ENTITY_ORDER.get(l["entity"], 9)):
        sig = tuple((h["stage"], h["time"], h["vendor"]) for h in lead["hits"])
        if sig in seen:
            continue
        seen.add(sig)
        out.append(lead)
    return out


def _iso(t: float) -> str:
    return datetime.fromtimestamp(t, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
