"""
Lab telemetry for the SIEM export packs (#41): a recorded lab run's events, shaped so the pack's
detections can fire on them in the user's own SIEM.

Reads a run under data/telemetry/lab (shikari.telemetry.lab): Windows events.xml (Sysmon, Security
4688) and macOS eslogger es.ndjson. Each event is read once into a neutral form, then written as

    elastic  Elastic Common Schema, for _bulk into the logs-endpoint.events.* data streams the
             detections query (Elastic Defend's names), namespace "shikari"
    splunk   HEC events per index, carrying the field names the detections themselves search. They
             are learned from the queries, not assumed: whatever mapping is in force (the CEF
             defaults or an organisation's), the events use its names, its renames undone
    wazuh    Windows events as Wazuh's eventchannel decoder holds them: win.system, win.eventdata

Only events a detection could match are written: process creation, network, file, registry and
DNS. Timestamps are shifted by default so the run ends at export time, keeping each event's
spacing: the detections look back a day, and a run recorded last week would match nothing. No AI.
"""

import html
import json
import os
import re
from datetime import datetime, timedelta, timezone
from typing import Dict, Iterable, List, Optional, Tuple

_XML_EVENT = re.compile(r"<Event[ >].*?</Event>", re.S)
_XML_DATA = re.compile(r"<Data Name=['\"]([^'\"]+)['\"]\s*>(.*?)</Data>", re.S)
SYSMON = "Microsoft-Windows-Sysmon"
SECURITY = "Microsoft-Windows-Security-Auditing"
NAMESPACE = "shikari"
SPLUNK_SOURCE = "shikari-lab"
CHUNK = 5000  # events per load file: under Elasticsearch's and HEC's default request limits

# (provider, event ID) -> the neutral kind of event
WINDOWS_KINDS = {(SYSMON, "1"): "process", (SECURITY, "4688"): "process", (SYSMON, "3"): "network",
                 (SYSMON, "11"): "file", (SYSMON, "12"): "registry", (SYSMON, "13"): "registry",
                 (SYSMON, "14"): "registry", (SYSMON, "22"): "dns"}


# ── Reading a run ─────────────────────────────────────────────────────────────

def _time(value: str) -> Optional[datetime]:
    """An ISO time with Windows' 7 or eslogger's 9 fractional digits, as UTC."""
    m = re.match(r"(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(?:\.(\d+))?", str(value or ""))
    if not m:
        return None
    frac = (m.group(2) or "0")[:6].ljust(6, "0")
    return datetime.strptime(f"{m.group(1)}.{frac}", "%Y-%m-%dT%H:%M:%S.%f").replace(tzinfo=timezone.utc)


def _base(path: str) -> str:
    return re.split(r"[\\/]", path or "")[-1]


def _user(value: str) -> str:
    return (value or "").split("\\")[-1]


def _windows(text: str, technique: str, host: str) -> Iterable[Dict]:
    for raw in _XML_EVENT.findall(text):
        provider = re.search(r"<Provider Name=['\"]([^'\"]+)", raw)
        eid = re.search(r"<EventID[^>]*>(\d+)</EventID>", raw)
        kind = WINDOWS_KINDS.get((provider.group(1) if provider else "", eid.group(1) if eid else ""))
        if not kind:
            continue
        when = re.search(r"<TimeCreated SystemTime=['\"]([^'\"]+)", raw)
        computer = re.search(r"<Computer>(.*?)</Computer>", raw)
        channel = re.search(r"<Channel>(.*?)</Channel>", raw)
        data = {k: html.unescape(v) for k, v in _XML_DATA.findall(raw)}
        ts = _time(when.group(1) if when else "")
        if not ts:
            continue
        ev = {"ts": ts, "kind": kind, "platform": "windows", "technique": technique,
              "host": html.unescape(computer.group(1)) if computer else host,
              "provider": provider.group(1), "event_id": eid.group(1),
              "channel": html.unescape(channel.group(1)) if channel else "", "data": data}
        if provider.group(1) == SECURITY:  # 4688's names, in Sysmon's terms
            ev.update(image=data.get("NewProcessName", ""), cmd=data.get("CommandLine", ""),
                      parent_image=data.get("ParentProcessName", ""), user=data.get("SubjectUserName", ""),
                      pid=_int(data.get("NewProcessId")), ppid=_int(data.get("ProcessId")))
        else:
            ev.update(image=data.get("Image", ""), cmd=data.get("CommandLine", ""),
                      parent_image=data.get("ParentImage", ""), parent_cmd=data.get("ParentCommandLine", ""),
                      user=_user(data.get("User", "")), pid=_int(data.get("ProcessId")),
                      ppid=_int(data.get("ParentProcessId")), hashes=data.get("Hashes", ""),
                      dst_ip=data.get("DestinationIp", ""), dst_port=_int(data.get("DestinationPort")),
                      dst_host=data.get("DestinationHostname", ""), file=data.get("TargetFilename", ""),
                      reg=data.get("TargetObject", ""), reg_value=data.get("Details", ""),
                      domain=data.get("QueryName", ""))
        yield ev


def _int(value) -> Optional[int]:
    try:
        return int(str(value), 0)
    except (TypeError, ValueError):
        return None


def _eslogger(text: str, technique: str, host: str) -> Iterable[Dict]:
    """macOS process launches (exec) and file creations from eslogger."""
    for line in text.splitlines():
        try:
            e = json.loads(line)
        except ValueError:
            continue
        if not isinstance(e, dict) or not isinstance(e.get("event"), dict):
            continue
        name, body = next(iter(e["event"].items()), ("", {}))
        body = body if isinstance(body, dict) else {}
        proc = e.get("process") if isinstance(e.get("process"), dict) else {}
        path = lambda f: f.get("path", "") if isinstance(f, dict) else ""
        ts = _time(e.get("time", ""))
        if not ts:
            continue
        base = {"ts": ts, "platform": "macos", "technique": technique, "host": host,
                "provider": "eslogger", "event_id": name, "channel": "Endpoint Security", "data": {}}
        if name == "exec":
            target = body.get("target") if isinstance(body.get("target"), dict) else {}
            args = body.get("args") if isinstance(body.get("args"), list) else []
            yield {**base, "kind": "process", "image": path(target.get("executable")),
                   "cmd": " ".join(map(str, args)), "args": [str(a) for a in args],
                   "parent_image": path(proc.get("executable")),
                   "pid": (target.get("audit_token") or {}).get("pid"),
                   "ppid": (proc.get("audit_token") or {}).get("pid"),
                   "user": str((target.get("audit_token") or {}).get("euid", ""))}
        elif name == "create":
            dest = body.get("destination") if isinstance(body.get("destination"), dict) else {}
            new = dest.get("new_path") if isinstance(dest.get("new_path"), dict) else {}
            file = path(dest.get("existing_file")) or (
                os.path.join(path(new.get("dir")), new.get("filename", "")) if new else "")
            if file:
                yield {**base, "kind": "file", "file": file, "image": path(proc.get("executable")),
                       "pid": (proc.get("audit_token") or {}).get("pid")}


def read_run(run_dir: str) -> Tuple[Dict, List[Dict]]:
    """(the run's manifest, its matchable events in time order)."""
    with open(os.path.join(run_dir, "manifest.json"), encoding="utf-8-sig") as fh:
        manifest = json.load(fh)
    host = manifest.get("host", "")
    events: List[Dict] = []
    for test in manifest.get("tests") or []:
        folder = os.path.join(run_dir, str(test.get("folder") or ""))
        technique = str(test.get("technique") or "")
        for name, reader in (("events.xml", _windows), ("es.ndjson", _eslogger)):
            path = os.path.join(folder, name)
            if os.path.isfile(path):
                with open(path, encoding="utf-8-sig", errors="replace") as fh:
                    events.extend(reader(fh.read(), technique, host))
    events.sort(key=lambda e: e["ts"])
    return manifest, events


def rebase(events: List[Dict], now: Optional[datetime] = None) -> timedelta:
    """Shift every event so the last one is a minute before `now`; returns the shift."""
    if not events:
        return timedelta(0)
    now = now or datetime.now(timezone.utc)
    shift = (now - timedelta(minutes=1)) - max(e["ts"] for e in events)
    for e in events:
        e["ts"] = e["ts"] + shift
    return shift


def _iso(ts: datetime) -> str:
    return ts.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


# ── Elastic ──────────────────────────────────────────────────────────────────

_ECS_STREAM = {"process": "process", "network": "network", "dns": "network", "file": "file", "registry": "registry"}


def _hashes(value: str) -> Dict[str, str]:
    """Sysmon's "SHA256=…,MD5=…,IMPHASH=…" as ECS hash fields."""
    out = {}
    for part in (value or "").split(","):
        algo, _, digest = part.partition("=")
        if algo.strip().lower() in ("md5", "sha1", "sha256") and digest:
            out[algo.strip().lower()] = digest.strip().lower()
    return out


def _proc(executable: str, cmd: str = "", pid=None) -> Dict:
    out = {"executable": executable, "name": _base(executable)}
    if cmd:
        out["command_line"] = cmd
    if pid is not None:
        out["pid"] = pid
    return {k: v for k, v in out.items() if v not in ("", None)}


def to_ecs(ev: Dict, run: str) -> Tuple[str, Dict]:
    """(data stream, document) in Elastic Defend's names."""
    dataset = f"endpoint.events.{_ECS_STREAM[ev['kind']]}"
    doc = {
        "@timestamp": _iso(ev["ts"]),
        "data_stream": {"type": "logs", "dataset": dataset, "namespace": NAMESPACE},
        "event": {"dataset": dataset, "code": ev["event_id"], "provider": ev["provider"], "kind": "event"},
        "host": {"name": ev["host"].lower(), "hostname": ev["host"], "os": {"type": ev["platform"]}},
        "labels": {"shikari_run": run, "shikari_technique": ev["technique"]},
        "tags": ["shikari-lab"],
    }
    if ev["platform"] == "windows":
        doc["winlog"] = {"channel": ev["channel"], "event_id": ev["event_id"], "provider_name": ev["provider"]}
    if ev.get("user"):
        doc["user"] = {"name": ev["user"]}
    process = _proc(ev.get("image", ""), ev.get("cmd", ""), ev.get("pid"))
    if ev["kind"] == "process":
        doc["event"].update(category=["process"], type=["start"], action="start")
        parent = _proc(ev.get("parent_image", ""), ev.get("parent_cmd", ""), ev.get("ppid"))
        if parent:
            process["parent"] = parent
        if ev.get("args"):
            process["args"] = ev["args"]
        hashes = _hashes(ev.get("hashes", ""))
        if hashes:
            process["hash"] = hashes
    elif ev["kind"] == "network":
        doc["event"].update(category=["network"], type=["connection", "start"], action="connection_attempted")
        doc["destination"] = {k: v for k, v in (("ip", ev.get("dst_ip")), ("port", ev.get("dst_port")),
                                                ("domain", ev.get("dst_host"))) if v not in ("", None)}
    elif ev["kind"] == "dns":
        doc["event"].update(category=["network"], type=["protocol", "info"], action="lookup_requested")
        doc["dns"] = {"question": {"name": ev.get("domain", "")}}
    elif ev["kind"] == "file":
        doc["event"].update(category=["file"], type=["creation"], action="creation")
        doc["file"] = {"path": ev.get("file", ""), "name": _base(ev.get("file", ""))}
        ext = os.path.splitext(doc["file"]["name"])[1].lstrip(".")
        if ext:
            doc["file"]["extension"] = ext.lower()
    elif ev["kind"] == "registry":
        doc["event"].update(category=["registry"], type=["change"], action="modification")
        key = ev.get("reg", "")
        doc["registry"] = {"path": key, "key": key.rsplit("\\", 1)[0], "value": _base(key)}
        if ev.get("reg_value"):
            doc["registry"]["data"] = {"strings": [ev["reg_value"]]}
    if process:
        doc["process"] = process
    return f"logs-{dataset}-{NAMESPACE}", doc


def elastic_bulk(events: List[Dict], run: str) -> List[str]:
    """_bulk bodies, CHUNK events each."""
    lines = []
    for ev in events:
        stream, doc = to_ecs(ev, run)
        lines.append(json.dumps({"create": {"_index": stream}}) + "\n" + json.dumps(doc, ensure_ascii=False) + "\n")
    return ["".join(lines[i:i + CHUNK]) for i in range(0, len(lines), CHUNK)]


# ── Splunk ───────────────────────────────────────────────────────────────────

# Indicator kinds (as the Splunk searches use them) -> the neutral event's values for that kind
_KIND_VALUES = {
    "cmd": lambda e: [e.get("cmd"), e.get("parent_cmd")],
    "sw": lambda e: [e.get("image"), e.get("parent_image")],
    "reg": lambda e: [e.get("reg")],
    "network": lambda e: [e.get("domain"), e.get("dst_host")],
    "port": lambda e: [str(e["dst_port"]) if e.get("dst_port") else None],
}
_KIND_ALIAS = {"domain": "network", "path": "sw", "file": "sw"}
_CLOUD_INDEX = re.compile(r"aws|azure|gcp|google|o365|office|m365|okta|entra|cloud|saas|identity|guardduty|wiz", re.I)
_FIELD_VALUE = re.compile(r"([A-Za-z_][\w.{}]*)\s*(?:IN\s*\(([^)]*)\)|=\s*\"((?:[^\"\\]|\\.)*)\")")
_RENAME = re.compile(r"(\"[^\"]+\"|[\w.{}@-]+)\s+AS\s+(\"[^\"]+\"|[\w.{}@-]+)", re.I)


def learn_splunk_fields(docs: Iterable[Dict]) -> Dict[str, Dict]:
    """{index: {"kinds": {kind: {raw field: count}}, "sourcetypes": [...], "host": raw field}} from the
    Splunk detections themselves: each `| search` field is tied to the indicator kind whose values it
    holds, and traced back through the query's renames to the name the indexed event carries."""
    learned: Dict[str, Dict] = {}
    for doc in docs:
        q = str(doc.get("query") or "")
        idx = re.search(r"\bindex\s*=\s*\"?([\w\-]+)", q)
        if not idx:
            continue
        entry = learned.setdefault(idx.group(1), {"kinds": {}, "sourcetypes": [], "host": ""})
        renames = {}
        for seg in re.findall(r"\|\s*rename\s+([^|]*)", q):
            for raw, alias in _RENAME.findall(seg):
                renames[alias.strip('"')] = raw.strip('"')
        if renames.get("device") and not entry["host"]:
            entry["host"] = renames["device"]
        for st in re.findall(r"sourcetype\s*(?:=\s*\"?([^\"\s|)]+)\"?|IN\s*\(([^)]*)\))", q):
            for v in (st[0] or st[1]).split(","):
                v = v.strip(" \"")
                if v and v not in entry["sourcetypes"]:
                    entry["sourcetypes"].append(v)
        # Every kind competes for a field, so one that holds API names (api) isn't taken for a
        # command line; only the kinds an endpoint event fills are kept
        indicators = {}
        for kind, values in (doc.get("indicators") or {}).items():
            kind = _KIND_ALIAS.get(kind, kind)
            indicators.setdefault(kind, set()).update(str(v).lower() for v in values or [] if len(str(v)) >= 3)
        for seg in re.findall(r"\|\s*search\s+([^|]*)", q):
            for field, in_list, single in _FIELD_VALUE.findall(seg):
                values = [v.strip(" \"*").replace("\\\\", "\\").lower() for v in (in_list.split(",") if in_list else [single])]
                values = [v for v in values if v]
                best, hits = None, 0
                for kind, inds in indicators.items():
                    n = sum(1 for v in values if any(v in i or i in v for i in inds))
                    if n > hits:
                        best, hits = kind, n
                if best in _KIND_VALUES:
                    raw = renames.get(field, field)
                    counts = entry["kinds"].setdefault(best, {})
                    counts[raw] = counts.get(raw, 0) + 1
    # Keep a kind's main fields, not a stray one a single search used; and no cloud index, whose
    # searches match command-line indicators against API names, not against a process
    for entry in learned.values():
        for kind, counts in entry["kinds"].items():
            top = max(counts.values())
            entry["kinds"][kind] = {f: n for f, n in counts.items() if n * 10 >= top}
    return {i: e for i, e in learned.items() if e["kinds"] and not _CLOUD_INDEX.search(i)}


def _splunk_value(field: str, kind: str, ev: Dict) -> Optional[str]:
    values = [v for v in _KIND_VALUES[kind](ev) if v]
    if not values:
        return None
    value = values[0]
    # A software field named for a path holds the full path; any other (process_name, dproc, process)
    # holds what the searches match exactly: the file name
    if kind == "sw" and not re.search(r"path|image|executable|exe$|binary", field, re.I):
        value = _base(value)
    return value


def _sourcetype(choices: List[str], ev: Dict) -> str:
    want = "sysmon" if ev["provider"] == SYSMON else ("macos" if ev["platform"] == "macos" else "windows")
    for st in choices:
        if want in st.lower():
            return st
    return choices[0] if choices else "shikari:lab"


_PLATFORM_WORDS = {"windows": ("windows", "win_", "wineventlog"), "macos": ("macos", "mac_", "osx"),
                   "linux": ("linux", "unix", "auditd")}


def _other_platform(index: str, info: Dict, platform: str) -> bool:
    """An index or sourcetype named for a different platform than the event's."""
    names = " ".join([index, *info.get("sourcetypes", [])]).lower()
    named = {p for p, words in _PLATFORM_WORDS.items() if any(w in names for w in words)}
    return bool(named) and platform not in named


def splunk_events(events: List[Dict], learned: Dict[str, Dict], run: str) -> Dict[str, List[Dict]]:
    """{index: [HEC event]}: each event goes to every index whose searches name a field it can fill,
    bar an index named for another platform (a Mac's events stay out of a Windows index)."""
    out: Dict[str, List[Dict]] = {}
    for ev in events:
        for index, info in learned.items():
            if _other_platform(index, info, ev["platform"]):
                continue
            fields, filled = {}, set()
            # In _KIND_VALUES' order, so a field two kinds were learned for holds the command line
            for kind in [k for k in _KIND_VALUES if k in info["kinds"]]:
                for raw in info["kinds"][kind]:
                    value = None if raw in filled else _splunk_value(raw, kind, ev)
                    if value:
                        _put(fields, raw, value)
                        filled.add(raw)
            if not fields:
                continue
            if info.get("host"):
                _put(fields, info["host"], ev["host"])
            fields.update(shikari_run=run, shikari_technique=ev["technique"], EventCode=ev["event_id"])
            out.setdefault(index, []).append({
                "time": round(ev["ts"].timestamp(), 3), "host": ev["host"], "index": index,
                "source": SPLUNK_SOURCE, "sourcetype": _sourcetype(info["sourcetypes"], ev), "event": fields})
    return out


def _put(fields: Dict, name: str, value) -> None:
    """A dotted name (properties.CommandLine) as nested JSON, which Splunk's JSON extraction names
    back with dots."""
    parts = name.split(".")
    node = fields
    for p in parts[:-1]:
        nxt = node.get(p)
        if not isinstance(nxt, dict):
            nxt = node[p] = {}
        node = nxt
    node[parts[-1]] = value


SPLUNK_PROPS = f"""# Search-time JSON extraction for Shikari's lab events only: scoped by source, so a sourcetype
# your real data shares keeps its own settings
[source::{SPLUNK_SOURCE}]
KV_MODE = json
"""


# ── Wazuh ────────────────────────────────────────────────────────────────────

def _lower_camel(name: str) -> str:
    return name[:1].lower() + name[1:]


def to_wazuh(ev: Dict) -> Optional[Dict]:
    """A Windows event as Wazuh's eventchannel decoder holds it, or None for macOS."""
    if ev["platform"] != "windows":
        return None
    return {"win": {
        "system": {"providerName": ev["provider"], "eventID": ev["event_id"], "channel": ev["channel"],
                   "computer": ev["host"], "systemTime": _iso(ev["ts"])},
        "eventdata": {_lower_camel(k): v for k, v in ev["data"].items() if v not in ("", None)},
    }}
