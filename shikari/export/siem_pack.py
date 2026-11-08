"""
SIEM export packs (#41): a zip the user imports into their own SIEM by hand.

No connection and no credentials, like the VECTR export: each pack holds the detections in that
SIEM's own import format with a README of the steps, and a manifest of what went in. Pushing over an
API is shikari.export.siem_push. No AI.

    elastic  rules.ndjson               Security → Rules → Import: ES|QL rules, created disabled
    splunk   shikari_detections.tgz     Apps → Install app from file: savedsearches.conf (disabled)
                                        and indexes.conf for every index the searches name
    wazuh    shikari_rules.xml          the manager's etc/rules: built from the detections'
                                        indicators (shikari.build.wazuh), Windows events only

A rule's ID is the detection YAML's own `id`, so importing a newer pack updates rules in place.
"""

import hashlib
import io
import json
import os
import re
import tarfile
import zipfile
from datetime import datetime, timezone
from typing import Callable, Dict, Iterable, List, Optional, Tuple

from shikari.export import siem_telemetry
from shikari.export.siem_telemetry import SPLUNK_PROPS
from shikari.visualization.navigator import _attack_id, _get, technique_index

SIEMS = {"elastic": {"label": "Elastic", "connector": "Elastic"},
         "splunk": {"label": "Splunk", "connector": "Splunk"},
         "wazuh": {"label": "Wazuh", "connector": None}}  # no Wazuh detections: rules from every SIEM's indicators

# Elastic's own severity → risk score bands
RISK_SCORE = {"low": 21, "medium": 47, "high": 73, "critical": 99}
# Splunk alert.severity: 2 info, 3 low, 4 medium, 5 high, 6 critical
SPLUNK_SEVERITY = {"informational": 2, "low": 3, "medium": 4, "high": 5, "critical": 6}
# Indexes every Splunk has, which indexes.conf must not redefine
SPLUNK_BUILTIN_INDEXES = {"main", "summary", "history", "splunklogger", "*"}
SPLUNK_APP = "shikari_detections"


def _version() -> str:
    try:
        from importlib.metadata import version as dist_version
        return dist_version("shikari")
    except Exception:
        return "unknown"


def _hours(span: str, default: int = 24) -> int:
    """'30m', '12h', '1d' (queryFrequency / queryPeriod) as whole hours, at least one."""
    m = re.fullmatch(r"\s*(\d+)\s*([mhd])\s*", str(span or ""))
    if not m:
        return default
    n, unit = int(m.group(1)), m.group(2)
    return max(1, {"m": n // 60, "h": n, "d": n * 24}[unit])


def _minutes(span: str, default: int = 1440) -> int:
    m = re.fullmatch(r"\s*(\d+)\s*([mhd])\s*", str(span or ""))
    if not m:
        return default
    n, unit = int(m.group(1)), m.group(2)
    return max(1, n * {"m": 1, "h": 60, "d": 1440}[unit])


def attack_lookup(bundle) -> Dict:
    """{tactics: {name: {id, shortname}}, techniques: {id: name}} from the loaded STIX bundle.

    Tactic IDs come from the bundle rather than a table here, so ATT&CK's renames (v18's Stealth and
    Defense Impairment) follow without a code change. An empty lookup still builds rules, without
    the tactic part of their ATT&CK mapping."""
    if bundle is None:
        return {"tactics": {}, "techniques": {}}
    tactics = {}
    for o in _get(bundle, "objects", []) or []:
        if _get(o, "type") == "x-mitre-tactic" and not _get(o, "x_mitre_deprecated"):
            tactics[_get(o, "name")] = {"id": _attack_id(o), "shortname": _get(o, "x_mitre_shortname")}
    index = technique_index(bundle)
    return {"tactics": tactics, "techniques": {tid: e["name"] for tid, e in index.items()},
            "technique_tactics": {tid: e["tactics"] for tid, e in index.items()}}


def _threat(doc: Dict, attack: Dict) -> List[Dict]:
    """Kibana's `threat` array: one entry per tactic, each naming the technique (and sub-technique)."""
    tid = str(doc.get("technique_id") or "")
    if not re.fullmatch(r"T\d{4}(\.\d{3})?", tid):
        return []
    names = attack.get("techniques", {})
    parent = tid.split(".")[0]
    technique = {"id": parent, "name": names.get(parent, parent),
                 "reference": f"https://attack.mitre.org/techniques/{parent}/"}
    if "." in tid:
        technique["subtechnique"] = [{"id": tid, "name": names.get(tid, tid),
                                      "reference": f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}/"}]
    # Matched without case: generated YAMLs say "Command And Control" where ATT&CK says "and"
    known = {name.lower(): (name, t) for name, t in attack.get("tactics", {}).items() if t.get("id")}
    chosen = [known[str(n).lower()] for n in doc.get("tactics") or [] if str(n).lower() in known]
    if not chosen:  # none of the YAML's tactics are ATT&CK's: use the technique's own
        chosen = [known[n.lower()] for n in attack.get("technique_tactics", {}).get(tid, []) if n.lower() in known]
    out = []
    for name, tactic in chosen:
        out.append({"framework": "MITRE ATT&CK",
                    "tactic": {"id": tactic["id"], "name": name,
                               "reference": f"https://attack.mitre.org/tactics/{tactic['id']}/"},
                    "technique": [technique]})
    return out


def elastic_rule(doc: Dict, attack: Dict) -> Dict:
    """A Kibana detection rule (ES|QL), created disabled. Import with Security → Rules → Import."""
    severity = str(doc.get("severity") or "medium").lower()
    severity = severity if severity in RISK_SCORE else "medium"
    period = _hours(doc.get("queryPeriod"))
    tags = ["Shikari"] + [str(t) for t in doc.get("tags") or []]
    if doc.get("technique_id"):
        tags.append(str(doc["technique_id"]))
    return {
        "rule_id": str(doc["id"]),
        "name": f"{doc.get('name') or doc.get('technique_id')} ({doc.get('technique_id')})",
        "description": str(doc.get("description") or doc.get("name") or "Generated by Shikari").strip(),
        "type": "esql",
        "language": "esql",
        "query": str(doc.get("query") or "").strip(),
        "severity": severity,
        "risk_score": RISK_SCORE[severity],
        "interval": f"{_minutes(doc.get('queryFrequency'))}m",
        "from": f"now-{period}h",
        "enabled": False,
        "threat": _threat(doc, attack),
        "tags": tags,
        "author": ["Shikari"],
        "references": [str(r) for r in doc.get("osint_sources") or []],
        "false_positives": [],
        "max_signals": 100,
        "version": 1,
    }


def _cron(span: str) -> str:
    minutes = _minutes(span)
    if minutes < 60:
        return f"*/{minutes} * * * *"
    if minutes < 1440:
        return f"0 */{max(1, minutes // 60)} * * *"
    return "0 0 * * *"


def _stanza(doc: Dict) -> str:
    """A savedsearches.conf stanza name: unique by the detection's ID, and free of the brackets and
    newlines a stanza name can't hold."""
    name = re.sub(r"[\[\]\r\n]+", " ", str(doc.get("name") or "")).strip()
    return f"Shikari - {doc.get('technique_id')} - {name} - {str(doc['id'])[:8]}"


def _one_line(text: str) -> str:
    # A conf value continues onto the next line only after a trailing backslash, which a Windows
    # path in the query would collide with; SPL reads newlines as spaces, so one line is the same search
    return " ".join(line.strip() for line in str(text or "").splitlines() if line.strip())


def splunk_saved_search(doc: Dict) -> Tuple[str, Dict[str, str]]:
    severity = str(doc.get("severity") or "medium").lower()
    period = _hours(doc.get("queryPeriod"))
    return _stanza(doc), {
        # A saved search reads $name$ as an argument placeholder (`| savedsearch`, and one level of
        # substitution on scheduled runs), so a literal $ such as $env:UserName is written $$
        "search": _one_line(doc.get("query")).replace("$", "$$"),
        "description": _one_line(doc.get("description") or doc.get("name") or ""),
        "disabled": "1",
        "enableSched": "1",
        "cron_schedule": _cron(doc.get("queryFrequency")),
        "dispatch.earliest_time": f"-{period}h",
        "dispatch.latest_time": "now",
        "alert_type": "number of events",
        "alert_comparator": "greater than",
        "alert_threshold": "0",
        "alert.track": "1",
        "alert.severity": str(SPLUNK_SEVERITY.get(severity, 4)),
    }


def splunk_indexes(queries: Iterable[str]) -> List[str]:
    """The indexes the searches name, bar Splunk's own, so the app can create them."""
    found = set()
    for q in queries:
        found.update(re.findall(r"\bindex\s*=\s*\"?([A-Za-z0-9_\-]+)", q or ""))
        for group in re.findall(r"\bindex\s+IN\s*\(([^)]*)\)", q or "", re.I):
            found.update(v.strip(" \"'") for v in group.split(","))
    return sorted(i for i in found if i and i not in SPLUNK_BUILTIN_INDEXES and not i.startswith("_"))


def _conf(stanzas: Iterable[Tuple[str, Dict[str, str]]]) -> str:
    parts = []
    for name, keys in stanzas:
        parts.append(f"[{name}]\n" + "".join(f"{k} = {v}\n" for k, v in keys.items()))
    return "\n".join(parts)


def splunk_app(docs: List[Dict], version: str) -> bytes:
    """The detections as a Splunk app (.tgz): Apps → Manage Apps → Install app from file."""
    searches = [splunk_saved_search(d) for d in docs]
    indexes = splunk_indexes(d.get("query", "") for d in docs)
    app_version = re.sub(r"[^0-9.]", "", version) or "1.0.0"
    files = {
        "default/app.conf": _conf([
            ("install", {"is_configured": "0"}),
            ("ui", {"is_visible": "0", "label": "Shikari Detections"}),
            ("launcher", {"author": "Shikari", "version": app_version,
                          "description": "Detections exported from Shikari, disabled until you enable them"}),
            ("package", {"id": SPLUNK_APP}),
        ]),
        "default/savedsearches.conf": _conf(searches),
        "default/indexes.conf": _conf((i, {"homePath": f"$SPLUNK_DB/{i}/db",
                                           "coldPath": f"$SPLUNK_DB/{i}/colddb",
                                           "thawedPath": f"$SPLUNK_DB/{i}/thaweddb"}) for i in indexes),
        "default/props.conf": SPLUNK_PROPS,
        "metadata/default.meta": "[]\naccess = read : [ * ], write : [ admin ]\nexport = system\n",
    }
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for rel, text in files.items():
            data = text.encode("utf-8")
            info = tarfile.TarInfo(f"{SPLUNK_APP}/{rel}")
            info.size, info.mode, info.mtime = len(data), 0o644, 0
            tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


README = {
    "elastic": """Shikari detections for Elastic: {count} rules{scope}

Import
  Kibana → Security → Rules → Detection rules (SIEM) → Import rules → rules.ndjson.
  Tick "Overwrite existing detection rules" to update rules from an earlier pack.

The rules are ES|QL (Elastic 8.14 or later) and arrive disabled: enable the ones you want.
They query {indexes}.
""",
    "splunk": """Shikari detections for Splunk: {count} saved searches{scope}

Install
  Splunk Web → Apps → Manage Apps → Install app from file → shikari_detections.tgz.
  To update from an earlier pack, tick "Upgrade app".
  Or on the server: $SPLUNK_HOME/bin/splunk install app shikari_detections.tgz -update 1, then restart.

The searches arrive disabled: enable them under Settings → Searches, reports, and alerts
(App: Shikari Detections). The app creates the indexes they search: {indexes}.
""",
    "wazuh": """Shikari rules for Wazuh: {count} rules over {techniques} techniques{scope}

Install, on the Wazuh manager
  cp shikari_rules.xml /var/ossec/etc/rules/
  chown wazuh:wazuh /var/ossec/etc/rules/shikari_rules.xml
  /var/ossec/bin/wazuh-control restart      (or: systemctl restart wazuh-manager)
Or in the dashboard: Server management → Rules → Custom rules → Import file.

The rules match Windows events from Sysmon (process, network, file, registry, DNS) and Security
4688 (process creation, with command-line auditing on). They are built from the indicators of
Shikari's detections, so each technique's rule IDs stay the same from one pack to the next.
Check a rule against an event with /var/ossec/bin/wazuh-logtest.
""",
}


def _mapping_hash(siem: str) -> str:
    """A hash of the mapping files the queries were written with, so two packs show whether they match."""
    from shikari import paths

    names = {"splunk": ["schemas/schemaSplunk.json", "indicatorMapping.json"],
             "elastic": ["schemas/schemaElastic.json"],
             "wazuh": ["indicatorMapping.json"]}[siem]
    h = hashlib.sha256()
    for name in names:
        try:
            h.update((paths.BESPOKE / "mappings" / name).read_bytes())
        except OSError:
            pass
    return h.hexdigest()[:16]


def select(siem: str, files: Iterable[str], generate_dir: str,
           exclude_unavailable: bool = True) -> Tuple[List[Dict], List[Dict]]:
    """The SIEM's detections among `files`, and those left out with the reason. Wazuh takes every
    SIEM's, for their indicators, and the data-source check doesn't apply: it's another SIEM's."""
    import yaml

    from shikari.build.availability import load as _load_avail, missing_sources

    connector = SIEMS[siem]["connector"]
    avail = _load_avail() if exclude_unavailable else {}
    docs, excluded = [], []
    for name in files:
        path = os.path.join(generate_dir, os.path.basename(name))
        try:
            with open(path, encoding="utf-8") as fh:
                doc = yaml.safe_load(fh) or {}
        except (OSError, ValueError, yaml.YAMLError):
            continue
        if connector is None:
            if doc.get("indicators"):
                docs.append(doc)
            continue
        conns = [c.get("connectorId") for c in doc.get("requiredDataConnectors") or [] if isinstance(c, dict)]
        if connector not in conns:
            continue
        if not doc.get("id") or not str(doc.get("query") or "").strip():
            excluded.append({"file": os.path.basename(name), "reason": "no id or no query"})
            continue
        if exclude_unavailable and avail:
            miss = missing_sources(doc, avail)
            if miss:
                excluded.append({"file": os.path.basename(name),
                                 "reason": "data source not ingested: "
                                           + ", ".join(sorted({m["dataType"] for m in miss}))})
                continue
        docs.append(doc)
    return docs, excluded


def build(siem: str, group: Optional[str], generate_dir: str, list_files: Callable[[str, str], List[str]],
          bundle=None, exclude_unavailable: bool = True, wazuh_ids: Optional[str] = None,
          telemetry_run: Optional[str] = None, rebase: bool = True) -> Tuple[bytes, Dict]:
    """The pack as zip bytes, and its manifest.

    group None exports every detection in generate_dir (All); otherwise list_files(group, generate_dir)
    gives the group's files (inject group_yaml_files). wazuh_ids is the rule-ID map file (default
    data/wazuh_rule_ids.json). telemetry_run, a lab run's folder, adds its events under telemetry/,
    shifted to end now unless rebase is False."""
    if siem not in SIEMS:
        raise ValueError(f"No export pack for {siem}: choose {', '.join(SIEMS)}")
    if group:
        files = list_files(group, generate_dir)
    else:
        files = sorted(n for n in os.listdir(generate_dir) if n.endswith(".yaml")) if os.path.isdir(generate_dir) else []
    docs, excluded = select(siem, files, generate_dir, exclude_unavailable)
    version = _version()

    out: Dict[str, bytes] = {}
    extra: Dict = {}
    if siem == "wazuh":
        from shikari import paths
        from shikari.build import wazuh

        ids = wazuh.RuleIds(wazuh_ids or str(paths.DATA / "wazuh_rule_ids.json"))
        pooled = wazuh.pool(docs)
        rule_list = wazuh.rules(pooled, ids, attack_lookup(bundle)["techniques"])
        ids.save()
        out["shikari_rules.xml"] = wazuh.to_xml(
            rule_list, header=f"Shikari {version}: {group or 'All'}, {len(rule_list)} rules").encode("utf-8")
        indexes = []
        extra = {"rules": len(rule_list), "techniques": sorted(pooled)}
    elif siem == "elastic":
        attack = attack_lookup(bundle)
        rules = [elastic_rule(d, attack) for d in docs]
        out["rules.ndjson"] = "".join(json.dumps(r, ensure_ascii=False) + "\n" for r in rules).encode("utf-8")
        indexes = sorted({m.group(1) for d in docs for m in [re.match(r"\s*FROM\s+([^\s|]+)", d["query"])] if m})
    else:
        out[f"{SPLUNK_APP}.tgz"] = splunk_app(docs, version)
        indexes = splunk_indexes(d["query"] for d in docs)

    if telemetry_run:
        extra["telemetry"] = _telemetry(siem, telemetry_run, rebase, docs, out)

    manifest = {
        "siem": siem,
        "group": group or "All",
        "shikari_version": version,
        "created": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "mapping_sha256": _mapping_hash(siem),
        "detections": len(docs),
        "techniques": sorted({str(d.get("technique_id")) for d in docs if d.get("technique_id")}),
        "indexes": indexes,
        "excluded": excluded,
        **extra,
    }
    scope = f" for {group}" if group else ""
    readme = README[siem].format(count=extra.get("rules", len(docs)), scope=scope,
                                 techniques=len(manifest["techniques"]), indexes=", ".join(indexes) or "none")
    if telemetry_run:
        readme += TELEMETRY_README[siem].format(**extra["telemetry"])
    out["README.txt"] = readme.encode("utf-8")
    out["manifest.json"] = (json.dumps(manifest, indent=2) + "\n").encode("utf-8")

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in out.items():
            zf.writestr(name, data)
    return buf.getvalue(), manifest


TELEMETRY_README = {
    "elastic": """
Lab telemetry: {events} events from {run}{shifted}
  telemetry/events-*.ndjson   Elastic Defend's field names, into logs-endpoint.events.*-shikari
  Load:  ES_URL=https://localhost:9200 ES_PASSWORD=… sh telemetry/load.sh
  Then enable the rules (or open Discover on logs-endpoint.events.*) and look for the run's alerts.
""",
    "splunk": """
Lab telemetry: {events} events from {run}{shifted}, written to {targets}
  telemetry/<index>-*.json    HEC events carrying the fields these searches use, source={source}
  Install the app first (it creates the indexes and parses these events as JSON), then make an HEC
  token allowed to write to those indexes, and load:
  SPLUNK_HEC_URL=https://localhost:8088 SPLUNK_HEC_TOKEN=… sh telemetry/load.sh
""",
    "wazuh": """
Lab telemetry: {events} Windows events from {run}{shifted}
  telemetry/events.json       one event per line, as Wazuh's eventchannel decoder holds it (win.system,
                              win.eventdata). Check a rule with /var/ossec/bin/wazuh-logtest.
""",
}

LOAD_SH = {
    "elastic": """#!/bin/sh
# Loads the pack's lab events into Elasticsearch: ES_URL (default https://localhost:9200),
# ES_USER (default elastic) and ES_PASSWORD. -k accepts a local self-signed certificate.
set -e
cd "$(dirname "$0")"
for f in events-*.ndjson; do
  if curl -sS -k -u "${ES_USER:-elastic}:${ES_PASSWORD:?set ES_PASSWORD}" -H 'Content-Type: application/x-ndjson' \
       -X POST "${ES_URL:-https://localhost:9200}/_bulk?refresh=wait_for" --data-binary @"$f" | grep -q '"errors":false'; then
    echo "OK     $f"
  else
    echo "ERRORS $f: some events weren't indexed"
  fi
done
""",
    "splunk": """#!/bin/sh
# Sends the pack's lab events to Splunk's HTTP Event Collector: SPLUNK_HEC_URL (default
# https://localhost:8088) and SPLUNK_HEC_TOKEN, a token allowed to write to the indexes named in
# the file names. -k accepts a local self-signed certificate.
set -e
cd "$(dirname "$0")"
for f in *.json; do
  printf '%s  ' "$f"
  curl -sS -k "${SPLUNK_HEC_URL:-https://localhost:8088}/services/collector/event" \
       -H "Authorization: Splunk ${SPLUNK_HEC_TOKEN:?set SPLUNK_HEC_TOKEN}" --data-binary @"$f"
  echo
done
""",
}


def _telemetry(siem: str, run_dir: str, rebase: bool, docs: List[Dict], out: Dict[str, bytes]) -> Dict:
    """Adds a lab run's events to the pack's files; returns what the manifest records."""
    manifest, events = siem_telemetry.read_run(run_dir)
    run = manifest.get("run") or os.path.basename(run_dir.rstrip("/\\"))
    shift = siem_telemetry.rebase(events) if rebase else None
    info = {"run": run, "events": 0, "rebased": bool(rebase),
            "shifted": f", shifted {shift.total_seconds() / 3600:+.1f} h to end now" if shift else "",
            "source": siem_telemetry.SPLUNK_SOURCE, "targets": "none"}
    if siem == "elastic":
        for n, body in enumerate(siem_telemetry.elastic_bulk(events, run), 1):
            out[f"telemetry/events-{n:03d}.ndjson"] = body.encode("utf-8")
        out["telemetry/load.sh"] = LOAD_SH["elastic"].encode("utf-8")
        info["events"] = len(events)
    elif siem == "splunk":
        by_index = siem_telemetry.splunk_events(events, siem_telemetry.learn_splunk_fields(docs), run)
        for index, evs in sorted(by_index.items()):
            for n in range(0, len(evs), siem_telemetry.CHUNK):
                chunk = evs[n:n + siem_telemetry.CHUNK]
                out[f"telemetry/{index}-{n // siem_telemetry.CHUNK + 1:03d}.json"] = "".join(
                    json.dumps(e, ensure_ascii=False) + "\n" for e in chunk).encode("utf-8")
        out["telemetry/load.sh"] = LOAD_SH["splunk"].encode("utf-8")
        info["events"] = len({id(e) for e in events})
        info["targets"] = ", ".join(f"{i} ({len(v)})" for i, v in sorted(by_index.items())) or "none"
        info["indexes"] = {i: len(v) for i, v in by_index.items()}
    else:
        lines = [json.dumps(w, ensure_ascii=False) for w in map(siem_telemetry.to_wazuh, events) if w]
        out["telemetry/events.json"] = ("\n".join(lines) + "\n" if lines else "").encode("utf-8")
        info["events"] = len(lines)
    return info


def filename(siem: str, group: Optional[str]) -> str:
    slug = re.sub(r"[^A-Za-z0-9]+", "-", group or "all").strip("-").lower() or "all"
    return f"shikari-{siem}-{slug}.zip"
