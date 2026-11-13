"""
A master hunt query for Defender XDR: one KQL query that runs every MDE detection a
hunt produced and ranks devices by how many of the group's techniques they show.

Each detection becomes a function (let D1 = () { <its query> | extend Technique, Detection };),
so a query's own let statements stay inside it. The functions are unioned (isfuzzy, so a table
the tenant doesn't have doesn't fail the whole query), and the result is summarised per device
and account: the techniques seen, when, and the commands behind them. A device showing several
of one group's techniques is the campaign signal a single detection can't give.

Built from the library's queries, no AI. A query that fails Shikari's static check is left out
and listed in the header.
"""

import os
import re
from datetime import datetime, timezone
from typing import Callable, Dict, List, Optional, Tuple

import yaml

from shikari.reports import tlp as tlp_mod

MDE_CONNECTOR = "MicrosoftThreatProtection"
# A whole group's library is hundreds of detections (Sandworm Team: 497, 400 KB of KQL), too much for
# one advanced hunting query. By default each technique keeps one, from the table most likely to see
# the activity; scope to a campaign's techniques and raise per_technique for more.
_TABLE_ORDER = ["DeviceProcessEvents", "DeviceEvents", "DeviceFileEvents", "DeviceRegistryEvents",
                "DeviceNetworkEvents", "DeviceImageLoadEvents", "DeviceLogonEvents"]
_WINDOW = re.compile(r"\bTimestamp\s*>=?\s*ago\(\s*\d+[smhd]\s*\)")
_LOOKBACK = re.compile(r"^\d{1,4}[hd]$")
# Warnings for a query on its own, but one function that doesn't parse fails the whole master query:
# unbalanced quotes or brackets, and a backslash escape in an ordinary string
_BREAKS_THE_UNION = {"KQL-5", "KQL-16", "KQL-17"}


def _detections(group: Optional[str], generate_dir: str, group_files: Callable) -> List[Dict]:
    paths = group_files(group, generate_dir) if group else sorted(
        os.path.join(generate_dir, f) for f in os.listdir(generate_dir) if f.endswith(".yaml"))
    out = []
    for path in paths:
        try:
            with open(path, encoding="utf-8") as fh:
                doc = yaml.safe_load(fh) or {}
        except (OSError, yaml.YAMLError):
            continue
        connectors = [c.get("connectorId") for c in doc.get("requiredDataConnectors") or [] if isinstance(c, dict)]
        if MDE_CONNECTOR in connectors and (doc.get("query") or "").strip():
            out.append({"file": os.path.basename(path), "name": doc.get("name") or "",
                        "technique": doc.get("technique_id") or "", "query": doc["query"].strip()})
    return sorted(out, key=lambda d: (d["technique"], d["file"]))


def _kql_string(s: str) -> str:
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _table_rank(query: str) -> int:
    first = query.lstrip().split("\n", 1)[0].strip()
    return _TABLE_ORDER.index(first) if first in _TABLE_ORDER else len(_TABLE_ORDER)


def build(group: Optional[str], generate_dir: str, group_files: Callable, tlp: str = "",
          lookback: str = "30d", techniques: Optional[List[str]] = None, per_technique: int = 1,
          now: Optional[datetime] = None) -> Tuple[str, Dict]:
    """(the master query, a manifest of what went in and what was left out). techniques limits it to
    those IDs (a sub-technique's parent takes in its sub-techniques); per_technique is how many
    detections each technique keeps (0: all)."""
    from shikari.validation.static_check import check_query

    label = tlp_mod.normalise(tlp)
    if not _LOOKBACK.match(lookback or ""):
        raise ValueError(f"Lookback {lookback!r}: give hours or days, such as 24h or 30d")
    stamp = (now or datetime.now(timezone.utc)).strftime("%Y-%m-%d %H:%M UTC")

    wanted = {t.strip().upper() for t in techniques or [] if t.strip()}
    chosen, capped = [], 0
    by_technique: Dict[str, List[Dict]] = {}
    for d in _detections(group, generate_dir, group_files):
        if wanted and d["technique"] not in wanted and d["technique"].split(".")[0] not in wanted:
            continue
        by_technique.setdefault(d["technique"], []).append(d)
    for tid in sorted(by_technique):
        ranked = sorted(by_technique[tid], key=lambda d: (_table_rank(d["query"]), d["file"]))
        keep = ranked[:per_technique] if per_technique > 0 else ranked
        capped += len(ranked) - len(keep)
        chosen += keep

    functions, used, excluded = [], [], []
    for d in chosen:
        result = check_query(d["query"], "kql")
        fatal = [f for f in result.get("findings") or []
                 if f.get("severity") == "error" or f.get("check") in _BREAKS_THE_UNION]
        if fatal:
            excluded.append({"file": d["file"], "reason": "; ".join(f["message"] for f in fatal)[:200]})
            continue
        body = _WINDOW.sub("Timestamp between (StartTime .. EndTime)", d["query"]).rstrip().rstrip(";")
        name = f"D{len(functions) + 1}"
        functions.append(
            f"// {d['technique']} {d['name']} ({d['file']})\n"
            f"let {name} = () {{\n{body}\n| extend Technique = {_kql_string(d['technique'])}, "
            f"Detection = {_kql_string(d['name'])}\n}};")
        used.append({"function": name, "file": d["file"], "technique": d["technique"]})

    techniques = sorted({u["technique"] for u in used})
    header = [
        "// " + "=" * 74,
        "// Shikari master hunt query: Defender XDR advanced hunting",
        f"// Scope     : {group.replace('_', ' ') if group else 'every detection in the library'}",
        f"// Generated : {stamp}",
        f"// {label}  {tlp_mod.rule(label)}",
        f"// Window    : the last {lookback} (each detection's own window is replaced)",
        f"// Detections: {len(used)}, covering {len(techniques)} techniques",
    ]
    if techniques:
        header.append("// Techniques: " + ", ".join(techniques))
    if capped:
        header.append(f"// Not shown : {capped} more detections for these techniques (one per technique; "
                      "raise per-technique to include them)")
    if excluded:
        header.append(f"// Left out  : {len(excluded)} that fail Shikari's static check: "
                      + ", ".join(e["file"] for e in excluded))
    header += [
        "// Result    : one row per device and account, most techniques first. Several of one",
        "//             group's techniques on a device is the campaign signal.",
        "// " + "=" * 74,
    ]
    if not used:
        text = "\n".join(header) + "\n// No Defender XDR detections to combine.\n"
        return text, {"group": group, "tlp": label, "detections": 0, "techniques": [], "excluded": excluded,
                      "capped": capped}

    names = ", ".join(f"{u['function']}()" for u in used)
    final = f"""union isfuzzy=true {names}
| extend Seen = coalesce(todatetime(column_ifexists("Timestamp", datetime(null))),
                         todatetime(column_ifexists("FirstSeen", datetime(null))))
| extend Device = tostring(column_ifexists("DeviceName", "")),
         Account = tostring(column_ifexists("AccountName", "")),
         Command = tostring(column_ifexists("ProcessCommandLine", ""))
| summarize FirstEvidence = min(Seen), LastEvidence = max(Seen), Techniques = make_set(Technique),
            Detections = make_set(Detection, 50), EvidenceCommands = make_set_if(Command, isnotempty(Command), 25),
            Hits = count() by Device, Account
| extend TechniqueCount = array_length(Techniques)
| project FirstEvidence, LastEvidence, Device, Account, TechniqueCount, Techniques, Detections, Hits, EvidenceCommands
| order by TechniqueCount desc, LastEvidence desc"""
    text = "\n".join(header) + "\n\n" + f"let StartTime = ago({lookback});\nlet EndTime = now();\n\n" \
        + "\n\n".join(functions) + "\n\n" + final + "\n"
    return text, {"group": group, "tlp": label, "detections": len(used), "techniques": techniques,
                  "functions": used, "excluded": excluded, "lookback": lookback, "capped": capped}


def filename(group: Optional[str]) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", (group or "all").lower()).strip("-") or "all"
    return f"shikari-master-hunt-{slug}.kql"
