"""
Emulation planner (#25).

Turns a target — a group, a CVE or a single technique — into a plan you review before acting: for
each technique, the most appropriate recorded dataset to validate against, the matching Atomic Red
Team test, the log sources to collect (native OS logs first), the OS platforms to run on, and the
SIEMs to validate in. "Deploy" exports the plan (MACATable TOML + run sheet); running it on a lab is
#22. No AI.
"""

import csv
import os
from typing import Dict, List, Optional

from archer.config import DATA_DIR

# How a dataset's collection ranks for a collection plan: native logs are everywhere, agents aren't.
_COLLECTION_RANK = {"native": 0, "sysmon": 1, "edr": 2, "cloud": 1, "": 3}


def _csv_lookup() -> Dict[str, Dict[str, str]]:
    """technique_id -> {name, tactic} from the MITRESaw CSV, for targets that aren't a group run."""
    path = os.path.join(DATA_DIR, "mitre_procedures.csv")
    out: Dict[str, Dict[str, str]] = {}
    if not os.path.exists(path):
        return out
    with open(path, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            tid = (row.get("technique_id") or "").strip()
            if tid and tid not in out:
                out[tid] = {"name": row.get("technique_name") or tid, "tactic": row.get("tactic") or ""}
    return out


def _resolve(kind: str, value: str, generate_dir: str) -> List[Dict]:
    """The target's techniques as [{technique_id, technique_name, tactic}]."""
    kind = (kind or "").lower()
    if kind == "technique":
        lut = _csv_lookup()
        tids = [t.strip().upper() for t in value.replace(",", " ").split() if t.strip()]
        return [{"technique_id": t, "technique_name": lut.get(t, {}).get("name", t),
                 "tactic": lut.get(t, {}).get("tactic", "")} for t in tids]
    if kind == "group":
        from archer.mitre.procedures import get_group_coverage

        cov = get_group_coverage(value, generate_dir) or {}
        techs = (cov.get("covered") or []) + (cov.get("gaps") or []) + (cov.get("intel_only") or [])
        return [{"technique_id": t["technique_id"], "technique_name": t.get("technique_name") or t["technique_id"],
                 "tactic": t.get("tactic") or ""} for t in techs]
    if kind == "cve":
        # A CVE's techniques come from the detections its hunt generated.
        from archer.build.group_files import group_yaml_files
        from archer.build.yaml import load_yaml_file

        lut = _csv_lookup()
        seen: Dict[str, Dict] = {}
        for name in group_yaml_files(value, generate_dir):
            doc = load_yaml_file(os.path.join(generate_dir, os.path.basename(name))) or {}
            tid = doc.get("technique_id")
            if tid and tid not in seen:
                seen[tid] = {"technique_id": tid, "technique_name": doc.get("name") or lut.get(tid, {}).get("name", tid),
                             "tactic": lut.get(tid, {}).get("tactic", "")}
        return list(seen.values())
    return []


def _best_dataset(recordings: List[Dict]) -> Optional[Dict]:
    """The dataset most worth validating against: one whose events are visible, most events first."""
    if not recordings:
        return None
    ranked = sorted(recordings, key=lambda r: (not r.get("visible"), -(r.get("events") or 0)))
    r = ranked[0]
    return {"source": r.get("source"), "title": r.get("title"), "platforms": r.get("platforms") or [],
            "url": r.get("url"), "events": r.get("events") or 0}


def _collect(event_types: List[Dict], limit: int = 6) -> List[Dict]:
    """Log sources to turn on, native first, de-duplicated by label."""
    rows = sorted(event_types, key=lambda e: (_COLLECTION_RANK.get(e.get("collection", ""), 3), -(e.get("recordings") or 0)))
    out, seen = [], set()
    for e in rows:
        label = e.get("label") or e.get("event")
        if label in seen:
            continue
        seen.add(label)
        out.append({"log": label, "collection": e.get("collection") or "", "event": e.get("event")})
        if len(out) >= limit:
            break
    return out


def build_plan(kind: str, value: str, siems: List[str], generate_dir: str) -> Dict:
    """A reviewable emulation plan for a target. siems are the user's SIEM keys to validate in."""
    from archer.assessments.library import atomic_index
    from archer.telemetry import check

    techniques = _resolve(kind, value, generate_dir)
    if not techniques:
        return {"success": False, "error": f"No techniques found for that {kind}."}

    atomics = atomic_index()
    steps = []
    recordable = with_atomic = 0
    for t in techniques:
        tid = t["technique_id"]
        try:
            chk = check.technique(tid)
        except Exception:
            chk = {"recordings": [], "event_types": []}
        dataset = _best_dataset(chk.get("recordings") or [])
        collect = _collect(chk.get("event_types") or [])
        atomic = (atomics.get(tid) or [None])[0]
        platforms = sorted({p for r in (chk.get("recordings") or []) for p in (r.get("platforms") or [])})
        if dataset:
            recordable += 1
        if atomic:
            with_atomic += 1
        steps.append({
            "technique_id": tid, "technique_name": t["technique_name"], "tactic": t["tactic"],
            "platforms": platforms, "dataset": dataset, "atomic_guid": atomic,
            "collect": collect, "validate_siems": siems,
            "recordings": len(chk.get("recordings") or []),
        })

    # Most prevalent/validatable first: recordable ones, then by number of recordings
    steps.sort(key=lambda s: (s["dataset"] is None, -s["recordings"]))
    return {
        "success": True,
        "target": {"kind": kind, "value": value},
        "siems": siems,
        "summary": {"techniques": len(steps), "recordable": recordable,
                    "with_atomic": with_atomic, "gaps": len(steps) - recordable},
        "techniques": steps,
    }


def plan_to_runsheet(plan: Dict) -> str:
    """A Markdown run sheet: one row per technique, what to run, collect and validate."""
    t = plan.get("target", {})
    s = plan.get("summary", {})
    out = [f"# Emulation run sheet — {t.get('kind')}: {t.get('value')}", "",
           f"{s.get('techniques', 0)} techniques · {s.get('recordable', 0)} with a reference dataset · "
           f"{s.get('with_atomic', 0)} with an Atomic test · validate in: {', '.join(plan.get('siems') or []) or '—'}",
           "", "| Technique | Tactic | Platforms | Atomic | Collect (logs) | Reference dataset |",
           "|---|---|---|---|---|---|"]
    for st in plan.get("techniques", []):
        collect = "; ".join(f"{c['log']}" for c in st.get("collect", [])) or "—"
        ds = st.get("dataset") or {}
        dataset = f"{ds.get('source', '')} {ds.get('title', '')}".strip() or "— (gap)"
        out.append(f"| {st['technique_id']} {st['technique_name']} | {st['tactic'] or '—'} | "
                   f"{', '.join(st.get('platforms') or []) or '—'} | {st.get('atomic_guid') or '—'} | "
                   f"{collect} | {dataset} |")
    out += ["", "Run the Atomics on a lab host with these logs on, then validate the detections in your SIEMs. "
            "Archer can't run them in-app yet (#22); export for MACAT to run and push results to VECTR."]
    return "\n".join(out) + "\n"


def plan_to_test_cases(plan: Dict) -> List[Dict]:
    """A plan's techniques as threat-library test-case dicts, for the MACATable export."""
    import hashlib

    target = plan.get("target", {})
    label = f"{target.get('kind')}:{target.get('value')}"
    cases = []
    for s in plan.get("techniques", []):
        sig = hashlib.sha1(f"plan|{label}|{s['technique_id']}".encode()).hexdigest()
        cases.append({"signature": sig, "technique_id": s["technique_id"], "technique_name": s["technique_name"],
                      "tactic": s["tactic"], "procedure": "", "atomic_guid": s.get("atomic_guid"),
                      "group_name": target.get("value") if target.get("kind") == "group" else "",
                      "indicators": {}})
    return cases
