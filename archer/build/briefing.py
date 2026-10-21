"""
Threat briefing for a run, without AI: coverage, the weakest tactic and the gaps to close
first, from the run's attack flow (archer.visualization.flow_view) and the techniques it
built nothing for (run_files' no_detection manifest).

Gaps are techniques ATT&CK attributes to the group that have no detection, plus the
run's own techniques that produced none, so a CVE, report or technique hunt (no ATT&CK
attribution) still gets one. Sub-techniques the run expanded from an attributed parent
(the flow's via_parent) aren't the group's: they're extra coverage, outside the count
and never gaps. ATT&CK isn't a sequence, so a gap's tactic position says
nothing about when it matters. Gaps are ranked by what closes them: one you can build
now (indicators exist, or the run never tried it) before one that needs research
(no indicators anywhere); then by severity (archer.build.severity: an alert there means
damage is under way); then by correlation links, which make a detection worth more.

An AI-written summary is optional (POST /api/briefing/summary): it's saved beside the
attack flows and shown until the run changes.
"""

import json
import os
import time
from typing import Dict, List, Optional

from archer.config import DATA_DIR

TOP_GAPS = 5

# How a gap closes, best first: (rank, what to do)
ACTIONS = {
    "build": (0, "Build it: ATT&CK attributes it and this run built nothing for it"),
    "source": (1, "Map a data source: it has indicators, but none fit a configured source"),
    "research": (2, "Needs research: no indicators from ATT&CK or OSINT"),
}
_REASON_ACTION = {"no_source": "source", "osint_empty": "research", "no_indicators": "research", "llm_empty": "research"}
BRIEFINGS_DIR = os.path.join(DATA_DIR, "briefings")


def build(flow: Optional[Dict], no_detection: Optional[List[Dict]] = None) -> Optional[Dict]:
    """The briefing for a results page; None when the run has no attack flow."""
    lanes = (flow or {}).get("lanes") or []
    if not lanes:
        return None
    from archer.build.severity import RATINGS, rate

    from archer.build.technique_yield import REASONS

    why = {m.get("technique"): m.get("text") or REASONS.get(m.get("reason"), m.get("reason") or "") for m in no_detection or []}
    reason = {m.get("technique"): m.get("reason") for m in no_detection or []}

    def gap(tid, name, tactic, url, degree):
        action = _REASON_ACTION.get(reason.get(tid), "build" if tid not in why else "research")
        severity = rate([tactic]) if tactic else "Medium"
        return {"id": tid, "name": name, "tactic": tactic, "url": url, "action": action,
                "todo": ACTIONS[action][1], "severity": severity,
                "why": why.get(tid, "ATT&CK attributes it; no detection yet"),
                "order": (ACTIONS[action][0], -RATINGS.index(severity), -(degree or 0), tid)}
    tactics, gaps, total, detected = [], [], 0, 0
    # Intel-only techniques (adversary-side Reconnaissance/Resource Development,
    # archer.tactic_scope) are neither coverage nor gaps
    intel = {n["id"] for lane in lanes for n in lane.get("nodes") or [] if n.get("intel_only")}
    from archer.visualization.flow_view import via_parent
    attributed_ids = {n["id"] for lane in lanes for n in lane.get("nodes") or [] if n.get("attributed")}
    extra = {n["id"]: n.get("detected") for lane in lanes for n in lane.get("nodes") or [] if n.get("via_parent")}
    for lane in lanes:
        nodes = [n for n in lane.get("nodes") or [] if n["id"] not in intel and n["id"] not in extra]
        n_intel = sum(1 for n in lane.get("nodes") or [] if n["id"] in intel)
        if not nodes:
            if n_intel:  # e.g. Resource Development: shown, but nothing to detect
                tactics.append({"tactic": lane["tactic"], "total": 0, "detected": 0, "intel": n_intel})
            continue
        hit = sum(1 for n in nodes if n.get("detected"))
        total += len(nodes)
        detected += hit
        tactics.append({"tactic": lane["tactic"], "total": len(nodes), "detected": hit, "intel": n_intel})
        for n in nodes:
            if not n.get("detected") and (n.get("attributed") or n["id"] in why):
                gaps.append(gap(n["id"], n.get("name", n["id"]), lane["tactic"], n.get("url"), n.get("degree")))
    # Techniques the run built nothing for that never reached the flow
    in_flow = {n["id"] for lane in lanes for n in lane.get("nodes") or []}
    for tid, text in why.items():
        if tid and tid not in in_flow and tid not in intel and not via_parent(tid, attributed_ids):
            gaps.append(gap(tid, tid, "", "https://attack.mitre.org/techniques/" + tid.replace(".", "/") + "/", 0))
    gaps.sort(key=lambda g: g["order"])
    for g in gaps:
        g.pop("order")

    weakest = min((t for t in tactics if t["total"] >= 2), default=None,
                  key=lambda t: (t["detected"] / t["total"], -t["total"]))
    if weakest and weakest["detected"] == weakest["total"]:
        weakest = None
    return {
        "techniques": total, "detected": detected, "gap_count": len(gaps),
        "coverage": round(100 * detected / total) if total else 0,
        "attributed": bool(attributed_ids),
        "extra_detected": sum(1 for hit in extra.values() if hit), "extra_total": len(extra),
        "tactics": tactics, "weakest": weakest, "gaps": gaps[:TOP_GAPS], "more_gaps": max(0, len(gaps) - TOP_GAPS),
        "by_action": {a: sum(1 for g in gaps if g["action"] == a) for a in ACTIONS},
        "build_ids": [g["id"] for g in gaps if g["action"] == "build"],
        "summary": _sentences(total, detected, sum(1 for t in tactics if t["total"]), weakest, gaps, bool(attributed_ids),
                              sum(1 for hit in extra.values() if hit)),
    }


def _sentences(total: int, detected: int, n_tactics: int, weakest: Optional[Dict], gaps: List[Dict],
               attributed: bool = False, extra: int = 0) -> str:
    pct = round(100 * detected / total) if total else 0
    parts = [f"Archer has detections for {detected} of {total} {'attributed ' if attributed else ''}techniques "
             f"({pct}%) across {n_tactics} tactic{'s' if n_tactics != 1 else ''}."]
    if extra:
        parts.append(f"It also covers {extra} sub-technique{'s' if extra != 1 else ''} of attributed techniques "
                     f"that ATT&CK doesn't attribute to the group.")
    if weakest:
        parts.append(f"The weakest tactic is {weakest['tactic']}: {weakest['detected']} of {weakest['total']} detected.")
    if gaps:
        first = ", ".join(f"{g['id']} {g['name']}" if g["name"] != g["id"] else g["id"] for g in gaps[:3])
        parts.append(f"Close first: {first}.")
    else:
        parts.append("Every technique in this run has a detection.")
    return " ".join(parts)


# ---------------------------------------------------------------------------
# Optional AI summary
# ---------------------------------------------------------------------------

def prompt(group: str, briefing: Dict) -> str:
    """Facts for the model: it writes prose from these, nothing else."""
    lines = [f"Run: {group.replace('_', ' ')}",
             f"Coverage: {briefing['detected']} of {briefing['techniques']} {'attributed ' if briefing.get('attributed') else ''}"
             f"techniques ({briefing['coverage']}%)"
             + (f"; plus {briefing['extra_detected']} unattributed sub-techniques of attributed ones"
                if briefing.get("extra_detected") else ""),
             "By ATT&CK tactic (not a sequence: groups use tactics in any order): " + "; ".join(
                 f"{t['tactic']} {t['detected']}/{t['total']}" for t in briefing["tactics"] if t["total"])]
    if briefing["weakest"]:
        lines.append(f"Weakest tactic: {briefing['weakest']['tactic']}")
    if briefing["gaps"]:
        lines.append("Gaps to close first (buildable before research, then by severity): " + "; ".join(
            f"{g['id']} {g['name']} ({g['tactic'] or 'no tactic'}, {g['severity']}): {g['todo']}" for g in briefing["gaps"]))
    return ("Write a threat briefing of 3 to 5 sentences for a detection engineer, in British English, "
            "from these facts only. Say what is covered, where the risk is, and what to build next. "
            "No headings, no lists, no preamble.\n\n" + "\n".join(lines))


def _path(group: str) -> str:
    return os.path.join(BRIEFINGS_DIR, f"{group}.json")


def load_summary(group: str, briefing: Optional[Dict]) -> Optional[Dict]:
    """The saved AI summary, if it was written for this same coverage."""
    path = _path(group)
    if not briefing or os.path.dirname(os.path.abspath(path)) != os.path.abspath(BRIEFINGS_DIR):
        return None
    try:
        with open(path, encoding="utf-8") as fh:
            saved = json.load(fh)
    except (OSError, ValueError):
        return None
    return saved if saved.get("key") == _key(briefing) else None


def save_summary(group: str, briefing: Dict, text: str, provider: str) -> Dict:
    saved = {"key": _key(briefing), "text": text.strip(), "provider": provider, "written": time.time()}
    os.makedirs(BRIEFINGS_DIR, exist_ok=True)
    with open(_path(group), "w", encoding="utf-8") as fh:
        json.dump(saved, fh)
    return saved


def _key(briefing: Dict) -> str:
    return f"{briefing['techniques']}:{briefing['detected']}:" + ",".join(g["id"] for g in briefing["gaps"])
