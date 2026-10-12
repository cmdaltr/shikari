"""
Threat briefing for a run, without AI: coverage, the weakest stage of the kill chain and
the gaps to close first, from the run's attack flow (archer.visualization.flow_view) and
the techniques it built nothing for (run_files' no_detection manifest).

Gaps are techniques ATT&CK attributes to the group that have no detection, plus the
run's own techniques that produced none, so a CVE, report or technique hunt (no ATT&CK
attribution) still gets one. The earlier a gap sits in the kill chain, the sooner a
detection there interrupts an intrusion, so gaps are ranked by tactic, then by how many
correlation links the technique has.

An AI-written summary is optional (POST /api/briefing/summary): it's saved beside the
attack flows and shown until the run changes.
"""

import json
import os
import time
from typing import Dict, List, Optional

from archer.config import DATA_DIR

TOP_GAPS = 5
BRIEFINGS_DIR = os.path.join(DATA_DIR, "briefings")


def build(flow: Optional[Dict], no_detection: Optional[List[Dict]] = None) -> Optional[Dict]:
    """The briefing for a results page; None when the run has no attack flow."""
    lanes = (flow or {}).get("lanes") or []
    if not lanes:
        return None
    from archer.visualization.flow_view import _lane_index

    why = {m.get("technique"): m.get("text") or m.get("reason") or "" for m in no_detection or []}
    tactics, gaps, total, detected = [], [], 0, 0
    for lane in lanes:
        nodes = lane.get("nodes") or []
        hit = sum(1 for n in nodes if n.get("detected"))
        total += len(nodes)
        detected += hit
        tactics.append({"tactic": lane["tactic"], "total": len(nodes), "detected": hit})
        for n in nodes:
            if not n.get("detected") and (n.get("attributed") or n["id"] in why):
                gaps.append({"id": n["id"], "name": n.get("name", n["id"]), "tactic": lane["tactic"],
                             "url": n.get("url"), "why": why.get(n["id"], "ATT&CK attributes it; no detection yet"),
                             "order": (_lane_index(lane["tactic"]), -(n.get("degree") or 0), n["id"])})
    # Techniques the run built nothing for that never reached the flow
    in_flow = {n["id"] for lane in lanes for n in lane.get("nodes") or []}
    for tid, text in why.items():
        if tid and tid not in in_flow:
            gaps.append({"id": tid, "name": tid, "tactic": "", "url": "https://attack.mitre.org/techniques/"
                         + tid.replace(".", "/") + "/", "why": text, "order": (99, 0, tid)})
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
        "tactics": tactics, "weakest": weakest, "gaps": gaps[:TOP_GAPS], "more_gaps": max(0, len(gaps) - TOP_GAPS),
        "summary": _sentences(total, detected, len(tactics), weakest, gaps),
    }


def _sentences(total: int, detected: int, n_tactics: int, weakest: Optional[Dict], gaps: List[Dict]) -> str:
    pct = round(100 * detected / total) if total else 0
    parts = [f"Archer has detections for {detected} of {total} techniques ({pct}%) across {n_tactics} "
             f"tactic{'s' if n_tactics != 1 else ''}."]
    if weakest:
        parts.append(f"The weakest stage is {weakest['tactic']}: {weakest['detected']} of {weakest['total']} detected.")
    if gaps:
        first = ", ".join(f"{g['id']} {g['name']}" if g["name"] != g["id"] else g["id"] for g in gaps[:3])
        parts.append(f"Close the earliest gaps first: {first}.")
    else:
        parts.append("Every technique in this run has a detection.")
    return " ".join(parts)


# ---------------------------------------------------------------------------
# Optional AI summary
# ---------------------------------------------------------------------------

def prompt(group: str, briefing: Dict) -> str:
    """Facts for the model: it writes prose from these, nothing else."""
    lines = [f"Run: {group.replace('_', ' ')}",
             f"Coverage: {briefing['detected']} of {briefing['techniques']} techniques ({briefing['coverage']}%)",
             "By tactic, in kill-chain order: " + "; ".join(
                 f"{t['tactic']} {t['detected']}/{t['total']}" for t in briefing["tactics"])]
    if briefing["weakest"]:
        lines.append(f"Weakest tactic: {briefing['weakest']['tactic']}")
    if briefing["gaps"]:
        lines.append("Earliest gaps: " + "; ".join(f"{g['id']} {g['name']} ({g['tactic'] or 'no tactic'}): {g['why']}"
                                                  for g in briefing["gaps"]))
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
