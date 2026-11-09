"""
What an assessment report says (#42), worked out from the recorded outcomes and the detection
library: no AI. assessment_report.py lays it out as Word and PDF.

Risk is likelihood x impact, each 1-3. Likelihood is what the attack did (executed 3, failed 2,
blocked 1); impact is what the defence saw (not logged 3, logged 2, alerted or prevented 1).
A test that wasn't run, or whose defence wasn't assessed, isn't rated.
"""

import os
import re
from collections import Counter, OrderedDict
from datetime import date
from typing import Dict, Iterable, List, Optional, Tuple

from shikari.reports.assessment_charts import BLUE_OUTCOMES, RED_OUTCOMES, rating_for
from shikari.visualization.flow_view import TACTIC_ORDER, canonical_tactic

BLUE_LABEL = {k: label for k, label, _ in BLUE_OUTCOMES}
RED_LABEL = {k: label for k, label, _ in RED_OUTCOMES}
LIKELIHOOD = {"executed": 3, "failed": 2, "blocked": 1}
IMPACT = {"not_logged": 3, "logged": 2, "alerted": 1, "prevented": 1}
LEVEL = {1: "Low", 2: "Medium", 3: "High"}
_RANK = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Unrated": 4}
_BLUE_WORST = ["not_logged", "logged", "alerted", "prevented", "not_assessed"]

_TID = re.compile(r"^technique_id: *(\S+)", re.M)
_NAME = re.compile(r"^name: *(.+)$", re.M)
_CONNECTOR = re.compile(r"connectorId: *(\S+)")
_AI_WRITTEN = re.compile(r"Generated via llm")   # build/detections.py's mark on an LLM-written detection
AI_MARK = "\u2020"   # a dagger: generated or influenced by AI, see ai_disclaimer()
_VENDORS = (("GoogleSecOps", "Google SecOps"), ("MicrosoftThreatProtection", "Defender XDR"),
            ("Splunk", "Splunk"), ("Elastic", "Elastic"))


def library_index(generate_dir: str) -> Dict[str, List[Dict]]:
    """{technique ID: [{file, name, siem}]} over every detection in the library."""
    index: Dict[str, List[Dict]] = {}
    entries = sorted(os.scandir(generate_dir), key=lambda e: e.name) if os.path.isdir(generate_dir) else []
    for entry in entries:
        if not entry.name.endswith(".yaml"):
            continue
        try:
            with open(entry.path, encoding="utf-8") as fh:
                text = fh.read()
        except OSError:
            continue
        tid = _TID.search(text)
        if not tid:
            continue
        connector = (_CONNECTOR.search(text) or [None, ""])[1]
        name = (_NAME.search(text) or [None, ""])[1].strip().strip("'\"")
        index.setdefault(tid.group(1), []).append({
            "file": entry.name, "name": name, "ai": bool(_AI_WRITTEN.search(text)),
            "siem": next((v for k, v in _VENDORS if k.lower() in connector.lower()), connector or "Unknown")})
    return index


def _tactic(raw: Optional[str]) -> str:
    first = (raw or "").split(",")[0].strip()
    return canonical_tactic(first) if first else "Unmapped"


def _tactic_key(t: str) -> int:
    return TACTIC_ORDER.index(t) if t in TACTIC_ORDER else len(TACTIC_ORDER)


def _pct(n: int, d: int) -> int:
    return round(100 * n / d) if d else 0


def build(assessment: Dict, results: List[Dict], generate_dir: str,
          lab_runs: Iterable[Tuple[str, Dict]] = (), summary: str = "", conclusion: str = "",
          today: Optional[date] = None) -> Dict:
    """Everything the report shows. assessment: name, target, operator, run_date, notes.
    results: technique_id, technique_name, tactic, red_outcome, blue_outcome, detection_file,
    notes, and from the test case procedure, group_name, source."""
    library = library_index(generate_dir)
    library_total = sum(len(v) for v in library.values())

    rows = []
    for r in results:
        red, blue = r.get("red_outcome") or "not_run", r.get("blue_outcome") or "not_assessed"
        lk, im = LIKELIHOOD.get(red), IMPACT.get(blue)
        rating = rating_for(lk * im) if lk and im else "Unrated"
        fired = r.get("detection_file") or ""
        fired_entry = next((d for ds in library.values() for d in ds if d["file"] == fired), {}) if fired else {}
        lib = library.get(r.get("technique_id") or "", [])
        rows.append({**r, "red_outcome": red, "blue_outcome": blue, "tactic_name": _tactic(r.get("tactic")),
                     "likelihood": lk, "impact": im, "score": (lk or 0) * (im or 0), "rating": rating,
                     "fired": fired, "fired_siem": fired_entry.get("siem", ""), "fired_ai": bool(fired_entry.get("ai")),
                     "library": lib, "library_ai": any(d["ai"] for d in lib)})
    rows.sort(key=lambda x: (_RANK[x["rating"]], -x["score"], x.get("technique_id") or ""))
    for i, x in enumerate(rows, 1):
        x["ref"] = f"F-{i:02d}"

    blue = Counter(x["blue_outcome"] for x in rows)
    red = Counter(x["red_outcome"] for x in rows)
    assessed = sum(n for k, n in blue.items() if k != "not_assessed")
    detected = blue["alerted"] + blue["prevented"]
    visible = detected + blue["logged"]

    by_tactic: Dict[str, Counter] = {}
    matrix: Dict[str, Dict[str, str]] = {}
    for x in rows:
        by_tactic.setdefault(x["tactic_name"], Counter())[x["blue_outcome"]] += 1
        cell = matrix.setdefault(x["tactic_name"], {})
        tid = x.get("technique_id") or "?"
        prev = cell.get(tid)
        # A technique tested more than once shows its worst outcome: the gap is what matters.
        if prev is None or _BLUE_WORST.index(x["blue_outcome"]) < _BLUE_WORST.index(prev):
            cell[tid] = x["blue_outcome"]
    tactic_order = sorted(by_tactic, key=_tactic_key)

    rated = [x for x in rows if x["rating"] != "Unrated"]
    heat = Counter((x["likelihood"], x["impact"]) for x in rated)
    ratings = Counter(x["rating"] for x in rated)
    gaps = [x for x in rows if x["blue_outcome"] in ("logged", "not_logged")]
    # Ready: logged, and the library already has a detection, so deploying it closes the gap.
    # A technique that wasn't logged needs its logging turned on first, whatever the library holds.
    ready = [x for x in gaps if x["library"] and x["blue_outcome"] == "logged"]

    techniques = sorted({x.get("technique_id") for x in rows if x.get("technique_id")})
    groups = sorted({x.get("group_name") for x in rows if x.get("group_name")})
    bases = {t.split(".")[0] for t in techniques}
    runs = []
    for name, manifest in lab_runs:
        tests = manifest.get("tests") or []
        hit = sorted({t.get("technique") for t in tests if (t.get("technique") or "").split(".")[0] in bases})
        if hit:
            runs.append({"run": name, "tool": manifest.get("tool") or "", "host": manifest.get("host") or "",
                         "platform": manifest.get("platform") or "", "started": (manifest.get("started") or "")[:16]
                         .replace("T", " "), "techniques": hit, "tests": len(tests)})

    ai_findings = any(x["fired_ai"] or x["library_ai"] for x in rows)
    ai_gaps = any(x["library_ai"] for x in gaps)
    ai_sections = set()
    if ai_findings:
        ai_sections.add("Findings")
    if ai_gaps:
        ai_sections.update({"Executive Summary", "Recommendations", "Appendices"})
    return {
        "ai_any": ai_findings, "ai_gaps": ai_gaps, "ai_sections": ai_sections,
        "assessment": assessment,
        "report_date": (today or date.today()).strftime("%d %B %Y").lstrip("0"),
        "summary": (summary or assessment.get("notes") or "").strip(),
        "conclusion": (conclusion or "").strip(),
        "rows": rows, "techniques": techniques, "groups": groups,
        "tactics": tactic_order,
        "by_tactic": OrderedDict((t, dict(by_tactic[t])) for t in tactic_order),
        "matrix": OrderedDict((t, sorted(matrix[t].items())) for t in tactic_order),
        "blue": dict(blue), "red": dict(red),
        "assessed": assessed, "detected": detected, "visible": visible,
        "detection_rate": _pct(detected, assessed), "visibility": _pct(visible, assessed),
        "rated": rated, "heat": dict(heat), "ratings": dict(ratings),
        "high_or_worse": ratings["Critical"] + ratings["High"],
        "gaps": gaps, "ready": len(ready), "unready": len(gaps) - len(ready),
        "library_total": library_total, "lab_runs": runs,
        "tactic_weakest": _weakest(by_tactic),
    }


def _weakest(by_tactic: Dict[str, Counter]) -> List[Tuple[str, int, int]]:
    """Tactics by how many of their assessed tests the defence missed: [(tactic, missed, assessed)]."""
    out = []
    for t, c in by_tactic.items():
        assessed = sum(n for k, n in c.items() if k != "not_assessed")
        missed = c["logged"] + c["not_logged"]
        if missed:
            out.append((t, missed, assessed))
    return sorted(out, key=lambda x: (-x[1] / max(x[2], 1), -x[1], _tactic_key(x[0])))


# ── Words ─────────────────────────────────────────────────────────────────────

def plural(n: int, word: str, many: str = "") -> str:
    return f"{n} {word if n == 1 else (many or word + 's')}"


def executive_paragraphs(c: Dict) -> List[str]:
    a = c["assessment"]
    if not c["rows"]:
        return [f"No test cases had been added to {a.get('name') or 'this assessment'} when this report "
                "was produced, so there are no outcomes to report."]
    against = f" against {a['target']}" if a.get("target") else ""
    when = f" on {a['run_date']}" if a.get("run_date") else ""
    who = f", emulating {_and(c['groups'])}" if c["groups"] else ""
    out = [f"This assessment tested {plural(len(c['techniques']), 'MITRE ATT&CK technique')}"
           f"{against}{when}{who}, across {plural(len(c['tactics']), 'tactic')}."]
    if c["assessed"]:
        b = c["blue"]
        out.append(
            f"Of the {plural(c['assessed'], 'test')} whose defensive outcome was assessed, "
            f"{b.get('prevented', 0)} {'was' if b.get('prevented', 0) == 1 else 'were'} prevented and "
            f"{b.get('alerted', 0)} raised an alert: a detection rate of {c['detection_rate']}%. "
            f"A further {b.get('logged', 0)} {'was' if b.get('logged', 0) == 1 else 'were'} logged without an alert, "
            f"and {b.get('not_logged', 0)} left no trace in the logs at all.")
    else:
        out.append("No defensive outcomes had been recorded yet, so detection and visibility can't be measured.")
    if c["rated"]:
        out.append(f"{plural(c['high_or_worse'], 'finding')} {'is' if c['high_or_worse'] == 1 else 'are'} rated "
                   f"High or Critical. "
                   + (_gap_sentence(c) + (AI_MARK if c["ai_gaps"] else "") if c["gaps"] else "No detection gaps were found."))
    return out


def _gap_sentence(c: Dict) -> str:
    n = len(c["gaps"])
    if c["ready"] == n:
        return f"All {plural(n, 'detection gap')} could be closed by deploying detections already in the Shikari library."
    if not c["ready"]:
        return f"None of the {plural(n, 'detection gap')} can be closed by deploying a detection alone: each needs logging or a new detection first."
    return (f"Of the {plural(n, 'detection gap')}, {c['ready']} could be closed by deploying detections already in the "
            f"Shikari library; {c['unready']} need logging or a new detection first.")


def no_gaps_sentence(c: Dict) -> str:
    if not c["assessed"]:
        return "No defensive outcomes had been recorded, so no detection gaps could be identified."
    return "No detection gaps were found: every assessed test was alerted on or prevented."


def gaps_paragraph(c: Dict) -> str:
    return (_gap_sentence(c) + (AI_MARK if c["ai_gaps"] else "") + " Appendix E lists the library's candidate detections for every gap; those for "
            "techniques that weren't logged only work once the logging is on.")


def conclusion_paragraphs(c: Dict) -> List[str]:
    if not c["rows"]:
        return ["With no recorded outcomes there is nothing to conclude yet. Add the test cases, record what "
                "the attack did and what the defence saw, and produce this report again."]
    out = []
    rate = c["detection_rate"]
    if c["assessed"]:
        if rate >= 80:
            verdict = "The defence detected or stopped most of what was run"
        elif rate >= 50:
            verdict = "The defence detected or stopped about half of what was run"
        else:
            verdict = "Most of what was run went undetected"
        out.append(f"{verdict}: {c['detected']} of {c['assessed']} assessed tests ({rate}%). "
                   f"Visibility, the share that reached the logs at all, was {c['visibility']}%.")
    weak = c["tactic_weakest"][:3]
    if weak:
        parts = [f"{t} ({m} of {n} missed)" for t, m, n in weak]
        out.append(f"The weakest areas were {_and(parts)}.")
    if c["ready"]:
        out.append(f"{c['ready']} of the {plural(len(c['gaps']), 'gap')} can be closed quickly: the activity was "
                   "logged and the Shikari library already holds detections for it, so deploying and tuning those "
                   "is the fastest improvement available."
                   + (f" The remaining {c['unready']} need logging or a new detection first." if c["unready"] else ""))
    elif c["gaps"]:
        out.append(f"None of the {plural(len(c['gaps']), 'gap')} can be closed by deploying a detection alone: each "
                   "needs logging turned on or a new detection written first.")
    out.append("Re-run the same test cases once the recommendations are in place, so the next report measures "
               "the change against this one.")
    return out


def assumptions(c: Dict) -> List[str]:
    a = c["assessment"]
    return [
        "Outcomes are as the operator recorded them in Shikari when this report was produced. Shikari did not "
        "verify them independently.",
        f"Tests ran against {a.get('target') or 'the target environment'} as it was configured"
        f"{' on ' + a['run_date'] if a.get('run_date') else ' at the time of testing'}. Changes made since, to "
        "controls, logging or detections, may change the outcomes.",
        "An executed test means the procedure ran to completion on the host. It does not mean the attacker "
        "achieved their objective beyond that step.",
        "Tests marked not run, or whose defence was not assessed, are excluded from the detection rate, "
        "visibility and risk ratings.",
        f"Candidate detections come from the Shikari detection library as it stood on {c['report_date']} "
        f"({plural(c['library_total'], 'detection')}). They have not been tuned for this environment and need "
        "testing before they go live.",
        "Risk ratings use the likelihood and impact model in Appendix B, not the organisation's own risk "
        "framework. Map them across before they enter a risk register.",
        "The procedures were emulations of the named adversaries' published tradecraft (MITRE ATT&CK). Real "
        "intrusions vary, and a technique detected here can still be missed with a different procedure.",
        "No AI wrote this report: every number and statement is computed from the recorded outcomes and the "
        f"detection library. Detections in the library that were written with an AI model are marked {AI_MARK}, as "
        "is every section that cites one; the disclaimer at the end of the report applies to them.",
    ]


def recommendation_for(x: Dict) -> str:
    n = len(x["library"])
    have = f"Deploy and tune the {plural(n, 'library detection')} for it" if n else None
    if x["blue_outcome"] == "not_logged":
        return ("Turn on the logging that records this technique; it left no trace. "
                + (f"Then {have[0].lower() + have[1:]}." if have else "Then write a detection for it: the library has none."))
    return (f"The activity reached the logs but nothing alerted. {have}." if have
            else "The activity reached the logs but nothing alerted, and the library has no detection for it: write one.")


def ai_disclaimer(c: Dict) -> List[str]:
    """The standard disclaimer for AI-assisted content, said once at the end of the report."""
    out = [f"{AI_MARK} AI-assisted content. Items marked {AI_MARK} were generated or influenced by an AI model (a "
           "large language model) when the Shikari detection library was built. AI output can be incomplete or "
           "wrong. These items have not been independently verified for this report and are provided without "
           "warranty of any kind: review and test them before relying on them or deploying them to a production "
           "environment."]
    out.append("Everything else in this report is computed directly from the outcomes recorded during the "
               "assessment and from the detection library, without AI."
               + ("" if c["ai_any"] else f" Nothing in this report is marked {AI_MARK}: none of the detections it "
                                         "cites were written with AI."))
    return out


GENERAL_RECOMMENDATIONS = [
    ("Re-test after remediation", "Run the same test cases again once the changes are in, and produce this "
     "report again. The difference between the two is the measure of the work."),
    ("Keep the library current", "Regenerate the detection library as ATT&CK and the threat groups change, so "
     "candidate detections reflect current tradecraft."),
    ("Record outcomes as they happen", "Record red and blue outcomes during the campaign, not afterwards, with "
     "the detection that fired. It makes the report a record of fact."),
    ("Hunt the logged-only techniques", "Until a detection is live for a technique that was logged but not "
     "alerted on, hunt for it periodically in the SIEM."),
]


def _and(items: List[str]) -> str:
    items = [i for i in items if i]
    if len(items) <= 1:
        return "".join(items)
    return ", ".join(items[:-1]) + " and " + items[-1]
