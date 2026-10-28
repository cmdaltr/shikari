"""
Detection quality and false-positive risk, without AI (#33).

quality() scores a detection out of 100, from the checks Archer already runs and what the
detection itself carries:

  validity     25  static_check: parses, known tables and fields, no placeholders
  precision    25  precision: conditions that can fire for the right reason (KQL, UDM, YARA-L)
  specificity  20  how much a match narrows it down: several values, arguments not just a
                   binary's name, hashes and paths
  context      15  description, severity, tactics, technique, data connector
  evidence     15  indicators traced to the procedure, reference queries, OSINT

and grades it A (85+) to F (under 40). Each factor says why it lost points.

fp_risk() predicts how noisy it will be before it's deployed: low, medium or high, with the
reasons. It counts what makes a query match ordinary activity (bare built-in binaries, generic
words, a port or protocol on its own, high-volume tables with few conditions) and the false
positives the community's Elastic and Splunk rules document for the same technique and tools,
which come back with it for triage. Hit counts (#16) measure the same thing against the SIEM.
"""

import re
from typing import Dict, Iterable, List, Optional

GRADES = ((85, "A"), (70, "B"), (55, "C"), (40, "D"), (0, "F"))
# Tables and event types that see most of an estate's activity: a few conditions on them match a lot
BROAD_SOURCES = ("DeviceEvents", "DeviceNetworkEvents", "DeviceProcessEvents", "NETWORK_CONNECTION",
                 "PROCESS_LAUNCH", "NETWORK_DNS", "index=edr", "index=os", "process.name", "event.category")
NOISY_CHECKS = {"PREC-BARE": 25, "PREC-GENERIC": 15, "PREC-PORT": 25, "PREC-CONTEXT": 30, "PREC-EMPTY": 35,
                "PREC-API": 10}
_HASH = re.compile(r"\b[a-f0-9]{32}\b|\b[a-f0-9]{40}\b|\b[a-f0-9]{64}\b", re.I)
_PATHLIKE = re.compile(r"[\\/].+[\\/]|^[a-z]:\\|^hk(lm|cu|ey)", re.I)


def _values(detection: Dict) -> List[str]:
    """The detection's indicator values (its indicators block, flattened)."""
    block = detection.get("indicators") or {}
    if isinstance(block, dict):
        return [str(v) for vals in block.values() for v in (vals if isinstance(vals, list) else [vals]) if v]
    return [str(v) for v in block if v] if isinstance(block, list) else []


def _findings(query: str, platform: Optional[str], technique_platforms) -> Dict:
    from archer.validation.static_check import check_query

    return check_query(query, platform, technique_platforms)


def quality(detection: Dict, platform: Optional[str] = None, technique_platforms: Optional[Iterable[str]] = None,
            checked: Optional[Dict] = None) -> Dict:
    """{score, grade, factors: [{name, points, max, notes}]} for a detection's YAML (as a dict)."""
    query = detection.get("query") or ""
    checked = checked or _findings(query, platform, technique_platforms)
    findings = checked.get("findings", [])
    factors = []

    static = [f for f in findings if not f["check"].startswith("PREC-")]
    errors = [f for f in static if f["severity"] == "error"]
    points = 0 if errors else max(0, 25 - 5 * len(static))
    factors.append({"name": "validity", "points": points, "max": 25,
                    "notes": [f["message"] for f in static[:4]] or ["parses, known tables and fields"]})

    prec = [f for f in findings if f["check"].startswith("PREC-")]
    if checked.get("platform") in ("kql", "udm", "yara_l"):
        points = max(0, 25 - sum(12 if f["severity"] == "error" else 5 for f in prec))
        notes = [f"{f['check']}: {f['message']}" for f in prec[:4]] or ["every condition can fire for the right reason"]
    else:
        points, notes = 20, ["precision checks cover KQL, UDM and YARA-L; not scored for this language"]
    factors.append({"name": "precision", "points": points, "max": 25, "notes": notes})

    values = _values(detection)
    distinct = {v.lower() for v in values}
    with_args = [v for v in values if " " in v.strip()]
    strong = [v for v in values if _HASH.search(v) or _PATHLIKE.search(v)]
    points, notes = 0, []
    if len(distinct) >= 3:
        points += 8
    elif distinct:
        points += 4
        notes.append(f"only {len(distinct)} indicator value{'s' if len(distinct) > 1 else ''}")
    else:
        notes.append("no indicator values: it matches on structure alone")
    if with_args:
        points += 7
    elif values:
        notes.append("no command-line arguments, only names")
    if strong:
        points += 5
    if values and not strong:
        notes.append("no paths or hashes")
    found = [f"{len(distinct)} values"] + (["arguments"] if with_args else []) + (["paths or hashes"] if strong else [])
    factors.append({"name": "specificity", "points": min(points, 20), "max": 20,
                    "notes": notes or [", ".join(found)]})

    missing = [label for label, present in (
        ("description", len(str(detection.get("description") or "")) > 30),
        ("severity", detection.get("severity")),
        ("tactics", detection.get("tactics")),
        ("technique", detection.get("technique_id") or re.search(r"T\d{4}", str(detection.get("description", "")))),
        ("data connector", detection.get("requiredDataConnectors") or detection.get("connectorId")),
    ) if not present]
    factors.append({"name": "context", "points": 15 - 3 * len(missing), "max": 15,
                    "notes": [f"missing {', '.join(missing)}"] if missing else ["fully described"]})

    points, notes = 0, []
    if values:
        points += 7
    else:
        notes.append("no indicators traced to the procedure")
    if detection.get("reference_used") or detection.get("reference_sources"):
        points += 4
    if "osint" in str(detection.get("tags", "")).lower() or detection.get("osint_enhanced") or detection.get("osint"):
        points += 4
    factors.append({"name": "evidence", "points": min(points, 15), "max": 15,
                    "notes": notes or ["indicators from the procedure" + (", reference queries" if points > 7 else "")]})

    score = sum(f["points"] for f in factors)
    return {"score": score, "grade": next(g for floor, g in GRADES if score >= floor), "factors": factors}


def fp_risk(detection: Dict, platform: Optional[str] = None, technique_platforms: Optional[Iterable[str]] = None,
            checked: Optional[Dict] = None, known: Optional[List[Dict]] = None) -> Dict:
    """{level, score, reasons, known_false_positives}: how much ordinary activity it will match."""
    from archer.validation.precision import builtin_binaries

    query = detection.get("query") or ""
    checked = checked or _findings(query, platform, technique_platforms)
    score, reasons = 0, []

    for f in checked.get("findings", []):
        if f["check"] in NOISY_CHECKS:
            score += NOISY_CHECKS[f["check"]]
            reasons.append(f["message"])

    values = _values(detection)
    names = {re.split(r"[\\/ ]", v.strip())[-1 if "\\" in v or "/" in v else 0].lower() for v in values if v.strip()}
    builtin = names & builtin_binaries()
    if builtin and not any(" " in v.strip() for v in values):
        score += 15
        reasons.append(f"dual-use built-in binaries without arguments: {', '.join(sorted(builtin)[:5])}")

    broad = [s for s in BROAD_SOURCES if s.lower() in query.lower()]
    # What it matches on: its own values that made it into the query (operators differ too much
    # across KQL, UDM, SPL and ES|QL to count them)
    plain = query.replace("\\", "").lower()  # UDM and regexes escape dots: svchost\.exe
    used = {v.lower() for v in values if v.strip() and v.strip().lower().replace("\\", "") in plain}
    if broad and len(used) <= 1:
        score += 10
        reasons.append(f"a high-volume source ({broad[0]}) matched on {'one value' if used else 'no indicator values'}")

    if known is None:
        known = _known(detection, names)
    if known:
        score += min(25, 5 * len(known))
        reasons.append(f"{len(known)} false positive{'s' if len(known) > 1 else ''} documented by community rules for this technique")

    if any(_HASH.search(v) for v in values):
        score -= 20
        reasons.append("matches file hashes, which rarely match benign activity")
    if "bespoke exclusions" in query.lower() or re.search(r"!=|not\s*\(|\bNOT\b", query):
        score -= 10
        reasons.append("excludes known-good activity")

    score = max(0, min(100, score))
    level = "high" if score >= 50 else "medium" if score >= 25 else "low"
    return {"level": level, "score": score, "reasons": reasons or ["nothing in it matches ordinary activity broadly"],
            "known_false_positives": known}


def _known(detection: Dict, names: Iterable[str]) -> List[Dict]:
    tid = detection.get("technique_id") or (re.search(r"T\d{4}(?:\.\d{3})?", str(detection.get("description", ""))) or [None])[0]
    if not tid:
        return []
    try:
        from archer.build.osint_index import known_false_positives

        return known_false_positives(str(tid), limit=5, terms=list(names)) if names else []
    except Exception:
        return []


def assess(detection: Dict, platform: Optional[str] = None, technique_platforms: Optional[Iterable[str]] = None) -> Dict:
    """Both, sharing one run of the checks: {quality, fp_risk}."""
    checked = _findings(detection.get("query") or "", platform, technique_platforms)
    return {"quality": quality(detection, platform, technique_platforms, checked),
            "fp_risk": fp_risk(detection, platform, technique_platforms, checked)}


if __name__ == "__main__":
    import json
    import sys

    import yaml

    for path in sys.argv[1:]:
        with open(path, encoding="utf-8") as fh:
            result = assess(yaml.safe_load(fh) or {})
        q, r = result["quality"], result["fp_risk"]
        print(f"{path}: quality {q['grade']} ({q['score']}), false-positive risk {r['level']} ({r['score']})")
        for f in q["factors"]:
            print(f"    {f['name']:<12} {f['points']:>2}/{f['max']}  {'; '.join(f['notes'])}")
        for reason in r["reasons"]:
            print(f"    fp: {reason}")
        if "--json" in sys.argv:
            print(json.dumps(result, indent=2, default=str))
