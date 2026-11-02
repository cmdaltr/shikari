"""
What a correlation inherits from its detections (#23), worked out when the results page shows it.

A correlation's combined query is built from its detections' queries, so the indicators OSINT
Enhancement merged into them are in it already. What it didn't carry is the rest of the
enrichment: the public rules each detection was compared with, the false positives those rules
document (LoFP-style: prose to tune with, not query exclusions) and the LOLBAS / LOLDrivers /
LOLRMM entries behind added indicators. inherited() gathers them from the detections as they
are now.

Detection files are shared between groups and runs, so a later run can rewrite one after the
correlation was built: the combined query then no longer matches its parts. stale_parts()
names the detections whose conditions are missing from the combined query.
"""

import re
from typing import Dict, List

MAX_FPS = 8


def _fps(detection: Dict) -> List[Dict]:
    """The detection's recorded false positives, or the OSINT index's for its technique."""
    fps = detection.get("known_false_positives") or []
    if fps or not detection.get("technique_id"):
        return fps
    try:
        from shikari.build.osint_index import known_false_positives

        indicators = detection.get("indicators") or {}
        terms = [str(t) for k in ("sw", "cmd") for t in indicators.get(k) or []]
        return known_false_positives(str(detection["technique_id"]), terms=terms) if terms else []
    except Exception:
        return []


def inherited(detections: List[Dict]) -> Dict:
    """
    {sources, known_false_positives, lol_references, snippets, enhanced} merged across the
    correlation's detections (YAML dicts), each false positive and LOL entry tagged with the
    technique it came from. Empty lists when none of them was enriched.
    """
    sources, fps, lol, snippets = [], [], [], []
    seen_fp, seen_lol = set(), set()
    enhanced = False
    for d in detections:
        tid = str(d.get("technique_id") or "")
        enhanced = enhanced or bool(d.get("osint_enhanced"))
        sources += [s for s in d.get("osint_sources") or [] if s not in sources]
        snippets += [s for s in (d.get("osint_indicators") or {}).get("query_snippets") or [] if s not in snippets]
        for fp in _fps(d):
            key = (fp.get("text") or "").lower()[:120]
            if key and key not in seen_fp:
                seen_fp.add(key)
                fps.append({**fp, "technique": tid})
        for ref in d.get("lol_references") or []:
            key = str(ref.get("url") or ref.get("name") or ref) if isinstance(ref, dict) else str(ref)
            if key not in seen_lol:
                seen_lol.add(key)
                lol.append({**ref, "technique": tid} if isinstance(ref, dict) else {"name": str(ref), "technique": tid})
    # Alternate between the detections so one with many doesn't push the other's out
    by_tid: Dict[str, List[Dict]] = {}
    for fp in fps:
        by_tid.setdefault(fp["technique"], []).append(fp)
    mixed = []
    while len(mixed) < MAX_FPS and any(by_tid.values()):
        for queue in by_tid.values():
            if queue and len(mixed) < MAX_FPS:
                mixed.append(queue.pop(0))
    return {"sources": sources, "known_false_positives": mixed, "lol_references": lol,
            "snippets": snippets, "enhanced": enhanced}


def _norm(text: str) -> str:
    # A UDM join binds each detection's fields to $e1, $e2 (a legacy rule renamed its $e):
    # compare the fields bare
    text = re.sub(r"\$e\d*\.", "", text or "")
    return re.sub(r"\s+", " ", re.sub(r"\$[a-z]+\d*\b", "$e", text)).strip()


def conditions(query: str) -> List[str]:
    """A detection's filter lines: KQL '| where' (not the time window), a UDM search's field
    tests, or a legacy YARA-L rule's regex/field tests."""
    lines = [l.strip() for l in (query or "").splitlines()]
    kql = [l[len("| where "):] for l in lines if l.startswith("| where ") and "ago(" not in l]
    if kql:
        return kql
    from shikari.build.udm import is_udm, is_yaral

    if is_udm(query) and not is_yaral(query):
        body = " ".join(l for l in lines if not l.startswith("//"))
        tests = re.findall(r'(?<![\w.$])[a-z_]+(?:\.[a-z_]+)+\s*=\s*(?:/(?:\\.|[^/\\])*/|"(?:\\.|[^"\\])*")(?:\s+nocase)?', body)
        return [t for t in tests if not t.startswith("metadata.event_type")]
    events, inside = [], False
    for l in lines:
        if l == "events:":
            inside = True
        elif l in ("match:", "outcome:", "condition:"):
            inside = False
        elif inside and l and "metadata.event_type" not in l:
            events.append(l)
    return events


def stale_parts(combined_query: str, detections: List[Dict]) -> List[str]:
    """Names of the detections with a condition the combined query no longer contains."""
    combined = _norm(combined_query)
    if not combined:
        return []
    return [d.get("name") or d.get("technique_id") or "?" for d in detections
            if any(_norm(c) not in combined for c in conditions(d.get("query", "")))]
