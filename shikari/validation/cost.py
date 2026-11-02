"""
What a detection costs the SIEM to run (#34), read from the query before it's deployed.

Each language has its own expensive habits; each finding says what it does and how to fix it:

  COST-NOTIME       no time bound: the search covers the whole retention window
  COST-SUBSTRING    substring matching (KQL contains, SPL/ES|QL leading wildcards) that can't use
                    the term index, so every value is scanned
  COST-REGEX        a regex where a term would do, or one unanchored at both ends
  COST-JOIN         joins, subsearches and transactions: the right side runs in full per search
  COST-WIDE         every table or index (union *, search *, index=*, logs-*)
  COST-CASE         lower-casing a column to compare it (defeats the index; use the
                    case-insensitive operator instead)
  COST-LATE-FILTER  filtering after an aggregation or projection instead of before it

cost() returns {level: low|medium|high, score, findings: [{check, message, fix}]}. Scheduled
detections run every few minutes, so a "high" one is worth fixing before it's deployed even
when it finds the right things. Runtime validation (detection_tester) times the query against
its sample events; hit counts (#16) are where cost against real volumes will be measured.
"""

import re
from typing import Dict, List, Optional

WEIGHTS = {"COST-NOTIME": 30, "COST-SUBSTRING": 20, "COST-REGEX": 15, "COST-JOIN": 25, "COST-WIDE": 35,
           "COST-CASE": 10, "COST-LATE-FILTER": 10}


def _finding(check: str, message: str, fix: str) -> Dict:
    return {"check": check, "message": message, "fix": fix}


def _kql(q: str) -> List[Dict]:
    out = []
    if not re.search(r"\bago\s*\(|\bbetween\s*\(|Timestamp\s*[><]|TimeGenerated\s*[><]", q):
        out.append(_finding("COST-NOTIME", "no Timestamp filter: the hunt covers the full 30 days of advanced hunting",
                            "add | where Timestamp > ago(1h) to match the rule's schedule"))
    n = len(re.findall(r"\bcontains(_cs)?\b", q))
    if n:
        out.append(_finding("COST-SUBSTRING", f"contains ({n}×) scans every value instead of using the term index",
                            "use has / has_any / has_all for whole terms; keep contains for genuine substrings"))
    if re.search(r"\bmatches\s+regex\b", q):
        out.append(_finding("COST-REGEX", "matches regex runs on every row that reaches it",
                            "filter with has first, then the regex on what's left"))
    if re.search(r"\|\s*join\b", q) and not re.search(r"join[^\n]*\([^)]*ago\(", q, re.S):
        out.append(_finding("COST-JOIN", "a join whose right side has no time bound",
                            "filter the right side by Timestamp and the join key before joining"))
    if re.search(r"\bunion\s+\*|^\s*search\s+[\"*]", q, re.M):
        out.append(_finding("COST-WIDE", "union * / search across every table",
                            "name the tables the behaviour is logged in"))
    if re.search(r"\b(tolower|toupper)\s*\(\s*\w+\s*\)\s*(==|has|contains)", q):
        out.append(_finding("COST-CASE", "lower-casing a column to compare it",
                            "use the case-insensitive operator (=~, has) on the column as it is"))
    if re.search(r"\|\s*summarize\b[\s\S]*\|\s*where\b", q) and not re.search(r"\|\s*where\b[\s\S]*\|\s*summarize\b", q):
        out.append(_finding("COST-LATE-FILTER", "the only filter comes after summarize",
                            "filter rows before summarizing them"))
    return out


def _spl(q: str) -> List[Dict]:
    out = []
    if not re.search(r"\bearliest\s*=|\b_index_earliest\s*=", q):
        out.append(_finding("COST-NOTIME", "no earliest=: the search runs over the time range the scheduler or user picks, "
                            "all time if nothing does", "add earliest=-15m (or the rule's schedule) to the base search"))
    if re.search(r"\bindex\s*=\s*\*|^\s*\*\s*$", q, re.M) or not re.search(r"\bindex\s*=", q):
        out.append(_finding("COST-WIDE", "no specific index: every index the role can read is searched",
                            "name the index the data lives in"))
    leading = re.findall(r"=\s*\"?\*[^\s\"*]+", q)
    if leading:
        out.append(_finding("COST-SUBSTRING", f"leading wildcards ({len(leading)}×) can't use the lexicon",
                            "match whole terms or the end of a path with a trailing wildcard only where possible"))
    if re.search(r"\|\s*(regex|rex)\b", q) and not re.search(r"\|\s*rex\b[^|]*field=", q):
        out.append(_finding("COST-REGEX", "regex over _raw for every event", "filter with terms in the base search first"))
    if re.search(r"\|\s*(join|append|appendcols|transaction)\b|\[\s*search\b", q):
        out.append(_finding("COST-JOIN", "join, append, transaction or a subsearch",
                            "use stats by the shared field, or tstats on an accelerated data model"))
    first_pipe = q.find("|")
    if first_pipe != -1 and re.search(r"\|\s*search\b", q[first_pipe:]) and len(re.findall(r"\"[^\"]+\"", q[:first_pipe])) == 0:
        out.append(_finding("COST-LATE-FILTER", "the conditions are in a later | search, after the events are retrieved",
                            "move the conditions into the base search, before the first pipe"))
    return out


def _esql(q: str) -> List[Dict]:
    out = []
    if not re.search(r"@timestamp\s*[><]|NOW\(\)", q, re.I):
        out.append(_finding("COST-NOTIME", "no @timestamp filter", "add | WHERE @timestamp > NOW() - 15 minutes"))
    if re.search(r"FROM\s+(\*|logs-\*)\s*(\||$)", q, re.I):
        out.append(_finding("COST-WIDE", "FROM every data stream", "name the data streams (logs-endpoint.events.process-*)"))
    if re.search(r"LIKE\s+\"\*", q, re.I):
        out.append(_finding("COST-SUBSTRING", "LIKE with a leading wildcard scans every value",
                            "match the whole value, or the end with a trailing wildcard"))
    if re.search(r"\bRLIKE\b", q, re.I):
        out.append(_finding("COST-REGEX", "RLIKE runs a regex on every row that reaches it", "filter with == or LIKE first"))
    return out


def _yaral(q: str) -> List[Dict]:
    out = []
    regexes = re.findall(r"re\.regex\([^,]+,\s*`([^`]*)`|=\s*/([^/]+)/", q)
    unanchored = [r for pair in regexes for r in pair if r and r.startswith(".*") and r.endswith(".*")]
    if unanchored:
        out.append(_finding("COST-REGEX", f"{len(unanchored)} regex{'es' if len(unanchored) > 1 else ''} unanchored at both ends",
                            "drop the leading and trailing .* (a regex already matches anywhere) or use = with nocase"))
    if not re.search(r"metadata\.event_type\s*=", q):
        out.append(_finding("COST-WIDE", "no metadata.event_type: every UDM event is considered",
                            "constrain the event type (PROCESS_LAUNCH, NETWORK_CONNECTION...)"))
    window = re.search(r"over\s+(\d+)\s*([mhd])", q)
    if window and (int(window.group(1)) * {"m": 1, "h": 60, "d": 1440}[window.group(2)]) > 24 * 60:
        out.append(_finding("COST-JOIN", f"a match window over {window.group(1)}{window.group(2)}",
                            "keep multi-event windows to what the behaviour needs (minutes or hours)"))
    return out


def cost(query: str, platform: Optional[str] = None) -> Dict:
    from shikari.validation.static_check import normalise_platform

    query = query or ""
    siem = normalise_platform(platform, query)
    findings = (_kql(query) if siem == "kql" else _spl(query) if siem == "spl" else _esql(query) if siem == "elastic"
                else _yaral(query) if siem in ("yara_l", "udm") else [])
    score = min(100, sum(WEIGHTS[f["check"]] for f in findings))
    return {"platform": siem, "level": "high" if score >= 45 else "medium" if score >= 20 else "low",
            "score": score, "findings": findings}
