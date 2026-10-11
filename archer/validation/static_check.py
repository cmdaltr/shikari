"""
Static checks for one query, any SIEM, without a running SIEM: what the repair agent,
the MCP server and the console validate against.

  kql (MDE)        contract lint (archer.contract) + MDE schema (table and field names)
  yara_l (SecOps)  contract lint
  spl (Splunk)     structure: quotes, brackets, known commands after each pipe, a search scope
  elastic          structure: quotes and brackets

The contract lint never covered SPL (lint_query returns an empty report for it); the
SPL checks here are deliberately conservative: they flag what Splunk would refuse to
parse, not style.
"""

import re
from typing import Dict, List, Optional

PLATFORM_ALIASES = {
    "mde": "kql", "kql": "kql", "microsoft": "kql", "microsoftthreatprotection": "kql", "defender": "kql",
    "secops": "yara_l", "googlesecops": "yara_l", "yara_l": "yara_l", "yaral": "yara_l",
    "splunk": "spl", "spl": "spl",
    "elastic": "elastic", "eql": "elastic", "lucene": "elastic",
}

# SPL search commands (Splunk Enterprise 9 search reference), the ones a detection uses
SPL_COMMANDS = {
    "abstract", "accum", "addcoltotals", "addinfo", "addtotals", "analyzefields", "anomalies", "anomalousvalue",
    "append", "appendcols", "appendpipe", "arules", "associate", "autoregress", "bin", "bucket", "bucketdir",
    "chart", "cluster", "collect", "concurrency", "contingency", "convert", "correlate", "datamodel", "dedup",
    "delta", "diff", "erex", "eval", "eventcount", "eventstats", "extract", "kv", "fieldformat", "fields",
    "fieldsummary", "filldown", "fillnull", "findtypes", "foreach", "format", "from", "gauge", "geom", "geostats",
    "head", "highlight", "history", "iconify", "inputcsv", "inputlookup", "iplocation", "join", "kmeans",
    "loadjob", "localize", "lookup", "makecontinuous", "makemv", "makeresults", "map", "metadata", "metasearch",
    "mpreview", "msearch", "mstats", "multikv", "multisearch", "mvcombine", "mvexpand", "nomv", "outlier",
    "outputcsv", "outputlookup", "outputtext", "overlap", "pivot", "predict", "rangemap", "rare", "regex",
    "reltime", "rename", "replace", "rest", "return", "reverse", "rex", "rtorder", "savedsearch", "script",
    "run", "search", "searchtxn", "selfjoin", "sendemail", "set", "setfields", "sichart", "sirare", "sistats",
    "sitimechart", "sitop", "sort", "spath", "stats", "strcat", "streamstats", "table", "tags", "tail",
    "timechart", "timewrap", "top", "transaction", "transpose", "trendline", "tscollect", "tstats", "typeahead",
    "typelearner", "typer", "union", "uniq", "untable", "walklex", "where", "x11", "xmlkv", "xmlunescape",
    "xpath", "xyseries", "makejson", "fieldsummary",
}


def normalise_platform(platform: Optional[str], query: str = "") -> Optional[str]:
    if platform:
        key = re.sub(r"[^a-z_]", "", platform.lower())
        if key in PLATFORM_ALIASES:
            return PLATFORM_ALIASES[key]
    from archer.contract.validator import detect_siem

    return detect_siem(query or "")


def _split_top_level(query: str, sep: str = "|") -> List[str]:
    """Split on sep outside quotes, brackets and backtick macros."""
    parts, depth, quote, buf, i = [], 0, None, [], 0
    while i < len(query):
        c = query[i]
        if quote:
            buf.append(c)
            if c == "\\" and i + 1 < len(query):
                buf.append(query[i + 1]); i += 2; continue
            if c == quote:
                quote = None
        elif c in "\"'`":
            quote = c; buf.append(c)
        elif c in "([{":
            depth += 1; buf.append(c)
        elif c in ")]}":
            depth -= 1; buf.append(c)
        elif c == sep and depth == 0:
            parts.append("".join(buf)); buf = []
        else:
            buf.append(c)
        i += 1
    parts.append("".join(buf))
    return parts


def _structure(query: str, findings: List[Dict], quotes: str = '"') -> None:
    """Unbalanced quotes or brackets: the query won't parse on any SIEM."""
    depth, quote, i, pairs = [], None, 0, {")": "(", "]": "[", "}": "{"}
    while i < len(query):
        c = query[i]
        if quote:
            if c == "\\":
                i += 2; continue
            if c == quote:
                quote = None
        elif c in quotes:
            quote = c
        elif c in "([{":
            depth.append(c)
        elif c in ")]}":
            if not depth or depth[-1] != pairs[c]:
                findings.append({"check": "STRUCT-1", "message": f"unbalanced '{c}' at character {i}"})
                return
            depth.pop()
        i += 1
    if quote:
        findings.append({"check": "STRUCT-2", "message": f"unterminated {quote} string"})
    if depth:
        findings.append({"check": "STRUCT-1", "message": f"{len(depth)} unclosed '{depth[-1]}'"})


def _placeholders(query: str, findings: List[Dict]) -> None:
    m = re.search(r"<[A-Z_]{3,}>|\{\{[^}]*\}\}|\bTODO\b|\[(?:INDEX|TABLE|FIELD|USER_ID|USER_NAME)\]", query)
    if m:
        findings.append({"check": "PLACEHOLDER", "message": f"template placeholder left in the query: {m.group(0)}"})


def _check_spl(query: str, findings: List[Dict]) -> None:
    _structure(query, findings)
    stages = [s.strip() for s in _split_top_level(query.strip())]
    first = stages[0] if stages else ""
    if not first and len(stages) > 1:
        # A leading pipe: a generating command must follow
        stages = stages[1:]
        first_cmd = stages[0].split(None, 1)[0].lower() if stages and stages[0] else ""
        if first_cmd not in {"tstats", "inputlookup", "makeresults", "rest", "datamodel", "mstats", "from", "metadata", "eventcount", "loadjob", "union", "multisearch"}:
            findings.append({"check": "SPL-1", "message": f"a query starting with '|' needs a generating command, not '{first_cmd}'"})
    elif not re.search(r"\b(index|sourcetype|source|eventtype|tag)\s*(=|IN\b)|`[a-z_]+(\([^`]*\))?`|\bdatamodel\b", first, re.I):
        findings.append({"check": "SPL-2", "message": "the base search names no index, sourcetype, source, eventtype, tag or macro (searches everything)"})
    for stage in stages[1:]:
        if not stage:
            findings.append({"check": "SPL-3", "message": "empty pipeline stage ('| |' or a trailing '|')"})
            continue
        command = stage.split(None, 1)[0].lower()
        if command not in SPL_COMMANDS and not command.startswith("`"):
            findings.append({"check": "SPL-4", "message": f"unknown command after a pipe: '{command}'"})


def _check_kql(query: str, findings: List[Dict], schema: bool = True) -> None:
    from archer.contract.validator import Report, lint_kql, mixed_andor, scope_check

    rep = Report()
    scope_check(query, rep)
    mixed_andor(query, "kql", rep)
    lint_kql(query, rep)
    for f in rep.fails:
        gate, _, msg = f.partition(": ")
        findings.append({"check": gate, "message": msg})
    # The schema check reads one table; across a union a column only has to exist in one
    # branch, so it would flag valid projections
    if schema and not re.search(r"^\s*union\b", query, re.M):
        from archer.validation.mde_field_validator import validate_mde_query

        result = validate_mde_query(query)
        if result.get("valid") is False:
            for field in result.get("invalid_fields") or []:
                findings.append({"check": "MDE-FIELD", "message": f"{field} isn't a column of {result.get('table')}. "
                                 f"{(result.get('suggestions') or {}).get(field, '')}".strip()})


def _check_yaral(query: str, findings: List[Dict]) -> None:
    from archer.contract.validator import Report, lint_yaral, mixed_andor, scope_check

    rep = Report()
    scope_check(query, rep)
    mixed_andor(query, "yara_l", rep)
    lint_yaral(query, rep)
    for f in rep.fails:
        gate, _, msg = f.partition(": ")
        findings.append({"check": gate, "message": msg})
    _structure(query, findings, quotes='"`')


# Findings that mean the query won't parse or can never match. Everything else is the
# contract's style rules (KQL-5 escaping, KQL-14/15 summarize shape, YL-1 naming...)
ERROR_CHECKS = {"EMPTY", "PLACEHOLDER", "STRUCT-1", "STRUCT-2", "SPL-1", "SPL-3", "SPL-4", "MDE-FIELD",
                "KQL-16", "YL-21"}


def severity(check: str) -> str:
    return "error" if check in ERROR_CHECKS else "warning"


def check_query(query: str, platform: Optional[str] = None) -> Dict:
    """
    {"platform", "ok", "errors", "warnings", "findings": [{"check", "severity", "message"}]}.
    ok is False when there are errors (warnings alone don't fail a query); None when the
    platform isn't recognised.
    """
    result = _check(query, platform)
    for f in result["findings"]:
        f["severity"] = severity(f["check"])
    result["errors"] = sum(f["severity"] == "error" for f in result["findings"])
    result["warnings"] = len(result["findings"]) - result["errors"]
    if result["ok"] is not None:
        result["ok"] = result["errors"] == 0
    return result


def _check(query: str, platform: Optional[str] = None) -> Dict:
    query = query or ""
    siem = normalise_platform(platform, query)
    findings: List[Dict] = []
    if not query.strip():
        return {"platform": siem, "ok": False, "findings": [{"check": "EMPTY", "message": "no query"}]}
    _placeholders(query, findings)
    if siem == "spl":
        _check_spl(query, findings)
    elif siem == "kql":
        _check_kql(query, findings)
    elif siem == "yara_l":
        _check_yaral(query, findings)
    elif siem == "elastic":
        _structure(query, findings)
    else:
        _structure(query, findings)
        return {"platform": None, "ok": None if not findings else False, "findings": findings,
                "note": "platform not recognised: only structure was checked"}
    return {"platform": siem, "ok": not findings, "findings": findings}


def mde_table_columns(table: str) -> Optional[List[str]]:
    """The columns of an MDE advanced hunting table (None if unknown)."""
    from archer.validation.mde_field_validator import get_mde_validator

    fields = get_mde_validator().table_fields
    for name, columns in fields.items():
        if name.lower() == table.lower():
            return sorted(columns)
    return None
