"""Shikari output contract validator (contract v1.0).

Dependency-light on purpose: stdlib, PyYAML, jsonschema. Nothing here imports the
rest of the shikari package, so it can run in CI, in the LLM pipeline and on its own.

Two entry points:
  validate_text(text) / validate_file(path)  - full contract validation of a YAML document
  lint_query(query, siem)                     - query-level lints only, for legacy Shikari YAML

Regex samples are evaluated with Python's `re`, a superset of RE2 for the constructs the
contract permits; the harness must re-run them in the target engine before promotion.
"""
from __future__ import annotations

import ipaddress
import json
import re
from pathlib import Path
from typing import Dict, List, Optional

import yaml
import jsonschema

CONTRACT_VERSION = "1.0"
HERE = Path(__file__).resolve().parent
SCHEMA = json.loads((HERE / "schema.json").read_text())

RULE_ORDER = ["rule_id", "name", "author", "created", "modified", "version", "status", "detection_type", "siem",
              "target_os", "log_sources", "attack", "lookback", "schedule", "confidence", "severity", "false_positives",
              "tuning_notes", "references", "indicators", "reference_lists", "entity_output", "correlation", "regexes",
              "complexity", "validation", "query"]
REJ_ORDER = ["reason_code", "secondary_codes", "detection_type_requested", "siem_requested", "technique_ids_requested",
             "blocking_criteria", "evidence", "remediation", "nearest_viable_alternative"]
TOP_ORDER = ["contract_version", "kind", "request_ref"]

TACTIC_PASCAL = {"initial_access": "InitialAccess", "execution": "Execution", "persistence": "Persistence",
                 "privilege_escalation": "PrivilegeEscalation", "stealth": "Stealth", "defense_impairment": "DefenseImpairment",
                 "credential_access": "CredentialAccess", "discovery": "Discovery", "lateral_movement": "LateralMovement",
                 "collection": "Collection", "command_and_control": "CommandAndControl", "exfiltration": "Exfiltration", "impact": "Impact"}
KQL_WINDOW = {"1h": 4, "3h": 12, "12h": 48, "24h": 720}
PLACEHOLDERS = re.compile(r"(evil|malware|example\.com|test\.exe|^1\.2\.3\.4$|^0\.0\.0\.0$|attacker|badguy|^foo$|^bar$)", re.I)
UDM_KNOWN_EMPTY = {"principal.process.parent_process.pid"}
# Fields that cannot carry a value for these UDM event types (workbook Q048: 24 of 115 rules)
UDM_EVENT_FIELD_CONTRADICTIONS = {
    "PROCESS_LAUNCH": ("network.", "target.url", "target.ip", "target.port", "principal.port"),
    "FILE_CREATION": ("network.", "target.url", "target.ip", "target.port"),
    "FILE_MODIFICATION": ("network.", "target.url", "target.ip", "target.port"),
    "REGISTRY_MODIFICATION": ("network.", "target.url", "target.ip", "target.port", "target.process.command_line"),
    "REGISTRY_CREATION": ("network.", "target.url", "target.ip", "target.port", "target.process.command_line"),
}
KQL_TABLE_PREFIX = r"(?:Device|Identity|Cloud|AAD|Email|Url|Alert|Behavior|Exposure|Urlclick)[A-Za-z]+"
STOPWORDS = {"and", "or", "the", "a", "an", "of", "to", "in", "on", "for", "with", "is", "are", "may"}


def hours(d: str) -> float:
    n, u = int(d[:-1]), d[-1]
    return n / 60 if u == "m" else n if u == "h" else n * 24


def _split_or(text: str) -> list:
    """Split at the top-level `or`s, outside brackets, strings and regexes."""
    parts, depth, quote, start, i = [], 0, None, 0, 0
    while i < len(text):
        c = text[i]
        if quote:
            if c == "\\":
                i += 1
            elif c == quote:
                quote = None
        elif c in "\"`'":
            quote = c
        elif c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
        elif depth == 0 and re.match(r"\sor\s", text[i:i + 4], re.I):
            parts.append(text[start:i])
            start = i + 3
        i += 1
    parts.append(text[start:])
    return [p.strip() for p in parts if p.strip()]


def _or_branches(text: str) -> list:
    """
    The alternatives of an events section, each with its own event-type guard:
    (type = PROCESS_LAUNCH and command_line ...) or (type = REGISTRY_* and registry_key ...)
    is two branches, so a field one branch tests isn't held against the other's type.
    """
    parts = _split_or(text)
    if len(parts) > 1:
        return [b for p in parts for b in _or_branches(p)]
    t = text.strip()
    if t.startswith("(") and t.endswith(")"):
        depth = 0
        for i, c in enumerate(t):
            depth += c == "("
            depth -= c == ")"
            if depth == 0 and i < len(t) - 1:
                return [t]
        return _or_branches(t[1:-1])
    return [t]


class Report:
    def __init__(self, path: str = "<text>"):
        self.path, self.fails = path, []

    def fail(self, gate: str, msg: str):
        self.fails.append(f"{gate}: {msg}")

    def ok(self) -> bool:
        return not self.fails

    def gates(self) -> List[str]:
        return [f.split(":")[0] for f in self.fails]


# ---------- lexical ----------
def without_query_block(text: str) -> str:
    """Drop the body of the `query: |` block scalar; its content is opaque to YAML (KQL uses !in~, !has)."""
    out, block_indent = [], None
    for line in text.splitlines():
        if block_indent is not None:
            if not line.strip() or len(line) - len(line.lstrip()) > block_indent: continue
            block_indent = None
        m = re.match(r"^(\s*)query:\s*\|", line)
        if m: block_indent = len(m.group(1))
        out.append(line)
    return "\n".join(out)


def lexical(text: str, rep: Report):
    if "\t" in text: rep.fail("LEX-1", "tab character present")
    if re.search(r"^\s*query:(?!\s*\|\s*$)", text, re.M): rep.fail("LEX-2", "query must be a literal block scalar (query: |)")
    yaml_only = without_query_block(text)
    if re.search(r"^\s*[a-z_]+:\s*[\[{](?![\]}])", yaml_only, re.M): rep.fail("LEX-3", "flow-style collection used; block style only")
    if re.search(r"(^|\s)[&*][A-Za-z]", yaml_only, re.M): rep.fail("LEX-4", "YAML anchor/alias used")
    if re.search(r"(^|\s)!!?[a-z]", yaml_only, re.M): rep.fail("LEX-5", "YAML tag used")
    if text.count("\n---") or text.startswith("---"): rep.fail("LEX-6", "document marker present")


def check_order(obj: dict, order: List[str], gate: str, rep: Report):
    keys = list(obj.keys())
    expected = [k for k in order if k in obj]
    if keys != expected: rep.fail(gate, f"key order {keys} != {expected}")


# ---------- scanning helpers ----------
def scrub(q: str, siem: str, keep_strings: bool = False) -> str:
    """Single pass: drop // comments; unless keep_strings, replace regex and string literals with placeholders."""
    out, i, n = [], 0, len(q)
    while i < n:
        c = q[i]
        if c == "`" and siem == "yara_l":
            j = q.find("`", i + 1); j = n if j < 0 else j
            out.append(q[i:j + 1] if keep_strings else "`RX`"); i = j + 1; continue
        if c == "@" and i + 1 < n and q[i + 1] == '"' and siem == "kql":
            j = i + 2
            while j < n:
                if q[j] == '"':
                    if j + 1 < n and q[j + 1] == '"': j += 2; continue
                    break
                j += 1
            out.append(q[i:j + 1] if keep_strings else '"S"'); i = j + 1; continue
        if c == '"' or (c == "'" and siem == "kql"):
            j = i + 1
            while j < n and q[j] != c:
                if q[j] == "\\": j += 1
                j += 1
            out.append(q[i:j + 1] if keep_strings else c + "S" + c); i = j + 1; continue
        if c == "/" and i + 1 < n and q[i + 1] == "/":
            j = q.find("\n", i); j = n if j < 0 else j
            i = j; continue
        out.append(c); i += 1
    return "".join(out)


def strip_comments(q: str, siem: str = "kql") -> str:
    return scrub(q, siem, keep_strings=True)


def mixed_andor(q: str, siem: str, rep: Report):
    """R12.5/R14.11: within one parenthesised group, 'and' and 'or' may not both appear."""
    s = scrub(q, siem)
    tokens = re.findall(r"\(|\)|\||\b(?:and|or)\b", s)
    stack = [set()]
    for t in tokens:
        if t == "(": stack.append(set())
        elif t == ")":
            if len(stack) > 1: stack.pop()
        elif t == "|":
            if siem == "kql" and len(stack) == 1: stack[0] = set()
        else:
            stack[-1].add(t)
            if {"and", "or"} <= stack[-1]:
                rep.fail("LOGIC-andor", "mixed and/or at one parenthesis level without full parenthesisation"); return


def query_lines(q: str) -> List[str]:
    return [l for l in q.splitlines() if l.strip()]


def detect_siem(query: str) -> Optional[str]:
    """Best-effort syntax detection for legacy files: yara_l, kql, spl or None."""
    q = query.strip()
    if re.match(r"rule\s+[A-Za-z_][A-Za-z0-9_]*\s*\{", q): return "yara_l"
    if re.match(r"index\s*(=|IN)", q, re.I) or re.search(r"^\s*`[a-z_]+`\s*$", q, re.M): return "spl"
    for line in q.splitlines():
        s = line.strip()
        if not s or s.startswith("//"): continue
        if s.startswith("let ") or re.match(KQL_TABLE_PREFIX, s) or s.startswith("|"): return "kql"
        break
    return None


# ---------- YARA-L lint ----------
def lint_yaral(q: str, rep: Report, rule: Optional[dict] = None) -> List[str]:
    m = re.match(r"\s*rule\s+([A-Za-z_][A-Za-z0-9_]*)\s*\{", q)
    if not m: rep.fail("YL-1", "missing 'rule <name> {' header"); return []
    if not re.fullmatch(r"[a-z][a-z0-9_]*", m.group(1)): rep.fail("YL-1", f"rule name {m.group(1)} is not lowercase snake_case")
    if rule and m.group(1) != rule["name"]: rep.fail("YL-2", f"rule name {m.group(1)} != contract name {rule['name']}")
    for sec in ("meta:", "events:", "condition:"):
        if not re.search(rf"^\s*{sec}\s*$", q, re.M): rep.fail("YL-3", f"missing section {sec}")
    if not q.rstrip().endswith("}"): rep.fail("YL-4", "rule not closed with }")
    body = scrub(q, "yara_l")
    raw = strip_comments(q, "yara_l")
    sections, raw_sections = {}, {}
    for name in ("meta", "events", "match", "outcome", "condition"):
        for src, dst in ((body, sections), (raw, raw_sections)):
            mm = re.search(rf"^\s*{name}:\s*$(.*?)(?=^\s*(?:meta|events|match|outcome|condition):\s*$|^\}})", src, re.M | re.S)
            if mm: dst[name] = mm.group(1)
    ev = sections.get("events", "")
    evars = set(re.findall(r"\$([a-z][a-z0-9_]*)\.", ev))
    placeholders = set(re.findall(r"=\s*\$([a-z][a-z0-9_]*)\s*$", ev, re.M)) | set(re.findall(r"^\s*\$([a-z][a-z0-9_]*)\s*!=", ev, re.M))
    placeholders -= evars
    cond = sections.get("condition", "")
    cvars = set(re.findall(r"\$([a-z][a-z0-9_]*)", cond))
    for v in evars:
        if v not in cvars: rep.fail("YL-5", f"event variable ${v} not used in condition")
    if len(evars) > 1 and "match" not in sections: rep.fail("YL-6", "multi-event rule without match section")
    # Mutually exclusive field for the declared event type (Q048 pattern)
    raw_ev = raw_sections.get("events", "")
    reported = set()
    for branch in _or_branches(raw_ev):
        for var in evars:
            etypes = re.findall(rf"\${var}\.metadata\.event_type\s*=\s*\"([A-Z_]+)\"", branch)
            for et in etypes:
                for bad in UDM_EVENT_FIELD_CONTRADICTIONS.get(et, ()):
                    if (var, et, bad) not in reported and re.search(rf"\${var}\.{re.escape(bad)}", branch):
                        reported.add((var, et, bad))
                        rep.fail("YL-21", f"${var} is {et} but is tested on {bad}* which that event type does not carry")
    for p in UDM_KNOWN_EMPTY:
        if p in body: rep.fail("YL-18", f"{p} is known_empty for MDE-sourced UDM")
    if re.search(r"\.pid\s*(>|<|>=|<=)\s*\d", ev): rep.fail("YL-13", "process.pid compared with an integer (UDM pid is a string)")
    if re.search(r"re\.regex\([^`]*`[^`]*`\s*nocase", q): rep.fail("YL-14", "nocase placed inside re.regex(...)")
    patterns = re.findall(r"`([^`]*)`", q)
    for p in patterns:
        if re.search(r"\b[A-Za-z]:\\[A-Za-z]", p): rep.fail("YL-22", f"unescaped Windows path inside regex: {p[:50]}")
        words = p.split()
        if "(Citation:" in p or len(words) >= 6 and not re.search(r"[\\\[\]()|^$]", p): rep.fail("YL-23", f"regex is prose, not an indicator: {p[:60]}")
        if p.strip().lower() in STOPWORDS or (len(p.strip()) <= 3 and p.strip().isalpha()): rep.fail("YL-24", f"regex is a stop-word or trivially short: {p!r}")
        if re.match(r"^[A-Za-z0-9 ]+$", p) and " " not in p and len(p) <= 8 and p.lower() in {"users", "desktop", "runas", "system"}:
            rep.fail("YL-24", f"regex is a generic token: {p!r}")
    if rule:
        if rule["detection_type"] in ("scheduled_detection", "ioc_sweep") and "outcome" not in sections: rep.fail("YL-7", "outcome section required")
        if "match" in sections:
            mm = re.search(r"over\s+(\d+[mhd])", sections["match"])
            if not mm: rep.fail("YL-8", "match section has no 'over <window>'")
            elif mm.group(1) != rule["correlation"]["window"]: rep.fail("YL-9", f"match window {mm.group(1)} != correlation.window")
            elif rule["detection_type"] == "scheduled_detection" and rule["correlation"]["window"] != rule["lookback"]: rep.fail("YL-9b", "detection: correlation.window must equal lookback")
            for v in re.findall(r"\$([a-z][a-z0-9_]*)", sections["match"].split("over")[0]):
                if v not in placeholders: rep.fail("YL-10", f"match variable ${v} not bound as a placeholder in events")
        if rule["detection_type"] == "scheduled_detection" and "$risk_score" not in sections.get("outcome", ""): rep.fail("YL-11", "$risk_score missing from outcome")
        for v in placeholders:
            if not re.search(rf"\${v}\s*!=\s*\"S\"", ev): rep.fail("YL-12", f"placeholder ${v} has no non-empty guard")
        for k in ("rule_id", "severity", "detection_type", "technique_ids"):
            if not re.search(rf"^\s*{k}\s*=\s*\"", raw_sections.get("meta", ""), re.M): rep.fail("YL-15", f"meta.{k} missing")
        sev = re.search(r'^\s*severity\s*=\s*"([A-Z]+)"', raw_sections.get("meta", ""), re.M)
        if sev and sev.group(1) != rule["severity"]["rating"].upper(): rep.fail("YL-16", "meta.severity != contract severity")
        for lst in re.findall(r"%([a-z][a-z0-9_]*)", body):
            if lst not in {r["name"] for r in rule["reference_lists"]}: rep.fail("YL-17", f"reference list %{lst} not declared")
        if len(evars) != rule["complexity"]["event_variables_or_joins"]: rep.fail("YL-19", f"event variable count {len(evars)} != complexity.event_variables_or_joins")
        if hours(rule["lookback"]) > 48 and rule["detection_type"] == "scheduled_detection": rep.fail("YL-20", "match window over 48h for a live rule")
    return patterns


# ---------- KQL lint ----------
def lint_kql(q: str, rep: Report, rule: Optional[dict] = None) -> List[str]:
    body = strip_comments(q, "kql")
    lets = re.findall(r"^\s*let\s+([A-Za-z_][A-Za-z0-9_]*)\s*=", body, re.M)
    for name in lets:
        uses = len(re.findall(rf"\b{name}\b", body)) - 1
        if uses < 1: rep.fail("KQL-1", f"let {name} defined and never consumed")
    table_lets = re.findall(rf"^\s*let\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?:materialize\()?\s*{KQL_TABLE_PREFIX}\b", body, re.M)
    um = re.search(r"^\s*union\s+([^\n|]+)", body, re.M)
    branches = []
    if um:
        branches = [b.strip() for b in um.group(1).split(",") if b.strip()]
        if len(branches) != len(set(branches)): rep.fail("KQL-2", "duplicate branch in union")
        missing = [b for b in table_lets if b not in branches]
        if missing: rep.fail("KQL-3", f"table-valued let(s) {missing} not in union")
    # Verbatim strings removed first so quotes pair correctly; a string ending in \" runs to end of line
    for m in re.finditer(r'"((?:[^"\\\n]|\\.)*)(?:"|$)', re.sub(r'@"(?:[^"]|"")*"', '@V', body), re.M):
        if "\\" in m.group(1): rep.fail("KQL-5", f"ordinary literal contains backslash: {m.group(0)[:40]} (use @\"...\")")
    if re.search(r"\bdatetime\s*\(", body): rep.fail("KQL-6", "absolute datetime literal")
    if re.search(r"\bcontains\b", body): rep.fail("KQL-7", "substring 'contains' used; use has/=~/in~ or an anchored regex")
    if re.search(r"isempty\([^)]*\)\s*or\s", body): rep.fail("KQL-13", "forbidden fail-open idiom isempty(x) or ...")
    for m in re.finditer(r"\|\s*summarize\b([^|;]*)", body):
        clause = m.group(1)
        bym = re.search(r"\bby\b(.*)", clause, re.S)
        if bym:
            keys = [k for k in bym.group(1).split(",") if k.strip()]
            if len(keys) > 8: rep.fail("KQL-14", "summarize by with more than 8 keys")
            if re.match(r"\s*by\b", clause) and re.match(r"\s*Timestamp\b", bym.group(1)):
                rep.fail("KQL-15", "summarize by Timestamp, ... is a per-event distinct, not an aggregation (every raw event alerts)")
    # Malformed string lists (Q042/Q043: indicator text inserted with embedded quotes or line breaks).
    # After scrubbing, every item of has_any/has_all/in/in~ must be a placeholder literal or an identifier.
    scrubbed = scrub(q, "kql")
    for m in re.finditer(r"\b(?:has_any|has_all|in~?|!in~?)\s*\(([^()]*)\)", scrubbed):
        for item in m.group(1).split(","):
            if not re.fullmatch(r"\s*(?:\"S\"|'S'|[A-Za-z_][A-Za-z0-9_]*|-?\d+(?:\.\d+)?)\s*", item):
                rep.fail("KQL-16", f"malformed string list item: {item.strip()[:50]!r}"); break
    for stmt in re.split(r"\n\s*\|", strip_comments(q, "kql")):
        # Verbatim @"..." strings double their quotes; ordinary strings escape them as \" (valid KQL)
        s = re.sub(r'@"(?:[^"]|"")*"', "", stmt)
        s = re.sub(r'"(?:[^"\\\n]|\\.)*"', "", s)
        if '"' in s: rep.fail("KQL-16", f"unbalanced double quotes in statement: {stmt.strip()[:60]}")
    if re.search(r"\bhas_(?:any|all)\s*\(\s*\"[^\"]*\n", q): rep.fail("KQL-16", "string literal inside has_any/has_all spans a line break")
    # Bracket structure, strings scrubbed: an empty group (not a call like count()) or an
    # unbalanced bracket is a query that won't parse, e.g. "where ())))) or (...)"
    depth = 0
    for ch in scrubbed:
        depth += (ch == "(") - (ch == ")")
        if depth < 0: break
    if depth: rep.fail("KQL-17", "unbalanced round brackets")
    if re.search(r"(?<![A-Za-z0-9_])\(\s*\)", scrubbed): rep.fail("KQL-17", "empty bracket group ()")
    joins = len(re.findall(r"\|\s*join\b", body))
    if rule:
        if um and len(branches) != rule["complexity"]["union_branches"]: rep.fail("KQL-4", "union branch count != complexity.union_branches")
        if not um and rule["complexity"]["union_branches"] != 0: rep.fail("KQL-4", "complexity.union_branches set but no union")
        if joins != rule["complexity"]["event_variables_or_joins"]: rep.fail("KQL-8", f"join count {joins} != complexity.event_variables_or_joins")
        if rule["detection_type"] == "scheduled_detection":
            last = scrub(q, "kql").strip().split("|")[-1]
            for col in ("Timestamp", "ReportId", "DeviceId"):
                if not re.search(rf"\b{col}\b", last): rep.fail("KQL-9", f"final projection lacks {col}")
            lb = re.search(r"let\s+lookback\s*=\s*(\d+[mhd])\s*;", body)
            if not lb or lb.group(1) != rule["lookback"]: rep.fail("KQL-10", "let lookback must equal contract lookback")
            if "ago(lookback)" not in body: rep.fail("KQL-11", "Timestamp not bounded by ago(lookback)")
            f = rule["schedule"].get("frequency")
            if f and not (hours(f) <= hours(rule["lookback"]) <= KQL_WINDOW[f]): rep.fail("KQL-12", "lookback outside [frequency, platform window]")
    return [m.group(1).replace('""', '"') for m in re.finditer(r'matches\s+regex\s+@"((?:[^"]|"")*)"', body)]


def scope_check(q: str, rep: Report):
    if re.search(r"\[(USER_ID|USER_NAME|SOC_DEPARTMENT)\]", q) or re.search(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[a-z]{2,}", q):
        rep.fail("SCOPE-1", "hardcoded entity token in query")


def lint_query(query: str, siem: Optional[str] = None) -> Report:
    """Query-level lints only (no contract metadata). Used for legacy Shikari YAML and raw LLM output."""
    rep = Report()
    siem = siem or detect_siem(query)
    if siem == "spl" or siem is None:
        rep.siem = siem
        return rep
    rep.siem = siem
    scope_check(query, rep)
    mixed_andor(query, siem, rep)
    if siem == "yara_l": lint_yaral(query, rep)
    else: lint_kql(query, rep)
    return rep


# ---------- contract-level checks ----------
def check_rule(rule: dict, rep: Report):
    check_order(rule, RULE_ORDER, "ORDER-rule", rep)
    if rule["status"] != "draft": rep.fail("STATUS", "model output must be status: draft")
    if rule["validation"]["compile"]["status"] != "not_run": rep.fail("VAL-compile", "compile status must be not_run on emission")
    tactic, tech = rule["attack"]["tactics"][0], rule["attack"]["technique_ids"][0]
    if rule["siem"] == "kql":
        name_ok = re.match(r"^[A-Z][A-Za-z]+_T\d{4}(\.\d{3})?_[A-Za-z]+_[A-Z][A-Za-z0-9]+$", rule["name"])
        if not name_ok: rep.fail("NAME-1", "KQL name pattern")
        exp_prefix = f"{TACTIC_PASCAL[tactic]}_{tech}_"
        if not rule["name"].startswith(exp_prefix): rep.fail("NAME-2", f"name must start with {exp_prefix}")
        suffix = {"hunt": "Hunt", "ioc_sweep": "Sweep"}.get(rule["detection_type"])
        if suffix and not rule["name"].endswith(suffix): rep.fail("NAME-3", f"descriptor must end with {suffix}")
        src = rule["name"].split("_")[2] if name_ok else None
        if src and src not in {ls["siem_source"] for ls in rule["log_sources"]}: rep.fail("NAME-4", f"log-source token {src} not a declared source")
    else:
        if not re.match(r"^[a-z][a-z_]+_t\d{4}(_\d{3})?_udm_[a-z_]+_[a-z0-9_]+$", rule["name"]): rep.fail("NAME-1", "YARA-L name pattern")
        exp_prefix = f"{tactic}_{tech.lower().replace('.', '_')}_udm_"
        if not rule["name"].startswith(exp_prefix): rep.fail("NAME-2", f"name must start with {exp_prefix}")
        suffix = {"hunt": "_hunt", "ioc_sweep": "_sweep"}.get(rule["detection_type"])
        if suffix and not rule["name"].endswith(suffix): rep.fail("NAME-3", f"descriptor must end with {suffix}")
    dt = rule["detection_type"]
    if dt != "scheduled_detection" and hours(rule["lookback"]) > 90 * 24: rep.fail("TYPE-1", "lookback over 90d")
    if dt == "scheduled_detection" and rule["siem"] == "yara_l" and rule["schedule"].get("mode") != "live": rep.fail("TYPE-2", "YARA-L detections are live")
    if dt == "scheduled_detection" and rule["siem"] == "kql" and "frequency" not in rule["schedule"]: rep.fail("TYPE-2", "KQL detections need frequency")
    sids = {s["id"] for s in rule["tuning_notes"]["suppressions"]}
    for fp in rule["false_positives"]:
        if fp["handled_by"] == "suppression" and fp["suppression_id"] not in sids: rep.fail("FP-1", f"{fp['id']} names unknown suppression")
        if fp["handled_by"] != "suppression" and fp["suppression_id"] is not None: rep.fail("FP-2", f"{fp['id']} suppression_id must be null")
        if re.search(r"may be benign|legitimate admin|normal (developer|user) (behaviour|activity)", fp["scenario"], re.I): rep.fail("FP-3", f"{fp['id']} generic scenario")
    for s in rule["tuning_notes"]["suppressions"]:
        if s["logic_ref"] not in rule["query"]: rep.fail("SUP-1", f"{s['id']} logic_ref not found verbatim in query")
    refs = {r["id"] for r in rule["references"]}
    seen = set()
    for i in rule["indicators"]:
        if i["reference_id"] not in refs: rep.fail("IOC-1", f"{i['id']} reference_id unresolved")
        if PLACEHOLDERS.search(i["value"]): rep.fail("IOC-2", f"{i['id']} placeholder value")
        v, t = i["value"], i["type"]
        if t == "sha256" and not re.fullmatch(r"[0-9a-f]{64}", v): rep.fail("IOC-3", f"{i['id']} sha256 format")
        if t == "sha1" and not re.fullmatch(r"[0-9a-f]{40}", v): rep.fail("IOC-3", f"{i['id']} sha1 format")
        if t == "md5" and not re.fullmatch(r"[0-9a-f]{32}", v): rep.fail("IOC-3", f"{i['id']} md5 format")
        if t in ("ipv4", "ipv6"):
            try:
                ip = ipaddress.ip_address(v)
                if ip.is_private or ip.is_loopback or ip.is_link_local: rep.fail("IOC-4", f"{i['id']} non-routable address")
            except ValueError: rep.fail("IOC-3", f"{i['id']} ip format")
        if t == "domain" and re.search(r"[/:]", v): rep.fail("IOC-3", f"{i['id']} domain contains scheme or path")
        if t == "filename" and re.search(r"[/\\]", v): rep.fail("IOC-3", f"{i['id']} filename contains a directory")
        if (t, v.lower()) in seen: rep.fail("IOC-5", f"duplicate indicator {v}")
        seen.add((t, v.lower()))
        if v != v.lower() and t in ("sha256", "sha1", "md5", "domain"): rep.fail("IOC-6", f"{i['id']} not normalised to lowercase")
    ioc_ids = {i["id"] for i in rule["indicators"]}
    listed = set()
    for rl in rule["reference_lists"]:
        for iid in rl["indicator_ids"]:
            if iid not in ioc_ids: rep.fail("RL-1", f"{rl['name']} references unknown {iid}")
            listed.add(iid)
    if dt == "ioc_sweep":
        for i in rule["indicators"]:
            if i["id"] not in listed and i["value"].lower() not in rule["query"].lower():
                rep.fail("IOC-7", f"{i['id']} not present in query or a declared reference list")
    q = rule["query"]
    scope_check(q, rep)
    n = len(query_lines(q))
    if n != rule["complexity"]["lines"]: rep.fail("CX-1", f"complexity.lines {rule['complexity']['lines']} != counted {n}")
    ls_ids = {l["id"] for l in rule["log_sources"]}
    for e in rule["correlation"]["events"]:
        if e["source_id"] not in ls_ids: rep.fail("COR-1", f"event {e['var']} source {e['source_id']} undeclared")
        if rule["siem"] == "yara_l" and f"${e['var']}." not in q: rep.fail("COR-2", f"event var ${e['var']} not in query")
    if len(rule["correlation"]["events"]) > 1:
        if not rule["correlation"]["join_keys"]: rep.fail("COR-3", "multi-event rule without join_keys")
        for jk in rule["correlation"]["join_keys"]:
            for os_ in rule["target_os"]:
                if os_ not in jk["holds_on"] and not jk["mitigation"]: rep.fail("COR-4", f"join key {jk['key']} does not hold on {os_} and no mitigation")
    for ls in rule["log_sources"]:
        if ls["ingestion"]["status"] == "not_ingested": rep.fail("ING-1", f"{ls['id']} declared not_ingested: must be a rejection")
        for f in ls["fields"]:
            if f["population"] == "known_empty": rep.fail("POP-1", f"{ls['id']} field {f['path']} known_empty: must be a rejection")
            if f["path"] not in q: rep.fail("POP-2", f"{ls['id']} declared field {f['path']} not in query")
    mixed_andor(q, rule["siem"], rep)
    pats = lint_yaral(q, rep, rule) if rule["siem"] == "yara_l" else lint_kql(q, rep, rule)
    declared = {r["pattern"] for r in rule["regexes"]}
    for p in pats or []:
        if p not in declared: rep.fail("RX-1", f"regex in query not declared in regexes[]: {p[:60]}")
    for r in rule["regexes"]:
        enc_ok = (r["literal_encoding"] == "yara_l_backtick") == (rule["siem"] == "yara_l")
        if not enc_ok: rep.fail("RX-2", f"{r['id']} literal_encoding does not match siem")
        if r["literal_encoding"] == "yara_l_backtick" and "`" in r["pattern"]: rep.fail("RX-3", f"{r['id']} backtick inside pattern")
        try: cre = re.compile(r["pattern"], re.I)
        except re.error as e: rep.fail("RX-4", f"{r['id']} does not compile: {e}"); continue
        for s in r["must_match"]:
            if not cre.search(s): rep.fail("RX-5", f"{r['id']} must_match sample does not match: {s}")
        for s in r["must_not_match"]:
            if cre.search(s): rep.fail("RX-6", f"{r['id']} must_not_match sample matches: {s}")
        if r["pattern"] not in q.replace('""', '"'): rep.fail("RX-7", f"{r['id']} pattern not found in query")


def check_rejection(rej: dict, rep: Report):
    check_order(rej, REJ_ORDER, "ORDER-rejection", rep)


def validate_text(text: str, path: str = "<text>") -> Report:
    rep = Report(path)
    lexical(text, rep)
    try: doc = yaml.safe_load(text)
    except yaml.YAMLError as e: rep.fail("YAML", str(e)); return rep
    if not isinstance(doc, dict) or "shikari_output" not in doc:
        rep.fail("SCHEMA", "document root must be shikari_output"); return rep
    try: jsonschema.validate(doc, SCHEMA)
    except jsonschema.ValidationError as e:
        rep.fail("SCHEMA", f"{'/'.join(str(p) for p in e.absolute_path)}: {e.message[:200]}")
        return rep
    top = doc["shikari_output"]
    rep.document = doc
    check_order(top, TOP_ORDER + ["rule", "rejection"], "ORDER-top", rep)
    if top["kind"] == "rule": check_rule(top["rule"], rep)
    else: check_rejection(top["rejection"], rep)
    return rep


def validate_file(path) -> Report:
    return validate_text(Path(path).read_text(), str(path))


def is_contract_document(text: str) -> bool:
    return bool(re.search(r"^\s*shikari_output:\s*$", text, re.M))
