"""
Precision checks: queries that parse but can't mean anything (#15).

static_check asks "will it parse?"; these ask "can it fire for the right reason?":

  PREC-CONTEXT      error  the only condition is the connection's protocol (every DNS lookup)
  PREC-PORT         warn   the only condition is a port (all traffic on it)
  PREC-NUMERIC      error  a string operator on an integer column (RemotePort has "135")
  PREC-PLACEHOLDER  error  a documentation stand-in kept as text ("v:{hostname", "[Username]")
  PREC-GENERIC      warn   a value that's an ordinary word (has "copy", has "Index")
  PREC-EMPTY        error  no condition but the event type (every process launch)
  PREC-DUPLICATE    warn   the same condition more than once
  PREC-TABLE        warn   a table the technique's ATT&CK platforms can't reach
  PREC-BARE         warn   every value is a built-in binary's name (every wmic.exe launch)
  PREC-API          warn   every value is a Windows API name (never on a command line unless a
                           script inlines it)

A correlation part needs more: one that trips PREC-BARE or PREC-API says nothing about what
the binary did, so pairing it with another technique pairs noise (see correlation_part_ok).

prune_kql removes the conditions an error or warning names, keeping the rest: generation
uses it before writing a detection, so a bad clause costs that clause, not the detection.
"""

import re
from typing import Dict, Iterable, List, Optional, Tuple

from archer.build.indicator_hygiene import GAP, _PLACEHOLDER, _SLOTS

# Ordinary words that match far more than the behaviour when they're a whole value
GENERIC_WORDS = {
    "index", "true", "false", "dir", "copy", "show", "version", "list", "get", "set", "run", "open", "start",
    "new", "help", "data", "value", "name", "type", "test", "temp", "info", "level", "admin", "file", "user",
    "system", "log", "path", "key", "home", "root", "config", "exec", "shell", "query", "search", "find",
    "default", "local", "remote", "service", "server", "client", "host", "update", "install", "load", "save",
    "read", "write", "delete", "create", "add", "remove", "send", "check", "status", "error", "output",
    "input", "network", "process", "command", "script", "session", "token", "password", "account",
}
NUMERIC_COLUMNS = {"RemotePort", "LocalPort", "ProcessId", "InitiatingProcessId", "InitiatingProcessParentId",
                   "FileSize", "InitiatingProcessFileSize", "LogonId", "InitiatingProcessLogonId", "ReportId",
                   "DestinationPort", "SourcePort", "Port", "EventId"}
_STRING_OPS = r"(?:has_any|has_all|has_cs|has|!has|contains|contains_cs|startswith|endswith|matches regex|=~|!~|in~)"
_NUMERIC_STRING = re.compile(r"\b(" + "|".join(sorted(NUMERIC_COLUMNS, key=len, reverse=True)) + r")\s+" + _STRING_OPS + r"\s*[(\"]")
_STRING = re.compile(r'@?"((?:[^"\\]|\\.)*)"')
_CONDITION_COLUMN = re.compile(r"\b([A-Z]\w+)\s+(?:" + _STRING_OPS + r"|==|!=|in|>=|<=|>|<)(?=[\s(\"@])")
# Which ATT&CK platforms can produce events in each kind of table
_TABLE_PLATFORMS = [
    (re.compile(r"^(Device\w+)$"), {"windows", "linux", "macos"}),
    (re.compile(r"^(Identity\w+|AADSignInEventsBeta|AADSpnSignInEventsBeta|EntraIdSignInEvents)$"),
     {"identity provider", "windows", "azure ad", "saas", "office suite", "office 365", "iaas"}),
    (re.compile(r"^(CloudAppEvents|CloudAuditEvents)$"), {"saas", "office suite", "office 365", "iaas",
                                                         "identity provider", "google workspace", "azure ad"}),
    (re.compile(r"^(Email\w+|UrlClickEvents)$"), {"office suite", "office 365", "saas", "windows", "linux", "macos"}),
]


def _top_level(text: str, sep: str = " or ") -> List[str]:
    """Split on sep outside quotes and brackets."""
    parts, depth, quote, start, i = [], 0, None, 0, 0
    while i < len(text):
        c = text[i]
        if quote:
            if c == "\\" and quote == '"' and i + 1 < len(text) and text[i - 1] != "@":
                i += 2
                continue
            if c == quote:
                quote = None
        elif c in "\"'`":
            quote = c
        elif c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
        elif depth == 0 and text.startswith(sep, i):
            parts.append(text[start:i])
            start = i + len(sep)
            i = start
            continue
        i += 1
    parts.append(text[start:])
    return [p.strip() for p in parts]


def _unwrap(clause: str) -> str:
    c = clause.strip()
    while c.startswith("(") and c.endswith(")") and _balanced(c[1:-1]):
        c = c[1:-1].strip()
    return c


def _balanced(text: str) -> bool:
    depth, quote = 0, None
    for c in text:
        if quote:
            if c == quote:
                quote = None
        elif c in "\"'`":
            quote = c
        elif c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth < 0:
                return False
    return depth == 0


# Built-in binaries when the LOLBAS index isn't cached (archer.build.lol)
_BUILTIN_BINARIES = {
    "cmd.exe", "powershell.exe", "pwsh.exe", "wmic.exe", "rundll32.exe", "regsvr32.exe", "mshta.exe",
    "cscript.exe", "wscript.exe", "certutil.exe", "bitsadmin.exe", "msiexec.exe", "net.exe", "net1.exe",
    "reg.exe", "sc.exe", "schtasks.exe", "svchost.exe", "explorer.exe", "conhost.exe", "whoami.exe",
    "nltest.exe", "tasklist.exe", "taskkill.exe", "netsh.exe", "vssadmin.exe", "wevtutil.exe", "at.exe",
    "msbuild.exe", "installutil.exe", "regasm.exe", "regsvcs.exe", "cmstp.exe", "forfiles.exe", "dsquery.exe",
}
_BINARY = re.compile(r"^(?:.*[\\/])?([\w.-]+\.(?:exe|com|dll|cpl|msc))$", re.I)


def builtin_binaries() -> set:
    from archer.build.lol import load_index

    index = load_index() or {}
    return _BUILTIN_BINARIES | {k for k in index.get("lolbas") or {} if _BINARY.match(k)}


def _whole_part(values: List[str]) -> List[Dict]:
    """PREC-BARE / PREC-API: what every value of a query has in common, if it's nothing useful."""
    from archer.mitre.extract import classify_name

    values = [v.strip() for v in values if v.strip()]
    if not values:
        return []
    names = [_BINARY.match(v) for v in values]
    if all(names):
        builtin = builtin_binaries()
        if all(m.group(1).lower() in builtin for m in names):
            shown = ", ".join(sorted({m.group(1).lower() for m in names}))
            return [{"check": "PREC-BARE", "message": f"every value is a built-in binary ({shown}): it matches every launch"}]
    if all(re.fullmatch(r"[A-Za-z]\w+", v) and classify_name(v) == "winapi" for v in values):
        return [{"check": "PREC-API", "message": f"every value is a Windows API name ({', '.join(values[:4])}): "
                 "process command lines don't carry them"}]
    return []


def is_placeholder(value: str) -> bool:
    return GAP in value or bool(_PLACEHOLDER.search(value)) or any(rx.search(value) for rx in _SLOTS)


def is_generic(value: str) -> bool:
    return value.strip().strip("\"'").lower() in GENERIC_WORDS


def _clause_findings(clause: str) -> List[Dict]:
    out = []
    body = _unwrap(clause)
    m = _NUMERIC_STRING.search(body)
    if m:
        out.append({"check": "PREC-NUMERIC", "message": f"{m.group(1)} is a number: a string operator on it never matches as meant ({body[:80]})"})
    for s in _STRING.findall(body):
        if is_placeholder(s):
            out.append({"check": "PREC-PLACEHOLDER", "message": f'"{s}" is a documentation stand-in, not text an event contains'})
    columns = set(_CONDITION_COLUMN.findall(body))
    if columns and columns <= {"Protocol"}:
        out.append({"check": "PREC-CONTEXT", "message": f"a protocol alone matches every such connection ({body[:80]})"})
    return out


def _where_bodies(query: str) -> List[Tuple[int, int]]:
    """(start, end) of each KQL where expression, Timestamp filters aside."""
    spans = []
    for m in re.finditer(r"^\|\s*where\s+", query, re.M):
        end = re.search(r"^\|", query[m.end():], re.M)
        stop = m.end() + end.start() if end else len(query)
        if not query[m.end():stop].lstrip().startswith("Timestamp"):
            spans.append((m.end(), stop))
    return spans


def check_kql(query: str, technique_platforms: Optional[Iterable[str]] = None) -> List[Dict]:
    findings: List[Dict] = []
    for start, stop in _where_bodies(query):
        clauses = [_unwrap(c) for c in _top_level(query[start:stop].strip())]
        seen = set()
        for c in clauses:
            findings += _clause_findings(c)
            key = re.sub(r"\s+", " ", c)
            if key in seen:
                findings.append({"check": "PREC-DUPLICATE", "message": f"the same condition is repeated: {key[:80]}"})
            seen.add(key)
            # A has_all term only narrows the others; a value that can match alone is the problem
            for s in _STRING.findall(re.sub(r"\bhas_all\s*\([^()]*\)", "", c)):
                if is_generic(s):
                    findings.append({"check": "PREC-GENERIC", "message": f'"{s}" is an ordinary word: it matches far more than the behaviour'})
        columns = set(_CONDITION_COLUMN.findall(query[start:stop]))
        if columns and columns <= {"RemotePort", "LocalPort"}:
            findings.append({"check": "PREC-PORT", "message": "the only condition is a port: it matches all traffic on it"})
    findings += _whole_part([v for start, stop in _where_bodies(query) for v in _STRING.findall(query[start:stop])])
    findings += _table_findings(query, technique_platforms)
    return _dedupe(findings)


def _table_findings(query: str, technique_platforms) -> List[Dict]:
    if not technique_platforms:
        return []
    table = next((l.strip() for l in query.splitlines() if l.strip() and not l.strip().startswith(("//", "let "))), "")
    platforms = {str(p).lower() for p in technique_platforms}
    for rx, reach in _TABLE_PLATFORMS:
        if rx.match(table) and not platforms & reach:
            return [{"check": "PREC-TABLE", "message": f"{table} records {', '.join(sorted(reach))} activity; "
                     f"the technique's platforms are {', '.join(sorted(platforms))}"}]
    return []


def check_yaral(query: str) -> List[Dict]:
    findings: List[Dict] = []
    events = re.search(r"^\s*events:\s*$(.*?)^\s*(?:match|outcome|condition):", query, re.M | re.S)
    body = events.group(1) if events else ""
    pairs = re.findall(r"re\.regex\(\$e\.([\w.]+),\s*`([^`]*)`\)", body)
    values = [v for _, v in pairs]
    for v in values:
        literal = re.sub(r"\\(.)", r"\1", v)
        if is_placeholder(literal):
            findings.append({"check": "PREC-PLACEHOLDER", "message": f"`{v}` is a documentation stand-in, not text an event contains"})
        if is_generic(literal):
            findings.append({"check": "PREC-GENERIC", "message": f"`{v}` is an ordinary word: it matches far more than the behaviour"})
    for (field, v), n in ((p, pairs.count(p)) for p in set(pairs)):
        if n > 1:
            findings.append({"check": "PREC-DUPLICATE", "message": f"`{v}` is matched on {field} {n} times"})
    findings += _whole_part([re.sub(r"\\(.)", r"\1", v) for v in values])
    fields = set(re.findall(r"\$e\.([\w.]+)", body)) - {"metadata.event_type"}
    if body.strip() and not fields:
        findings.append({"check": "PREC-EMPTY", "message": "the only condition is the event type: it matches every such event"})
    elif fields and fields <= {"network.application_protocol"}:
        findings.append({"check": "PREC-CONTEXT", "message": "a protocol alone matches every such connection"})
    elif fields and fields <= {"target.port", "network.application_protocol"}:
        findings.append({"check": "PREC-PORT", "message": "the only condition is a port: it matches all traffic on it"})
    return _dedupe(findings)


def _dedupe(findings: List[Dict]) -> List[Dict]:
    out, seen = [], set()
    for f in findings:
        key = (f["check"], f["message"])
        if key not in seen:
            seen.add(key)
            out.append(f)
    return out


ERRORS = {"PREC-CONTEXT", "PREC-NUMERIC", "PREC-PLACEHOLDER", "PREC-EMPTY"}


# What a correlation part can't have on top of the errors: it would pair noise with a technique
NOT_FOR_CORRELATION = {"PREC-BARE", "PREC-API"}


def correlation_part_ok(query: str, siem: str) -> bool:
    """A part worth correlating: some condition, no errors, and more than a binary's or API's name."""
    return bool(query.strip()) and not any(f["severity"] == "error" or f["check"] in NOT_FOR_CORRELATION
                                           for f in check(query, siem))


def severity(check: str) -> str:
    return "error" if check in ERRORS else "warning"


def check(query: str, siem: Optional[str], technique_platforms: Optional[Iterable[str]] = None) -> List[Dict]:
    """Findings ({check, severity, message}) for a KQL, UDM or YARA-L query; [] for other SIEMs."""
    if siem == "udm":
        # The same checks, on the rule the search amounts to (joins aren't checked)
        from archer.build.udm import to_yaral

        query, siem = to_yaral(query), "yara_l"
    found = check_kql(query, technique_platforms) if siem == "kql" else check_yaral(query) if siem == "yara_l" else []
    for f in found:
        f["severity"] = severity(f["check"])
    return found


# ── Pruning at generation time ─────────────────────────────────────────────

def _prune_list(clause: str) -> Optional[str]:
    """Drop generic and placeholder values from has_any(...) lists; None if none are left."""
    def fix(m):
        values = [v for v in _STRING.findall(m.group(2)) if not is_generic(v) and not is_placeholder(v)]
        if not values:
            return "\0"
        return f"{m.group(1)}(" + ", ".join(f'"{v}"' for v in values) + ")"
    out = re.sub(r"\b(has_any|in~?)\s*\(([^()]*)\)", fix, clause)
    return None if "\0" in out else out


def prune_kql(query: str, technique_platforms: Optional[Iterable[str]] = None) -> Tuple[Optional[str], List[Dict]]:
    """
    The query without the conditions that can't mean anything, and what was removed.
    None when no condition is left (the detection isn't written).
    """
    removed: List[Dict] = []
    out = query
    for start, stop in reversed(_where_bodies(query)):
        expr = query[start:stop]
        trailing = expr[len(expr.rstrip()):]
        kept, seen = [], set()
        for clause in _top_level(expr.strip()):
            problems = [f for f in _clause_findings(clause) if f["check"] in ERRORS]
            body = _unwrap(clause)
            if problems:
                removed += problems
                continue
            if not re.search(r"\b(has_any|in~?)\s*\(", body):
                single = _STRING.findall(body)
                if single and len(single) == 1 and is_generic(single[0]) and re.search(r"\bhas\b|==|=~", body):
                    removed.append({"check": "PREC-GENERIC", "message": f'"{single[0]}" is an ordinary word'})
                    continue
            pruned = _prune_list(clause)
            if pruned is None:
                removed.append({"check": "PREC-GENERIC", "message": f"every value was an ordinary word or a stand-in ({body[:60]})"})
                continue
            key = re.sub(r"\s+", " ", _unwrap(pruned))
            if key in seen:
                removed.append({"check": "PREC-DUPLICATE", "message": f"repeated condition dropped: {key[:60]}"})
                continue
            seen.add(key)
            kept.append(pruned)
        if not kept:
            return None, removed
        out = out[:start] + " or ".join(kept) + trailing + out[stop:]
    return out, _dedupe(removed)
