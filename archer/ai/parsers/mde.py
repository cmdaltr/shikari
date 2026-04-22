"""
Microsoft Defender for Endpoint / Sentinel KQL query parsing, validation,
and combination utilities.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import List, Optional, Tuple


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class KQLQuery:
    """Parsed representation of a KQL query."""
    raw: str
    tables: List[str] = field(default_factory=list)
    operators: List[str] = field(default_factory=list)
    fields: List[str] = field(default_factory=list)
    filters: List[str] = field(default_factory=list)
    has_join: bool = False
    has_union: bool = False
    has_summarize: bool = False
    has_project: bool = False
    has_extend: bool = False
    has_mv_expand: bool = False
    time_window: Optional[str] = None

    @property
    def is_empty(self) -> bool:
        return not self.raw.strip()


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------

_KQL_TABULAR_OPERATORS = {
    "where", "project", "extend", "summarize", "join", "union", "limit",
    "top", "sort", "order", "render", "take", "count", "distinct",
    "mv-expand", "mv-apply", "evaluate", "parse", "extract", "getschema",
    "sample", "reduce", "make-series", "range", "print", "datatable",
    "search", "find", "lookup", "invoke", "serialize", "partition",
}

# MDE / Sentinel table names (common set for detection engineering)
_KNOWN_TABLES = {
    "DeviceEvents", "DeviceProcessEvents", "DeviceNetworkEvents",
    "DeviceFileEvents", "DeviceRegistryEvents", "DeviceLogonEvents",
    "DeviceImageLoadEvents", "DeviceNetworkInfo", "DeviceInfo",
    "IdentityLogonEvents", "IdentityQueryEvents", "IdentityDirectoryEvents",
    "AlertEvidence", "AlertInfo", "EmailEvents", "EmailAttachmentInfo",
    "EmailUrlInfo", "CloudAppEvents", "BehaviorEntities", "BehaviorInfo",
    "SecurityEvent", "SigninLogs", "AADNonInteractiveUserSignInLogs",
    "AuditLogs", "OfficeActivity", "Syslog", "CommonSecurityLog",
}

_TABLE_RE = re.compile(
    r'^([A-Za-z][A-Za-z0-9_]*)\b',
    re.MULTILINE,
)
_TIME_AGO_RE = re.compile(r'ago\((\d+[dhms])\)', re.IGNORECASE)
_OPERATOR_RE = re.compile(
    r'\|\s*([a-z][a-z\-]*)',
    re.IGNORECASE,
)
_WHERE_FIELD_RE = re.compile(r'\b([A-Za-z][A-Za-z0-9_\.]*)\s*(?:==|!=|=~|!~|has|contains|startswith|endswith)', re.IGNORECASE)


def parse_kql_query(query: str) -> KQLQuery:
    """Parse a raw KQL string into a KQLQuery dataclass."""
    q = KQLQuery(raw=query)
    if not query.strip():
        return q

    lines = query.strip().splitlines()

    # First non-empty, non-comment token is usually the table name
    for line in lines:
        stripped = line.strip()
        if stripped and not stripped.startswith("//") and not stripped.startswith("|"):
            m = re.match(r'^([A-Za-z][A-Za-z0-9_]*)', stripped)
            if m and m.group(1) in _KNOWN_TABLES:
                q.tables.append(m.group(1))
            break

    # Also catch union/join targets
    union_re = re.compile(r'\bunion\b\s+([A-Za-z][A-Za-z0-9_,\s]*)', re.IGNORECASE)
    for m in union_re.finditer(query):
        for t in re.split(r'[\s,]+', m.group(1)):
            if t in _KNOWN_TABLES:
                q.tables.append(t)

    # Pipe operators
    q.operators = [
        m.strip().lower()
        for m in _OPERATOR_RE.findall(query)
        if m.strip().lower() in _KQL_TABULAR_OPERATORS
    ]

    q.has_join = "join" in q.operators
    q.has_union = "union" in q.operators
    q.has_summarize = "summarize" in q.operators
    q.has_project = "project" in q.operators
    q.has_extend = "extend" in q.operators
    q.has_mv_expand = "mv-expand" in q.operators

    # Time window from ago()
    time_m = _TIME_AGO_RE.search(query)
    if time_m:
        q.time_window = time_m.group(1)

    # Field references in where clauses
    q.fields = list(dict.fromkeys(_WHERE_FIELD_RE.findall(query)))

    return q


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

def validate_kql_query(query: str) -> Tuple[bool, str]:
    """
    Basic structural validation of a KQL query.

    Returns:
        (True, "") on success
        (False, reason) on failure
    """
    if not query or not query.strip():
        return False, "Query is empty"

    raw = query.strip()

    # Must start with a known table or a let statement
    first_token = re.match(r'^(let\s+|[A-Za-z][A-Za-z0-9_]*)', raw, re.IGNORECASE)
    if not first_token:
        return False, "Query does not begin with a table name or 'let' statement"

    # Balanced parentheses
    if raw.count("(") != raw.count(")"):
        return False, "Unbalanced parentheses"

    # No double pipes
    if "| |" in raw:
        return False, "Double pipe (| |) is invalid KQL syntax"

    # Warn if no time scoping
    if "ago(" not in raw.lower() and "datetime(" not in raw.lower() and "startofday(" not in raw.lower():
        # Not invalid, but flag it
        pass  # Would be a warning, not an error

    # Must reference at least one known MDE/Sentinel table
    parsed = parse_kql_query(raw)
    if not parsed.tables:
        return False, "No recognised MDE/Sentinel table found — query may not run in Defender Advanced Hunting"

    return True, ""


# ---------------------------------------------------------------------------
# Combination
# ---------------------------------------------------------------------------

def combine_kql_queries(query_a: str, query_b: str) -> str:
    """
    Combine two KQL queries using union.

    The result wraps both queries as subqueries passed to union, producing
    a unified result set. This is the standard KQL pattern for multi-table
    detection correlation.
    """
    a = query_a.strip()
    b = query_b.strip()

    if not a:
        return b
    if not b:
        return a

    parsed_a = parse_kql_query(a)
    parsed_b = parse_kql_query(b)

    # If same table, try to union with OR on the where clause
    if parsed_a.tables and parsed_a.tables == parsed_b.tables:
        # Indent b's body to merge as union subquery
        pass  # Fall through to full union pattern

    combined = (
        f"union (\n"
        f"    {a.replace(chr(10), chr(10) + '    ')}\n"
        f"),\n"
        f"(\n"
        f"    {b.replace(chr(10), chr(10) + '    ')}\n"
        f")\n"
        f"| sort by TimeGenerated desc"
    )
    return combined
