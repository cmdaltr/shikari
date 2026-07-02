"""
Splunk SPL query parsing, validation, and combination utilities.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import List, Optional, Tuple


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class SplunkQuery:
    """Parsed representation of a Splunk SPL query."""
    raw: str
    indexes: List[str] = field(default_factory=list)
    sourcetypes: List[str] = field(default_factory=list)
    commands: List[str] = field(default_factory=list)
    fields: List[str] = field(default_factory=list)
    filters: List[str] = field(default_factory=list)
    has_stats: bool = False
    has_eval: bool = False
    has_transaction: bool = False
    has_lookup: bool = False
    has_subsearch: bool = False

    @property
    def is_empty(self) -> bool:
        return not self.raw.strip()


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------

# SPL pipe commands (non-exhaustive but covers common detection use)
_SPL_COMMANDS = {
    "search", "index", "stats", "eval", "where", "table", "fields",
    "rename", "sort", "head", "tail", "dedup", "transaction", "lookup",
    "join", "append", "inputlookup", "outputlookup", "rex", "regex",
    "tstats", "mstats", "bucket", "bin", "timechart", "chart", "top",
    "rare", "eventstats", "streamstats", "delta", "autoregress",
    "predict", "anomalydetection", "cluster", "makemv", "mvexpand",
    "map", "foreach", "return", "format", "makejson", "spath",
    "xmlkv", "multikv", "extract", "kvform", "convert", "fillnull",
    "replace", "outputtext", "collect", "sendemail", "sendalert",
}

_INDEX_RE = re.compile(r'\bindex\s*=\s*["\']?(\w[\w\-\.]*)["\']?', re.IGNORECASE)
_SOURCETYPE_RE = re.compile(r'\bsourcetype\s*=\s*["\']?([\w\-\.\:\*]+)["\']?', re.IGNORECASE)
_FIELD_EQ_RE = re.compile(r'\b([A-Za-z_][\w\.]*)\s*=\s*(?:"[^"]*"|\'[^\']*\'|\S+)', re.IGNORECASE)
_COMMAND_RE = re.compile(r'(?:^|\|)\s*([a-z]+)', re.IGNORECASE)


def parse_splunk_query(query: str) -> SplunkQuery:
    """Parse a raw SPL string into a SplunkQuery dataclass."""
    q = SplunkQuery(raw=query)
    if not query.strip():
        return q

    q.indexes = _INDEX_RE.findall(query)
    q.sourcetypes = _SOURCETYPE_RE.findall(query)

    # Extract pipe commands
    q.commands = [
        m.strip().lower()
        for m in _COMMAND_RE.findall(query)
        if m.strip().lower() in _SPL_COMMANDS
    ]

    q.has_stats = "stats" in q.commands or "tstats" in q.commands
    q.has_eval = "eval" in q.commands
    q.has_transaction = "transaction" in q.commands
    q.has_lookup = "lookup" in q.commands or "inputlookup" in q.commands
    q.has_subsearch = "[" in query and "search" in query.lower()

    # Extract field names from field=value patterns (excluding index/sourcetype)
    skip = {"index", "sourcetype", "source", "host", "splunk_server"}
    q.fields = [
        m
        for m in _FIELD_EQ_RE.findall(query)
        if m.lower() not in skip
    ]

    return q


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

def validate_splunk_query(query: str) -> Tuple[bool, str]:
    """
    Basic structural validation of a Splunk SPL query.

    Returns:
        (True, "") on success
        (False, reason) on failure
    """
    if not query or not query.strip():
        return False, "Query is empty"

    raw = query.strip()

    # Must start with a search command or pipe
    if not (
        raw.lower().startswith("search")
        or raw.lower().startswith("index")
        or raw.lower().startswith("|")
        or raw.lower().startswith("tstats")
        or re.match(r'^["\']?\*', raw)
    ):
        # Allow bare field=value or index=x as implicit search
        if not re.match(r'^\w[\w\-\.]*\s*=', raw):
            return False, "Query does not begin with a recognised SPL search term or command"

    # Balanced brackets
    if raw.count("[") != raw.count("]"):
        return False, "Unbalanced square brackets (subsearch)"
    if raw.count("(") != raw.count(")"):
        return False, "Unbalanced parentheses"

    # Must have at least one index or sourcetype restriction for detection queries
    has_scope = bool(
        _INDEX_RE.search(raw)
        or _SOURCETYPE_RE.search(raw)
        or raw.lower().startswith("| tstats")
    )
    if not has_scope:
        return False, "No index= or sourcetype= restriction found — query may be too broad"

    # No obvious syntax traps
    if "| |" in raw:
        return False, "Double pipe (| |) is invalid SPL syntax"

    return True, ""


# ---------------------------------------------------------------------------
# Combination
# ---------------------------------------------------------------------------

def combine_splunk_queries(query_a: str, query_b: str) -> str:
    """
    Combine two SPL queries into a single query using an append + stats pattern.

    The result runs both queries independently and unions the events, which is
    suitable for detecting the same technique across different data sources or
    indexes.
    """
    a = query_a.strip().rstrip("|").strip()
    b = query_b.strip().rstrip("|").strip()

    if not a:
        return b
    if not b:
        return a

    # If both queries share the same index, use OR to union them inline
    indexes_a = set(_INDEX_RE.findall(a))
    indexes_b = set(_INDEX_RE.findall(b))

    if indexes_a and indexes_a == indexes_b:
        # Same index — try to merge the WHERE clauses with OR
        # Strip leading "search" from b and wrap in (...)
        b_core = re.sub(r'^search\s+', '', b, count=1, flags=re.IGNORECASE).strip()
        return f"{a}\nOR ({b_core})"

    # Different indexes — use append to union results
    combined = (
        f"({a})\n"
        f"| append [\n"
        f"    {b}\n"
        f"]\n"
        f"| dedup _time, host, source\n"
        f"| sort -_time"
    )
    return combined
