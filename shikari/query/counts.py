"""
How many results a detection's query finds, and nothing else: what a hunt run's execution keeps
(shikari/hunt_runs.py, docs/suite/INTEGRATION.md: "Results are counted, never kept").

Each query is asked for its count in the SIEM itself, so only a count row ever comes back:

- Splunk: `<query> | stats count AS shikari_hits`, its window as earliest=-<n>d
- Elasticsearch: `<query> | STATS shikari_hits = COUNT(*)`, its window as the request's @timestamp filter
- Defender XDR: `<query> | count`, read from its Count column

A query's own window (earliest=-1d, NOW() - 1 day, ago(1d)) is rewritten to the run's, so a hunt over
seven days doesn't quietly search one. The clients are the ones shikari/query already builds on
samarkand.siem, configured from the same environment as X-SIEM pivots and validation
(docs/features/QUERY_EXECUTION.md). A platform with no client configured has no counter: the run
records it as skipped.
"""

import os
import re
from datetime import datetime, timedelta, timezone
from typing import Callable, Dict, Optional

# (query, window in days, timeout in seconds) -> how many results
Counter = Callable[[str, int, float], int]

COUNT_COLUMN = "shikari_hits"


def platform_key(label: str) -> Optional[str]:
    """The counter a detection's platform label runs on ("Splunk", "MicrosoftThreatProtection",
    "Elastic", "Defender XDR", "mde"...), or None for one Shikari can't run queries in (Google SecOps)."""
    text = re.sub(r"[^a-z]", "", (label or "").lower())
    if "splunk" in text:
        return "splunk"
    if "elastic" in text or "esql" in text:
        return "elastic"
    if any(k in text for k in ("microsoftthreatprotection", "defender", "mde")):
        return "mde"
    return None


_SPLUNK_EARLIEST = re.compile(r"\bearliest\s*=\s*(\"[^\"]*\"|\S+)", re.IGNORECASE)
_ESQL_NOW = re.compile(r"NOW\(\)\s*-\s*\d+\s*(?:days?|hours?|minutes?|d|h|m)\b", re.IGNORECASE)
_KQL_AGO = re.compile(r"\bago\(\s*\d+(?:\.\d+)?\s*[dhms]\s*\)", re.IGNORECASE)


class WindowProblem(ValueError):
    """The query's time window can't be set to the run's."""


def windowed(platform: str, query: str, days: int) -> str:
    """The query with its own time terms set to the last `days` days. Pure."""
    if platform == "splunk":
        return _SPLUNK_EARLIEST.sub(f"earliest=-{days}d", query)
    if platform == "elastic":
        return _ESQL_NOW.sub(f"NOW() - {days} days", query)
    if platform == "mde":
        if _KQL_AGO.search(query):
            return _KQL_AGO.sub(f"ago({days}d)", query)
        # No window of its own: Advanced Hunting would search all 30 days. Filter straight after the
        # table, which only a query that starts with one has.
        head, pipe, rest = query.partition("|")
        if re.fullmatch(r"\s*[A-Za-z_][A-Za-z0-9_]*\s*", head):
            return f"{head.strip()}\n| where Timestamp > ago({days}d)" + (f"\n|{rest}" if pipe else "")
        raise WindowProblem("This query has no ago() term and doesn't start with a table, so its window "
                            "can't be set.")
    return query


def counted(platform: str, query: str) -> str:
    """The query asked for its count instead of its rows. Pure."""
    if platform == "splunk":
        return f"{query.rstrip()}\n| stats count AS {COUNT_COLUMN}"
    if platform == "elastic":
        return f"{query.rstrip()}\n| STATS {COUNT_COLUMN} = COUNT(*)"
    if platform == "mde":
        return f"{query.rstrip()}\n| count"
    raise ValueError(f"No counter for {platform}")


def read_count(platform: str, rows) -> int:
    """The count from a counted query's answer (a single row, or none for no results)."""
    if not rows:
        return 0
    row = rows[0]
    value = row.get("Count") if platform == "mde" else row.get(COUNT_COLUMN)
    if value is None:
        raise ValueError("The SIEM answered without a count")
    return int(float(value))


def _counter(platform: str, client) -> Counter:
    """A counter over a samarkand.siem client: the rows it gets back (one count row) go no further."""

    def count(query: str, days: int, timeout: float) -> int:
        text = counted(platform, windowed(platform, query, days))
        if platform == "splunk":
            start = f"-{days}d"
        elif platform == "elastic":
            start = datetime.now(timezone.utc) - timedelta(days=days)
        else:
            start = None
        result = client.query(text, start=start, max_rows=1, timeout=timeout)
        return read_count(platform, result.rows)

    return count


def counters() -> Dict[str, Counter]:
    """A counter for each SIEM whose query client is configured here, by platform key."""
    env = os.environ.get
    found: Dict[str, Counter] = {}
    if env("SPLUNK_HOST") and (env("SPLUNK_TOKEN") or (env("SPLUNK_USERNAME") and env("SPLUNK_PASSWORD"))):
        from shikari.query.splunk import SplunkClient

        found["splunk"] = _counter("splunk", SplunkClient().client)
    if (env("ELASTIC_URL") or env("ELASTIC_HOST")) and (
            env("ELASTIC_API_KEY") or (env("ELASTIC_USERNAME") and env("ELASTIC_PASSWORD"))):
        from shikari.query.elastic import ElasticClient

        found["elastic"] = _counter("elastic", ElasticClient().client)
    if env("SHIKARI_MDE_TENANT_ID") and env("SHIKARI_MDE_CLIENT_ID") and env("SHIKARI_MDE_CLIENT_SECRET"):
        from shikari.query.mde import MDEClient

        found["mde"] = _counter("mde", MDEClient().client)
    return found
