"""
Elastic detection generator.

Produces ES|QL — Elastic's piped query language and the modern form an Elastic Security detection
rule takes (`FROM … | WHERE … | STATS …`), the Elastic analogue of MDE's KQL, Splunk's SPL and
SecOps' UDM/YARA-L. Fields are ECS (process.command_line, registry.path, destination.ip …), from
bespoke/mappings/schemas/schemaElastic.json where a mapping is given. No AI: the indicators map to
`WHERE` clauses the same way the other generators build their queries.
"""

import json
import os
import re
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# Indicator kind (archer/build indicator kinds) → the ECS fields it's matched against
FIELD_MAP: Dict[str, List[str]] = {
    "cmd": ["process.command_line", "process.parent.command_line"],
    "sw": ["process.name", "process.executable"],
    "file": ["file.path", "file.name", "process.executable"],
    "path": ["file.path", "process.executable", "process.command_line"],
    "reg": ["registry.path", "registry.value"],
    "network": ["url.full", "dns.question.name", "destination.domain"],
    "domain": ["dns.question.name", "destination.domain", "url.domain"],
    "url": ["url.full", "url.original"],
    "service": ["service.name"],
    "acct": ["user.name"],
}
# Exact-match kinds (no substring/regex)
IP_FIELDS = ["source.ip", "destination.ip"]
PORT_FIELDS = ["destination.port", "source.port"]

DEFAULT_INDEX = "logs-endpoint.events.*"

# Columns summarised on, kept to fields the query can reference
BASE_GROUP_FIELDS = ["host.name", "user.name"]


def _rlike_literal(value: str) -> str:
    """A case-insensitive ES|QL substring match as an RLIKE regex string literal.

    The value is regex-escaped (so backslashes in Windows paths and other metacharacters are
    literal), lower-cased to pair with TO_LOWER(), wrapped in .* … .*, then escaped for the ES|QL
    double-quoted string. Deterministic, so a path like C:\\Windows survives intact."""
    regex = ".*" + re.escape(str(value).lower()) + ".*"
    return '"' + regex.replace("\\", "\\\\").replace('"', '\\"') + '"'


class ElasticQueryGenerator:
    """Generates Elastic ES|QL detection queries for a technique."""

    def __init__(self):
        self.schema = self._load_schema()

    def _load_schema(self) -> Dict:
        schema_path = Path(__file__).parent.parent.parent / "bespoke" / "mappings" / "schemas" / "schemaElastic.json"
        try:
            with open(schema_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except (OSError, ValueError):
            return {}

    def generate_query(
        self,
        technique_id: str,
        technique_name: str,
        tactic: str,
        description: str,
        indicators: Optional[Dict] = None,
        osint_data: Optional[Dict] = None,
        group_name: Optional[str] = None,
    ) -> Dict[str, object]:
        """Return {query_name, query (ES|QL text), description, index_pattern}."""
        indicators = indicators or {}
        query_name = f"{technique_id}_{technique_name.replace(' ', '_')}"
        index_pattern = self._index_pattern(indicators)
        query = self._build_esql(index_pattern, indicators)
        return {
            "query_name": query_name,
            "query": query,
            "description": f"Detects {technique_name} ({technique_id})",
            "index_pattern": index_pattern,
        }

    # Which ECS endpoint stream each indicator kind lives in
    _STREAM = {"cmd": "process", "sw": "process", "reg": "registry", "file": "file", "path": "file",
               "network": "network", "domain": "network", "url": "network", "ip": "network", "port": "network"}
    _STREAM_INDEX = {"process": "logs-endpoint.events.process-*", "registry": "logs-endpoint.events.registry-*",
                     "network": "logs-endpoint.events.network-*", "file": "logs-endpoint.events.file-*"}

    def _index_pattern(self, indicators: Dict) -> str:
        """A single stream's index when all indicators share one; otherwise the broad endpoint
        pattern, so STATS BY can reference fields from every stream the query touches."""
        streams = {self._STREAM[k] for k in indicators if indicators.get(k) and k in self._STREAM}
        if len(streams) == 1:
            return self._STREAM_INDEX.get(next(iter(streams)), DEFAULT_INDEX)
        return DEFAULT_INDEX

    def _match_clauses(self, indicators: Dict) -> Tuple[List[str], List[str]]:
        """(WHERE clauses, fields referenced) from the indicators."""
        clauses: List[str] = []
        fields: List[str] = []

        for kind, ecs_fields in FIELD_MAP.items():
            values = indicators.get(kind) or []
            if not values:
                continue
            for field in ecs_fields:
                fields.append(field)
            ors = []
            for value in list(values)[:8]:
                value = str(value).strip()
                if not value:
                    continue
                lit = _rlike_literal(value)
                ors.extend(f"TO_LOWER({field}) RLIKE {lit}" for field in ecs_fields)
            if ors:
                clauses.append("(" + " OR ".join(ors) + ")")

        # IPs: exact match
        ips = [str(v).strip() for v in (indicators.get("ip") or []) if str(v).strip()]
        if ips:
            fields.extend(IP_FIELDS)
            ors = [f'{field} == "{ip}"' for ip in ips[:8] for field in IP_FIELDS]
            clauses.append("(" + " OR ".join(ors) + ")")

        # Ports: numeric exact match
        ports = []
        for v in indicators.get("port") or []:
            try:
                ports.append(int(str(v).strip()))
            except (ValueError, TypeError):
                continue
        if ports:
            fields.extend(PORT_FIELDS)
            ors = [f"{field} == {port}" for port in ports[:8] for field in PORT_FIELDS]
            clauses.append("(" + " OR ".join(ors) + ")")

        return clauses, fields

    def _build_esql(self, index_pattern: str, indicators: Dict) -> str:
        clauses, fields = self._match_clauses(indicators)
        lines = [f"FROM {index_pattern}", "| WHERE @timestamp >= NOW() - 1 day"]
        if clauses:
            lines.append("| WHERE " + ("\n    OR ".join(clauses) if len(clauses) > 1 else clauses[0]))
        # Summarise on the fields used, de-duplicated and ordered, with host/user first
        group = list(dict.fromkeys(BASE_GROUP_FIELDS + fields))
        lines.append("| STATS Events = COUNT(*), FirstSeen = MIN(@timestamp), LastSeen = MAX(@timestamp)")
        lines.append("    BY " + ", ".join(group))
        lines.append("| SORT Events DESC")
        lines.append("| LIMIT 100")
        return "\n".join(lines)

    def validate_query(self, query: str) -> Tuple[bool, str]:
        """A light ES|QL structural check (not a full parser)."""
        if not isinstance(query, str) or not query.strip():
            return False, "Empty query"
        head = query.lstrip()
        if not head.upper().startswith("FROM "):
            return False, "ES|QL must start with FROM <index>"
        if "|" not in query:
            return False, "ES|QL needs at least one piped command"
        if query.count("(") != query.count(")"):
            return False, "Unbalanced parentheses"
        if query.count('"') % 2 != 0:
            return False, "Unbalanced quotes"
        return True, ""

    def format_query_for_display(self, query: str) -> str:
        return query if isinstance(query, str) else str(query)

    def generate_correlation_query(
        self,
        techniques: List[Dict],
        group_name: str,
        time_window: str = "5m",
    ) -> Dict[str, object]:
        """A multi-technique ES|QL correlation: events for any of the techniques' indicators,
        counted by host over the window so several in one place stand out."""
        query_name = f"{group_name.replace(' ', '_')}_correlation"
        all_clauses: List[str] = []
        for tech in techniques:
            clauses, _ = self._match_clauses(tech.get("indicators") or {})
            if clauses:
                all_clauses.append("(" + " OR ".join(clauses) + ")")
        lines = ["FROM logs-endpoint.events.*", "| WHERE @timestamp >= NOW() - 1 day"]
        if all_clauses:
            lines.append("| WHERE " + ("\n    OR ".join(all_clauses) if len(all_clauses) > 1 else all_clauses[0]))
        lines += [
            "| STATS Techniques = COUNT_DISTINCT(event.action), Events = COUNT(*),"
            " FirstSeen = MIN(@timestamp), LastSeen = MAX(@timestamp) BY host.name",
            f"| WHERE Techniques >= {min(2, max(1, len(techniques)))}",
            "| SORT Techniques DESC, Events DESC",
            "| LIMIT 100",
        ]
        return {
            "query_name": query_name,
            "query": "\n".join(lines),
            "description": f"Correlation query for {group_name}",
            "index_pattern": "logs-endpoint.events.*",
        }
