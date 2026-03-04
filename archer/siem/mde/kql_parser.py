"""
KQL (Kusto Query Language) Parser and Executor

Simplified parser for executing MDE Advanced Hunting queries against device events.
Supports basic filtering, projections, and aggregations.
"""

import re
from typing import Dict, List, Any, Optional, Callable
from dataclasses import dataclass


@dataclass
class KqlQuery:
    """Parsed KQL query components"""
    table: str
    where_clauses: List[str]
    project_fields: Optional[List[str]]
    summarize: Optional[Dict[str, Any]]
    take_limit: Optional[int]
    extend_fields: Dict[str, str]


class KqlParser:
    """Parse and execute KQL queries"""

    # MDE table schemas (simplified)
    TABLE_SCHEMAS = {
        "DeviceProcessEvents": [
            "Timestamp", "DeviceId", "DeviceName", "ActionType",
            "FileName", "FolderPath", "SHA256", "SHA1", "MD5",
            "ProcessId", "ProcessCommandLine", "ProcessIntegrityLevel",
            "ProcessTokenElevation", "ProcessCreationTime",
            "AccountDomain", "AccountName", "AccountSid",
            "InitiatingProcessFileName", "InitiatingProcessFolderPath",
            "InitiatingProcessCommandLine", "InitiatingProcessSHA256",
            "InitiatingProcessAccountName", "InitiatingProcessId",
        ],
        "DeviceNetworkEvents": [
            "Timestamp", "DeviceId", "DeviceName", "ActionType",
            "RemoteIP", "RemotePort", "RemoteUrl", "LocalIP", "LocalPort",
            "Protocol", "InitiatingProcessFileName", "InitiatingProcessCommandLine",
            "InitiatingProcessId", "InitiatingProcessAccountName",
        ],
        "DeviceFileEvents": [
            "Timestamp", "DeviceId", "DeviceName", "ActionType",
            "FileName", "FolderPath", "SHA256", "SHA1", "MD5",
            "FileSize", "InitiatingProcessFileName", "InitiatingProcessCommandLine",
            "InitiatingProcessId", "InitiatingProcessAccountName",
        ],
        "DeviceRegistryEvents": [
            "Timestamp", "DeviceId", "DeviceName", "ActionType",
            "RegistryKey", "RegistryValueName", "RegistryValueData",
            "RegistryValueType", "PreviousRegistryKey", "PreviousRegistryValueName",
            "InitiatingProcessFileName", "InitiatingProcessCommandLine",
        ],
        "DeviceLogonEvents": [
            "Timestamp", "DeviceId", "DeviceName", "ActionType",
            "AccountDomain", "AccountName", "AccountSid",
            "LogonType", "LogonId", "RemoteDeviceName", "RemoteIP",
            "InitiatingProcessFileName", "InitiatingProcessCommandLine",
        ],
        "DeviceImageLoadEvents": [
            "Timestamp", "DeviceId", "DeviceName", "ActionType",
            "FileName", "FolderPath", "SHA256", "SHA1", "MD5",
            "InitiatingProcessFileName", "InitiatingProcessCommandLine",
            "InitiatingProcessId",
        ],
        "DeviceEvents": [
            "Timestamp", "DeviceId", "DeviceName", "ActionType",
            "FileName", "FolderPath", "ProcessCommandLine",
            "InitiatingProcessFileName", "InitiatingProcessCommandLine",
            "AdditionalFields",
        ],
    }

    def parse(self, kql: str) -> KqlQuery:
        """
        Parse a KQL query into structured components.

        Args:
            kql: KQL query string

        Returns:
            Parsed KqlQuery object
        """
        kql = kql.strip()

        # Extract table name (first word or table before |)
        table_match = re.match(r'^(\w+)', kql)
        if not table_match:
            raise ValueError("Invalid KQL: no table specified")
        table = table_match.group(1)

        # Split by pipe to get query operators
        parts = [p.strip() for p in kql.split('|')]

        where_clauses = []
        project_fields = None
        summarize = None
        take_limit = None
        extend_fields = {}

        for part in parts[1:]:  # Skip table name
            part_lower = part.lower()

            # Parse where clauses
            if part_lower.startswith('where '):
                condition = part[6:].strip()
                where_clauses.append(condition)

            # Parse project
            elif part_lower.startswith('project '):
                fields_str = part[8:].strip()
                project_fields = [f.strip() for f in fields_str.split(',')]

            # Parse take/limit
            elif part_lower.startswith('take ') or part_lower.startswith('limit '):
                limit_str = re.search(r'(\d+)', part)
                if limit_str:
                    take_limit = int(limit_str.group(1))

            # Parse extend
            elif part_lower.startswith('extend '):
                extend_str = part[7:].strip()
                # Simple extend parsing: field = expression
                extend_match = re.match(r'(\w+)\s*=\s*(.+)', extend_str)
                if extend_match:
                    extend_fields[extend_match.group(1)] = extend_match.group(2)

            # Parse summarize (basic)
            elif part_lower.startswith('summarize '):
                summarize = {"raw": part[10:].strip()}

        return KqlQuery(
            table=table,
            where_clauses=where_clauses,
            project_fields=project_fields,
            summarize=summarize,
            take_limit=take_limit,
            extend_fields=extend_fields,
        )

    def execute(self, query: KqlQuery, events: Dict[str, List[Dict]]) -> List[Dict[str, Any]]:
        """
        Execute a KQL query against stored events.

        Args:
            query: Parsed KqlQuery
            events: Dict mapping table names to event lists

        Returns:
            List of matching/projected events
        """
        # Get events from the specified table
        table_events = events.get(query.table, [])

        if not table_events:
            return []

        # Apply where clauses
        filtered = table_events
        for where_clause in query.where_clauses:
            filtered = [e for e in filtered if self._evaluate_where(where_clause, e)]

        # Apply take limit
        if query.take_limit:
            filtered = filtered[:query.take_limit]

        # Apply project
        if query.project_fields:
            projected = []
            for event in filtered:
                proj_event = {}
                for field in query.project_fields:
                    if field in event:
                        proj_event[field] = event[field]
                projected.append(proj_event)
            filtered = projected

        return filtered

    def _evaluate_where(self, clause: str, event: Dict[str, Any]) -> bool:
        """
        Evaluate a KQL where clause against an event.

        Supports:
        - Field == "value" / Field != "value"
        - Field contains "value" / Field !contains "value"
        - Field startswith "value" / Field endswith "value"
        - Field matches regex "pattern"
        - Field in ("val1", "val2")
        - Field has "value"
        - and / or / not operators
        """
        clause = clause.strip()

        # Handle 'or' operator (split and check any)
        if ' or ' in clause.lower():
            parts = re.split(r'\s+or\s+', clause, flags=re.IGNORECASE)
            return any(self._evaluate_where(p.strip('() '), event) for p in parts)

        # Handle 'and' operator (split and check all)
        if ' and ' in clause.lower():
            parts = re.split(r'\s+and\s+', clause, flags=re.IGNORECASE)
            return all(self._evaluate_where(p.strip('() '), event) for p in parts)

        # Handle 'not' operator
        if clause.lower().startswith('not '):
            return not self._evaluate_where(clause[4:].strip(), event)

        # Handle 'contains' operator
        contains_match = re.match(
            r'(\w+)\s+(contains|has|!contains|!has)\s+["\']([^"\']+)["\']',
            clause, re.IGNORECASE
        )
        if contains_match:
            field = contains_match.group(1)
            operator = contains_match.group(2).lower()
            value = contains_match.group(3).lower()

            field_value = str(event.get(field, "")).lower()

            if operator in ('contains', 'has'):
                return value in field_value
            else:  # !contains, !has
                return value not in field_value

        # Handle 'startswith' / 'endswith'
        sw_match = re.match(
            r'(\w+)\s+(startswith|endswith)\s+["\']([^"\']+)["\']',
            clause, re.IGNORECASE
        )
        if sw_match:
            field = sw_match.group(1)
            operator = sw_match.group(2).lower()
            value = sw_match.group(3).lower()

            field_value = str(event.get(field, "")).lower()

            if operator == 'startswith':
                return field_value.startswith(value)
            else:
                return field_value.endswith(value)

        # Handle 'in' operator
        in_match = re.match(
            r'(\w+)\s+in\s*\(([^)]+)\)',
            clause, re.IGNORECASE
        )
        if in_match:
            field = in_match.group(1)
            values_str = in_match.group(2)
            values = [v.strip().strip('"\'').lower() for v in values_str.split(',')]

            field_value = str(event.get(field, "")).lower()
            return field_value in values

        # Handle 'matches regex'
        regex_match = re.match(
            r'(\w+)\s+matches\s+regex\s+["\']([^"\']+)["\']',
            clause, re.IGNORECASE
        )
        if regex_match:
            field = regex_match.group(1)
            pattern = regex_match.group(2)

            field_value = str(event.get(field, ""))

            try:
                return bool(re.search(pattern, field_value, re.IGNORECASE))
            except re.error:
                return False

        # Handle equality (==, !=)
        eq_match = re.match(
            r'(\w+)\s*(==|!=|=~)\s*["\']?([^"\']+)["\']?',
            clause
        )
        if eq_match:
            field = eq_match.group(1)
            operator = eq_match.group(2)
            value = eq_match.group(3).strip().lower()

            field_value = str(event.get(field, "")).lower()

            if operator in ('==', '=~'):
                return field_value == value
            else:  # !=
                return field_value != value

        # Handle numeric comparisons
        num_match = re.match(
            r'(\w+)\s*(>=|<=|>|<|==)\s*(\d+)',
            clause
        )
        if num_match:
            field = num_match.group(1)
            operator = num_match.group(2)
            value = int(num_match.group(3))

            try:
                field_value = int(event.get(field, 0))
            except (ValueError, TypeError):
                return False

            if operator == '>=':
                return field_value >= value
            elif operator == '<=':
                return field_value <= value
            elif operator == '>':
                return field_value > value
            elif operator == '<':
                return field_value < value
            else:  # ==
                return field_value == value

        # Unknown clause format - return True to avoid false negatives
        return True
