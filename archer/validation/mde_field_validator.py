"""
MDE Field Validator

Validates that fields used in MDE/KQL queries exist in the target table.
Automatically fixes or warns about invalid field usage.
"""

import json
import re
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple


class MDEFieldValidator:
    """Validates and fixes field usage in MDE/KQL queries."""

    def __init__(self):
        """Initialize the MDE field validator."""
        self.field_mappings = self._load_field_mappings()
        self.table_fields = self._build_table_fields()
        self.field_aliases = self._build_field_aliases()

    def _load_field_mappings(self) -> Dict:
        """Load MDE field mappings from JSON file."""
        # Try multiple possible locations
        possible_paths = [
            Path(__file__).parent.parent.parent
            / "data"
            / "external"
            / "detections"
            / "field_mappings"
            / "mde.json",
            Path("data/external/detections/field_mappings/mde.json"),
        ]

        for path in possible_paths:
            if path.exists():
                try:
                    with open(path, "r", encoding="utf-8") as f:
                        return json.load(f)
                except Exception as e:
                    print(f"Warning: Could not load MDE field mappings from {path}: {e}")

        # Return default mappings if file not found
        return self._get_default_mappings()

    def _get_default_mappings(self) -> Dict:
        """Return default MDE field mappings."""
        return {
            "tables": {
                "DeviceProcessEvents": {
                    "fields": [
                        "Timestamp",
                        "DeviceId",
                        "DeviceName",
                        "ActionType",
                        "FileName",
                        "FolderPath",
                        "SHA1",
                        "SHA256",
                        "MD5",
                        "ProcessId",
                        "ProcessCommandLine",
                        "AccountDomain",
                        "AccountName",
                        "AccountSid",
                        "InitiatingProcessFileName",
                        "InitiatingProcessFolderPath",
                        "InitiatingProcessCommandLine",
                        "InitiatingProcessId",
                        "InitiatingProcessParentFileName",
                    ],
                    "invalid_fields": ["RegistryKey", "RegistryValueName", "RegistryValueData"],
                },
                "DeviceRegistryEvents": {
                    "fields": [
                        "Timestamp",
                        "DeviceId",
                        "DeviceName",
                        "ActionType",
                        "RegistryKey",
                        "RegistryValueType",
                        "RegistryValueName",
                        "RegistryValueData",
                        "InitiatingProcessFileName",
                        "InitiatingProcessFolderPath",
                        "InitiatingProcessCommandLine",
                    ],
                    "invalid_fields": ["FileName", "FolderPath", "ProcessCommandLine"],
                },
                "DeviceFileEvents": {
                    "fields": [
                        "Timestamp",
                        "DeviceId",
                        "DeviceName",
                        "ActionType",
                        "FileName",
                        "FolderPath",
                        "SHA1",
                        "SHA256",
                        "MD5",
                        "InitiatingProcessFileName",
                        "InitiatingProcessFolderPath",
                        "InitiatingProcessCommandLine",
                    ],
                    "invalid_fields": ["RegistryKey", "RegistryValueName", "ProcessCommandLine"],
                },
                "DeviceNetworkEvents": {
                    "fields": [
                        "Timestamp",
                        "DeviceId",
                        "DeviceName",
                        "ActionType",
                        "RemoteIP",
                        "RemotePort",
                        "RemoteUrl",
                        "LocalIP",
                        "LocalPort",
                        "Protocol",
                        "InitiatingProcessFileName",
                        "InitiatingProcessCommandLine",
                    ],
                    "invalid_fields": ["RegistryKey", "FileName", "FolderPath"],
                },
                "DeviceEvents": {
                    "fields": [
                        "Timestamp",
                        "DeviceId",
                        "DeviceName",
                        "ActionType",
                        "FileName",
                        "FolderPath",
                        "SHA1",
                        "SHA256",
                        "MD5",
                        "AccountDomain",
                        "AccountName",
                        "ProcessId",
                        "ProcessCommandLine",
                        "RegistryKey",
                        "RegistryValueName",
                        "RegistryValueData",
                        "RemoteIP",
                        "RemotePort",
                        "LocalIP",
                        "LocalPort",
                        "InitiatingProcessFileName",
                        "InitiatingProcessCommandLine",
                    ],
                    "invalid_fields": [],
                },
            },
            "common_aliases": {
                "CommandLine": "ProcessCommandLine",
                "Process": "FileName",
                "ProcessName": "FileName",
                "ParentProcess": "InitiatingProcessFileName",
            },
        }

    def _build_table_fields(self) -> Dict[str, Set[str]]:
        """Build a mapping of table names to valid fields."""
        table_fields = {}
        for table_name, table_info in self.field_mappings.get("tables", {}).items():
            fields = set(table_info.get("fields", []))
            table_fields[table_name] = fields
            # Also store lowercase version for case-insensitive matching
            table_fields[table_name.lower()] = fields
        return table_fields

    def _build_field_aliases(self) -> Dict[str, str]:
        """Build field alias mapping."""
        return self.field_mappings.get("common_aliases", {})

    def extract_table_from_query(self, query: str) -> Optional[str]:
        """
        Extract the primary table name from a KQL query.

        Args:
            query: The KQL query

        Returns:
            Table name or None if not found
        """
        # Common MDE tables
        mde_tables = [
            "DeviceProcessEvents",
            "DeviceRegistryEvents",
            "DeviceFileEvents",
            "DeviceNetworkEvents",
            "DeviceEvents",
            "DeviceLogonEvents",
            "DeviceImageLoadEvents",
            "DeviceInfo",
            "DeviceNetworkInfo",
        ]

        # Check if query starts with a table name
        query_stripped = query.strip()
        for table in mde_tables:
            if query_stripped.startswith(table):
                return table
            # Also check lowercase
            if query_stripped.lower().startswith(table.lower()):
                return table

        # Try regex to find table in query
        for table in mde_tables:
            if re.search(rf"\b{table}\b", query, re.IGNORECASE):
                return table

        return None

    def extract_fields_from_query(self, query: str) -> Set[str]:
        """
        Extract field names used in a KQL query.

        Args:
            query: The KQL query

        Returns:
            Set of field names found in the query
        """
        fields = set()

        # Common KQL patterns for field usage
        patterns = [
            r"\b(\w+)\s*==\s*",  # FieldName ==
            r"\b(\w+)\s*=~\s*",  # FieldName =~ (case insensitive)
            r"\b(\w+)\s*!=\s*",  # FieldName !=
            r"\b(\w+)\s+has\s+",  # FieldName has
            r"\b(\w+)\s+has_any\s*\(",  # FieldName has_any()
            r"\b(\w+)\s+has_all\s*\(",  # FieldName has_all()
            r"\b(\w+)\s+contains\s+",  # FieldName contains
            r"\b(\w+)\s+startswith\s+",  # FieldName startswith
            r"\b(\w+)\s+endswith\s+",  # FieldName endswith
            r"\b(\w+)\s+matches\s+regex\s+",  # FieldName matches regex
            r"\b(\w+)\s+in\s*\(",  # FieldName in ()
            r"\b(\w+)\s+!in\s*\(",  # FieldName !in ()
            r"\|\s*where\s+(\w+)\s+",  # | where FieldName
            r"\|\s*project\s+([^|]+)",  # | project fields
            r"\|\s*extend\s+\w+\s*=\s*(\w+)",  # | extend x = FieldName
            r"\|\s*summarize\s+[^|]*\bby\s+([^|]+)",  # | summarize by fields
        ]

        for pattern in patterns:
            matches = re.findall(pattern, query, re.IGNORECASE)
            for match in matches:
                if isinstance(match, str):
                    # Handle comma-separated fields
                    for field in match.split(","):
                        field = field.strip()
                        # Extract just the field name (remove any operators/functions)
                        field_match = re.match(r"^(\w+)", field)
                        if field_match:
                            field_name = field_match.group(1)
                            # Filter out KQL keywords
                            if field_name.lower() not in [
                                "where",
                                "project",
                                "extend",
                                "summarize",
                                "by",
                                "and",
                                "or",
                                "not",
                                "true",
                                "false",
                                "null",
                                "let",
                                "ago",
                                "now",
                                "datetime",
                                "timespan",
                                "count",
                                "sum",
                                "avg",
                                "min",
                                "max",
                                "dcount",
                            ]:
                                fields.add(field_name)

        # Columns the query makes itself (extend Uri = tostring(...), summarize n = count() by ...,
        # let lists) exist whatever the table, and a name before "(" is a function, not a column
        made = set()
        for stage in re.split(r"\|", query):
            if re.match(r"\s*(extend|project|project-rename|summarize|parse|let)\b", stage, re.I) or stage.lstrip().startswith("let "):
                made.update(re.findall(r"\b(\w+)\s*=(?![=~])", stage))
        made.update(re.findall(r"^\s*let\s+(\w+)\s*=", query, re.M))
        functions = {f for f in fields if re.search(rf"\b{re.escape(f)}\s*\(", query)}
        return fields - made - functions

    def validate_query(self, query: str, table: str = None) -> Dict:
        """
        Validate fields in a KQL query against the specified table.

        Args:
            query: The KQL query
            table: Table name (auto-detected if not provided)

        Returns:
            Validation result with invalid fields and suggestions
        """
        # Auto-detect table if not provided
        if table is None:
            table = self.extract_table_from_query(query)

        if table is None:
            return {
                "valid": None,
                "table": None,
                "message": "Could not determine table from query",
                "invalid_fields": [],
                "suggestions": {},
            }

        # Get valid fields for this table
        valid_fields = self.table_fields.get(table, self.table_fields.get(table.lower(), set()))

        if not valid_fields:
            return {
                "valid": None,
                "table": table,
                "message": f"No field mapping available for table {table}",
                "invalid_fields": [],
                "suggestions": {},
            }

        # Extract fields from query
        query_fields = self.extract_fields_from_query(query)

        # Check each field
        invalid_fields = []
        suggestions = {}

        for field in query_fields:
            # Check if field is valid
            if field not in valid_fields:
                # Check if it's an alias
                canonical = self.field_aliases.get(field)
                if canonical and canonical in valid_fields:
                    suggestions[field] = f"Use '{canonical}' instead of '{field}'"
                else:
                    invalid_fields.append(field)
                    # Find similar valid fields
                    similar = self._find_similar_fields(field, valid_fields)
                    if similar:
                        suggestions[field] = f"Did you mean: {', '.join(similar)}?"

        return {
            "valid": len(invalid_fields) == 0,
            "table": table,
            "invalid_fields": invalid_fields,
            "suggestions": suggestions,
            "fields_checked": list(query_fields),
            "valid_fields_for_table": len(valid_fields),
        }

    def _find_similar_fields(
        self, field: str, valid_fields: Set[str], max_suggestions: int = 3
    ) -> List[str]:
        """
        Similar field names, closest first. valid_fields is a set, so without ranking the
        first three were arbitrary and a typo's real column (ProcessCommandLne →
        ProcessCommandLine) could be left out.
        """
        from difflib import SequenceMatcher

        field_lower = field.lower()
        scored = []
        for valid_field in valid_fields:
            valid_lower = valid_field.lower()
            score = SequenceMatcher(None, field_lower, valid_lower).ratio()
            # Partial matches and shared prefixes stay candidates however the ratio scores
            if field_lower in valid_lower or valid_lower in field_lower or field_lower[:4] == valid_lower[:4]:
                score += 0.25
            if score >= 0.6:
                scored.append((-score, valid_field))
        return [name for _, name in sorted(scored)[:max_suggestions]]

    def fix_query(self, query: str, table: str = None) -> Tuple[str, List[str]]:
        """
        Attempt to fix invalid fields in a query.

        Args:
            query: The KQL query
            table: Table name (auto-detected if not provided)

        Returns:
            Tuple of (fixed_query, list_of_changes_made)
        """
        validation = self.validate_query(query, table)
        changes = []

        if validation["valid"] is True or validation["valid"] is None:
            return query, []

        fixed_query = query

        # Apply alias fixes
        for field, suggestion in validation.get("suggestions", {}).items():
            if suggestion.startswith("Use '"):
                # Extract the suggested field name
                match = re.search(r"Use '(\w+)'", suggestion)
                if match:
                    canonical = match.group(1)
                    # Replace field with canonical name (preserve case sensitivity context)
                    fixed_query = re.sub(rf"\b{re.escape(field)}\b", canonical, fixed_query)
                    changes.append(f"Replaced '{field}' with '{canonical}'")

        return fixed_query, changes

    def get_table_fields(self, table: str) -> List[str]:
        """Get list of valid fields for a table."""
        fields = self.table_fields.get(table, self.table_fields.get(table.lower(), set()))
        return sorted(list(fields))

    def get_invalid_fields_for_table(self, table: str) -> List[str]:
        """Get list of fields that are invalid for a specific table."""
        table_info = self.field_mappings.get("tables", {}).get(table, {})
        return table_info.get("invalid_fields", [])


# Fields to always exclude from MDE queries (not useful for detection)
EXCLUDED_MDE_FIELDS = [
    "SHA256",
    "SHA1",
    "MD5",
    "InitiatingProcessSHA256",
    "InitiatingProcessSHA1",
    "InitiatingProcessMD5",
    "InitiatingProcessVersionInfoCompanyName",
    "InitiatingProcessVersionInfoProductName",
    "ProcessVersionInfoCompanyName",
    "ProcessVersionInfoProductName",
    "IsRemoteSession",
    "IsProcessRemoteSession",
    "AdditionalFields",
    "LocalIP",
    "RemoteIP",
    "FileOriginUrl",
]

# Fields to conditionally exclude (only include if query searches for related indicators)
CONDITIONAL_FIELDS = {
    # Registry fields: only include if query searches for registry patterns
    "RegistryKey": ["RegistryKey", "Registry", "HKLM", "HKCU", "HKEY_"],
    "RegistryValueName": ["RegistryKey", "RegistryValueName", "Registry", "HKLM", "HKCU", "HKEY_"],
    "RegistryValueData": ["RegistryKey", "RegistryValueData", "Registry", "HKLM", "HKCU", "HKEY_"],
}


def _should_include_field(field: str, query: str) -> bool:
    """
    Check if a conditional field should be included based on query content.

    Args:
        field: The field name to check
        query: The full query text

    Returns:
        True if field should be included, False if it should be excluded
    """
    if field not in CONDITIONAL_FIELDS:
        return True  # Not a conditional field, include by default

    # Check if any of the related patterns are in the query's where clause
    patterns = CONDITIONAL_FIELDS[field]
    for pattern in patterns:
        if pattern.lower() in query.lower():
            return True

    return False


# Excluded from output columns but still allowed to filter: on DeviceEvents most ActionTypes
# carry their detail only in AdditionalFields, so dropping these conditions threw away
# thousands of DeviceEvents detections.
FILTERABLE_EXCLUDED_FIELDS = {"AdditionalFields"}

_EXCLUDED_CONDITION = re.compile(
    r"^(?:" + "|".join(f for f in EXCLUDED_MDE_FIELDS if f not in FILTERABLE_EXCLUDED_FIELDS) + r")\s*(?:==|=~|!=|!has|has_any|has_all|has|contains|startswith|endswith|in~?|matches)(?![A-Za-z0-9_])",
    re.IGNORECASE,
)


def _outer_parens(expr: str) -> bool:
    """True when expr is one bracketed group, e.g. "(a or b)" but not "(a) or (b)"."""
    if not (expr.startswith("(") and expr.endswith(")")):
        return False
    depth = 0
    for i, ch in enumerate(expr):
        depth += ch == "("
        depth -= ch == ")"
        if depth == 0 and i < len(expr) - 1:
            return False
    return True


def _drop_excluded_conditions(expr: str) -> str:
    """A where expression without its conditions on EXCLUDED_MDE_FIELDS ("" if none remain)."""
    expr = expr.strip()
    if not expr:
        return ""
    if _outer_parens(expr):
        inner = _drop_excluded_conditions(expr[1:-1])
        return f"({inner})" if inner else ""
    parts = _split_conditions(expr, " or ")
    if len(parts) > 1:
        return " or ".join(k for k in map(_drop_excluded_conditions, parts) if k)
    # An "and" loses the whole group: dropping one of its conditions would widen it
    # (RemoteIPType == "Public" and RemoteIP in~ (...) is not RemoteIPType == "Public")
    parts = _split_conditions(expr, " and ")
    if len(parts) > 1:
        kept = [_drop_excluded_conditions(p) for p in parts]
        return " and ".join(kept) if all(k == p.strip() for k, p in zip(kept, parts)) else ""
    return "" if _EXCLUDED_CONDITION.match(expr) else expr


def strip_excluded_fields(query: str) -> str:
    """
    Remove excluded fields from MDE query projection clauses.

    These fields (SHA256, SHA1, etc.) are not useful for behavioral detection
    and add noise to queries.

    Args:
        query: The KQL query

    Returns:
        Query with excluded fields removed from project clauses
    """
    if not query:
        return query

    result = query

    # Remove excluded fields from project clauses
    # Pattern: | project Field1, SHA256, Field2 -> | project Field1, Field2
    for field in EXCLUDED_MDE_FIELDS:
        # Remove field with comma before
        result = re.sub(rf",\s*{field}\b", "", result)
        # Remove field with comma after
        result = re.sub(rf"\b{field}\s*,\s*", "", result)
        # Remove standalone field in project (between | project and next |)
        result = re.sub(rf"(\|\s*project[^|]*)\b{field}\b([^|]*)", r"\1\2", result)

    # Clean up any double commas or trailing commas in project
    result = re.sub(r",\s*,", ",", result)
    result = re.sub(r",\s*(\|)", r" \1", result)
    result = re.sub(r"(\|\s*project)\s*,", r"\1 ", result)

    # Remove conditions on these fields from where clauses too, a whole condition at a
    # time: regex edits here used to stop at the first ")" of has_all(...), leaving
    # "where ())))) or ..." behind. A where clause with nothing left drops the query,
    # since the clause would otherwise match every event.
    lines = []
    for line in result.split("\n"):
        m = re.match(r"^(\s*\|\s*where\s+)(.*?)(\s*//[^\"]*)?$", line)
        if m:
            kept = _drop_excluded_conditions(m.group(2))
            if not kept:
                return ""
            line = m.group(1) + kept + (m.group(3) or "")
        lines.append(line)
    result = "\n".join(lines)

    # Clean up empty where clauses
    result = re.sub(r"\|\s*where\s+\|", "|", result)
    result = re.sub(r"\|\s*where\s*$", "", result)

    # Clean up leading/trailing and/or in where clauses
    result = re.sub(r"(\|\s*where\s+)(?:and|or)\s+", r"\1", result)
    result = re.sub(r"\s+(?:and|or)\s*(\|)", r" \1", result)

    return result


_KQL_STRING = re.compile(r'@"(?:[^"]|"")*"|"(?:[^"\\\n]|\\.)*"|\'(?:[^\'\\\n]|\\.)*\'')


def verbatim_backslash_literals(query: str) -> str:
    """An ordinary "..." literal holding a backslash becomes verbatim @"...", so a path reads
    as written (output contract KQL-5). The value is unchanged."""
    def fix(m):
        lit = m.group(0)
        if lit.startswith('@') or lit.startswith("'") or "\\" not in lit:
            return lit
        value = re.sub(r'\\(.)', r'\1', lit[1:-1])
        return '@"' + value.replace('"', '""') + '"'
    return _KQL_STRING.sub(fix, query)


def _mask_strings(text: str) -> str:
    """The text with every string literal's contents blanked to spaces (same length)."""
    return _KQL_STRING.sub(lambda m: m.group(0)[0] + " " * (len(m.group(0)) - 2) + m.group(0)[-1], text)


def bracket_and_runs(expr: str) -> str:
    """
    Where 'and' and 'or' meet at one bracket level, bracket each run of 'and'. KQL binds
    'and' tighter than 'or', so the meaning is unchanged; the reader no longer has to know
    that (output contract LOGIC-andor). Works inside every bracket level; strings untouched.
    """
    masked = _mask_strings(expr)
    # Innermost groups first, by recursing into each top-level bracket pair
    depth, start = 0, None
    pieces, last = [], 0
    for i, ch in enumerate(masked):
        if ch == "(":
            if depth == 0:
                start = i
            depth += 1
        elif ch == ")" and depth:
            depth -= 1
            if depth == 0 and start is not None:
                pieces.append(expr[last:start + 1])
                pieces.append(bracket_and_runs(expr[start + 1:i]))
                last = i
    pieces.append(expr[last:])
    expr = "".join(pieces)
    masked = _mask_strings(expr)
    # Top-level 'or' / 'and' positions (outside brackets and strings)
    depth, ors, has_and = 0, [], False
    for m in re.finditer(r"[()]|\b(?:and|or)\b", masked):
        t = m.group(0)
        if t == "(":
            depth += 1
        elif t == ")":
            depth = max(0, depth - 1)
        elif depth == 0:
            if t == "or":
                ors.append(m.span())
            else:
                has_and = True
    if not ors or not has_and:
        return expr
    segments, prev = [], 0
    for a, b in ors:
        segments.append((expr[prev:a], expr[a:b]))
        prev = b
    segments.append((expr[prev:], ""))
    result = []
    for seg, sep in segments:
        if re.search(r"\band\b", _top_level(seg)):
            lead = seg[:len(seg) - len(seg.lstrip())]
            trail = seg[len(seg.rstrip()):]
            seg = f"{lead}({seg.strip()}){trail}"
        result.append(seg + sep)
    return "".join(result)


def _top_level(text: str) -> str:
    """The text with bracketed parts and strings blanked: what sits at the top level."""
    masked, out, depth = _mask_strings(text), [], 0
    for ch in masked:
        if ch == "(":
            depth += 1
        out.append(ch if depth == 0 else " ")
        if ch == ")" and depth:
            depth -= 1
    return "".join(out)


def normalise_where_logic(query: str) -> str:
    """bracket_and_runs on every '| where' clause (a clause runs to the next '|' line)."""
    lines = query.split("\n")
    out, i = [], 0
    while i < len(lines):
        m = re.match(r"^(\s*\|\s*where\s+)(.*)$", lines[i])
        if not m:
            out.append(lines[i]); i += 1
            continue
        block = [m.group(2)]
        i += 1
        while i < len(lines) and not re.match(r"^\s*\|", lines[i]) and lines[i].strip():
            block.append(lines[i]); i += 1
        out.extend((m.group(1) + bracket_and_runs("\n".join(block))).split("\n"))
    return "\n".join(out)


def format_mde_query(query: str) -> str:
    """
    Format an MDE/KQL query for readability with proper line breaks and indentation.
    Also removes duplicate conditions.

    Args:
        query: The KQL query

    Returns:
        Formatted query with line breaks and deduplication
    """
    if not query:
        return query

    # First, strip excluded fields
    query = strip_excluded_fields(query)
    # Contract KQL-5 and LOGIC-andor, whichever path wrote the query (template, OSINT, LLM)
    query = normalise_where_logic(verbatim_backslash_literals(query))

    # Split into lines and process
    lines = query.split('\n')
    formatted_lines = []

    for line in lines:
        line = line.strip()
        if not line:
            continue

        # Check if this is a where clause with multiple conditions
        if '| where' in line and ' or ' in line:
            # Extract the where clause
            match = re.match(r'^(.*?\|\s*where\s+)(.+)$', line)
            if match:
                prefix = match.group(1)
                conditions = match.group(2)

                # Split conditions by ' or ' while preserving parentheses
                # Use regex to find top-level 'or' separators
                condition_list = _split_conditions(conditions, ' or ')

                # Remove duplicates while preserving order
                seen = set()
                unique_conditions = []
                for cond in condition_list:
                    cond_normalized = cond.strip()
                    if cond_normalized and cond_normalized not in seen:
                        seen.add(cond_normalized)
                        unique_conditions.append(cond_normalized)

                if len(unique_conditions) > 1:
                    # Format with line breaks - put 'or' at end of previous line
                    for i, cond in enumerate(unique_conditions):
                        if i == 0:
                            formatted_lines.append(prefix + cond + ' or')
                        elif i < len(unique_conditions) - 1:
                            formatted_lines.append('        ' + cond + ' or')
                        else:
                            formatted_lines.append('        ' + cond)
                else:
                    formatted_lines.append(prefix + ' or '.join(unique_conditions))
            else:
                formatted_lines.append(line)
        # The schema's "summarize by Timestamp, <fields>" is a per-event distinct: every raw
        # event alerts (output contract KQL-15). Aggregate per finding instead.
        elif re.match(r'^\|\s*summarize\s+by\s+Timestamp\s*,', line):
            fields = [f.strip() for f in line.split('by', 1)[1].split(',') if f.strip()]
            fields = [f for f in fields if f not in EXCLUDED_MDE_FIELDS and _should_include_field(f, query)]
            formatted_lines.extend(_aggregate_summarize(fields))
        # Check if this is a summarize clause with many fields
        elif '| summarize' in line and line.count(',') > 5:
            # Format summarize with line breaks every few fields
            match = re.match(r'^(.*?\|\s*summarize\s+(?:by\s+)?)(.+)$', line)
            if match:
                prefix = match.group(1)
                fields = match.group(2)
                field_list = [f.strip() for f in fields.split(',')]

                # Remove excluded fields and conditional fields that don't apply
                field_list = [
                    f for f in field_list
                    if f not in EXCLUDED_MDE_FIELDS and _should_include_field(f, query)
                ]

                # Group fields (5 per line)
                groups = []
                for i in range(0, len(field_list), 5):
                    groups.append(', '.join(field_list[i:i+5]))

                if len(groups) > 1:
                    formatted_lines.append(prefix + groups[0] + ',')
                    for i, group in enumerate(groups[1:], 1):
                        if i < len(groups) - 1:
                            formatted_lines.append('        ' + group + ',')
                        else:
                            formatted_lines.append('        ' + group)
                else:
                    formatted_lines.append(prefix + ', '.join(field_list))
            else:
                formatted_lines.append(line)
        else:
            formatted_lines.append(line)

    return '\n'.join(formatted_lines)


# What makes two events the same finding, in order of preference. At most eight are used
# (output contract KQL-14); the rest are carried from the latest event by arg_max.
SUMMARIZE_KEYS = (
    "DeviceName", "AccountName", "InitiatingProcessAccountName", "ActionType", "LogonType",
    "FileName", "FolderPath", "RegistryKey", "RegistryValueName", "RemoteIP", "RemotePort",
    "RemoteUrl", "ProcessCommandLine", "InitiatingProcessFileName", "InitiatingProcessCommandLine",
)
MAX_SUMMARIZE_KEYS = 8


def _aggregate_summarize(fields: List[str]) -> List[str]:
    """
    One row per finding rather than per event: how many events, first and last seen, the
    latest event's other columns (arg_max keeps Timestamp, which custom detection rules
    need, and every column the entity mappings name), grouped by up to eight keys.
    """
    fields = [f for f in dict.fromkeys(fields) if f != "Timestamp"]
    keys = [k for k in SUMMARIZE_KEYS if k in fields][:MAX_SUMMARIZE_KEYS] or fields[:1]
    rest = [f for f in fields if f not in keys]
    lines = ["| summarize Events = count(), FirstSeen = min(Timestamp),"]
    if rest:
        chunks = [", ".join(rest[i:i + 5]) for i in range(0, len(rest), 5)]
        lines.append("    arg_max(Timestamp, " + chunks[0] + ("," if len(chunks) > 1 else ")"))
        for i, chunk in enumerate(chunks[1:], 1):
            lines.append("        " + chunk + ("," if i < len(chunks) - 1 else ")"))
    else:
        lines[0] = "| summarize Events = count(), FirstSeen = min(Timestamp), LastSeen = max(Timestamp)"
    lines.append("    by " + ", ".join(keys))
    return lines


def _split_conditions(text: str, separator: str) -> List[str]:
    """
    Split conditions by separator while respecting parentheses.

    Args:
        text: The text to split
        separator: The separator to split by (e.g., ' or ')

    Returns:
        List of conditions
    """
    conditions = []
    depth = 0
    current = []
    i = 0

    while i < len(text):
        # Track parentheses depth
        if text[i] == '(':
            depth += 1
            current.append(text[i])
        elif text[i] == ')':
            depth -= 1
            current.append(text[i])
        # Check for separator at depth 0
        elif depth == 0 and text[i:i+len(separator)].lower() == separator.lower():
            conditions.append(''.join(current).strip())
            current = []
            i += len(separator) - 1
        else:
            current.append(text[i])
        i += 1

    # Add the last condition
    if current:
        conditions.append(''.join(current).strip())

    return conditions


# Singleton instance
_validator: Optional[MDEFieldValidator] = None


def get_mde_validator() -> MDEFieldValidator:
    """Get the singleton MDE field validator instance."""
    global _validator
    if _validator is None:
        _validator = MDEFieldValidator()
    return _validator


def validate_mde_query(query: str, table: str = None) -> Dict:
    """
    Convenience function to validate an MDE query.

    Args:
        query: The KQL query
        table: Table name (auto-detected if not provided)

    Returns:
        Validation result dictionary
    """
    validator = get_mde_validator()
    return validator.validate_query(query, table)


def fix_mde_query(query: str, table: str = None) -> Tuple[str, List[str]]:
    """
    Convenience function to fix an MDE query.

    Args:
        query: The KQL query
        table: Table name (auto-detected if not provided)

    Returns:
        Tuple of (fixed_query, list_of_changes)
    """
    validator = get_mde_validator()
    return validator.fix_query(query, table)
