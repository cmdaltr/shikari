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
            Path(__file__).parent.parent.parent / "data" / "external" / "detections" / "field_mappings" / "mde.json",
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
                        "Timestamp", "DeviceId", "DeviceName", "ActionType",
                        "FileName", "FolderPath", "SHA1", "SHA256", "MD5",
                        "ProcessId", "ProcessCommandLine", "AccountDomain",
                        "AccountName", "AccountSid", "InitiatingProcessFileName",
                        "InitiatingProcessFolderPath", "InitiatingProcessCommandLine",
                        "InitiatingProcessId", "InitiatingProcessParentFileName"
                    ],
                    "invalid_fields": ["RegistryKey", "RegistryValueName", "RegistryValueData"]
                },
                "DeviceRegistryEvents": {
                    "fields": [
                        "Timestamp", "DeviceId", "DeviceName", "ActionType",
                        "RegistryKey", "RegistryValueType", "RegistryValueName",
                        "RegistryValueData", "InitiatingProcessFileName",
                        "InitiatingProcessFolderPath", "InitiatingProcessCommandLine"
                    ],
                    "invalid_fields": ["FileName", "FolderPath", "ProcessCommandLine"]
                },
                "DeviceFileEvents": {
                    "fields": [
                        "Timestamp", "DeviceId", "DeviceName", "ActionType",
                        "FileName", "FolderPath", "SHA1", "SHA256", "MD5",
                        "InitiatingProcessFileName", "InitiatingProcessFolderPath",
                        "InitiatingProcessCommandLine"
                    ],
                    "invalid_fields": ["RegistryKey", "RegistryValueName", "ProcessCommandLine"]
                },
                "DeviceNetworkEvents": {
                    "fields": [
                        "Timestamp", "DeviceId", "DeviceName", "ActionType",
                        "RemoteIP", "RemotePort", "RemoteUrl", "LocalIP", "LocalPort",
                        "Protocol", "InitiatingProcessFileName", "InitiatingProcessCommandLine"
                    ],
                    "invalid_fields": ["RegistryKey", "FileName", "FolderPath"]
                },
                "DeviceEvents": {
                    "fields": [
                        "Timestamp", "DeviceId", "DeviceName", "ActionType",
                        "FileName", "FolderPath", "SHA1", "SHA256", "MD5",
                        "AccountDomain", "AccountName", "ProcessId", "ProcessCommandLine",
                        "RegistryKey", "RegistryValueName", "RegistryValueData",
                        "RemoteIP", "RemotePort", "LocalIP", "LocalPort",
                        "InitiatingProcessFileName", "InitiatingProcessCommandLine"
                    ],
                    "invalid_fields": []
                }
            },
            "common_aliases": {
                "CommandLine": "ProcessCommandLine",
                "Process": "FileName",
                "ProcessName": "FileName",
                "ParentProcess": "InitiatingProcessFileName"
            }
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
            "DeviceNetworkInfo"
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
            if re.search(rf'\b{table}\b', query, re.IGNORECASE):
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
            r'\b(\w+)\s*==\s*',      # FieldName ==
            r'\b(\w+)\s*=~\s*',      # FieldName =~ (case insensitive)
            r'\b(\w+)\s*!=\s*',      # FieldName !=
            r'\b(\w+)\s+has\s+',     # FieldName has
            r'\b(\w+)\s+has_any\s*\(', # FieldName has_any()
            r'\b(\w+)\s+has_all\s*\(', # FieldName has_all()
            r'\b(\w+)\s+contains\s+', # FieldName contains
            r'\b(\w+)\s+startswith\s+', # FieldName startswith
            r'\b(\w+)\s+endswith\s+', # FieldName endswith
            r'\b(\w+)\s+matches\s+regex\s+', # FieldName matches regex
            r'\b(\w+)\s+in\s*\(',    # FieldName in ()
            r'\b(\w+)\s+!in\s*\(',   # FieldName !in ()
            r'\|\s*where\s+(\w+)\s+', # | where FieldName
            r'\|\s*project\s+([^|]+)', # | project fields
            r'\|\s*extend\s+\w+\s*=\s*(\w+)', # | extend x = FieldName
            r'\|\s*summarize\s+[^|]*\bby\s+([^|]+)', # | summarize by fields
        ]

        for pattern in patterns:
            matches = re.findall(pattern, query, re.IGNORECASE)
            for match in matches:
                if isinstance(match, str):
                    # Handle comma-separated fields
                    for field in match.split(','):
                        field = field.strip()
                        # Extract just the field name (remove any operators/functions)
                        field_match = re.match(r'^(\w+)', field)
                        if field_match:
                            field_name = field_match.group(1)
                            # Filter out KQL keywords
                            if field_name.lower() not in [
                                'where', 'project', 'extend', 'summarize', 'by',
                                'and', 'or', 'not', 'true', 'false', 'null',
                                'let', 'ago', 'now', 'datetime', 'timespan',
                                'count', 'sum', 'avg', 'min', 'max', 'dcount'
                            ]:
                                fields.add(field_name)

        return fields

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
                "suggestions": {}
            }

        # Get valid fields for this table
        valid_fields = self.table_fields.get(table, self.table_fields.get(table.lower(), set()))

        if not valid_fields:
            return {
                "valid": None,
                "table": table,
                "message": f"No field mapping available for table {table}",
                "invalid_fields": [],
                "suggestions": {}
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
            "valid_fields_for_table": len(valid_fields)
        }

    def _find_similar_fields(self, field: str, valid_fields: Set[str], max_suggestions: int = 3) -> List[str]:
        """Find similar field names for suggestions."""
        field_lower = field.lower()
        similar = []

        for valid_field in valid_fields:
            valid_lower = valid_field.lower()
            # Check for partial matches
            if field_lower in valid_lower or valid_lower in field_lower:
                similar.append(valid_field)
            # Check for common prefixes
            elif field_lower[:4] == valid_lower[:4]:
                similar.append(valid_field)

        return similar[:max_suggestions]

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
                    fixed_query = re.sub(
                        rf'\b{re.escape(field)}\b',
                        canonical,
                        fixed_query
                    )
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
