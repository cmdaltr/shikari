"""
Query Syntax Validator

Validates that queries use correct syntax and valid tables/indexes for their target platform.
- SPL (Splunk Processing Language): Uses index=, | search, | rename, | eval, | stats
- KQL (Kusto Query Language): Uses table names, | where, | summarize, contains, has_any
"""

import json
import os
import re
from pathlib import Path
from typing import Tuple, List, Optional


# Cache for loaded schemas
_splunk_schema = None
_mde_schema = None


def load_splunk_schema() -> dict:
    """Load Splunk schema with valid indexes."""
    global _splunk_schema
    if _splunk_schema is not None:
        return _splunk_schema

    mappings_dir = Path(__file__).parent.parent.parent / "data" / "bespoke" / "mappings"

    # Try custom mapping file first
    custom_schema_file = mappings_dir / "schemaSplunk_custom.json"
    if custom_schema_file.exists():
        try:
            with open(custom_schema_file, "r") as f:
                _splunk_schema = json.load(f)
                return _splunk_schema
        except Exception:
            pass

    # Fall back to default mapping file
    schema_file = mappings_dir / "schemaSplunk.json"
    if not schema_file.exists():
        _splunk_schema = {}
        return _splunk_schema

    try:
        with open(schema_file, "r") as f:
            _splunk_schema = json.load(f)
            return _splunk_schema
    except Exception:
        _splunk_schema = {}
        return _splunk_schema


def load_mde_schema() -> dict:
    """Load MDE schema with valid table names."""
    global _mde_schema
    if _mde_schema is not None:
        return _mde_schema

    mappings_dir = Path(__file__).parent.parent.parent / "data" / "bespoke" / "mappings"

    # Try custom mapping file first
    custom_schema_file = mappings_dir / "schemaMDE_custom.json"
    if custom_schema_file.exists():
        try:
            with open(custom_schema_file, "r") as f:
                _mde_schema = json.load(f)
                return _mde_schema
        except Exception:
            pass

    # Fall back to default mapping file
    schema_file = mappings_dir / "schemaMDE.json"
    if not schema_file.exists():
        _mde_schema = {}
        return _mde_schema

    try:
        with open(schema_file, "r") as f:
            _mde_schema = json.load(f)
            return _mde_schema
    except Exception:
        _mde_schema = {}
        return _mde_schema


def get_valid_splunk_indexes() -> set:
    """Get set of valid Splunk index names from schema."""
    schema = load_splunk_schema()
    indexes = set()
    # Schema structure: {"indicator_type": {"index_name": "transformation"}}
    for indicator_type, index_map in schema.items():
        if isinstance(index_map, dict):
            indexes.update(index_map.keys())
    return indexes


def get_valid_mde_tables() -> set:
    """Get set of valid MDE table names from schema."""
    schema = load_mde_schema()
    return set(schema.keys())


def detect_query_language(query: str) -> str:
    """
    Detect if query is SPL (Splunk) or KQL (MDE) based on syntax patterns.

    Args:
        query: The query string to analyze

    Returns:
        'spl' for Splunk Processing Language
        'kql' for Kusto Query Language
        'unknown' if cannot determine
    """
    if not query or not isinstance(query, str):
        return "unknown"

    query_stripped = query.strip()

    # SPL indicators (weighted more heavily)
    spl_score = 0
    if re.search(r'\bindex\s*=', query, re.IGNORECASE):
        spl_score += 3  # Strong indicator
    if re.search(r'\|\s*search\b', query, re.IGNORECASE):
        spl_score += 2
    if re.search(r'\|\s*rename\b', query, re.IGNORECASE):
        spl_score += 2
    if re.search(r'\|\s*eval\b', query, re.IGNORECASE):
        spl_score += 1
    if re.search(r'\|\s*stats\b', query, re.IGNORECASE):
        spl_score += 1
    if re.search(r'\|\s*table\b', query, re.IGNORECASE):
        spl_score += 1
    if re.search(r'\|\s*fields\b', query, re.IGNORECASE):
        spl_score += 1
    if re.search(r'\bearliest\s*=', query, re.IGNORECASE):
        spl_score += 2
    if re.search(r'\blatest\s*=', query, re.IGNORECASE):
        spl_score += 1
    if re.search(r'strftime\s*\(', query, re.IGNORECASE):
        spl_score += 2

    # KQL indicators
    kql_score = 0
    # Starts with a table name followed by whitespace and pipe
    valid_mde_tables = get_valid_mde_tables()
    first_word = query_stripped.split()[0] if query_stripped.split() else ""
    if first_word in valid_mde_tables:
        kql_score += 3  # Strong indicator
    if re.search(r'\|\s*where\b', query, re.IGNORECASE):
        kql_score += 2
    if re.search(r'\|\s*summarize\b', query, re.IGNORECASE):
        kql_score += 2
    if re.search(r'\bhas_any\s*\(', query, re.IGNORECASE):
        kql_score += 2
    if re.search(r'\bhas_all\s*\(', query, re.IGNORECASE):
        kql_score += 2
    if re.search(r'\bcontains\b', query, re.IGNORECASE):
        kql_score += 1
    if re.search(r'\bago\s*\(', query, re.IGNORECASE):
        kql_score += 2
    if re.search(r'\bTimestamp\s*>', query):
        kql_score += 2
    # Check for common MDE table names in the query
    for table in valid_mde_tables:
        if table in query:
            kql_score += 1
            break

    # Determine based on scores
    if spl_score > kql_score and spl_score >= 2:
        return "spl"
    elif kql_score > spl_score and kql_score >= 2:
        return "kql"
    elif spl_score > 0:
        return "spl"
    elif kql_score > 0:
        return "kql"
    else:
        return "unknown"


def extract_query_tables(query: str, language: str) -> List[str]:
    """
    Extract table/index names from a query.

    Args:
        query: The query string
        language: 'spl' or 'kql'

    Returns:
        List of table/index names found in the query
    """
    tables = []

    if language == "spl":
        # Extract index names: index=<name> or index="<name>"
        matches = re.findall(r'\bindex\s*=\s*["\']?(\w+)["\']?', query, re.IGNORECASE)
        tables.extend(matches)
    elif language == "kql":
        # Extract table name from start of query (first word before |)
        query_stripped = query.strip()
        # KQL queries start with table name
        first_line = query_stripped.split('\n')[0]
        # Get the first word (table name) before any pipe or where clause
        match = re.match(r'^(\w+)\s*(?:\||$)', first_line.strip())
        if match:
            tables.append(match.group(1))

    return tables


def validate_query_tables(query: str, vendor: str) -> Tuple[bool, List[str]]:
    """
    Validate that a query uses valid tables/indexes for the specified vendor.

    Args:
        query: The query string to validate
        vendor: The vendor platform ('splunk', 'mde', 'googlesecops', 'elastic')

    Returns:
        Tuple of (is_valid, list of invalid tables)
    """
    if not query or not isinstance(query, str):
        return True, []  # Empty queries are valid (no tables to check)

    # Detect the actual query language
    detected_lang = detect_query_language(query)

    invalid_tables = []

    if vendor.lower() == "splunk":
        valid_indexes = get_valid_splunk_indexes()
        tables = extract_query_tables(query, "spl")

        for table in tables:
            if table.lower() not in {idx.lower() for idx in valid_indexes}:
                invalid_tables.append(table)

        # Also check if SPL query is actually using KQL syntax (wrong language)
        if detected_lang == "kql":
            # This is a KQL query incorrectly categorized as Splunk
            # Extract the KQL table name and add it to invalid
            kql_tables = extract_query_tables(query, "kql")
            for t in kql_tables:
                if t not in invalid_tables:
                    invalid_tables.append(f"{t} (KQL table in Splunk query)")

    elif vendor.lower() == "mde":
        valid_tables = get_valid_mde_tables()
        tables = extract_query_tables(query, "kql")

        for table in tables:
            if table not in valid_tables:
                invalid_tables.append(table)

        # Also check if MDE query is actually using SPL syntax (wrong language)
        if detected_lang == "spl":
            spl_indexes = extract_query_tables(query, "spl")
            for idx in spl_indexes:
                if idx not in invalid_tables:
                    invalid_tables.append(f"{idx} (SPL index in MDE query)")

    is_valid = len(invalid_tables) == 0
    return is_valid, invalid_tables


def validate_query_syntax(query: str, vendor: str) -> dict:
    """
    Comprehensive query validation.

    Args:
        query: The query string to validate
        vendor: The vendor platform ('splunk', 'mde', 'googlesecops', 'elastic')

    Returns:
        Dict with validation results:
        {
            'is_valid': bool,
            'detected_language': str,
            'expected_language': str,
            'language_mismatch': bool,
            'invalid_tables': list,
            'warnings': list
        }
    """
    if not query or not isinstance(query, str):
        return {
            'is_valid': True,
            'detected_language': 'unknown',
            'expected_language': 'unknown',
            'language_mismatch': False,
            'invalid_tables': [],
            'warnings': []
        }

    detected_lang = detect_query_language(query)

    # Map vendor to expected language
    expected_lang_map = {
        'splunk': 'spl',
        'mde': 'kql',
        'microsoft': 'kql',
        'googlesecops': 'unknown',  # Google SecOps can vary
        'elastic': 'unknown'  # Elastic can vary
    }
    expected_lang = expected_lang_map.get(vendor.lower(), 'unknown')

    language_mismatch = (
        expected_lang != 'unknown' and
        detected_lang != 'unknown' and
        expected_lang != detected_lang
    )

    is_valid, invalid_tables = validate_query_tables(query, vendor)

    warnings = []
    if language_mismatch:
        warnings.append(f"Query appears to be {detected_lang.upper()} but is categorized as {vendor}")
    if invalid_tables:
        warnings.append(f"Query uses invalid tables/indexes: {', '.join(invalid_tables)}")

    return {
        'is_valid': is_valid and not language_mismatch,
        'detected_language': detected_lang,
        'expected_language': expected_lang,
        'language_mismatch': language_mismatch,
        'invalid_tables': invalid_tables,
        'warnings': warnings
    }
