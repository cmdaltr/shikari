"""
Parser for Splunk Search Processing Language (SPL).
"""

import re
from dataclasses import dataclass
from typing import List, Dict, Optional, Any, Tuple


@dataclass
class SplunkCommand:
    """Represents a Splunk command in the pipeline."""

    name: str
    arguments: str  # Raw argument string
    parsed_args: Dict[str, Any] = None  # Parsed arguments where applicable


@dataclass
class SplunkQuery:
    """Represents a parsed Splunk query with components."""

    raw_query: str
    index: Optional[str] = None
    time_range: Dict[str, str] = None  # earliest, latest
    search_terms: str = ""
    commands: List[SplunkCommand] = None
    fields: List[str] = (
        None  # Fields explicitly mentioned in commands like table/fields
    )

    def __post_init__(self):
        if self.commands is None:
            self.commands = []
        if self.time_range is None:
            self.time_range = {}
        if self.fields is None:
            self.fields = []


def parse_splunk_query(query: str) -> SplunkQuery:
    """
    Parse a Splunk query into its components.

    Args:
        query: The Splunk query string to parse

    Returns:
        SplunkQuery object with parsed components
    """
    if not query or not isinstance(query, str):
        return SplunkQuery(raw_query="")

    # Normalize whitespace and clean up query
    query = query.strip()
    result = SplunkQuery(raw_query=query)

    # Extract index if present
    index_match = re.match(r"index\s*=\s*(\w+)", query)
    if index_match:
        result.index = index_match.group(1)
        # Remove index part from query for further parsing
        remaining_query = query[
            query.find(index_match.group(1)) + len(index_match.group(1)) :
        ].lstrip()
    else:
        remaining_query = query

    # Extract time range parameters
    time_patterns = [
        # earliest=-1d latest=now
        r"earliest\s*=\s*([^\s]+)",
        r"latest\s*=\s*([^\s]+)",
    ]

    for pattern, key in zip(time_patterns, ["earliest", "latest"]):
        match = re.search(pattern, remaining_query)
        if match:
            result.time_range[key] = match.group(1)
            # Remove time params from remaining query
            remaining_query = re.sub(pattern, "", remaining_query)

    # Extract commands from pipeline
    commands = []
    parts = re.split(r"\s*\|\s*", remaining_query)

    # First part is the search term if no pipe
    if parts and not parts[0].strip().startswith("|"):
        result.search_terms = parts[0].strip()
        command_parts = parts[1:]
    else:
        command_parts = parts

    # Process each command in the pipeline
    for cmd_str in command_parts:
        if not cmd_str.strip():
            continue

        # Extract command name and args
        cmd_match = re.match(r"(\w+)\s*(.*)", cmd_str.strip())
        if cmd_match:
            cmd_name = cmd_match.group(1).lower()
            cmd_args = cmd_match.group(2).strip()

            command = SplunkCommand(name=cmd_name, arguments=cmd_args)

            # Extract fields from commands like table, fields
            if cmd_name in ["table", "fields"]:
                fields = [f.strip() for f in cmd_args.split() if f.strip()]
                result.fields.extend(fields)
                command.parsed_args = {"fields": fields}

            commands.append(command)

    result.commands = commands
    return result


def validate_splunk_query(query: str) -> Tuple[bool, str]:
    """
    Validate a Splunk query for basic syntax correctness.

    Args:
        query: The Splunk query to validate

    Returns:
        Tuple of (is_valid, error_message)
    """
    if not query or not isinstance(query, str):
        return False, "Query is empty or not a string"

    # Check for balanced quotes
    single_quotes = query.count("'") % 2
    double_quotes = query.count('"') % 2

    if single_quotes != 0:
        return False, "Unbalanced single quotes"
    if double_quotes != 0:
        return False, "Unbalanced double quotes"

    # Check for balanced parentheses
    if query.count("(") != query.count(")"):
        return False, "Unbalanced parentheses"

    # Check for common required elements
    if (
        "index=" not in query
        and not re.search(r"\bsource\s*=", query)
        and not re.search(r"\bsourcetype\s*=", query)
    ):
        return False, "Query should specify at least an index, source, or sourcetype"

    # Check for common syntax errors
    if "||" in query:
        return False, "Consecutive pipes (||) found"

    # Parse the query to detect structural issues
    try:
        parsed = parse_splunk_query(query)
        if not parsed.search_terms and not parsed.commands:
            return False, "Query has no search terms or commands"
    except Exception as e:
        return False, f"Parse error: {str(e)}"

    return True, ""


def combine_splunk_queries(query_a: str, query_b: str) -> str:
    """
    Combine two Splunk queries into a proper correlation search using transaction.

    Creates a correlation that finds devices where BOTH patterns occur within a 1-hour window.

    Args:
        query_a: First Splunk query
        query_b: Second Splunk query

    Returns:
        Combined correlation query string
    """
    # Parse both queries
    parsed_a = parse_splunk_query(query_a)
    parsed_b = parse_splunk_query(query_b)

    # Use index from first query if available, otherwise from second
    index = parsed_a.index or parsed_b.index or "main"

    # Use most restrictive time range
    earliest = "earliest=-1d"  # Default
    if "earliest" in parsed_a.time_range and "earliest" in parsed_b.time_range:
        # Simple heuristic: use the smaller time window (less data)
        if "-1h" in parsed_a.time_range["earliest"]:
            earliest = f"earliest={parsed_a.time_range['earliest']}"
        elif "-1h" in parsed_b.time_range["earliest"]:
            earliest = f"earliest={parsed_b.time_range['earliest']}"
        else:
            earliest = f"earliest={parsed_a.time_range['earliest']}"
    elif "earliest" in parsed_a.time_range:
        earliest = f"earliest={parsed_a.time_range['earliest']}"
    elif "earliest" in parsed_b.time_range:
        earliest = f"earliest={parsed_b.time_range['earliest']}"

    # Extract search terms and clean them up
    import re

    def clean_search_terms(terms):
        """Remove duplicate conditions and unnecessary parentheses"""
        if not terms:
            return terms

        # Extract individual conditions
        conditions = []
        # Split by OR but keep quoted strings intact
        parts = re.split(r'\s+OR\s+', terms, flags=re.IGNORECASE)
        seen = set()

        for part in parts:
            # Normalize whitespace
            normalized = " ".join(part.strip().strip('()').split())
            if normalized and normalized not in seen:
                conditions.append(part.strip().strip('()'))
                seen.add(normalized)

        if len(conditions) == 1:
            return conditions[0]
        else:
            return " OR ".join(conditions)

    search_a = clean_search_terms(parsed_a.search_terms)
    search_b = clean_search_terms(parsed_b.search_terms)

    # Build correlation query using transaction command
    # This creates a proper correlation by finding devices where both patterns occur
    combined = f"""index={index} {earliest}
  ({search_a}) OR ({search_b})
  | eval pattern_a=if(({search_a}), "true", "false")
  | eval pattern_b=if(({search_b}), "true", "false")
  | transaction properties.DeviceName maxspan=1h
  | search pattern_a="true" AND pattern_b="true"
  | stats count AS event_count, min(_time) AS first_seen, max(_time) AS last_seen, values(properties.FileName) AS file_names, values(properties.ProcessCommandLine) AS command_lines, values(properties.AccountName) AS accounts BY properties.DeviceName
  | eval first_seen=strftime(first_seen, "%Y-%m-%d %H:%M:%S"), last_seen=strftime(last_seen, "%Y-%m-%d %H:%M:%S")
  | where event_count >= 2
  | sort - event_count"""

    return combined
