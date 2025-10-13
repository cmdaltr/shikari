"""
Parser for Microsoft Defender for Endpoint (MDE) / KQL queries.
"""

import re
from dataclasses import dataclass
from typing import List, Dict, Optional, Any, Tuple


@dataclass
class KQLOperator:
    """Represents a KQL operator like where, project, etc."""

    name: str
    expression: str  # Raw expression string
    parsed_expr: Dict[str, Any] = None  # Parsed expression where applicable


@dataclass
class KQLQuery:
    """Represents a parsed KQL query with components."""

    raw_query: str
    table_name: Optional[str] = None
    time_filter: Optional[str] = None  # Time filter expression
    operators: List[KQLOperator] = None
    projected_fields: List[str] = None  # Fields in project operators

    def __post_init__(self):
        if self.operators is None:
            self.operators = []
        if self.projected_fields is None:
            self.projected_fields = []


def parse_kql_query(query: str) -> KQLQuery:
    """
    Parse a KQL/MDE query into its components.

    Args:
        query: The KQL query string to parse

    Returns:
        KQLQuery object with parsed components
    """
    if not query or not isinstance(query, str):
        return KQLQuery(raw_query="")

    # Normalize whitespace and clean up query
    query = query.strip()
    result = KQLQuery(raw_query=query)

    # Extract table name (first word before any operator)
    lines = query.split("\n")
    first_line = lines[0].strip() if lines else ""

    # Handle comments at the beginning
    if first_line.startswith("//"):
        comment_lines = []
        for i, line in enumerate(lines):
            if line.strip().startswith("//"):
                comment_lines.append(i)
            else:
                break

        # Skip comment lines for table name extraction
        if len(lines) > len(comment_lines):
            first_line = lines[len(comment_lines)].strip()
        else:
            first_line = ""

    # Extract table name
    table_match = re.match(r"^(\w+)(\s|$)", first_line)
    if table_match:
        result.table_name = table_match.group(1)

    # Process operators
    operators = []
    current_op = None
    current_expr = []

    for line in lines:
        line = line.strip()
        if not line or line.startswith("//"):
            continue

        # Check if this line starts a new operator
        op_match = re.match(r"^(?:(?:\|\s*)?(\w+))(.*)$", line)

        if op_match:
            # Save previous operator if there was one
            if current_op and current_expr:
                operators.append(
                    KQLOperator(name=current_op, expression="\n".join(current_expr))
                )
                current_expr = []

            # Start new operator
            current_op = op_match.group(1)
            expr = op_match.group(2).strip()
            if expr:
                current_expr.append(expr)
        elif current_op:
            # Continue previous operator
            current_expr.append(line)

    # Add the last operator if there is one
    if current_op and current_expr:
        operators.append(
            KQLOperator(name=current_op, expression="\n".join(current_expr))
        )

    result.operators = operators

    # Extract time filter if present
    for op in operators:
        if op.name == "where" and (
            "ago(" in op.expression or "timestamp" in op.expression
        ):
            time_filter_match = re.search(
                r"(timestamp\s*[><]=?\s*ago\([^)]+\))", op.expression
            )
            if time_filter_match:
                result.time_filter = time_filter_match.group(1)

    # Extract projected fields
    for op in operators:
        if (
            op.name == "project"
            or op.name == "project-away"
            or op.name == "project-keep"
        ):
            fields = [f.strip() for f in re.split(r",|\s+", op.expression) if f.strip()]
            result.projected_fields.extend(fields)

    return result


def validate_kql_query(query: str) -> Tuple[bool, str]:
    """
    Validate a KQL/MDE query for basic syntax correctness.

    Args:
        query: The KQL query to validate

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

    # Check for table name
    try:
        parsed = parse_kql_query(query)
        if not parsed.table_name:
            return False, "No table name found"
    except Exception as e:
        return False, f"Parse error: {str(e)}"

    return True, ""


def combine_kql_queries(query_a: str, query_b: str) -> str:
    """
    Intelligently combine two KQL/MDE queries.

    Args:
        query_a: First KQL query
        query_b: Second KQL query

    Returns:
        Combined query string
    """
    # Parse both queries
    parsed_a = parse_kql_query(query_a)
    parsed_b = parse_kql_query(query_b)

    # Check if tables match for a simple join
    if parsed_a.table_name and parsed_b.table_name:
        if parsed_a.table_name == parsed_b.table_name:
            # Same table - use union approach
            return _combine_same_table(parsed_a, parsed_b)
        else:
            # Different tables - try a join approach
            return _combine_different_tables(parsed_a, parsed_b)
    elif parsed_a.table_name:
        # Only query_a has a table
        return _enhance_single_query(parsed_a, parsed_b)
    elif parsed_b.table_name:
        # Only query_b has a table
        return _enhance_single_query(parsed_b, parsed_a)
    else:
        # No tables detected - return a commented error
        return f"""
// Error: Could not detect table names in the queries
// Query A:
{query_a}

// Query B:
{query_b}

// Could not generate a combined query
"""


def _combine_same_table(parsed_a: KQLQuery, parsed_b: KQLQuery) -> str:
    """Combine queries operating on the same table."""
    table = parsed_a.table_name

    # Get time filters from both queries, or use default
    time_filter = parsed_a.time_filter or parsed_b.time_filter or "timestamp > ago(1d)"

    # Extract where conditions (excluding time filters)
    where_conditions = []
    for parsed in [parsed_a, parsed_b]:
        for op in parsed.operators:
            if (
                op.name == "where"
                and op.expression
                and (not parsed.time_filter or parsed.time_filter not in op.expression)
            ):
                where_conditions.append(op.expression)

    # Build combined query with union
    combined = f"""
// Combined query for table {table}
{table}
| where {time_filter}
| where ({" or ".join(where_conditions) if where_conditions else "true"})
"""

    # Add projection if we have fields
    all_fields = list(set(parsed_a.projected_fields + parsed_b.projected_fields))
    if all_fields:
        combined += f"| project {', '.join(all_fields)}\n"

    return combined


def _combine_different_tables(parsed_a: KQLQuery, parsed_b: KQLQuery) -> str:
    """Combine queries operating on different tables using join."""
    table_a = parsed_a.table_name
    table_b = parsed_b.table_name

    # Default time filter
    time_filter = "timestamp > ago(1d)"

    # Use existing time filters if available
    time_filter_a = parsed_a.time_filter or time_filter
    time_filter_b = parsed_b.time_filter or time_filter

    # Common join keys between MDE tables (educated guess)
    join_candidates = ["DeviceId", "DeviceName", "Timestamp", "ReportId", "ActionType"]

    combined = f"""
// Combined query joining {table_a} and {table_b}
let query_a = (
    {table_a}
    | where {time_filter_a}
    {_extract_where_conditions(parsed_a)}
);
let query_b = (
    {table_b}
    | where {time_filter_b}
    {_extract_where_conditions(parsed_b)}
);
query_a
| join kind=inner query_b on $left.DeviceId == $right.DeviceId
| project-away DeviceId1, Timestamp1
"""

    return combined


def _enhance_single_query(parsed_main: KQLQuery, parsed_secondary: KQLQuery) -> str:
    """Use one query as the main query and enhance it with elements from the second."""
    table = parsed_main.table_name
    time_filter = parsed_main.time_filter or "timestamp > ago(1d)"

    # Extract where conditions from both
    main_where = _extract_where_conditions(parsed_main)
    secondary_where = _extract_where_conditions(parsed_secondary)

    combined = f"""
// Enhanced query for {table}
{table}
| where {time_filter}
{main_where}
// Additional conditions from secondary query:
{secondary_where}
"""

    # Add projection if we have fields
    all_fields = parsed_main.projected_fields
    if all_fields:
        combined += f"| project {', '.join(all_fields)}\n"

    return combined


def _extract_where_conditions(parsed: KQLQuery) -> str:
    """Extract where conditions from parsed query, excluding time filters."""
    conditions = []
    for op in parsed.operators:
        if (
            op.name == "where"
            and op.expression
            and (not parsed.time_filter or parsed.time_filter not in op.expression)
        ):
            conditions.append(f"| where {op.expression}")

    return "\n".join(conditions)
