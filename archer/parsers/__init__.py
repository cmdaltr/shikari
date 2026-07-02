"""
Query parsing and validation package.
"""

from .splunk import parse_splunk_query, validate_splunk_query, combine_splunk_queries
from .mde import parse_kql_query, validate_kql_query, combine_kql_queries

__all__ = [
    "parse_splunk_query",
    "validate_splunk_query",
    "combine_splunk_queries",
    "parse_kql_query",
    "validate_kql_query",
    "combine_kql_queries",
]
