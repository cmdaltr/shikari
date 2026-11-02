"""
Shikari Mappings Module

Provides schema management and normalization for Splunk data sources.
"""

from .normalize_manual import SplunkSchemaNormalizer
from .normalize_auto import (
    normalize_auto_schema,
    is_schema_normalized,
    validate_schema,
    get_schema_stats,
    on_schema_update_hook,
    pre_query_validation_hook,
)

__all__ = [
    "SplunkSchemaNormalizer",
    "normalize_auto_schema",
    "is_schema_normalized",
    "validate_schema",
    "get_schema_stats",
    "on_schema_update_hook",
    "pre_query_validation_hook",
]
