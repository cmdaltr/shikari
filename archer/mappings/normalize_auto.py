#!/usr/bin/env python3
"""
Auto-normalization helper for Archer application.

This module provides simple functions to integrate schema normalization
into Archer's workflow for Splunk, Google SecOps, and Elastic schemas.
"""

from pathlib import Path
from typing import Dict, Optional
from .normalize_manual import SplunkSchemaNormalizer


def normalize_auto_schema(
    schema_path: Optional[Path] = None,
    platform: str = "splunk",
    force: bool = False,
    silent: bool = False
) -> Dict:
    """
    Automatically normalize new indexes/sources in platform schemas.

    This is the main entry point for integrating schema normalization
    into Archer's workflow. It will:
    1. Detect unnormalized indexes/sources
    2. Apply field normalization and security filtering
    3. Update the schema file
    4. Return statistics

    Args:
<<<<<<< HEAD
        schema_path: Path to schema file (default: data/bespoke/mappings/schema{Platform}.json)
=======
        schema_path: Path to schema file (default: archer/mappings/schema{Platform}.json)
>>>>>>> 534dbed55db820eea689f7a2b6dc4330fafc6b07
        platform: Platform type - "splunk", "googlesecops", or "elastic" (default: "splunk")
        force: Force re-normalization of all indexes (default: False)
        silent: Suppress output (default: False)

    Returns:
        Dict with keys:
            - total_indexes: Total number of indexes
            - normalized_indexes: Already normalized count
            - new_indexes: Newly normalized count
            - updated_indexes: Re-normalized count (when force=True)
            - errors: List of error messages

    Example:
        >>> from archer.mappings import normalize_auto_schema
        >>> # Normalize Splunk schema
        >>> stats = normalize_auto_schema(platform="splunk")
        >>> # Normalize Google SecOps schema
        >>> stats = normalize_auto_schema(platform="googlesecops")
        >>> # Normalize Elastic schema
        >>> stats = normalize_auto_schema(platform="elastic")
        >>> if stats['new_indexes'] > 0:
        ...     print(f"Normalized {stats['new_indexes']} new indexes")
    """
    # For now, only Splunk normalization is implemented
    # Google SecOps and Elastic use different schema structures (UDM and ECS)
    # which don't require the same normalization approach
    if platform.lower() != "splunk":
        return {
            "total_indexes": 0,
            "normalized_indexes": 0,
            "new_indexes": 0,
            "updated_indexes": 0,
            "errors": [f"Normalization not required for {platform} - uses standardized schema"]
        }

    normalizer = SplunkSchemaNormalizer(schema_path=schema_path)

    # Suppress output if silent mode
    if silent:
        import sys
        import os
        from contextlib import redirect_stdout

        with open(os.devnull, "w") as devnull:
            with redirect_stdout(devnull):
                stats = normalizer.normalize_all(force=force)
    else:
        stats = normalizer.normalize_all(force=force)

    return stats


def is_schema_normalized(query: str) -> bool:
    """
    Check if a single query is normalized.

    Args:
        query: SPL query string

    Returns:
        True if query is normalized, False otherwise

    Example:
        >>> query = "| fields _time user action\\n| eval Time=strftime(_time, '%F %T')"
        >>> is_schema_normalized(query)
        True
    """
    normalizer = SplunkSchemaNormalizer()
    return normalizer.is_normalized(query)


def validate_schema() -> bool:
    """
    Validate that all indexes in the schema are normalized.

    Returns:
        True if all indexes are normalized, False if any need normalization

    Example:
        >>> if not validate_schema():
        ...     print("Some indexes need normalization")
        ...     normalize_auto_schema()
    """
    normalizer = SplunkSchemaNormalizer()
    normalizer.load_schema()

    for category, indexes in normalizer.schema.items():
        for index_name, query in indexes.items():
            if not normalizer.is_normalized(query):
                return False

    return True


def get_schema_stats() -> Dict:
    """
    Get statistics about the current schema normalization state.

    Returns:
        Dict with keys:
            - total_indexes: Total number of indexes
            - normalized_count: Number of normalized indexes
            - unnormalized_count: Number of unnormalized indexes
            - unnormalized_indexes: List of unnormalized index names

    Example:
        >>> stats = get_schema_stats()
        >>> print(f"Schema: {stats['normalized_count']}/{stats['total_indexes']} normalized")
    """
    normalizer = SplunkSchemaNormalizer()
    normalizer.load_schema()

    total = 0
    normalized = 0
    unnormalized = []

    for category, indexes in normalizer.schema.items():
        for index_name, query in indexes.items():
            total += 1
            if normalizer.is_normalized(query):
                normalized += 1
            else:
                unnormalized.append(f"{category}.{index_name}")

    return {
        "total_indexes": total,
        "normalized_count": normalized,
        "unnormalized_count": len(unnormalized),
        "unnormalized_indexes": unnormalized,
    }


# Example integration hooks for Archer application


def on_schema_update_hook():
    """
    Hook to run after schema updates.

    Call this function whenever schemaSplunk.json is modified
    to automatically normalize any new indexes.

    Example:
        >>> # In your schema update function
        >>> def update_schema(new_data):
        ...     # Save new schema data
        ...     save_schema(new_data)
        ...     # Auto-normalize new indexes
        ...     on_schema_update_hook()
    """
    stats = normalize_auto_schema(silent=True)

    if stats["new_indexes"] > 0:
        print(f"✅ Auto-normalized {stats['new_indexes']} new indexes")

    if stats["errors"]:
        print(f"⚠️  Normalization errors: {len(stats['errors'])}")
        for error in stats["errors"]:
            print(f"   - {error}")

    return stats


def pre_query_validation_hook(index_name: str, query: str) -> bool:
    """
    Hook to run before executing queries.

    Validates that the query is from a normalized index.
    If not, triggers auto-normalization.

    Args:
        index_name: Name of the index
        query: SPL query string

    Returns:
        True if query is normalized, False otherwise

    Example:
        >>> # In your query execution function
        >>> def execute_query(index_name, query):
        ...     if not pre_query_validation_hook(index_name, query):
        ...         # Reload the normalized schema
        ...         query = load_normalized_query(index_name)
        ...     # Execute query
        ...     return splunk_client.execute(query)
    """
    if not is_schema_normalized(query):
        print(f"⚠️  Index '{index_name}' is not normalized")
        print("   Running auto-normalization...")

        stats = normalize_auto_schema(silent=False)

        if stats["new_indexes"] > 0:
            print(f"✅ Normalized {stats['new_indexes']} indexes including '{index_name}'")
            return False  # Query needs to be reloaded

    return True  # Query is normalized


if __name__ == "__main__":
    # Run auto-normalization when script is executed directly
    import sys

    force = "--force" in sys.argv
    stats = normalize_auto_schema(force=force)

    sys.exit(0 if not stats["errors"] else 1)
