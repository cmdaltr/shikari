def compile_mde_queries(indicator_mapping, indicators, indicator_type, mde_queries):
    # Mapping and building MDE queries
    for table, fields in indicator_mapping[indicator_type]["MDE"].items():
        has_all_indicators = []
        has_any_indicators = []
        for indicator in indicators:
            if " " in indicator:
                # Split into parts for has_all
                parts = [part.strip() for part in indicator.split()]
                has_all_indicators.append(parts)
            else:
                has_any_indicators.append(indicator)

        # Format indicators
        indicator_clauses = []
        for parts in has_all_indicators:
            all_str = '", "'.join(parts)
            indicator_clauses.append(f'has_all("{all_str}")')
        if has_any_indicators:
            any_str = '", "'.join(has_any_indicators)
            indicator_clauses.append(f'has_any("{any_str}")')

        condition = " or ".join(
            [f"{field} {clause}" for field in fields for clause in indicator_clauses]
        )
        mde_queries.append(f"{table}\n| where Timestamp > ago(1d)\n| where {condition}")

    return mde_queries


def compile_splunk_queries(
    indicator_mapping, indicators, indicator_type, splunk_queries
):
    # Mapping and building Splunk queries
    for index, fields in indicator_mapping[indicator_type]["Splunk"].items():
        field_clauses = []
        for field in fields:
            indicator_clauses = []
            for indicator in indicators:
                if " " in indicator:
                    # Multi-word indicator: AND each part, grouped in parentheses
                    parts = indicator.split()
                    and_clauses = []
                    for part in parts:
                        and_clauses.append(f'properties.{field}="*{part}*"')
                    indicator_clauses.append("(" + " AND ".join(and_clauses) + ")")
                else:
                    # Single-word indicator
                    indicator_clauses.append(f'properties.{field}="*{indicator}*"')
            field_clauses.append(" OR ".join(indicator_clauses))

        condition = " OR ".join(field_clauses)
        splunk_queries.append(f"index={index} earliest=-1d\n({condition})")

    return splunk_queries


def load_platform_mappings():
    """Load platform mappings from platforms.json"""
    import os
    import json
    from pathlib import Path

    platforms_file = (
        Path(os.path.dirname(__file__)) / ".." / "mappings" / "platforms.json"
    )
    if not platforms_file.exists():
        return {}

    try:
        with open(platforms_file, "r") as f:
            return json.load(f)
    except Exception:
        return {}


# Load platform mappings once when the module is imported
PLATFORM_MAPPINGS = load_platform_mappings()


def get_platforms_for_index(index_name):
    """
    Get platforms associated with a given index/table name

    Args:
        index_name: The index or table name (possibly with "index=" prefix)

    Returns:
        List of platforms that include this index
    """
    # Remove "index=" prefix if present
    clean_index_name = index_name.replace("index=", "")

    # Find all platforms that include this index
    matching_platforms = []
    for platform, sources in PLATFORM_MAPPINGS.items():
        for source_type, indices in sources.items():
            if clean_index_name in indices:
                matching_platforms.append(platform)

    return matching_platforms


def is_query_applicable(procedure_platforms, software_platforms, index_name):
    """
    Determine if a query should be built based on platform compatibility

    Args:
        procedure_platforms: List of platforms applicable to the procedure
        software_platforms: Dict of platforms applicable to each software
        index_name: Name of the Splunk index or MDE table

    Returns:
        Boolean indicating if query should be built
    """
    # If there's no platform information, assume compatibility
    if not procedure_platforms and not software_platforms:
        return True

    # Get platforms for this index from our mapping
    index_platforms = get_platforms_for_index(index_name)

    # If we couldn't determine the platform of the index, be permissive
    if not index_platforms:
        return True

    # Check if there's any overlap between procedure platforms and index platforms
    for platform in procedure_platforms:
        if platform in index_platforms:
            return True

    # Special case: If the index is cloud-only and the procedure is Windows/OS-only
    cloud_platforms = ["IaaS", "SaaS", "Identity Provider"]
    os_platforms = ["Windows", "Linux", "macOS"]

    index_is_cloud_only = all(
        platform in cloud_platforms for platform in index_platforms
    )
    procedure_is_os_only = all(
        platform in os_platforms for platform in procedure_platforms
    )

    # Block OS-only procedures on cloud-only indices
    if index_is_cloud_only and procedure_is_os_only:
        return False

    # Default: No match found, be conservative and don't generate the query
    return False
