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

    index_name_lower = index_name.lower()

    # Define platform categories based on common terms
    windows_terms = ["windows", "microsoft", "defender"]
    unix_terms = ["unix", "linux", "macos", "mac"]
    cloud_terms = ["aws", "azure", "gcp", "cloud", "office365", "saas", "iaas"]
    network_terms = ["network", "cisco", "firewall", "proxy"]

    # Categorize the index
    is_windows_index = any(term in index_name_lower for term in windows_terms)
    is_unix_index = any(term in index_name_lower for term in unix_terms)
    is_cloud_index = any(term in index_name_lower for term in cloud_terms)
    is_network_index = any(term in index_name_lower for term in network_terms)

    # Categorize the procedure platforms
    procedure_platforms_lower = [p.lower() for p in procedure_platforms]
    has_windows = any("windows" in p for p in procedure_platforms_lower)
    has_unix = any(
        unix in p
        for p in procedure_platforms_lower
        for unix in ["linux", "macos", "mac os"]
    )
    has_cloud = any(
        cloud in p
        for p in procedure_platforms_lower
        for cloud in ["saas", "iaas", "aws", "azure", "gcp", "cloud", "office 365"]
    )
    has_network = any("network" in p for p in procedure_platforms_lower)

    # Windows-only test (all platforms are Windows)
    is_windows_only = has_windows and not has_unix and not has_cloud and not has_network

    # CRITICAL FIX: Windows-only procedures should not run on non-Windows indices
    if is_windows_only:
        if is_unix_index:
            return False
        if (
            is_cloud_index and not is_windows_index
        ):  # Allow if it's both Windows and Cloud
            return False

    # Basic compatibility rules:

    # Rule 1: If platform includes this index type, it's compatible
    if is_windows_index and has_windows:
        return True

    if is_unix_index and has_unix:
        return True

    if is_cloud_index and has_cloud:
        return True

    if is_network_index and has_network:
        return True

    # Rule 2: Cloud procedures can run on any platform
    if has_cloud:
        return True

    # Rule 3: If index has no clear platform identifier, be permissive
    if (
        not is_windows_index
        and not is_unix_index
        and not is_cloud_index
        and not is_network_index
    ):
        return True

    # Rule 4: If procedure runs on multiple OS types, be permissive unless it's clearly incompatible
    if (
        (has_windows and has_unix)
        or (has_windows and has_network)
        or (has_unix and has_network)
    ):
        # Still enforce Windows-only techniques on Windows-only indices
        if "ntds" in index_name_lower or "volume shadow" in index_name_lower:
            if not is_windows_index:
                return False
        return True

    # Default case: If we've made it here, we likely have a mismatch
    return False
