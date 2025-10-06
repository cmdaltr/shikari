import os
import json
from pathlib import Path


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


PLATFORM_MAPPINGS = load_platform_mappings()


def get_platforms_for_index(index_name):
    # Get platforms associated with a given index/table name and returns list of platforms that include this index
    clean_index_name = index_name.replace("index=", "")

    # Find all platforms that include this index
    matching_platforms = []
    for platform, sources in PLATFORM_MAPPINGS.items():
        for _, indices in sources.items():
            if clean_index_name in indices:
                matching_platforms.append(platform)

    return matching_platforms


def is_query_applicable(procedure_platforms, software_platforms, index_name):
    index_platforms = get_platforms_for_index(index_name)

    if not index_platforms:
        return False

    # If procedure is platform-specific (only one platform),
    # ensure index supports that exact platform
    if len(procedure_platforms) == 1:
        procedure_platform = procedure_platforms[0]
        # Strict check: index must support this specific platform
        if procedure_platform not in index_platforms:
            return False
        return True

    # Multi-platform procedures: require at least one overlap
    for platform in procedure_platforms:
        if platform in index_platforms:
            return True

    return False
