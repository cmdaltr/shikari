from .queries import compile_mde_queries, compile_splunk_queries
from archer.build.queries import is_query_applicable

import json
import os
import re


"""def define_vectr_values(payload, technique_descriptions, retrieved_data):
    name = payload["variables"]["input"]["createTestCasedata"][0]["testCaseData"][
        "name"
    ]
    tid = payload["variables"]["input"]["createTestCasedata"][0]["testCaseData"][
        "technique"
    ]
    for description in technique_descriptions:
        if description.startswith(f"{tid}: "):
            tdesc = description.split(f"{tid}: ")[1]
    tactic = payload["variables"]["input"]["createTestCasedata"][0]["testCaseData"][
        "phase"
    ]
    tag = retrieved_data["group_name"]
    identifiers = payload["variables"]["input"]["createTestCasedata"][0][
        "testCaseData"
    ]["identifiers"]
    redTools = payload["variables"]["input"]["createTestCasedata"][0]["testCaseData"][
        "redTools"
    ]
    log_sources = payload["variables"]["input"]["createTestCasedata"][0][
        "testCaseData"
    ]["log_sources"]

    return (
        name,
        tid,
        tdesc,
        tactic,
        tag,
        identifiers,
        redTools,
        log_sources,
    )
"""


def merge_queries_for_same_table(query1, query2):
    """
    Merge two queries for the same table by combining their WHERE clauses with OR.

    Args:
        query1: First query string
        query2: Second query string

    Returns:
        Merged query string with combined WHERE conditions
    """
    # Parse both queries
    lines1 = query1.split('\n')
    lines2 = query2.split('\n')

    # Extract table name (first line)
    table = lines1[0].strip()

    # Extract WHERE clause from each query
    where_clause1 = None
    where_clause2 = None

    for i, line in enumerate(lines1):
        if '| where' in line and 'Timestamp' not in line:
            # Find the WHERE clause (skip the Timestamp filter)
            where_clause1 = line.split('| where')[1].strip()
            break

    for i, line in enumerate(lines2):
        if '| where' in line and 'Timestamp' not in line:
            where_clause2 = line.split('| where')[1].strip()
            break

    if not where_clause1 or not where_clause2:
        # If we can't find WHERE clauses, return query1
        return query1

    # Combine WHERE clauses with OR
    # Remove outer parentheses if they exist to avoid double-wrapping
    where_clause1 = where_clause1.strip()
    where_clause2 = where_clause2.strip()

    if where_clause1.startswith('(') and where_clause1.endswith(')'):
        where_clause1 = where_clause1[1:-1]
    if where_clause2.startswith('(') and where_clause2.endswith(')'):
        where_clause2 = where_clause2[1:-1]

    combined_where = f"({where_clause1}) or ({where_clause2})"

    # Build merged query
    merged_query = f"{table}\n| where Timestamp > ago(1d)\n| where {combined_where}"

    return merged_query


def collate_data(identifiers, log_sources, procedure_platforms, software_platforms, detection_name="", technique_id=None, osint_indicators=None):
    from archer.build.platform_indicator_validator import normalize_platform_name
    from archer.build.osint_comparison import extract_operations_from_osint_snippets

    # Extract structured indicators from OSINT query snippets if provided
    structured_osint_indicators = None
    if osint_indicators:
        structured_osint_indicators = extract_operations_from_osint_snippets(osint_indicators)
        if structured_osint_indicators:
            print(f"  📊 Extracted structured OSINT indicators: {list(structured_osint_indicators.keys())}")

    # Map identified log_sources with the data sources and return the logging table/indexes
    with open(
        os.path.join("bespoke", "mappings", "sources", "dataSources.json")
    ) as datasourcesjson:
        data_sources = json.load(datasourcesjson)

    mitre_data_sources = data_sources["mitreDataSources"]
    alignment_results = []
    for step in log_sources:
        matched_sources = []
        for ds_name, ds_content in mitre_data_sources.items():
            if step.startswith(f"{ds_name} "):
                matched_sources.append(
                    {
                        "data_source": ds_name,
                        "MDE": ds_content.get("MDE", []),
                        "Splunk": ds_content.get("Splunk", []),
                    }
                )
        alignment_results.append({"detection_step": step, "matches": matched_sources})

    # For each indicator type (cmd, evt, reg, sw) in operator_guidance, fetch mapping
    # Check for custom Splunk schema first, fall back to default
    splunk_custom_file = os.path.join("bespoke", "mappings", "schemas", "schemaSplunk_custom.json")
    splunk_default_file = os.path.join("bespoke", "mappings", "schemas", "schemaSplunk.json")
    if os.path.exists(splunk_custom_file):
        with open(splunk_custom_file) as f:
            map_splunk_indices = json.load(f)
    else:
        with open(splunk_default_file) as f:
            map_splunk_indices = json.load(f)

    with open(os.path.join("bespoke", "mappings", "indicatorMapping.json"), "r") as f:
        indicator_mapping = json.load(f)

    # Check for custom MDE schema first, fall back to default
    mde_custom_file = os.path.join("bespoke", "mappings", "schemas", "schemaMDE_custom.json")
    mde_default_file = os.path.join("bespoke", "mappings", "schemas", "schemaMDE.json")
    if os.path.exists(mde_custom_file):
        with open(mde_custom_file) as f:
            map_defender_tables = json.load(f)
    else:
        with open(mde_default_file) as f:
            map_defender_tables = json.load(f)

    # Note: This validation loop is unused - variables assigned but never used
    # Commented out due to incompatibility with new schemaSplunk.json structure
    # for step in alignment_results:
    #     if step["matches"]:
    #         for match in step["matches"]:
    #             for mde_table in match["MDE"]:
    #                 mde_mapping = map_defender_tables.get(mde_table)
    #             for splunk_index in match["Splunk"]:
    #                 splunk_mapping = map_splunk_indices.get(splunk_index)

    mde_queries = []
    splunk_queries = []
    # Use dict to accumulate queries by table name, allowing merging of conditions
    mde_queries_by_table = {}
    all_splunk_queries = []  # Accumulate all Splunk queries across indicator types

    for indicator_type, indicators in identifiers.items():
        if len(indicators) > 0:
            if indicator_type in indicator_mapping:
                # Determine platform for cloud filtering
                # Use procedure platforms if available, otherwise derive from indicators
                platform = None
                if procedure_platforms:
                    # Use first procedure platform as the primary platform
                    platform = list(procedure_platforms)[0] if isinstance(procedure_platforms, set) else procedure_platforms[0] if isinstance(procedure_platforms, list) else procedure_platforms

                # Mapping and building MDE queries
                mde_queries = compile_mde_queries(
                    indicator_mapping, indicators, indicator_type, mde_queries, detection_name, platform=platform
                )

                # Group queries by table for potential merging
                for query in mde_queries:
                    # Extract the table name from the query string (assumes first line is the table name)
                    table_name = query.split("\n")[0].strip()

                    if table_name not in mde_queries_by_table:
                        # First query for this table
                        mde_queries_by_table[table_name] = query
                    else:
                        # Merge this query with existing query for same table
                        existing_query = mde_queries_by_table[table_name]
                        merged_query = merge_queries_for_same_table(existing_query, query)
                        mde_queries_by_table[table_name] = merged_query

                # Mapping and building Splunk queries
                # Extract platform from index name for validation (if not already set)
                if not platform:
                    index_name = None
                    if "Splunk" in indicator_mapping.get(indicator_type, {}):
                        splunk_indices = list(indicator_mapping[indicator_type]["Splunk"].keys())
                        if splunk_indices:
                            index_name = splunk_indices[0].replace("index=", "")
                            platform = normalize_platform_name(index_name)
                        else:
                            platform = None
                    else:
                        platform = None

                prev_splunk_count = len(splunk_queries)
                splunk_queries = compile_splunk_queries(
                    indicator_mapping, indicators, indicator_type, splunk_queries, structured_osint_indicators, detection_name,
                    platform=platform, technique_id=technique_id
                )

                # Only process queries newly added in this iteration to avoid duplicates
                for query in splunk_queries[prev_splunk_count:]:
                    # Extract the index name from the query string
                    index_name = None
                    if query.startswith("index="):
                        index_name = query.split()[0].replace("index=", "")
                        # Add compatibility check here!
                        if is_query_applicable(
                            procedure_platforms, software_platforms, index_name
                        ):
                            # No need to append anything - compile_splunk_queries() already generates complete queries
                            # with transformation pipelines from schemaSplunk.json included
                            all_splunk_queries.append(query)
                    else:
                        # Query doesn't start with "index=" - likely an MDE query that got mixed in
                        # Skip it silently (this is expected in mixed query results)
                        pass

            else:
                pass

    # Build final list of MDE queries with table mappings appended
    appended_mde_queries = []
    for table_name, query in mde_queries_by_table.items():
        mde_mapping = map_defender_tables.get(table_name, "")
        appended_query = f"{query}{mde_mapping}"
        appended_mde_queries.append(appended_query)

    return appended_mde_queries, all_splunk_queries
