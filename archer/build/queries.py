import os
import json
from pathlib import Path
from archer.build.malware_iocs import enrich_indicators_with_iocs, log_ioc_enrichment


def load_splunk_schema():
    """Load Splunk transformation pipelines from schemaSplunk.json"""
    schema_file = (
        Path(os.path.dirname(__file__)) / ".." / "mappings" / "schemaSplunk.json"
    )
    if not schema_file.exists():
        return {}

    try:
        with open(schema_file, "r") as f:
            return json.load(f)
    except Exception:
        return {}


SPLUNK_SCHEMA = load_splunk_schema()


def compile_search_clause(field_value_pairs):
    """
    Compiles field-value pairs into proper | search syntax

    Args:
        field_value_pairs: Dict of {field_name: [values]}

    Returns:
        String for | search command

    Rules:
    - Single-word values: use IN operator
      field IN ("value1", "value2")
    - Multi-word values: use wildcards with implicit AND (spaces)
      Each multi-word indicator becomes: (field="*word1 *" field="* word2 *" field="* word3*")
      Strategic spacing ensures word boundaries are matched correctly
    - Single value: use = operator
      field="value"
    - Bare strings (field=None): just include them
      "Success"
    - Multi-word groups joined with OR: IN_clause OR (multi_word_group1) OR (multi_word_group2)
    """
    search_parts = []

    # Group by field name
    for field_name, values in field_value_pairs.items():
        # Deduplicate values while preserving order
        unique_values = []
        seen = set()
        for v in values:
            if v not in seen:
                unique_values.append(v)
                seen.add(v)

        if field_name is None:
            # Bare string values (no field name)
            for v in unique_values:
                search_parts.append(f'"{v}"')
        else:
            # Separate single-word and multi-word values
            single_word_values = []
            multi_word_values = []

            for v in unique_values:
                if ' ' in v:
                    multi_word_values.append(v)
                else:
                    single_word_values.append(v)

            # Handle single-word values with IN operator
            if len(single_word_values) > 1:
                values_str = ', '.join([f'"{v}"' for v in single_word_values])
                search_parts.append(f'{field_name} IN ({values_str})')
            elif len(single_word_values) == 1:
                search_parts.append(f'{field_name}="{single_word_values[0]}"')

            # Handle multi-word values with wildcards and implicit AND
            # Each multi-word indicator becomes a separate OR group
            for multi_word in multi_word_values:
                words = multi_word.split()
                word_conditions = []
                for i, word in enumerate(words):
                    # Strategic spacing: first word "*word *", middle "* word *", last "* word*"
                    if i == 0:
                        # First word: space after
                        word_conditions.append(f'{field_name}="*{word} *"')
                    elif i == len(words) - 1:
                        # Last word: space before
                        word_conditions.append(f'{field_name}="* {word}*"')
                    else:
                        # Middle words: spaces before and after
                        word_conditions.append(f'{field_name}="* {word} *"')
                # Join with spaces (implicit AND)
                word_clause = ' '.join(word_conditions)
                search_parts.append(f'OR ({word_clause})')

    # Join parts with spaces
    result = ' '.join(search_parts)

    # Clean up: if result starts with "OR ", remove it
    if result.startswith('OR '):
        result = result[3:]

    return result


def compile_mde_queries(indicator_mapping, indicators, indicator_type, mde_queries, detection_name=""):
    # Enrich indicators with malware IOCs before building queries
    enriched_indicators, ioc_metadata = enrich_indicators_with_iocs(indicators, indicator_type)

    # Log enrichment if any occurred
    if ioc_metadata and ioc_metadata.get("enriched_iocs"):
        log_ioc_enrichment(detection_name or "MDE Detection", ioc_metadata)

    # Use enriched indicators for query building
    indicators_to_use = enriched_indicators if enriched_indicators else indicators

    # Mapping and building MDE queries
    for table, fields in indicator_mapping[indicator_type]["MDE"].items():
        has_all_indicators = []
        has_any_indicators = []
        for indicator in indicators_to_use:
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

        # Only generate query if there are indicators
        if not indicator_clauses:
            print(f"⚠️  Warning: Skipping MDE query for {table} - no valid indicators")
            continue

        condition = " or ".join(
            [f"{field} {clause}" for field in fields for clause in indicator_clauses]
        )

        # Add malware family name as comment if enrichment occurred
        query = f"{table}\n| where Timestamp > ago(1d)\n| where {condition}"
        if ioc_metadata and ioc_metadata.get("malware_family_names"):
            malware_names_str = ", ".join(ioc_metadata["malware_family_names"])
            query += f" // {malware_names_str}"

        mde_queries.append(query)

    return mde_queries


def compile_splunk_queries(
    indicator_mapping, indicators, indicator_type, splunk_queries, osint_indicators=None, detection_name=""
):
    """
    Builds Splunk queries with proper structure:
    1. Clean index search: index={index} earliest=-1d
    2. Transformation pipeline from schemaSplunk.json
    3. Final | search with compiled indicators

    Args:
        indicator_mapping: Mapping of indicator types to data sources
        indicators: List of indicator values from MITRE
        indicator_type: Type of indicator (cmd, reg, evt, sw, cve, operation, etc.)
        splunk_queries: List to append queries to
        osint_indicators: Optional dict of OSINT-extracted indicators {field: [values]}
        detection_name: Name of the detection for logging purposes

    Returns:
        Updated splunk_queries list
    """
    # Enrich indicators with malware IOCs before building queries
    enriched_indicators, ioc_metadata = enrich_indicators_with_iocs(indicators, indicator_type)

    # Log enrichment if any occurred
    if ioc_metadata and ioc_metadata.get("enriched_iocs"):
        log_ioc_enrichment(detection_name or "Splunk Detection", ioc_metadata)

    # Use enriched indicators for query building
    indicators_to_use = enriched_indicators if enriched_indicators else indicators

    # Get transformation pipeline from schema
    transformation_pipeline = SPLUNK_SCHEMA.get(indicator_type, {})

    # Build queries for each index
    for index, fields in indicator_mapping[indicator_type]["Splunk"].items():
        # Get the transformation pipeline for this index
        pipeline = transformation_pipeline.get(index, "")

        if not pipeline:
            # Fallback if no pipeline found - skip this query
            print(f"⚠️  Warning: No transformation pipeline found for {index} with indicator type {indicator_type}")
            continue

        # Extract field names available in the pipeline
        pipeline_fields = extract_field_names_from_pipeline(pipeline)

        # Build field-value pairs for | search clause
        field_value_pairs = {}

        # Add MITRE indicators - validate fields exist in pipeline
        for field in fields:
            # Check if field exists in pipeline fields
            matched_field = find_matching_field(field, pipeline_fields)

            if matched_field:
                if matched_field not in field_value_pairs:
                    field_value_pairs[matched_field] = []
                field_value_pairs[matched_field].extend(indicators_to_use)
            else:
                # Field from indicatorMapping.json not found in pipeline
                # Log warning but continue (don't break the entire query)
                print(f"⚠️  Warning: Field '{field}' from indicatorMapping.json not found in pipeline fields for {index}")
                # Skip this field instead of using invalid field name

        # Add OSINT indicators if enhancement enabled
        if osint_indicators:
            for osint_field, osint_values in osint_indicators.items():
                # Map OSINT field names to Splunk field names
                # OSINT uses generic names like 'operation', but Splunk uses specific names like 'operationName'
                # We need to check which fields from the transformation pipeline match

                # Find matching field (operationName, Operation, operation_name, etc.)
                matched_field = find_matching_field(osint_field, pipeline_fields)

                if matched_field:
                    if matched_field not in field_value_pairs:
                        field_value_pairs[matched_field] = []
                    field_value_pairs[matched_field].extend(osint_values)
                else:
                    # If no match found, try the osint_field name directly
                    if osint_field not in field_value_pairs:
                        field_value_pairs[osint_field] = []
                    field_value_pairs[osint_field].extend(osint_values)

        # Compile the search clause
        search_clause = compile_search_clause(field_value_pairs)

        # Only generate query if there are actual indicators in the search clause
        if not search_clause or search_clause.strip() == "":
            print(f"⚠️  Warning: Skipping query for {index} - no valid indicators to search for")
            continue

        # Build final query with proper structure
        query = f"index={index} earliest=-1d\n{pipeline}\n| search {search_clause}"

        # Add malware family name as comment if enrichment occurred
        if ioc_metadata and ioc_metadata.get("malware_family_names"):
            malware_names_str = ", ".join(ioc_metadata["malware_family_names"])
            query += f" ```{malware_names_str}```"

        splunk_queries.append(query)

    return splunk_queries


def extract_field_names_from_pipeline(pipeline):
    """Extract field names from the | fields command in transformation pipeline"""
    import re

    # Find the | fields command
    fields_match = re.search(r'\| fields ([^\n|]+)', pipeline)
    if fields_match:
        fields_str = fields_match.group(1)
        # Split by whitespace and filter out empty strings
        return [f.strip() for f in fields_str.split() if f.strip()]
    return []


def find_matching_field(osint_field, pipeline_fields):
    """
    Find matching field name from pipeline fields

    Matches variations like:
    - operation -> operationName, Operation, operation_name
    - cmd -> command, Command
    """
    osint_lower = osint_field.lower()

    # Direct match
    if osint_field in pipeline_fields:
        return osint_field

    # Case-insensitive match
    for field in pipeline_fields:
        if field.lower() == osint_lower:
            return field

    # Partial match (operation matches operationName)
    for field in pipeline_fields:
        field_lower = field.lower()
        if osint_lower in field_lower or field_lower in osint_lower:
            return field

    # Check for common variations
    variations = [
        osint_field + "Name",  # operation -> operationName
        osint_field + "_name",  # operation -> operation_name
        osint_field.capitalize(),  # operation -> Operation
    ]

    for variation in variations:
        if variation in pipeline_fields:
            return variation
        # Case-insensitive check
        for field in pipeline_fields:
            if field.lower() == variation.lower():
                return field

    return None


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
    # Special case: Windows Event Logs (windows_events) should NEVER be used for non-Windows platforms
    if index_name == "windows_events":
        # Only allow if procedure is explicitly for Windows
        if "Windows" not in procedure_platforms:
            return False

    # Special case: Unix logs (linux_syslog) should NEVER be used for Windows-only procedures
    if index_name == "linux_syslog":
        # Block if procedure is Windows-only
        if procedure_platforms == ["Windows"]:
            return False

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
