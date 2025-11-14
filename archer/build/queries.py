import os
import json
import re
from pathlib import Path
from collections import defaultdict
from archer.build.malware_iocs import enrich_indicators_with_iocs, log_ioc_enrichment


def validate_and_clean_indicators(indicators: list, indicator_type: str = "cmd") -> list:
    """
    Validate and clean indicators before using them in queries.

    Filters out:
    - Description/citation text
    - Overly generic terms
    - Duplicates
    - Very short strings (< 3 chars)
    - Common English words
    - Invalid characters/formatting

    Args:
        indicators: List of raw indicators
        indicator_type: Type of indicator (cmd, process, file, etc.)

    Returns:
        List of cleaned and validated indicators
    """
    if not indicators:
        return []

    # Common words to filter out (case-insensitive)
    GENERIC_WORDS = {
        'and', 'or', 'the', 'to', 'from', 'for', 'in', 'on', 'at', 'by', 'with',
        'as', 'is', 'was', 'are', 'be', 'been', 'being', 'have', 'has', 'had',
        'do', 'does', 'did', 'will', 'would', 'should', 'could', 'may', 'might',
        'can', 'a', 'an', 'of', 'it', 'this', 'that', 'these', 'those',
        'file', 'files', 'show', 'shows', 'shown', 'used', 'use', 'using',
        'each', 'all', 'any', 'some', 'process', 'memory', 'system', 'data',
        'r', 'n', 'x', 'i', 'v', 't', 'f', 'l', 'd', 's', 'p', 'e', 'c', 'w'
    }

    # Citation patterns to filter out
    CITATION_PATTERNS = [
        r'\(Citation:.*?\)',  # (Citation: ...)
        r'https?://',  # URLs
        r'www\.',  # www links
        r'\d{4}',  # Years (2018, 2022, etc.)
        r'GitHub',  # Platform names
        r'Adversaries',  # ATT&CK description language
        r'pseudo-filesystem',
        r'interface',
        r'kernel',
        r'virtual',
        r'address space',
        r'cleartext',
        r'passwords',
        r'identify',
        r'regex patterns',
        r'dump'
    ]

    cleaned = []
    seen = set()  # Track duplicates

    for indicator in indicators:
        if not indicator or not isinstance(indicator, str):
            continue

        # Strip whitespace
        indicator = indicator.strip()

        # Skip empty or very short indicators (< 3 characters)
        if len(indicator) < 3:
            continue

        # Skip if it matches citation patterns
        is_citation = False
        for pattern in CITATION_PATTERNS:
            if re.search(pattern, indicator, re.IGNORECASE):
                is_citation = True
                break
        if is_citation:
            continue

        # Skip generic single words
        if ' ' not in indicator and indicator.lower() in GENERIC_WORDS:
            continue

        # Skip indicators that are mostly common words
        if ' ' in indicator:
            words = indicator.split()
            # If more than 60% of words are generic, skip it
            generic_count = sum(1 for w in words if w.lower() in GENERIC_WORDS)
            if len(words) > 2 and generic_count / len(words) > 0.6:
                continue

        # Skip if it contains multiple consecutive dots or suspicious patterns
        if '..' in indicator or '  ' in indicator:
            continue

        # Remove duplicate quotes and fix escaping issues
        # Replace double-double quotes with single quotes
        indicator = indicator.replace('""', '"')

        # Skip if already seen (case-insensitive deduplication)
        indicator_lower = indicator.lower()
        if indicator_lower in seen:
            continue
        seen.add(indicator_lower)

        # Add to cleaned list
        cleaned.append(indicator)

    return cleaned


def load_splunk_schema():
    """Load Splunk transformation pipelines from schemaSplunk.json

    Checks for custom mapping file first (schemaSplunk_custom.json),
    then falls back to default mapping file (schemaSplunk.json).
    """
    mappings_dir = Path(os.path.dirname(__file__)) / ".." / "mappings"

    # Try custom mapping file first
    custom_schema_file = mappings_dir / "schemaSplunk_custom.json"
    if custom_schema_file.exists():
        try:
            with open(custom_schema_file, "r") as f:
                return json.load(f)
        except Exception:
            # If custom file fails to load, fall back to default
            pass

    # Fall back to default mapping file
    schema_file = mappings_dir / "schemaSplunk.json"
    if not schema_file.exists():
        return {}

    try:
        with open(schema_file, "r") as f:
            return json.load(f)
    except Exception:
        return {}


SPLUNK_SCHEMA = load_splunk_schema()


def load_log_source_categories():
    """Load log source categorization from logSourceCategories.json"""
    categories_file = (
        Path(os.path.dirname(__file__)) / ".." / "mappings" / "logSourceCategories.json"
    )
    if not categories_file.exists():
        return {}

    try:
        with open(categories_file, "r") as f:
            data = json.load(f)
            return data.get("categories", {}), data.get("cloud_indicator_mappings", {})
    except Exception:
        return {}, {}


LOG_SOURCE_CATEGORIES, CLOUD_INDICATOR_MAPPINGS = load_log_source_categories()


def detect_cloud_platform_from_indicators(indicators, indicator_type):
    """
    Detects which cloud platform(s) the indicators belong to based on API calls, commands, or tools.

    Args:
        indicators: List of indicator values (e.g., ["DescribeInstances", "ListBuckets"])
        indicator_type: Type of indicator (cmd, api, sw, etc.)

    Returns:
        Set of cloud platforms: {"aws", "azure", "gcp"} or empty set if not cloud-specific
    """
    if not indicators or not CLOUD_INDICATOR_MAPPINGS:
        return set()

    detected_platforms = set()

    # Check each indicator against cloud platform mappings
    for indicator in indicators:
        indicator_lower = indicator.lower()

        # Check AWS
        aws_mapping = CLOUD_INDICATOR_MAPPINGS.get("aws", {})
        for category in ["api_calls", "commands", "tools"]:
            if any(indicator_lower in item.lower() or item.lower() in indicator_lower
                   for item in aws_mapping.get(category, [])):
                detected_platforms.add("aws")
                break

        # Check Azure
        azure_mapping = CLOUD_INDICATOR_MAPPINGS.get("azure", {})
        for category in ["api_calls", "commands", "tools"]:
            if any(indicator_lower in item.lower() or item.lower() in indicator_lower
                   for item in azure_mapping.get(category, [])):
                detected_platforms.add("azure")
                break

        # Check GCP
        gcp_mapping = CLOUD_INDICATOR_MAPPINGS.get("gcp", {})
        for category in ["api_calls", "commands", "tools"]:
            if any(indicator_lower in item.lower() or item.lower() in indicator_lower
                   for item in gcp_mapping.get(category, [])):
                detected_platforms.add("gcp")
                break

    return detected_platforms


def get_valid_indices_for_platform(indicator_mapping_section, vendor, detected_platforms, technique_platform, indicator_type=None):
    """
    Returns valid indices/tables based on detected cloud platform and technique platform.

    Args:
        indicator_mapping_section: The indicator mapping section from indicatorMapping.json (e.g., mapping["api"]["Splunk"])
        vendor: "Splunk" or "MDE"
        detected_platforms: Set of detected cloud platforms from indicators {"aws", "azure", "gcp"}
        technique_platform: MITRE technique platform (e.g., "AWS", "Azure", "GCP", "Windows")
        indicator_type: The indicator type (e.g., "api", "cmd", "sw", etc.) - only "api" has cloud categorization

    Returns:
        Dict of {index/table: fields} that are valid for this platform combination
    """
    valid_indices = {}

    # Only "api" indicator type has the nested cloud categorization structure
    # Other types (cmd, reg, evt, sw, network) have flat structures
    has_cloud_categories = (indicator_type == "api" and
                           any(key.startswith("cloud_native_") or key == "endpoint"
                               for key in indicator_mapping_section.keys()))

    if not has_cloud_categories:
        # Legacy flat structure - return all indices
        return indicator_mapping_section

    # Handle endpoint sources
    # For non-API indicators: Always include endpoint sources
    # For API indicators: Include endpoint sources when cloud platforms are detected
    #   - This covers cloud CLI tools (aws, gcloud, az) where API calls appear in command lines
    #   - Example: "aws ec2 DescribeInstances" contains the API call "DescribeInstances" in ProcessCommandLine
    if "endpoint" in indicator_mapping_section:
        if indicator_type != "api":
            # Non-API indicators: always include endpoint sources
            valid_indices.update(indicator_mapping_section["endpoint"])
        elif detected_platforms or technique_platform:
            # API indicators with cloud platforms: include endpoint sources for CLI detection
            # When cloud platforms are detected (AWS, Azure, GCP), API indicators may appear in CLI commands
            valid_indices.update(indicator_mapping_section["endpoint"])

    # If no cloud platforms detected and no technique platform, return what we have so far
    if not detected_platforms and not technique_platform:
        return valid_indices

    # Add cloud-native sources only if they match detected platform or technique platform
    platform_map = {
        "AWS": "cloud_native_aws",
        "Azure": "cloud_native_azure",
        "Azure AD": "cloud_native_azure",
        "GCP": "cloud_native_gcp"
    }

    # Check technique platform
    if technique_platform in platform_map:
        cloud_key = platform_map[technique_platform]
        if cloud_key in indicator_mapping_section:
            valid_indices.update(indicator_mapping_section[cloud_key])

    # Check detected platforms from indicators
    for platform in detected_platforms:
        cloud_key = f"cloud_native_{platform}"
        if cloud_key in indicator_mapping_section:
            valid_indices.update(indicator_mapping_section[cloud_key])

    return valid_indices


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


def compile_mde_queries(indicator_mapping, indicators, indicator_type, mde_queries, detection_name="", platform=None):
    # Enrich indicators with malware IOCs before building queries
    enriched_indicators, ioc_metadata = enrich_indicators_with_iocs(indicators, indicator_type)

    # Log enrichment if any occurred
    if ioc_metadata and ioc_metadata.get("enriched_iocs"):
        log_ioc_enrichment(detection_name or "MDE Detection", ioc_metadata)

    # Use enriched indicators for query building
    indicators_to_use = enriched_indicators if enriched_indicators else indicators

    # Validate and clean indicators to remove description text, duplicates, and generic terms
    indicators_to_use = validate_and_clean_indicators(indicators_to_use, indicator_type)

    # Detect cloud platform from indicators (for API calls, commands, etc.)
    detected_platforms = detect_cloud_platform_from_indicators(indicators_to_use, indicator_type)

    # Get valid tables based on platform filtering
    mde_mapping = indicator_mapping[indicator_type].get("MDE", {})
    valid_tables = get_valid_indices_for_platform(
        mde_mapping,
        "MDE",
        detected_platforms,
        platform,
        indicator_type
    )

    # Mapping and building MDE queries
    for table, fields in valid_tables.items():
        has_all_indicators = []
        has_any_indicators = []
        azure_operation_indicators = []  # For Azure operations with has_all + boolean logic

        for indicator in indicators_to_use:
            # Escape backslashes for KQL
            escaped_indicator = indicator.replace('\\', '\\\\')

            # Detect Azure operations (e.g., Microsoft.Authorization/elevateAccess/action)
            # Pattern: Contains dots or slashes (but not backslashes) indicating hierarchical operations
            if ('.' in escaped_indicator or '/' in escaped_indicator) and not escaped_indicator.startswith('\\'):
                # Azure API operation or similar hierarchical identifier
                # Split on dots and slashes to extract components
                parts = []
                # Replace delimiters with spaces, then split
                temp = escaped_indicator.replace('.', ' ').replace('/', ' ')
                parts = [part.strip() for part in temp.split() if part.strip()]

                if len(parts) >= 2:
                    # Store as Azure operation for special handling
                    azure_operation_indicators.append({
                        'original': escaped_indicator,
                        'parts': parts
                    })
                else:
                    # Single part after splitting, treat as regular indicator
                    has_any_indicators.append(escaped_indicator)
            elif " " in escaped_indicator:
                # Split into parts for has_all
                parts = [part.strip() for part in escaped_indicator.split()]
                has_all_indicators.append(parts)
            else:
                has_any_indicators.append(escaped_indicator)

        # Format indicators
        indicator_clauses = []

        # Handle regular has_all indicators (space-separated)
        for parts in has_all_indicators:
            all_str = '", "'.join(parts)
            indicator_clauses.append(f'has_all("{all_str}")')

        # Handle Azure operations with has_all + boolean logic
        # Group Azure operations by common namespace prefix for optimal queries
        if azure_operation_indicators:
            # Group operations by their namespace (first 1-2 parts)
            # Example: Microsoft.Authorization/elevateAccess/action and Microsoft.Authorization/roleAssignments/write
            # Both share "Microsoft.Authorization" namespace
            namespace_groups = defaultdict(list)

            for az_op in azure_operation_indicators:
                parts = az_op['parts']
                if len(parts) >= 2:
                    # Namespace is first 1-2 parts depending on structure
                    # For "Microsoft.Authorization.X.Y" -> namespace is "Microsoft.Authorization"
                    # For "service.operation" -> namespace is "service"
                    namespace_parts = tuple(parts[:2]) if len(parts) > 2 else (parts[0],)
                    operation_parts = parts[2:] if len(parts) > 2 else [parts[1]]
                    namespace_groups[namespace_parts].append(operation_parts)

            # Build queries with grouped operations
            # Use {FIELD} placeholder that will be replaced with actual field name later
            for namespace_parts, operation_groups in namespace_groups.items():
                namespace_str = '", "'.join(namespace_parts)

                if len(operation_groups) == 1:
                    # Single operation for this namespace
                    operation_str = '", "'.join(operation_groups[0])
                    clause = f'{{FIELD}} has_all("{namespace_str}") and {{FIELD}} has_all("{operation_str}")'
                    indicator_clauses.append(clause)
                else:
                    # Multiple operations for same namespace - use OR logic
                    # Example: {FIELD} has_all("Microsoft", "Authorization") and ({FIELD} has_all("elevateAccess", "action") or {FIELD} has_all("roleAssignments", "write"))
                    operation_clauses = []
                    for op_parts in operation_groups:
                        operation_str = '", "'.join(op_parts)
                        operation_clauses.append(f'{{FIELD}} has_all("{operation_str}")')

                    operations_or = ' or '.join(operation_clauses)
                    clause = f'{{FIELD}} has_all("{namespace_str}") and ({operations_or})'
                    indicator_clauses.append(clause)

        # Handle regular has_any/contains indicators
        if has_any_indicators:
            # Use 'contains' for single value, 'has_any' for multiple
            if len(has_any_indicators) == 1:
                indicator_clauses.append(f'contains "{has_any_indicators[0]}"')
            else:
                any_str = '", "'.join(has_any_indicators)
                indicator_clauses.append(f'has_any("{any_str}")')

        # Only generate query if there are indicators
        if not indicator_clauses:
            # Skip silently - this is expected for some table/indicator combinations
            continue

        # Build conditions with dual field checks where appropriate
        # For command-line fields, check both ProcessCommandLine and InitiatingProcessCommandLine together
        if "ProcessCommandLine" in fields and "InitiatingProcessCommandLine" in fields:
            # Group both command-line fields for each clause
            dual_conditions = []
            for clause in indicator_clauses:
                # Check if clause contains {FIELD} placeholder (Azure operations)
                if "{FIELD}" in clause:
                    # Replace placeholder with field names
                    proc_clause = clause.replace("{FIELD}", "ProcessCommandLine")
                    init_proc_clause = clause.replace("{FIELD}", "InitiatingProcessCommandLine")
                    dual_conditions.append(f"({proc_clause} or {init_proc_clause})")
                else:
                    # Standard clause without placeholder
                    dual_conditions.append(f"(ProcessCommandLine {clause} or InitiatingProcessCommandLine {clause})")

            # Handle AdditionalFields if present in DeviceEvents
            if "AdditionalFields" in fields:
                for clause in indicator_clauses:
                    if "{FIELD}" in clause:
                        additional_clause = clause.replace("{FIELD}", "AdditionalFields")
                        dual_conditions.append(additional_clause)
                    else:
                        dual_conditions.append(f"AdditionalFields {clause}")
            condition = " or ".join(dual_conditions)
        else:
            # Standard condition for non-command-line fields
            formatted_conditions = []
            for field in fields:
                for clause in indicator_clauses:
                    if "{FIELD}" in clause:
                        # Replace placeholder with actual field name
                        formatted_conditions.append(clause.replace("{FIELD}", field))
                    else:
                        formatted_conditions.append(f"{field} {clause}")
            condition = " or ".join(formatted_conditions)

        # Add malware family name as comment if enrichment occurred
        query = f"{table}\n| where Timestamp > ago(1d)\n| where {condition}"
        if ioc_metadata and ioc_metadata.get("malware_family_names"):
            malware_names_str = ", ".join(ioc_metadata["malware_family_names"])
            query += f" // {malware_names_str}"

        mde_queries.append(query)

    return mde_queries


def compile_splunk_queries(
    indicator_mapping, indicators, indicator_type, splunk_queries, osint_indicators=None, detection_name="", platform=None, technique_id=None
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
        platform: Optional platform name for validation (e.g., "Windows", "Azure AD", "AWS")
        technique_id: Optional technique ID for validation (e.g., "T1136", "T1003.001")

    Returns:
        Updated splunk_queries list
    """
    # Enrich indicators with malware IOCs before building queries (with platform awareness)
    enriched_indicators, ioc_metadata = enrich_indicators_with_iocs(
        indicators,
        indicator_type,
        platform=platform,
        technique_id=technique_id
    )

    # Log enrichment if any occurred
    if ioc_metadata and ioc_metadata.get("enriched_iocs"):
        log_ioc_enrichment(detection_name or "Splunk Detection", ioc_metadata)

    # Use enriched indicators for query building
    indicators_to_use = enriched_indicators if enriched_indicators else indicators

    # Validate and clean indicators to remove description text, duplicates, and generic terms
    indicators_to_use = validate_and_clean_indicators(indicators_to_use, indicator_type)

    # Detect cloud platform from indicators (for API calls, commands, etc.)
    detected_platforms = detect_cloud_platform_from_indicators(indicators_to_use, indicator_type)

    # Get valid indices based on platform filtering
    splunk_mapping = indicator_mapping[indicator_type].get("Splunk", {})
    valid_indices = get_valid_indices_for_platform(
        splunk_mapping,
        "Splunk",
        detected_platforms,
        platform,
        indicator_type
    )

    # Get transformation pipeline from schema
    transformation_pipeline = SPLUNK_SCHEMA.get(indicator_type, {})

    # Build queries for each valid index
    for index, fields in valid_indices.items():
        # Get the transformation pipeline for this index
        pipeline = transformation_pipeline.get(index, "")

        if not pipeline:
            # Fallback if no pipeline found - skip this query silently
            # (This is expected for indexes not configured for this indicator type)
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
                # Skip this field silently (this is expected for some index/field combinations)
                pass

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
            # Skip silently - this is expected when no valid field mappings exist
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
    # Special case: Cloud-native log sources (CloudTrail, Azure Activity Log, GCP Audit)
    # These should ALWAYS be applicable when their cloud platform is involved
    # They log API calls that happen regardless of the underlying OS (Windows/Linux/macOS)
    cloud_native_indices = {
        "aws_cloudtrail": "AWS",
        "aws_guardduty": "AWS",
        "aws_waf": "AWS",
        "aws_directory": "AWS",
        "azure_activity": "Azure",
        "azure_signin": "Azure AD",
        "gcp_audit": "GCP"
    }

    if index_name in cloud_native_indices:
        # Cloud-native logs are always applicable - they capture cloud API activity
        # regardless of the OS platform of the MITRE technique
        return True

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
