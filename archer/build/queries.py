import os
import json
import re
from pathlib import Path
from collections import defaultdict
from archer.build.index_platforms import is_cloud_native, platforms_of
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
    schemas_dir = Path(os.path.dirname(__file__)) / ".." / ".." / "bespoke" / "mappings" / "schemas"

    # Try custom mapping file first
    custom_schema_file = schemas_dir / "schemaSplunk_custom.json"
    if custom_schema_file.exists():
        try:
            with open(custom_schema_file, "r") as f:
                return json.load(f)
        except Exception:
            # If custom file fails to load, fall back to default
            pass

    # Fall back to default mapping file
    schema_file = schemas_dir / "schemaSplunk.json"
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
        Path(os.path.dirname(__file__)) / ".." / ".." / "bespoke" / "mappings" / "sources" / "logSourceCategories.json"
    )
    if not categories_file.exists():
        return {}, {}

    try:
        with open(categories_file, "r") as f:
            data = json.load(f)
            return data.get("categories", {}), data.get("cloud_indicator_mappings", {})
    except Exception:
        return {}, {}


LOG_SOURCE_CATEGORIES, CLOUD_INDICATOR_MAPPINGS = load_log_source_categories()

# ATT&CK platforms whose activity cloud-native sources (CloudAppEvents, IdentityLogonEvents,
# CloudTrail…) record. A technique on none of these, with no cloud indicators, gets no
# cloud-native table: Windows API names searched in IdentityLogonEvents can never match.
CLOUD_PLATFORMS = {"AWS", "Azure", "Azure AD", "GCP", "IaaS", "SaaS", "Office 365", "Office Suite",
                   "Identity Provider", "Google Workspace"}


def _cloud_native_sources(vendor):
    """The vendor's tables/indexes logSourceCategories.json files under a cloud_native_* category."""
    return {t for key, cat in LOG_SOURCE_CATEGORIES.items() if key.startswith("cloud_native_")
            for t in (cat or {}).get(vendor, []) or []}


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
    # One platform or all of a procedure's
    platforms = {technique_platform} if isinstance(technique_platform, str) else set(technique_platform or ())
    platforms.discard(None)
    technique_platform = next(iter(platforms & {"AWS", "Azure", "Azure AD", "GCP"}), None) or next(iter(platforms), None)

    # Only "api" indicator type has the nested cloud categorization structure
    # Other types (cmd, reg, evt, sw, network) have flat structures
    has_cloud_categories = (indicator_type == "api" and
                           any(key.startswith("cloud_native_") or key == "endpoint"
                               for key in indicator_mapping_section.keys()))

    if not has_cloud_categories:
        # Flat structure: every source, but (Defender XDR) a cloud-native table only for a cloud
        # technique or cloud indicators. Splunk keeps its rule: cloud indexes always apply
        # (is_query_applicable).
        if vendor != "MDE" or detected_platforms or platforms & CLOUD_PLATFORMS:
            return indicator_mapping_section
        cloud = _cloud_native_sources(vendor)
        return {k: v for k, v in indicator_mapping_section.items() if k.replace("index=", "") not in cloud}

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


def _q(value) -> str:
    """Escape a value for a double-quoted SPL or KQL string literal."""
    return str(value).replace("\\", "\\\\").replace('"', '\\"')


def _kql(value) -> str:
    """A KQL string literal. Verbatim (@"...") when it holds a backslash, so a Windows path
    reads as written instead of doubled escapes (output contract KQL-5)."""
    s = str(value)
    if "\\" in s:
        return '@"' + s.replace('"', '""') + '"'
    return '"' + s.replace('"', '\\"') + '"'


def _kql_list(values) -> str:
    return ", ".join(_kql(v) for v in values)


def _grouped(clause: str) -> str:
    """A clause joined to others with 'or' keeps its own 'and' in brackets (contract LOGIC-andor)."""
    return f"({clause})" if " and " in clause else clause


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
                search_parts.append(f'"{_q(v)}"')
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
                values_str = ', '.join([f'"{_q(v)}"' for v in single_word_values])
                search_parts.append(f'{field_name} IN ({values_str})')
            elif len(single_word_values) == 1:
                search_parts.append(f'{field_name}="{_q(single_word_values[0])}"')

            # Handle multi-word values with wildcards and implicit AND
            # Each multi-word indicator becomes a separate OR group
            for multi_word in multi_word_values:
                words = multi_word.split()
                word_conditions = []
                for i, word in enumerate(words):
                    # Strategic spacing: first word "*word *", middle "* word *", last "* word*"
                    if i == 0:
                        # First word: space after
                        word_conditions.append(f'{field_name}="*{_q(word)} *"')
                    elif i == len(words) - 1:
                        # Last word: space before
                        word_conditions.append(f'{field_name}="* {_q(word)}*"')
                    else:
                        # Middle words: spaces before and after
                        word_conditions.append(f'{field_name}="* {_q(word)} *"')
                # Join with spaces (implicit AND)
                word_clause = ' '.join(word_conditions)
                search_parts.append(f'OR ({word_clause})')

    # Join parts with spaces
    result = ' '.join(search_parts)

    # Clean up: if result starts with "OR ", remove it
    if result.startswith('OR '):
        result = result[3:]

    return result


# Integer columns: a string operator on them ("RemotePort has_all(...)") never means anything
MDE_NUMERIC_COLUMNS = {"RemotePort", "LocalPort", "ProcessId", "InitiatingProcessId", "InitiatingProcessParentId",
                       "FileSize", "InitiatingProcessFileSize", "LogonId", "InitiatingProcessLogonId", "ReportId",
                       "DestinationPort", "SourcePort", "Port", "EventId"}
# An operation path (Microsoft.Authorization/roleAssignments/write), as opposed to a
# file name (mstsc.exe) or a command line with a dot in it
_OPERATION_PATH = re.compile(r"^(?:Microsoft\.[\w.]+/[\w./*-]+|[A-Za-z][\w-]*(?:\.[A-Za-z][\w-]*){2,})$")
# MDE indicator types that only describe the connection: on their own they match all such
# traffic, so they never become a query (SecOps keeps them as rule context)
_CONTEXT_ONLY_TYPES = {"protocol"}


def compile_mde_queries(indicator_mapping, indicators, indicator_type, mde_queries, detection_name="", platform=None):
    if indicator_type in _CONTEXT_ONLY_TYPES:
        return mde_queries
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
            escaped_indicator = str(indicator)  # quoted by _kql when the query is built

            # Detect Azure operations (e.g., Microsoft.Authorization/elevateAccess/action)
            # Pattern: dots or slashes indicating hierarchical operations. A backslash means a
            # Windows path (C:\Windows\System32\sethc.exe), which the split would break into
            # has_all("C:\Windows\System32\sethc") and has_all("exe")
            if _OPERATION_PATH.match(escaped_indicator):
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
            elif " " in escaped_indicator or "\u2026" in escaped_indicator:
                # Split into parts for has_all; a placeholder's gap splits too
                parts = [part.strip() for part in re.split(r"\s+|\u2026", escaped_indicator) if part.strip()]
                has_all_indicators.append(parts)
            else:
                has_any_indicators.append(escaped_indicator)

        # Format indicators
        indicator_clauses = []

        # Handle regular has_all indicators (space-separated)
        for parts in has_all_indicators:
            indicator_clauses.append(f'has_all({_kql_list(parts)})')

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
                namespace_str = _kql_list(namespace_parts)

                if len(operation_groups) == 1:
                    # Single operation for this namespace
                    operation_str = _kql_list(operation_groups[0])
                    clause = f'{{FIELD}} has_all({namespace_str}) and {{FIELD}} has_all({operation_str})'
                    indicator_clauses.append(clause)
                else:
                    # Multiple operations for same namespace - use OR logic
                    # Example: {FIELD} has_all("Microsoft", "Authorization") and ({FIELD} has_all("elevateAccess", "action") or {FIELD} has_all("roleAssignments", "write"))
                    operation_clauses = []
                    for op_parts in operation_groups:
                        operation_str = _kql_list(op_parts)
                        operation_clauses.append(f'{{FIELD}} has_all({operation_str})')

                    operations_or = ' or '.join(operation_clauses)
                    clause = f'{{FIELD}} has_all({namespace_str}) and ({operations_or})'
                    indicator_clauses.append(clause)

        # Handle regular has_any/contains indicators
        if has_any_indicators:
            # Term match like has_any; 'contains' is a substring scan the contract lint rejects (KQL-7)
            if len(has_any_indicators) == 1:
                indicator_clauses.append(f'has {_kql(has_any_indicators[0])}')
            else:
                indicator_clauses.append(f'has_any({_kql_list(has_any_indicators)})')

        # Only generate query if there are indicators
        if not indicator_clauses:
            # Skip silently - this is expected for some table/indicator combinations
            continue

        # Ports and other integer columns compare as numbers; anything else on them is dropped
        numeric = [f for f in fields if f in MDE_NUMERIC_COLUMNS]
        if numeric:
            values = sorted({int(v) for v in indicators_to_use if str(v).strip().isdigit()})
            fields = [f for f in fields if f not in MDE_NUMERIC_COLUMNS]
        else:
            values = []

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
                    dual_conditions.append(f"({_grouped(proc_clause)} or {_grouped(init_proc_clause)})")
                else:
                    # Standard clause without placeholder
                    dual_conditions.append(f"(ProcessCommandLine {clause} or InitiatingProcessCommandLine {clause})")

            # Handle AdditionalFields if present in DeviceEvents
            if "AdditionalFields" in fields:
                for clause in indicator_clauses:
                    if "{FIELD}" in clause:
                        additional_clause = clause.replace("{FIELD}", "AdditionalFields")
                        dual_conditions.append(_grouped(additional_clause))
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
                        formatted_conditions.append(_grouped(clause.replace("{FIELD}", field)))
                    else:
                        formatted_conditions.append(f"{field} {clause}")
            if values:
                in_list = ", ".join(str(v) for v in values)
                formatted_conditions += [f"{f} in ({in_list})" if len(values) > 1 else f"{f} == {values[0]}" for f in numeric]
            if not formatted_conditions:
                continue
            condition = " or ".join(formatted_conditions)

        # Add malware family name as comment if enrichment occurred
        query = f"{table}\n| where Timestamp > ago(1d)\n| where {condition}"
        if ioc_metadata and ioc_metadata.get("malware_family_names"):
            malware_names_str = ", ".join(ioc_metadata["malware_family_names"])
            query += f" // {malware_names_str}"

        mde_queries.append(query)

    return mde_queries


def _is_new_format_pipeline(pipeline: str) -> bool:
    """Return True if the pipeline uses the Detection Generation format (mde_clean or action_lc)."""
    return "`mde_clean`" in pipeline or "action_lc" in pipeline


def _escape_indicator_regex(ind: str) -> str:
    """Escape a raw indicator for use in a regex pattern, replacing spaces with \\s+."""
    ind = ind.strip().strip('"').strip("'")
    # Escape regex metacharacters except *
    esc = re.sub(r'([.+?^${}()\[\]\\|])', r'\\\1', ind)
    # Wildcards → .*
    esc = esc.replace("\\*", ".*")
    # Spaces → \s+ so "az vm list" matches regardless of whitespace variation
    esc = re.sub(r' +', r'\\s+', esc)
    return esc


# Cloud-provider keyword hints used for generating operation labels
_CLOUD_HINTS = [
    (("gcloud", "gsutil"), "GCP"),
    (("az ", "get-az", "new-az", "set-az", "remove-az"), "Azure"),
    (("aws ", "describeinstances", "describevpcs", "describesubnets", "listbuckets",
      "describedbinstances", "describeloadbalancers", "s3 ls", "s3api",
      "ec2 describe", "iam list", "sts get"), "AWS"),
    (("get-vm", "get-azvm", "get-azstorageaccount", "get-azresource",
      "get-azsubscription", "get-azvirtualnetwork"), "Azure"),
]


def _indicator_to_label(ind: str, technique_name: str) -> str:
    """Derive a human-readable operation label from an indicator and technique name."""
    ind_l = ind.lower()
    provider = None
    for hints, prov in _CLOUD_HINTS:
        if any(h in ind_l for h in hints):
            provider = prov
            break

    # Strip cloud/OS qualifier from technique name to get the base concept
    base = technique_name or "Detection"
    for strip_word in ("Cloud ", "Windows ", "Linux ", "macOS ", "Network "):
        base = base.replace(strip_word, "")

    if provider:
        return f"{provider} {base}"

    # Fallback: humanize the indicator itself (first 4 significant words)
    words = re.sub(r'[^a-zA-Z0-9\s]', ' ', ind).split()
    skip = {'the', 'and', 'or', 'for', 'in', 'on', 'at', 'to', 'of', 'a', 'an'}
    words = [w for w in words if len(w) > 1 and w.lower() not in skip]
    return " ".join(w.capitalize() for w in words[:4]) or base


def _build_prefilter(indicators: list) -> str:
    """Build a prefilter keyword group for the base search line.

    Multi-word indicators are AND-split so Splunk can use index-time lookups.
    AWS commands are grouped by service to avoid repeating "aws" for every
    subcommand:

      aws ec2 describe-instances          ─┐
      aws s3api list-buckets              ─┤ → ("aws" AND (
      aws s3api head-bucket               ─┤       ("ec2" AND "describe-instances") OR
      aws rds describe-db-instances       ─┘       ("s3api" AND ("list-buckets" OR "head-bucket")) OR
                                                    ("rds" AND "describe-db-instances")))

    Other multi-word commands:
      "gcloud compute instances list" → ("gcloud" AND "compute" AND "instances" AND "list")
    """
    if not indicators:
        return "*"

    # Separate AWS commands from everything else
    aws_by_service: dict = {}  # service → [subcommand, ...]
    other_keywords = []

    for ind in indicators[:12]:
        ind = ind.strip().strip('"').strip("'")
        if not ind:
            continue
        words = ind.split()
        if len(words) >= 3 and words[0].lower() == "aws":
            service = words[1].lower()
            subcommand = " ".join(words[2:])
            aws_by_service.setdefault(service, []).append(subcommand)
        elif len(words) > 1:
            other_keywords.append("(" + " AND ".join(f'"{_q(w)}"' for w in words) + ")")
        else:
            other_keywords.append(f'"{ind}"' if ind.isidentifier() else ind)

    top_level = []

    # Build grouped AWS clause
    if aws_by_service:
        service_parts = []
        for service, subs in aws_by_service.items():
            if len(subs) == 1:
                service_parts.append(f'("{_q(service)}" AND "{_q(subs[0])}")')
            else:
                sub_or = " OR ".join(f'"{_q(s)}"' for s in subs)
                service_parts.append(f'("{_q(service)}" AND ({sub_or}))')
        inner = " OR ".join(service_parts)
        if len(service_parts) == 1:
            top_level.append(f'("aws" AND {service_parts[0]})')
        else:
            top_level.append(f'("aws" AND ({inner}))')

    top_level.extend(other_keywords)

    if not top_level:
        return "*"
    if len(top_level) == 1:
        return top_level[0]
    # Indent multi-branch expressions for readability
    indent = " " * 5
    joined = f" OR\n{indent}".join(top_level)
    return f"({joined})"


def _build_action_lc_filter(indicators: list) -> str:
    """Build a | where match(action_lc, ...) filter from indicators.

    Spaces in indicators are replaced with \\s+ so the regex handles
    varying whitespace between command tokens.
    """
    if not indicators:
        return ""
    escaped = [_escape_indicator_regex(ind) for ind in indicators if ind.strip()]
    escaped = [e for e in escaped if e]
    if not escaped:
        return ""
    pattern = "|".join(escaped)
    return f'| where match(action_lc,"(?i)({pattern})")'


_AWS_SERVICE_LABELS = {
    "ec2":             "AWS EC2 Discovery",
    "s3api":           "AWS S3 Discovery",
    "s3":              "AWS S3 Discovery",
    "rds":             "AWS RDS Discovery",
    "iam":             "AWS IAM Discovery",
    "sts":             "AWS STS Discovery",
    "lambda":          "AWS Lambda Discovery",
    "cloudformation":  "AWS CloudFormation Discovery",
    "elbv2":           "AWS ELB Discovery",
    "elb":             "AWS ELB Discovery",
    "eks":             "AWS EKS Discovery",
    "ecs":             "AWS ECS Discovery",
    "route53":         "AWS Route53 Discovery",
    "secretsmanager":  "AWS Secrets Manager Discovery",
    "ssm":             "AWS SSM Discovery",
    "cloudtrail":      "AWS CloudTrail Discovery",
}


def _build_operation_eval(indicators: list, detection_name: str) -> str:
    """Build an eval operation=case(...) block.

    AWS commands are grouped by service into a single branch with a combined
    OR regex and a service-specific label (e.g. 'AWS EC2 Discovery',
    'AWS S3 Discovery').  Non-AWS multi-word and single-word indicators each
    get their own branch as before.
    """
    if not indicators:
        op_label = detection_name or "Detected Activity"
        return (
            f'| eval operation="{op_label}"\n'
            f'| where isnotnull(operation)'
        )

    # Partition: aws_by_service → {service: [full_indicator, ...]}
    #            others         → [(escaped_regex, label), ...]
    aws_by_service: dict = {}
    others = []

    for ind in indicators:
        ind = ind.strip().strip('"').strip("'")
        if not ind:
            continue
        words = ind.split()
        if len(words) >= 3 and words[0].lower() == "aws":
            service = words[1].lower()
            aws_by_service.setdefault(service, []).append(ind)
        else:
            esc = _escape_indicator_regex(ind)
            label = _indicator_to_label(ind, detection_name or "Detected Activity")
            others.append((esc, label))

    branches = []

    # One branch per AWS service, regex groups subcommands with |
    for service, inds in aws_by_service.items():
        label = _AWS_SERVICE_LABELS.get(service, f"AWS {service.upper()} Discovery")
        # Build compressed regex: aws\s+{service}\s+(sub1|sub2|sub3)
        # Extract just the subcommand portion of each indicator (words after "aws service")
        subs = []
        for i in inds:
            words = i.split()
            sub = _escape_indicator_regex(" ".join(words[2:])) if len(words) > 2 else _escape_indicator_regex(i)
            subs.append(sub)
        esc_service = re.escape(service)
        if len(subs) == 1:
            combined = f"aws\\s+{esc_service}\\s+{subs[0]}"
        else:
            combined = f"aws\\s+{esc_service}\\s+({'|'.join(subs)})"
        branches.append((combined, label))

    # Cap non-AWS branches so total stays reasonable
    remaining = max(0, 8 - len(branches))
    branches.extend(others[:remaining])

    if not branches:
        return f'| eval operation="{detection_name or "Detected Activity"}"\n| where isnotnull(operation)'

    case_lines = []
    for esc, label in branches:
        case_lines.append(f'    match(action_lc,"(?i)({esc})"),' + f'"{label}"')
    case_lines.append('    true(),"Other"')

    return (
        '| eval operation=case(\n'
        + ',\n'.join(case_lines)
        + ')\n| where operation!="Other"'
    )


def _build_mde_normalization_tail(technique_name: str) -> str:
    """Build the normalization + output tail for MDE Detection Generation format."""
    tname = technique_name or "Detection"
    return (
        '| eval is_benign_cmd=if(match(action_lc,"(?i)(\n'
        '    \\\\config\\\\systemprofile\\\\scriptlaunchcache\\\\\n'
        '    |\\\\bpdq\\\\b|pdq-connect-agent\\.exe\n'
        '    |\\\\bnexthink\\\\b|\\\\programdata\\\\nexthink\\\\\n'
        '    |\\\\bqualys\\\\b|qualysagent|\\\\bcrowdstrike\\\\b|csfalcon\n'
        '    |\\\\bsentinel\\\\b|sentinelagent\n'
        '    |\\\\bdefender\\\\b|msmpeng|senseir\n'
        '    )"),1,0)\n'
        '| where is_benign_cmd=0\n'
        '| eval object=mvappend(FileName, InitiatingProcessFileName, InitiatingProcessParentFileName)\n'
        '| search object!="null"\n'
        '| eval object_lc=mvmap(object, lower(object))\n'
        '| where NOT match(mvjoin(object_lc," "),"(?i)\\\\b(msmpeng|senseir|csfalconservice|elastic-endpoint|sentinelagent)\\.exe\\\\b")\n'
        '| eval time=strftime(_time, "%F %H:%M")\n'
        '| eval resource=coalesce(DeviceName, DeviceId, LocalIP)\n'
        '| eval identity=mvappend(AccountName, InitiatingProcessAccountName)\n'
        '| eval identity=mvfilter(isnotnull(identity) AND identity!="")\n'
        '| eval object=mvfilter(isnotnull(object) AND object!="" AND object!="null")\n'
        '| eval identity=mvdedup(identity)\n'
        '| eval object=mvdedup(object)\n'
        '| stats count values(operation) AS operation values(action) AS action values(object) AS object BY time identity resource\n'
        f'| eval technique="{tname}"\n'
        '| table time technique identity resource operation action object count\n'
        '| sort -time -count'
    )


def _build_windows_normalization_tail(technique_name: str) -> str:
    """Build the normalization + output tail for Windows Event Log Detection Generation format."""
    tname = technique_name or "Detection"
    return (
        '| eval is_benign_cmd=if(match(action_lc,"(?i)(\n'
        '    \\\\bpdq\\\\b|pdq-connect-agent\\.exe\n'
        '    |\\\\bnexthink\\\\b|\\\\programdata\\\\nexthink\\\\\n'
        '    |\\\\bqualys\\\\b|qualysagent|\\\\bcrowdstrike\\\\b|csfalcon\n'
        '    |\\\\bsentinel\\\\b|sentinelagent\n'
        '    |\\\\bdefender\\\\b|msmpeng|senseir\n'
        '    )"),1,0)\n'
        '| where is_benign_cmd=0\n'
        '| eval time=strftime(_time, "%F %H:%M")\n'
        '| eval resource=coalesce(host, ComputerName)\n'
        '| eval identity=mvappend(User, AccountName, SubjectUserName)\n'
        '| eval identity=mvfilter(isnotnull(identity) AND identity!="")\n'
        '| eval object=mvappend(NewProcessName, ProcessName, ParentProcessName, TargetObject)\n'
        '| eval object=mvfilter(isnotnull(object) AND object!="" AND object!="null")\n'
        '| eval identity=mvdedup(identity)\n'
        '| eval object=mvdedup(object)\n'
        '| stats count values(operation) AS operation values(action_lc) AS action values(object) AS object BY time identity resource\n'
        f'| eval technique="{tname}"\n'
        '| table time technique identity resource operation action object count\n'
        '| sort -time -count'
    )


def compile_splunk_queries(
    indicator_mapping, indicators, indicator_type, splunk_queries, osint_indicators=None, detection_name="", platform=None, technique_id=None
):
    """
    Builds Splunk queries with proper structure.

    For MDE/Windows pipelines using the Detection Generation format (mde_clean or action_lc):
      index={index} earliest=-3d@d ({prefilter})
      {pipeline}  (includes NOT exclusions, mde_clean, action normalization)
      | where match(action_lc, ...)
      | eval operation=case(...)
      {normalization + stats/table/sort tail}

    For legacy pipelines (rename properties.* format):
      index={index} earliest=-1d
      {pipeline}
      | search {search_clause}

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

        # ── NEW FORMAT: Detection Generation structure (mde_clean / action_lc pipelines) ──
        if _is_new_format_pipeline(pipeline):
            if not indicators_to_use:
                continue  # Can't build a meaningful filter without indicators

            # Collect all indicators including OSINT
            all_indicators = list(indicators_to_use)
            if osint_indicators:
                for vals in osint_indicators.values():
                    all_indicators.extend(vals)
            all_indicators = validate_and_clean_indicators(all_indicators, indicator_type)

            prefilter = _build_prefilter(all_indicators)
            action_filter = _build_action_lc_filter(all_indicators)
            operation_eval = _build_operation_eval(all_indicators, detection_name)

            # Choose correct normalization tail based on index
            if "microsoft_defender" in index:
                norm_tail = _build_mde_normalization_tail(detection_name)
            else:
                norm_tail = _build_windows_normalization_tail(detection_name)

            parts = [f"index={index} earliest=-3d@d {prefilter}", pipeline]
            if action_filter:
                parts.append(action_filter)
            parts.append(operation_eval)
            parts.append(norm_tail)
            query = "\n".join(parts)

            if ioc_metadata and ioc_metadata.get("malware_family_names"):
                malware_names_str = ", ".join(ioc_metadata["malware_family_names"])
                query += f"\n`/** {malware_names_str} **/`"

            splunk_queries.append(query)
            continue

        # ── LEGACY FORMAT: rename properties.* pipelines ──
        # Extract field names available in the pipeline
        pipeline_fields = extract_field_names_from_pipeline(pipeline)

        # Build field-value pairs for | search clause
        field_value_pairs = {}

        # Add MITRE indicators - validate fields exist in pipeline
        for field in fields:
            matched_field = find_matching_field(field, pipeline_fields)
            if matched_field:
                if matched_field not in field_value_pairs:
                    field_value_pairs[matched_field] = []
                field_value_pairs[matched_field].extend(indicators_to_use)

        # Add OSINT indicators if enhancement enabled
        if osint_indicators:
            for osint_field, osint_values in osint_indicators.items():
                matched_field = find_matching_field(osint_field, pipeline_fields)
                if matched_field:
                    if matched_field not in field_value_pairs:
                        field_value_pairs[matched_field] = []
                    field_value_pairs[matched_field].extend(osint_values)
                else:
                    if osint_field not in field_value_pairs:
                        field_value_pairs[osint_field] = []
                    field_value_pairs[osint_field].extend(osint_values)

        # Compile the search clause
        search_clause = compile_search_clause(field_value_pairs)

        # Only generate query if there are actual indicators in the search clause
        if not search_clause or search_clause.strip() == "":
            continue

        query = f"index={index} earliest=-1d\n{pipeline}\n| search {search_clause}"

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
        Path(os.path.dirname(__file__)) / ".." / ".." / "bespoke" / "mappings" / "sources" / "platforms.json"
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
    # Cloud-native log sources (CloudTrail, Activity Log, Entra ID, GCP audit) log API calls
    # whatever the OS of the technique, so they always apply. Which indexes those are comes
    # from bespoke/mappings/sources/platforms.json (archer.build.index_platforms).
    if is_cloud_native(index_name):
        return True

    serves = platforms_of(index_name)
    # Windows event logs never serve non-Windows procedures
    if serves and "Windows" in serves and not serves & {"Linux", "macOS"}:
        if "Windows" not in procedure_platforms:
            return False

    # Unix logs never serve Windows-only procedures
    if serves and serves & {"Linux", "macOS"} and "Windows" not in serves:
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
