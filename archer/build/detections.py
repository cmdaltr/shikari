from .yaml import construct_yaml
from .queries import get_platforms_for_index
from archer.mitre.enterprise import (
    get_stix_data,
    obtain_all_techniques,
    obtain_technique_descriptions,
)
from archer.mitre.retrieve import retrieve_procedures
import os
from pathlib import Path


def filter_generic_indicators(identifiers):
    """
    Filter out overly generic terms from indicators.
    Returns filtered identifiers dict and True if any real indicators remain.

    Generic terms that are too common to be useful indicators:
    - condition, value, data, file, process, command, user, system, event, log, etc.

    Args:
        identifiers: Dict with indicator types as keys (cmd, reg, file, etc.)

    Returns:
        Tuple of (filtered_identifiers, has_real_indicators)
    """
    generic_terms = {
        'condition', 'conditions', 'value', 'values', 'data', 'file', 'files',
        'process', 'processes', 'command', 'commands', 'user', 'users',
        'system', 'event', 'events', 'log', 'logs', 'entry', 'entries',
        'action', 'actions', 'type', 'types', 'name', 'names', 'path',
        'paths', 'string', 'strings', 'text', 'info', 'information'
    }

    filtered_identifiers = {}
    has_real_indicators = False

    for indicator_type, indicator_list in identifiers.items():
        filtered_list = []
        for indicator in indicator_list:
            indicator_str = str(indicator).strip().lower()

            # Skip if too short
            if len(indicator_str) < 3:
                continue

            # Skip if it's a generic term
            if indicator_str in generic_terms:
                continue

            # This is a real indicator
            filtered_list.append(indicator)
            has_real_indicators = True

        if filtered_list:
            filtered_identifiers[indicator_type] = filtered_list

    return filtered_identifiers, has_real_indicators


def load_indicator_mappings():
    """Load indicator mappings from JSON files in the mappings directory"""
    import os
    import json
    import sys

    # Use bespoke mappings directory (org-specific)
    mappings_dir = (
        Path(os.path.dirname(__file__)) / ".." / ".." / "bespoke" / "mappings"
    )  # bespoke/mappings

    # Check for user-specific mappings first (not committed to GitHub)
    user_mapping_file = mappings_dir / "indicatorMapping.json"
    sample_mapping_file = mappings_dir / "indicatorMapping_sample.json"

    # Check if directory exists
    if not mappings_dir.exists():
        print(
            f"CRITICAL ERROR: Mappings directory does not exist: {mappings_dir.resolve()}"
        )
        print("Please create the mappings directory and add your JSON mapping files.")
        sys.exit(1)

    # Load JSON files in order of preference
    mappings = {}

    # Try to load user-specific mappings first
    if user_mapping_file.exists():
        try:
            with open(user_mapping_file, "r") as f:
                mappings = json.load(f)
            print(f"Using custom mappings from: {user_mapping_file}")
        except json.JSONDecodeError as e:
            print(f"ERROR: Could not parse {user_mapping_file}: {e}")
            print("Falling back to sample mappings...")

    # If no user mappings or they failed to load, try sample mappings
    if not mappings and sample_mapping_file.exists():
        try:
            with open(sample_mapping_file, "r") as f:
                mappings = json.load(f)
            print(f"Using sample mappings from: {sample_mapping_file}")
        except json.JSONDecodeError as e:
            print(f"ERROR: Could not parse {sample_mapping_file}: {e}")

    # If we still don't have mappings, try other JSON files in the directory
    if not mappings:
        json_files = list(mappings_dir.glob("*.json"))
        if not json_files:
            print(f"CRITICAL ERROR: No JSON files found in: {mappings_dir.resolve()}")
            print("Please add JSON mapping files to the mappings directory.")
            sys.exit(1)

        # Load each JSON file in the mappings directory
        for mapping_file in json_files:
            try:
                with open(mapping_file, "r") as f:
                    mapping_data = json.load(f)
                    mappings.update(mapping_data)
            except json.JSONDecodeError as e:
                print(f"WARNING: Could not parse {mapping_file}: {e}")

    # Make sure we have the expected indicator types
    required_types = ["cmd", "reg", "evt", "sw", "port", "protocol", "service", "api", "network"]
    missing_types = [t for t in required_types if t not in mappings]
    if missing_types:
        print(
            f"CRITICAL ERROR: Missing required indicator types in mappings: {', '.join(missing_types)}"
        )
        print(f"Please ensure your mapping files include all required indicator types.")
        sys.exit(1)

    return mappings


def create_indicatorMappings():
    """Create default mappings if none are found"""
    print("Creating default mappings")
    indicatorMappings = {
        "cmd": {
            "Splunk": {
                "index=windows_events": [
                    "properties.command",
                    "properties.CommandLine",
                    "properties.Process_CommandLine",
                ],
                "index=linux_syslog": ["properties.command", "properties.cmdline"],
                "index=aws_cloudtrail": [
                    "properties.command",
                    "properties.commandline",
                ],
                "index=aws_directoryservicead": ["properties.command"],
            },
            "MDE": {
                "DeviceProcessEvents": ["ProcessCommandLine"],
                "DeviceEvents": ["AdditionalFields"],
            },
        },
        "reg": {
            "Splunk": {
                "index=windows_events": [
                    "properties.TargetObject",
                    "properties.Registry_Key_Path",
                ]
            },
            "MDE": {"DeviceRegistryEvents": ["RegistryKey", "RegistryValueData"]},
        },
        "evt": {
            "Splunk": {
                "index=windows_events": ["properties.event_id", "properties.EventID"]
            },
            "MDE": {"DeviceEvents": ["ActionType"]},
        },
        "sw": {
            "Splunk": {
                "index=windows_events": [
                    "properties.Image",
                    "properties.process_path",
                    "properties.process_name",
                    "properties.ParentImage",
                ],
                "index=linux_syslog": ["properties.process", "properties.process_name"],
                "index=aws_cloudtrail": ["properties.service", "properties.process"],
            },
            "MDE": {
                "DeviceProcessEvents": [
                    "FileName",
                    "ProcessVersionInfoProductName",
                    "ProcessVersionInfoCompanyName",
                ],
                "DeviceFileEvents": ["FileName"],
            },
        },
    }
    return indicatorMappings


def compile_query(retrieved_data, osint_enhancement=False, osint_comparison=False, excluded_vendors=None):
    from archer.build.queries import is_query_applicable
    from archer.build.platform_validator_v2 import validate_procedure_for_index
    from archer.build.platform_indicator_validator import (
        validate_indicators_for_platform,
        normalize_platform_name,
        validate_detection_before_generation
    )
    from archer.build.osint_comparison import filter_osint_indicators_by_relevance

    # Load indicator mappings
    indicator_mappings = load_indicator_mappings()

    name = retrieved_data.get("technique")
    tid = retrieved_data.get("technique_id")
    tdesc = retrieved_data.get("activity_desc")
    tactic = retrieved_data.get("tactic")
    tag = retrieved_data.get("group_name")
    op_guidance = retrieved_data.get("op_guidance", {})
    red_tool = retrieved_data.get("red_tool", {})
    log_sources = retrieved_data.get("detect_guidance", [])

    # Get procedure text and technique metadata for enhanced platform validation
    procedure_text = retrieved_data.get("procedure", "") or tdesc or ""
    technique_description = retrieved_data.get("technique_description", "") or tdesc or ""
    technique_platforms = retrieved_data.get("technique_platforms", [])

    # Get all identifiers
    if isinstance(op_guidance, dict) and isinstance(red_tool, dict):
        identifiers = {**op_guidance, **red_tool}
    elif isinstance(op_guidance, dict):
        identifiers = op_guidance
    elif isinstance(red_tool, dict):
        identifiers = red_tool
    else:
        identifiers = {}

    print(f"  - Final identifiers count: {len(identifiers)}")

    # Filter out generic terms from identifiers
    filtered_identifiers, has_real_indicators = filter_generic_indicators(identifiers)

    if not has_real_indicators and identifiers:
        print(f" ⚠️  All indicators are generic terms (e.g., 'condition', 'value', 'data')")
        identifiers = {}  # Clear identifiers to trigger OSINT path
    else:
        identifiers = filtered_identifiers  # Use filtered identifiers

    # Extract platform information if available
    procedure_platforms = retrieved_data.get("procedure_platforms", [])
    software_platforms = retrieved_data.get("software_platforms", {})

    # OSINT comparison data (will be populated if indicators exist or if no indicators)
    osint_enhancement_data = None

    # Only construct YAML if there are identifiers for detection
    if identifiers:
        # Run OSINT search if either comparison OR enrichment is enabled
        if osint_comparison or osint_enhancement:
            print(f" 📊 Indicators found - comparing with OSINT sources...")

            from archer.build.osint_comparison import search_osint_for_technique

            osint_found, osint_data = search_osint_for_technique(
                technique_id=tid,
                technique_name=name,
                technique_description=technique_description,
                platforms=technique_platforms
            )

            if osint_found:
                print(f" ✅ OSINT comparison successful - additional detection patterns found")
                osint_enhancement_data = osint_data
        else:
            # Skip OSINT comparison
            osint_found = False
            osint_data = None

        if osint_enhancement_data:

            # Only merge OSINT indicators if enhancement is enabled
            if osint_enhancement:
                print(f" 🔧 OSINT Enhancement ENABLED - merging indicators from OSINT sources")

                # Extract indicators from OSINT query snippets
                osint_indicators_raw = osint_data.get("osint_indicators", {})
                query_snippets = osint_indicators_raw.get("query_snippets", [])

                # Extract operation names and other searchable values from query snippets
                # Note: Splunk-to-KQL field translation and filtering is now handled by
                # osint_query_enhancer.py during query enhancement, so we just extract
                # indicator values here
                extracted_operations = []
                extracted_commands = []

                import re
                for snippet in query_snippets:
                    # Extract from snippet (format: [Source] query|||url)
                    if isinstance(snippet, str) and '|||' in snippet:
                        query_part = snippet.split('|||')[0]

                        # Extract Operation/operationName values
                        # Pattern: Operation IN ("value1", "value2") or operationName="value"
                        op_patterns = [
                            r'[Oo]peration(?:Name)?\s+IN\s*\(["\']([^"\']+)["\'](?:\s*,\s*["\']([^"\']+)["\'])*\)',
                            r'[Oo]peration(?:Name)?\s*[=:]\s*["\']([^"\']+)["\']',
                        ]

                        for pattern in op_patterns:
                            matches = re.findall(pattern, query_part)
                            for match in matches:
                                if isinstance(match, tuple):
                                    extracted_operations.extend([m for m in match if m])
                                else:
                                    extracted_operations.append(match)

                # Add extracted operations to identifiers
                if extracted_operations:
                    # Remove duplicates and clean up
                    extracted_operations = list(set([op.strip().rstrip('.') for op in extracted_operations if op]))

                    if 'operation' not in identifiers:
                        identifiers['operation'] = []

                    identifiers['operation'].extend(extracted_operations)
                    identifiers['operation'] = list(set(identifiers['operation']))  # Remove duplicates

                    print(f" 📊 Extracted {len(extracted_operations)} operation(s) from OSINT queries: {extracted_operations[:5]}")

                print(f" 📈 Enhanced indicator count: {sum(len(v) if isinstance(v, list) else 1 for v in identifiers.values())}")
            else:
                print(f" ℹ️  OSINT Enhancement DISABLED - OSINT data will be included as reference only (not merged into queries)")
        else:
            print(f" ℹ️  No additional OSINT patterns found")

        compatible_found = False
        yaml_files_created = False

        name_clean = name.replace(" ", "").replace("/", "")
        existing_yamls = []
        if os.path.exists("data/groups"):
            for fname in os.listdir("data/groups"):
                if fname.startswith(name_clean) and fname.endswith(".yaml"):
                    existing_yamls.append(fname)

        if existing_yamls:
            yaml_files_created = True

        # Collect all compatible tables/indices (deduplicated)
        compatible_sources = set()

        # Check each indicator type
        for indicator_type in identifiers:
            if indicator_type not in indicator_mappings:
                continue

            indicators = identifiers[indicator_type]
            if not indicators:
                continue

            # Combine all indicator values into text for validation
            if isinstance(indicators, list):
                indicator_text = " ".join(str(i) for i in indicators)
            elif isinstance(indicators, dict):
                indicator_text = " ".join(str(v) for v in indicators.values())
            else:
                indicator_text = str(indicators)


            # SPLUNK
            if "Splunk" in indicator_mappings[indicator_type]:
                for index_name in indicator_mappings[indicator_type]["Splunk"]:
                    clean_index_name = index_name.replace("index=", "")

                    # Check technique-level platform compatibility
                    is_compatible = is_query_applicable(
                        procedure_platforms, software_platforms, clean_index_name
                    )

                    # NEW: Validate indicators using platform-indicator validator
                    platform = normalize_platform_name(clean_index_name)
                    indicator_dict = {indicator_type: indicators if isinstance(indicators, list) else [indicators]}

                    should_generate, validation_error, filtered_indicators_dict = validate_detection_before_generation(
                        technique_id=tid,
                        platform=platform,
                        data_source=clean_index_name,
                        indicators=indicator_dict,
                        strict_mode=False  # Allow with warnings
                    )

                    if not should_generate:
                        indicator_compatible = False
                    else:
                        # Use filtered indicators (invalid ones removed)
                        if filtered_indicators_dict and indicator_type in filtered_indicators_dict:
                            filtered_count = len(filtered_indicators_dict[indicator_type])
                            original_count = len(indicators) if isinstance(indicators, list) else 1
                            if filtered_count < original_count:
                                print(f"     ℹ️  Filtered {original_count - filtered_count} invalid indicators for {platform}")

                        # Check indicator-level platform compatibility (enhanced v2)
                        # ONLY validate actual indicators, NOT procedure text (which has URLs and generic descriptions)
                        indicator_compatible = validate_procedure_for_index(
                            indicator_text,  # CHANGED: Only validate actual indicators
                            clean_index_name,
                            vendor="Splunk",
                            technique_desc=technique_description,
                            technique_platforms=technique_platforms
                        )

                    if is_compatible and indicator_compatible:
                        compatible_sources.add(index_name)
                    elif is_compatible and not indicator_compatible:
                        print(f"  ⚠️  Skipped {index_name}: Indicator incompatible with platform")

            # MDE
            if "MDE" in indicator_mappings[indicator_type]:
                for table_name in indicator_mappings[indicator_type]["MDE"]:
                    # Check technique-level platform compatibility
                    is_compatible = is_query_applicable(
                        procedure_platforms, software_platforms, table_name
                    )

                    # Check indicator-level platform compatibility (enhanced v2)
                    # ONLY validate actual indicators, NOT procedure text (which has URLs and generic descriptions)
                    indicator_compatible = validate_procedure_for_index(
                        indicator_text,  # CHANGED: Only validate actual indicators
                        table_name,
                        vendor="MDE",
                        technique_desc=technique_description,
                        technique_platforms=technique_platforms
                    )

                    if is_compatible and indicator_compatible:
                        compatible_sources.add(table_name)
                    elif is_compatible and not indicator_compatible:
                        print(f"  ⚠️  Skipped {table_name}: Indicator incompatible with platform")

        # Print grouped output and create YAMLs
        if compatible_sources:
            compatible_found = True
            print(f" Queries built for {name} ({tid}) on:")
            for source in sorted(compatible_sources):
                print(f"  ✅ {source}")
                construct_yaml(
                    name,
                    tid,
                    tdesc,
                    tactic,
                    tag,
                    identifiers,
                    log_sources,
                    source,
                    procedure_platforms,
                    software_platforms,
                    osint_enhancement_data=osint_enhancement_data,  # Pass OSINT comparison data
                    osint_enhancement=osint_enhancement,  # Pass OSINT comparison flag
                    excluded_vendors=excluded_vendors,  # Pass excluded vendors list
                )
            print()  # Empty line after technique

        # Print summary for this technique
        if not compatible_found:
            if yaml_files_created:
                print(f" ❌ No more compatible platforms found for {name}\n")
            else:
                print(f" ❌ No identifiers found for {name}; no detections generated\n")
    else:
        # No identifiers from MITRE - try OSINT search if either comparison or enrichment is enabled
        print(f" ⚠️  No identifiers found for {name} from MITRE ATT&CK data")

        if osint_comparison or osint_enhancement:
            from archer.build.osint_comparison import search_osint_for_technique, should_create_detection

            # Search OSINT sources
            osint_found, osint_data = search_osint_for_technique(
                technique_id=tid,
                technique_name=name,
                technique_description=technique_description,
                platforms=technique_platforms
            )
        else:
            # Both OSINT features disabled
            print(f" ℹ️  OSINT Comparison and Enrichment disabled - skipping OSINT search")
            osint_found = False
            osint_data = None

        # Determine if we should create the detection
        if osint_found and (osint_comparison or osint_enhancement):
            from archer.build.osint_comparison import should_create_detection
            if should_create_detection(has_mitre_indicators=False, osint_found=osint_found):
                print(f" ✅ OSINT comparison successful - creating detection with OSINT metadata")

                # Create detection with OSINT data as identifiers
                osint_identifiers = osint_data.get("osint_indicators", {})
                if osint_identifiers:
                    print(f" 📝 Creating OSINT-compared detection for {name}")

                    # Use OSINT indicators to create detections
                    # Re-run the platform compatibility checks with OSINT indicators
                    compatible_sources = set()

                    # Check each indicator type from OSINT
                    for indicator_type in osint_identifiers:
                        if indicator_type not in indicator_mappings:
                            continue

                        indicators_list = osint_identifiers[indicator_type]
                        if not indicators_list:
                            continue

                        # Combine indicators into text for validation
                        indicator_text = " ".join(str(i) for i in indicators_list)

                        # Check SPLUNK compatibility
                        if "Splunk" in indicator_mappings[indicator_type]:
                            for index_name in indicator_mappings[indicator_type]["Splunk"]:
                                clean_index_name = index_name.replace("index=", "")

                                is_compatible = is_query_applicable(
                                    procedure_platforms, software_platforms, clean_index_name
                                )

                                indicator_compatible = validate_procedure_for_index(
                                    indicator_text,
                                    clean_index_name,
                                    vendor="Splunk",
                                    technique_desc=technique_description,
                                    technique_platforms=technique_platforms
                                )

                                if is_compatible and indicator_compatible:
                                    compatible_sources.add(index_name)

                        # Check MDE compatibility
                        if "MDE" in indicator_mappings[indicator_type]:
                            for table_name in indicator_mappings[indicator_type]["MDE"]:
                                is_compatible = is_query_applicable(
                                    procedure_platforms, software_platforms, table_name
                                )

                                indicator_compatible = validate_procedure_for_index(
                                    indicator_text,
                                    table_name,
                                    vendor="MDE",
                                    technique_desc=technique_description,
                                    technique_platforms=technique_platforms
                                )

                                if is_compatible and indicator_compatible:
                                    compatible_sources.add(table_name)

                    # Create YAMLs for compatible sources
                    if compatible_sources:
                        print(f" ✅ OSINT-compared queries built for {name} ({tid}) on:")
                        for source in sorted(compatible_sources):
                            print(f"  ✅ {source}")
                            construct_yaml(
                                name,
                                tid,
                                tdesc,
                                tactic,
                                tag,
                                osint_identifiers,
                                log_sources,
                                source,
                                procedure_platforms,
                                software_platforms,
                                osint_enhancement_data=osint_data,  # Pass OSINT metadata
                                osint_enhancement=osint_enhancement,  # Pass OSINT comparison flag
                                excluded_vendors=excluded_vendors,  # Pass excluded vendors list
                            )
                        print()
                    else:
                        print(f" ⚠️  No compatible platforms found for OSINT indicators")
                else:
                    # No actual indicators but OSINT found relevant information
                    print(f" 📝 OSINT found relevant information but no specific indicators")
                    print(f" ⚠️  Detection creation skipped - manual review required")
            else:
                print(f" ❌ OSINT data found but not sufficient for detection creation\n")
        elif not osint_comparison:
            print(f" ❌ No OSINT data available (OSINT Comparison disabled); detection NOT created\n")
        else:
            print(f" ❌ No OSINT sources found for {name}; detection NOT created\n")


def main():
    # Load MITRE enterprise ATT&CK bundle
    bundle = get_stix_data(
        "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"
    )

    # Get all techniques
    techniques = obtain_all_techniques(bundle)

    # Process each technique
    for technique in techniques:
        # Find procedures for the technique
        procedures = retrieve_procedures(bundle, [technique])
        for procedure in procedures:
            compile_query(procedure)


def is_query_applicable(procedure_platforms, software_platforms, index_name):
    # Get platforms for this index from mapping
    index_platforms = get_platforms_for_index(index_name)

    # If no mapping, be strict
    if not index_platforms:
        return False

    # If procedure is Windows-only, only allow if index is also Windows
    procedure_is_windows_only = (
        len(procedure_platforms) == 1 and procedure_platforms[0].lower() == "windows"
    )
    index_is_windows = "Windows" in index_platforms

    if procedure_is_windows_only and not index_is_windows:
        return False

    # Otherwise, require at least one overlap
    for platform in procedure_platforms:
        if platform in index_platforms:
            return True

    return False


if __name__ == "__main__":
    main()
