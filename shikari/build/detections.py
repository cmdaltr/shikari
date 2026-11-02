from .yaml import construct_yaml
from .queries import get_platforms_for_index
from .indicator_hygiene import clean_identifier_map
from shikari.mitre.enterprise import (
    get_stix_data,
    obtain_all_techniques,
    obtain_technique_descriptions,
)
from shikari.mitre.retrieve import retrieve_procedures
from shikari.tactic_scope import intel_only
import json
import os
import re
from pathlib import Path
from shikari import paths


ALL_SIEMS = frozenset({"mde", "secops", "elastic", "splunk"})

# Display labels for each SIEM key
_SIEM_LABELS = {
    "mde": "Defender XDR",
    "splunk": "Splunk",
    "elastic": "Elastic",
    "secops": "Google SecOps",
}


def excluded_for(siem_filter):
    """The vendor keys construct_yaml skips for an include-list of SIEMs. It (and the web app) name
    SecOps "googlesecops": excluding "secops" left a SecOps file written whatever the filter said."""
    return sorted("googlesecops" if s == "secops" else s for s in ALL_SIEMS - set(siem_filter))


def _print_preview_queries(name, tid, tactic, mde_queries, splunk_queries,
                           elastic_queries=None, secops_queries=None):
    """Print generated queries to stdout for dry-run / preview mode."""
    elastic_queries = elastic_queries or []
    secops_queries = secops_queries or []

    sep = "─" * 60
    total = len(mde_queries) + len(splunk_queries) + len(elastic_queries) + len(secops_queries)
    parts = []
    if mde_queries:
        parts.append(f"{len(mde_queries)} MDE")
    if splunk_queries:
        parts.append(f"{len(splunk_queries)} Splunk")
    if elastic_queries:
        parts.append(f"{len(elastic_queries)} Elastic")
    if secops_queries:
        parts.append(f"{len(secops_queries)} SecOps")

    print(f"\n{sep}")
    print(f"  Technique : {name} ({tid})")
    print(f"  Tactic    : {tactic}")
    print(f"  Queries   : {total}" + (f" ({', '.join(parts)})" if parts else ""))
    print(sep)

    for i, q in enumerate(mde_queries, 1):
        print(f"\n  [MDE {i}]\n")
        for line in q.strip().splitlines():
            print(f"    {line}")

    for i, q in enumerate(splunk_queries, 1):
        print(f"\n  [Splunk {i}]\n")
        for line in q.strip().splitlines():
            print(f"    {line}")

    for i, q in enumerate(elastic_queries, 1):
        print(f"\n  [Elastic {i}]\n")
        for line in q.strip().splitlines():
            print(f"    {line}")

    for i, q in enumerate(secops_queries, 1):
        print(f"\n  [Google SecOps {i}]\n")
        for line in q.strip().splitlines():
            print(f"    {line}")

    if total == 0:
        print("  (no queries generated — indicators present but no compatible sources)")
    print()


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

    # Prose and markup captured by extraction (citations, sentences, HTML entities)
    identifiers = clean_identifier_map(identifiers)

    for indicator_type, indicator_list in identifiers.items():
        filtered_list = []
        for indicator in indicator_list:
            indicator_str = str(indicator).strip().lower()

            # Skip if too short (ports such as 22 are short but real)
            if len(indicator_str) < 3 and not indicator_str.isdigit():
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


class MappingsError(RuntimeError):
    """Indicator mappings are missing or incomplete; generation cannot proceed."""


def load_indicator_mappings():
    """Load indicator mappings from JSON files in the mappings directory"""
    import os
    import json

    # Use bespoke mappings directory (org-specific)
    mappings_dir = (
        paths.BESPOKE / "mappings"
    )  # bespoke/mappings

    # Check for user-specific mappings first (not committed to GitHub)
    user_mapping_file = mappings_dir / "indicatorMapping.json"
    sample_mapping_file = mappings_dir / "indicatorMapping_sample.json"

    # Check if directory exists
    if not mappings_dir.exists():
        print(f"Mappings directory does not exist: {mappings_dir.resolve()}")
        raise MappingsError(
            "Indicator mappings directory bespoke/mappings/ does not exist. "
            "Restore your organisation's mapping set into bespoke/mappings/ (see bespoke/README.md)."
        )

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
            print(f"No indicator mapping files found in {mappings_dir.resolve()}")
            raise MappingsError(
                "No indicator mapping files found in bespoke/mappings/. "
                "Restore your organisation's mapping set there (see bespoke/README.md)."
            )

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
        raise MappingsError(
            f"Indicator mappings are missing required types: {', '.join(missing_types)}. "
            "Add them to bespoke/mappings/indicatorMapping.json."
        )

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
        "api_event": {
            # Windows API calls Defender XDR records as ActionTypes (WriteProcessMemoryApiCall...)
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


def lol_enrichment(identifiers, tid, procedure_text, enabled=True):
    """
    LOLBAS / LOLRMM / LOLDrivers: what they document about the tools this technique's
    indicators and procedure already name (lol.py). The LOL datasets option; may give a
    technique with no indicators its first ones, from a tool the group is seen using.
    Returns (identifiers, references), leaving the caller's dict as it was.
    """
    if not enabled:
        return identifiers, []
    from shikari.build import lol

    added, refs = lol.enrich(identifiers, tid, procedure_text)
    identifiers = dict(identifiers)
    for kind, values in added.items():
        identifiers[kind] = list(identifiers.get(kind, [])) + values
    if refs:
        print(f" 🧰 LOL datasets: {', '.join(r['source'] + ' ' + r['name'] for r in refs)}"
              f" (+{sum(len(v) for v in added.values())} indicator(s))")
    return identifiers, refs


def compile_query(retrieved_data, osint_enhancement=False, osint_comparison=False, lol_datasets=True, excluded_vendors=None, use_llm=False, llm_config=None, dry_run=False, siem_filter=None, index_filter=None):
    from shikari.build.queries import is_query_applicable
    from shikari.build.platform_validator_v2 import validate_procedure_for_index
    from shikari.build.platform_indicator_validator import (
        validate_indicators_for_platform,
        normalize_platform_name,
        validate_detection_before_generation
    )
    from shikari.build.osint_comparison import filter_osint_indicators_by_relevance

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

    # Derive excluded_vendors from siem_filter if provided (include-list → exclude-list)
    if siem_filter is not None:
        excluded_vendors = excluded_for(siem_filter)

    # Dry-run: print raw queries without file I/O and return early
    if dry_run:
        from shikari.build.collate import collate_data

        active_siems = siem_filter if siem_filter else ALL_SIEMS

        if identifiers:
            raw_mde, raw_splunk = collate_data(
                identifiers, log_sources or [], procedure_platforms, software_platforms, name, technique_id=tid
            )

            mde_queries = raw_mde if "mde" in active_siems else []
            # As construct_yaml writes them: conditions that can't mean anything removed
            from shikari.validation.precision import prune_kql
            mde_queries = [q for q in (prune_kql(q)[0] for q in mde_queries) if q]
            splunk_queries = raw_splunk if "splunk" in active_siems else []

            # Elastic preview
            elastic_queries = []
            if "elastic" in active_siems:
                try:
                    from shikari.build.elastic import ElasticQueryGenerator
                    eg = ElasticQueryGenerator()
                    result = eg.generate_query(
                        technique_id=tid, technique_name=name, tactic=tactic,
                        description=tdesc, indicators=identifiers, group_name=tag
                    )
                    if result and result.get("query"):
                        valid, _ = eg.validate_query(result["query"])
                        if valid:
                            elastic_queries = [eg.format_query_for_display(result["query"])]
                except Exception as e:
                    print(f"  ⚠️  Elastic preview failed: {e}")

            # Google SecOps preview
            secops_queries = []
            if "secops" in active_siems:
                try:
                    from shikari.build.secops import SecOpsGenerator
                    cg = SecOpsGenerator()
                    result = cg.generate_query(
                        technique_id=tid, technique_name=name, tactic=tactic,
                        description=tdesc, indicators=identifiers, group_name=tag
                    )
                    if result and result.get("query"):
                        secops_queries = [result["query"]]
                except Exception as e:
                    print(f"  ⚠️  Google SecOps preview failed: {e}")

            # Apply index/table filter across all SIEMs.
            # Splunk: matches "index=<name>" in query body.
            # MDE:    matches table name on the first line of the query.
            # Elastic/SecOps: substring match anywhere in the query text.
            if index_filter:
                def _matches_index(q: str) -> bool:
                    ql = q.lower()
                    return any(p.lower() in ql for p in index_filter)

                mde_queries     = [q for q in mde_queries     if _matches_index(q)]
                splunk_queries  = [q for q in splunk_queries  if _matches_index(q)]
                elastic_queries = [q for q in elastic_queries if _matches_index(q)]
                secops_queries  = [q for q in secops_queries  if _matches_index(q)]

            _print_preview_queries(name, tid, tactic, mde_queries, splunk_queries,
                                   elastic_queries, secops_queries)
        else:
            print(f"  [{tid}] {name} — no indicators extracted, no queries to preview")
        return

    identifiers, lol_refs = lol_enrichment(identifiers, tid, procedure_text, enabled=lol_datasets)
    known_fps = []
    if osint_comparison or osint_enhancement:
        from shikari.build.osint_index import known_false_positives
        known_fps = known_false_positives(tid, terms=list(identifiers.get("sw", [])))

    # OSINT comparison data (will be populated if indicators exist or if no indicators)
    osint_enhancement_data = None
    # Why nothing was built, if nothing is (technique_yield.REASONS); returned to the orchestrator
    reason = "no_source" if identifiers else "no_indicators"

    # Only construct YAML if there are identifiers for detection
    if identifiers:
        # Run OSINT search if either comparison OR enrichment is enabled
        if osint_comparison or osint_enhancement:
            print(f" 📊 Indicators found - comparing with OSINT sources...")

            from shikari.build.osint_comparison import search_osint_for_technique

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

        if lol_refs or known_fps:
            osint_enhancement_data = dict(osint_enhancement_data or {})
            if lol_refs:
                osint_enhancement_data["lol_references"] = lol_refs
            if known_fps:
                osint_enhancement_data["known_false_positives"] = known_fps

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
            from shikari.build.osint_comparison import search_osint_for_technique, should_create_detection
            reason = "osint_empty"

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
            from shikari.build.osint_comparison import should_create_detection
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

    # -----------------------------------------------------------------
    # Bespoke query generation (Mode 1: LLM / Mode 2: Fallback)
    # Runs after the standard pipeline, using MITRESaw evidence data
    # -----------------------------------------------------------------
    if use_llm is not None and use_llm is not False:
        reason = _run_bespoke_generation(
            retrieved_data, identifiers, use_llm, llm_config
        ) or reason
    return reason


def _run_bespoke_generation(retrieved_data, identifiers, use_llm, llm_config):
    """Run bespoke query generation (LLM or fallback)."""
    name = retrieved_data.get("technique", "")
    tid = retrieved_data.get("technique_id", "")
    tactic = retrieved_data.get("tactic", "")
    procedure_text = retrieved_data.get("procedure", "") or retrieved_data.get("activity_desc", "")
    technique_platforms = retrieved_data.get("technique_platforms", [])
    group_name = retrieved_data.get("group_name", "")

    # Build evidence JSON from identifiers (MITRESaw format)
    evidence_json = retrieved_data.get("evidence_json", "")
    if not evidence_json and identifiers:
        evidence_json = json.dumps(identifiers)

    detectable_via = retrieved_data.get("detectable_via", "")

    tactics = tactic if isinstance(tactic, (list, tuple)) else re.split(r"[,;|]", tactic or "")
    if use_llm == "llm" and intel_only(tid, [t.strip() for t in tactics]):
        # Adversary-side Reconnaissance/Resource Development: nothing in the indexes sees
        # it, the LLM says so and the call is spent for no queries (shikari.tactic_scope)
        print(f"  ⏭️  {tid} is intel only ({tactic}); no LLM call")
        return "pre_compromise"

    if use_llm == "llm":
        from shikari.build import technique_yield

        empty_runs = technique_yield.llm_exhausted(tid)
        if empty_runs:
            # The AI has come back empty for this technique run after run; the call would
            # spend another prompt for nothing (python -m shikari.build.technique_yield --reset-llm)
            print(f"  ⏭️  {tid}: AI returned no queries on its last {empty_runs} runs; no LLM call")
            return "llm_empty"

    if use_llm == "llm" and llm_config and llm_config.get("max_calls"):
        # A run's LLM spend is capped (profile setting): a group can have hundreds of
        # procedures and every one is a ~29k-token prompt
        llm_config["_calls"] = llm_config.get("_calls", 0) + 1
        if llm_config["_calls"] > llm_config["max_calls"]:
            if llm_config["_calls"] == llm_config["max_calls"] + 1:
                print(f"  ⏹️  LLM call limit for this run reached ({llm_config['max_calls']}); "
                      f"remaining techniques use the standard pipeline only")
            return

    if use_llm == "llm":
        # Mode 1: LLM-powered generation
        from shikari.build.llm_queries import generate_llm_queries
        print(f"  🤖 Generating LLM-powered queries for {tid}"
              f"{' with ' + llm_config['label'] if llm_config and llm_config.get('label') else ''}...")
        queries = generate_llm_queries(
            technique_id=tid,
            technique_name=name,
            tactic=tactic,
            procedure_example=procedure_text,
            evidence_json=evidence_json,
            platforms=technique_platforms,
            detectable_via=detectable_via,
            group_name=group_name,
            use_local=bool((llm_config or {}).get("use_local")),
            config=llm_config,
        )
    else:
        # Mode 2: Fallback template-based generation
        from shikari.build.bespoke_queries import generate_fallback_queries
        print(f"  📋 Generating template-based queries for {tid}...")
        queries = generate_fallback_queries(
            technique_id=tid,
            technique_name=name,
            tactic=tactic,
            evidence_json=evidence_json,
            platforms=technique_platforms,
            detectable_via=detectable_via,
        )

    if use_llm == "llm" and queries is not None:
        from shikari.build import technique_yield

        technique_yield.record_llm(tid, bool(queries))

    if queries:
        # Write bespoke queries to data/groups/ as YAML files
        _write_bespoke_yamls(queries, group_name, tid, name, tactic)
        print(f"  ✅ {len(queries)} bespoke queries generated for {tid}")
    else:
        print(f"  ⚠️  No bespoke queries generated for {tid}")
        if use_llm == "llm":
            return "ai_failed" if queries is None else "ai_none"


def _write_bespoke_yamls(queries, group_name, technique_id, technique_name, tactic):
    """Write bespoke-generated queries to YAML files in data/groups/."""
    import yaml
    import uuid
    from datetime import datetime

    output_dir = Path("data/groups")
    output_dir.mkdir(parents=True, exist_ok=True)

    for q in queries:
        platform = q.get("platform", "Splunk")
        data_source = q.get("data_source", "unknown")
        query_text = q.get("query", "")
        source_label = q.get("source", "bespoke")

        if not query_text:
            continue

        # Build YAML structure matching Shikari's detection format
        detection = {
            "id": str(uuid.uuid4()),
            "name": technique_name,
            "type": "detection",
            "status": "new",
            "date_created": datetime.now().strftime("%Y-%m-%d"),
            "tactics": [tactic] if tactic else [],
            "techniques": [technique_id] if technique_id else [],
            "threat_groups": [group_name] if group_name else [],
            "detection_platforms": [platform],
            "queries": [{
                "id": str(uuid.uuid4()),
                "platform": platform,
                "data_source": data_source,
                "query": query_text,
                "comment": f"Generated via {source_label} mode",
            }],
            "references": [{
                "type": "MITRE",
                "url": f"https://attack.mitre.org/techniques/{technique_id.replace('.', '/')}/",
            }],
        }

        # Write YAML file
        safe_name = re.sub(r"[^a-zA-Z0-9]", "", technique_name)
        safe_source = re.sub(r"[^a-zA-Z0-9_]", "", data_source)
        filename = f"{safe_name}_{safe_source}_bespoke.yaml"
        filepath = output_dir / filename

        # Contract gate (shikari.contract): warn-only unless SHIKARI_CONTRACT_STRICT=1
        try:
            from shikari.contract import gate_query
            allowed, _ = gate_query(query_text, label=filename)
        except Exception as gate_err:
            print(f"  [contract] gate error for {filename}: {gate_err}")
            allowed = True
        if not allowed:
            print(f"  [contract BLOCKED] not written: {filepath}")
            continue

        with open(filepath, "w") as f:
            yaml.dump(detection, f, default_flow_style=False, sort_keys=False)
        from shikari.build import run_files

        run_files.note(str(filepath), group_name)


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
