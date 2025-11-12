from archer.build.collate import collate_data
from archer.config import GENERATE_DIR

import getpass
import json
import os
import re
import uuid

# BeautifulSoup and requests only needed for OLD slow additional_tactics function
# This function is replaced by yaml_patch.py, so these imports are optional
try:
    from bs4 import BeautifulSoup
    import requests

    HAS_SCRAPING = True
except ImportError:
    HAS_SCRAPING = False
    # Not needed if yaml_patch is applied (which it is in orchestrator.py)


def create_id():
    return str(uuid.uuid4())


def check_id(existing_ids):
    if len(existing_ids) > 0:
        # Check both old queries directory and new generate directory
        for directory in ["data/queries", "data/generate"]:
            if os.path.exists(directory):
                for queryfile in os.listdir(directory):
                    if queryfile.endswith(".yaml"):
                        filepath = os.path.join(directory, queryfile)
                        try:
                            with open(filepath) as qf:
                                existing_ids.append(qf.readline())
                        except:
                            pass
    uid = create_id()
    if uid in str(existing_ids):
        check_id(existing_ids)

    return uid


def get_team(author):
    with open(os.path.join("archer", "mappings", "members.json")) as membersjson:
        members = json.load(membersjson)

    team = "CTH"
    for key, people in members.items():
        for person in people:
            if person["username"].lower() == author.lower():
                team = key
                break
        if team:
            return team


def additional_tactics(tid, tactic):
    """
    DEPRECATED: This function is SLOW (10-30 seconds per call).
    It is automatically replaced by yaml_patch.additional_tactics_fast() in orchestrator.py.

    If you see this function being called, the patch was not applied.
    Ensure: from archer.build import yaml_patch
    """

    def extract_tactics(extract_from):
        extracted_tactics = re.findall(
            "Reconnaissance|Resource Development|Initial Access|Execution|Persistence|Privilege Escalation|Defense Evasion|Credential Access|Discovery|Lateral Movement|Collection|Command and Control|Exfiltration|Impact",
            extract_from,
        )

        return extracted_tactics

    # Warn if scraping dependencies not available
    if not HAS_SCRAPING:
        print("WARNING: BeautifulSoup/requests not available. Using fallback regex extraction.")
        print("         Install with: pip install beautifulsoup4 requests")
        print("         Or apply yaml_patch for fast STIX-based extraction.")
        return extract_tactics(tactic)

    tid_uri = tid.replace(".", "/")
    url = f"https://attack.mitre.org/techniques/{tid_uri}"

    # Try to fetch from MITRE with retry logic and timeout handling
    max_retries = 3
    timeout = 10

    for attempt in range(max_retries):
        try:
            response = requests.get(url, timeout=timeout)
            soup = BeautifulSoup(response.text, "html.parser")
            text = soup.text

            if "Tactics:\\n" in text:
                extracted_tactics = extract_tactics(
                    text.split("Sub-technique of")[1][0:200]
                    .split("Platforms:")[0]
                    .split("Tactics:")[1],
                )
            else:
                extracted_tactics = extract_tactics(tactic)

            return extracted_tactics

        except (requests.exceptions.Timeout, requests.exceptions.RequestException) as e:
            if attempt < max_retries - 1:
                # Retry with exponential backoff
                wait_time = 2**attempt
                print(
                    f"Warning: Failed to fetch tactics from MITRE (attempt {attempt + 1}/{max_retries}), retrying in {wait_time}s..."
                )
                import time

                time.sleep(wait_time)
            else:
                # Final fallback: use the tactic provided
                print(
                    f"Warning: Could not fetch additional tactics from {url} after {max_retries} attempts, using provided tactic: {tactic}"
                )
                extracted_tactics = extract_tactics(tactic)
                return extracted_tactics


def find_nested_entity(field, entity_mappings):
    for entity, values in entity_mappings.items():
        for v in values:
            if isinstance(v, str):
                if v == field:
                    return (field, entity)
            elif isinstance(v, dict):
                for nested, nested_fields in v.items():
                    if field == nested:
                        return (nested, entity)
                    if isinstance(nested_fields, list) and field in nested_fields:
                        return (nested, entity)
    return None


def map_entities(query):
    """
    Extract entity mappings from a KQL query.

    Returns:
        tuple: (query, entity_mappings_string) where entity_mappings_string is empty for non-MDE queries
    """
    # Check if this is a Splunk query (starts with "index=") or KQL/MDE query
    # Splunk queries don't use "| summarize by Timestamp," syntax
    if query.strip().startswith("index="):
        # This is a Splunk query - entity mapping not applicable
        # Return query unchanged with no entity mappings
        return (query, "")

    # Check if query contains the expected KQL syntax
    if "| summarize by Timestamp, " not in query:
        # Query doesn't have the expected format - return unchanged
        return (query, "")

    # Process KQL/MDE queries with entity mapping
    fields = query.split("| summarize by Timestamp, ")[1].split(", ")
    with open(os.path.join("archer", "mappings", "entityMappings.json")) as f:
        entity_mappings = json.load(f)

    # Find and print nested field/entity matches
    results = []
    for field in fields:
        result = find_nested_entity(field, entity_mappings)
        if result:
            # Store as tuple for later formatting
            results.append((result[1], result[0], field))

    # Build entityMappings string efficiently
    entities = ""
    if results:
        entities = "entityMappings:"
        for entity_type, identifier, column_name in results:
            entities += (
                f"\n- entityType: {entity_type}\n"
                f"  fieldMappings:\n"
                f"    - identifier: {identifier}\n"
                f"      columnName: {column_name}"
            )

    return (query, entities)


def write_yaml(query_file, name, tid, tdesc, connector_id, tactic, tag, query, indicators=None, osint_data=None, osint_enhanced=False, entity_mappings=None):
    with open(os.path.join("archer", "mappings", "template.yaml")) as queryTemplate:
        template = queryTemplate.read()

    uid = check_id([])
    desc = tdesc.replace("\n  \n", "\n  ").replace("\n* ", "\n  * ")
    desc = re.sub(r"</?code>", r"`", desc)

    # Extract datatype from first non-comment, non-let line
    datatype = ""
    for line in query.split("\n"):
        stripped = line.strip()
        # Skip empty lines, comments, and let statements
        if stripped and not stripped.startswith("//") and not stripped.startswith("let "):
            datatype = stripped.split(" earliest=")[0].replace("index=", "").replace("_prod", "")
            break

    # Fallback if no valid line found
    if not datatype:
        datatype = "UnknownDataType"
    tactic = str(tactic)[2:-2].replace("', '", "\n  - ")

    # Indent ALL query lines properly for YAML literal block
    # Split query into lines, indent each non-empty line with 2 spaces
    # Strip existing indentation first to ensure consistent spacing
    query_lines = query.split("\n")
    indented_lines = []
    for line in query_lines:
        if line.strip():  # Non-empty line
            stripped = line.lstrip()
            # For KQL queries, ensure pipe operators are properly aligned
            # If line starts with |, it should have no extra indentation beyond the 2-space YAML indent
            if stripped.startswith("|"):
                indented_lines.append("  " + stripped)
            else:
                # Non-pipe lines get standard 2-space indent
                indented_lines.append("  " + stripped)
        else:
            # Empty line - keep it empty
            indented_lines.append(line)
    query = "\n".join(indented_lines)

    author = getpass.getuser()
    team = get_team(author)

    # Format the threat group tag with (Group) suffix
    formatted_tag = f"{tag} (Group)" if tag else ""

    # Format entity mappings
    # Template already has newlines before and after placeholder, so no modification needed
    entity_mappings_formatted = entity_mappings if entity_mappings else ""

    yaml_content = (
        template.replace("§id§", uid)
        .replace("§name§", name)
        .replace("§tid§", tid)
        .replace("§tdesc§", desc)
        .replace("§severity§", "")
        .replace("§connectorId§", connector_id)
        .replace("§dataTypes§", datatype)
        .replace("§tactic§", tactic)
        .replace("§group§", formatted_tag)
        .replace("§query§", query)
        .replace("§entityMappings§", entity_mappings_formatted)
        .replace("§ver§", "1.0")
        .replace("§source§", "Archer")
        .replace("§author§", author)
        .replace("§support§", team)
        .replace("query:  |", "query: |")
        # NOTE: Old indentation logic removed - now handled by pre-indenting query lines above
        # .replace("  | ", " | ")
        # .replace("\n | ", "\n  | ")
    )
    # Fix: Don't add extra indentation to query lines (lines starting with "  |" after blank lines)
    # Only add indentation to description text after blank lines
    # Split on double newlines, check if next line is a query pipe, and only add indent if it's not
    def fix_blank_line_indent(match):
        # Get the text after the blank line
        next_char_idx = match.end()
        if next_char_idx < len(yaml_content):
            # Check if the next line starts with "  |" (query pipe)
            remaining = yaml_content[next_char_idx:]
            if remaining.startswith("  |"):
                # This is a query line, don't add extra indent
                return "\n\n"
        # Not a query line, add indent for description formatting
        return "\n  "

    # Note: Can't use the function approach above in re.sub easily, so use a simpler fix:
    # Only apply indentation to description section, not query section
    # Split at "query: |" marker and only apply regex to the part before it
    if "query: |" in yaml_content:
        parts = yaml_content.split("query: |", 1)
        # Apply regex only to content before query
        parts[0] = re.sub(r"\n\n", r"\n  ", parts[0])
        yaml_content = "query: |".join(parts)
    else:
        # Fallback: apply to whole content if no query marker found
        yaml_content = re.sub(r"\n\n", r"\n  ", yaml_content)

    yaml_content = re.sub(r"(\(Citation: [^\)]+\))", r"", yaml_content)
    # NOTE: Old pipe reformatting removed - now handled by pre-indenting query lines above
    # yaml_content = yaml_content.replace(" | where ", "\n   | where ").replace("   | ", "  | ")

    # Add indicators section if present
    if indicators:
        import yaml as yaml_module
        indicators_section = "\n# Extracted Indicators\n"
        indicators_section += "indicators:\n"

        # Handle dict or list format
        if isinstance(indicators, dict):
            for indicator_type, values in indicators.items():
                if values:
                    indicators_section += f"  {indicator_type}:\n"
                    for value in values:
                        yaml_str = yaml_module.dump([value], default_flow_style=False, width=1000000)
                        yaml_value = yaml_str.strip().replace('- ', '', 1).strip()
                        indicators_section += f'    - {yaml_value}\n'
        elif isinstance(indicators, list) and indicators:
            for value in indicators:
                yaml_str = yaml_module.dump([value], default_flow_style=False, width=1000000)
                yaml_value = yaml_str.strip().replace('- ', '', 1).strip()
                indicators_section += f'  - {yaml_value}\n'

        yaml_content += indicators_section

    # Add OSINT metadata if data was found during comparison
    # Debug logging removed for cleaner output
    if osint_data and osint_data.get("osint_compared"):
        osint_section = "\n# OSINT Comparison Metadata\n"
        osint_section += f"osint_compared: true\n"

        # Add osint_enhanced flag if enhancement was enabled
        if osint_enhanced:
            osint_section += f"osint_enhanced: true\n"

        osint_section += f"comparison_date: {osint_data.get('comparison_date', '')}\n"

        if osint_data.get("osint_sources"):
            osint_section += "osint_sources:\n"
            for source in osint_data["osint_sources"]:
                osint_section += f"  - {source}\n"

        # Add osint_indicators (always included for reference, even if not merged)
        if osint_data.get("osint_indicators"):
            import yaml as yaml_module
            osint_section += "osint_indicators:\n"
            for indicator_type, values in osint_data["osint_indicators"].items():
                if values:
                    osint_section += f"  {indicator_type}:\n"
                    for value in values:
                        # Use YAML library to properly escape the value
                        # This handles all special characters including backslashes
                        # Use width=1000000 to prevent line wrapping
                        yaml_str = yaml_module.dump([value], default_flow_style=False, width=1000000)
                        # Extract just the value part (remove the list syntax)
                        yaml_value = yaml_str.strip().replace('- ', '', 1).strip()
                        osint_section += f'    - {yaml_value}\n'

        if osint_data.get("enrichment_notes"):
            notes = osint_data["enrichment_notes"].replace("\n", "\n  ")

            # Add explanation if OSINT comparison succeeded but query was not enhanced
            if not osint_enhanced:
                # Determine the reason based on available data
                has_indicators = any(
                    osint_data.get("osint_indicators", {}).get(ind_type)
                    for ind_type in ["cmd", "sw", "path", "acct", "reg", "api", "op", "evt"]
                )

                if not has_indicators:
                    notes += "; Query not enhanced: no actionable indicators extracted from OSINT sources (only query snippets available)"
                else:
                    notes += "; Query not enhanced: extracted indicators may be duplicates or incompatible with target platform"

            osint_section += f"enrichment_notes: |\n  {notes}\n"

        yaml_content += osint_section

    if "()" in query or "( OR )" in query or "\n  | where \n  | " in query:
        pass
    else:
        with open(query_file, "w") as new_yaml:
            new_yaml.write(yaml_content)


def update_yaml(yamlfile, tag):

    def increment_version(match):
        major = match.group(1)
        minor = int(match.group(2)) + 1  # increment minor version
        patch = match.group(3)

        return f"{major}{minor}{patch}"

    with open(yamlfile) as yfile:
        old_content = yfile.read()

    # Format the threat group tag with (Group) suffix
    formatted_tag = f"{tag} (Group)" if tag else ""

    if formatted_tag not in old_content:
        # Insert new Threat Group
        prefix, suffix = old_content.split("tags:\n  - ")
        added_tags = f"{prefix}tags:\n  - {formatted_tag}\n  - {suffix}"

        # Update version
        newver = re.sub(r"(version: \d+\.)(\d+)((\.\d+)?)", increment_version, added_tags)
        prefix = added_tags.split("version: ")[0]
        suffix = added_tags.split("kind:")[1]

        with open(yamlfile, "w") as yfile:
            yfile.write(newver)


def construct_yaml(
    name,
    tid,
    tdesc,
    tactic,
    tag,
    identifiers,
    log_sources,
    index_name,
    procedure_platforms,
    software_platforms,
    osint_enhancement_data=None,
    osint_enhancement=False,
):
    """
    Construct a YAML file for a detection

    Args:
        name: Name of the technique
        tid: Technique ID
        tdesc: Activity description
        tactic: Tactic
        tag: Group name tag
        identifiers: Dictionary of identifiers
        log_sources: List of log sources
        index_name: Optional index name to include in the filename
        osint_enhancement: Optional OSINT enrichment metadata dict
    """
    # CRITICAL: Don't create YAML files if there are no indicators
    # This prevents "Needs Review - no indicators extracted" detections from being created
    if not identifiers or len(identifiers) == 0:
        print(f" ⚠️  construct_yaml called with empty identifiers - skipping YAML creation for {name}")
        return

    # Check if identifiers contains only empty values
    has_real_indicators = False
    for indicator_type, values in identifiers.items():
        if values:  # Check if the value is not None, not empty list, not empty string
            if isinstance(values, list) and len(values) > 0:
                has_real_indicators = True
                break
            elif isinstance(values, str) and len(values.strip()) > 0:
                has_real_indicators = True
                break
            elif isinstance(values, dict) and len(values) > 0:
                has_real_indicators = True
                break

    if not has_real_indicators:
        print(f" ⚠️  construct_yaml: All indicator values are empty - skipping YAML creation for {name}")
        return

    # Debug logging removed for cleaner output

    # Extract OSINT indicators if enhancement is enabled
    osint_indicators_to_pass = None
    if osint_enhancement and osint_enhancement_data:
        osint_indicators_to_pass = osint_enhancement_data.get("osint_indicators", {})

    appended_mde_queries, appended_splunk_queries = collate_data(
        identifiers, log_sources, procedure_platforms, software_platforms, name, technique_id=tid, osint_indicators=osint_indicators_to_pass
    )

    # Apply OSINT enhancement if requested (merge OSINT patterns into queries)
    # Track which queries were actually enhanced (not just attempted)
    mde_queries_enhanced = {}  # Map query -> was_enhanced bool
    splunk_queries_enhanced = {}  # Map query -> was_enhanced bool

    if osint_enhancement and osint_enhancement_data and osint_enhancement_data.get("osint_indicators"):
        from archer.build.osint_query_enhancer import enhance_query_with_osint

        osint_indicators = osint_enhancement_data.get("osint_indicators", {})

        # Enhance MDE queries and track which ones were actually modified
        enhanced_mde_queries = []
        for query in appended_mde_queries:
            enhanced_query, was_enhanced = enhance_query_with_osint(query, osint_indicators, target_vendor="MDE")
            enhanced_mde_queries.append(enhanced_query)
            mde_queries_enhanced[enhanced_query] = was_enhanced
        appended_mde_queries = enhanced_mde_queries

        # Enhance Splunk queries
        # NOTE: OSINT enhancement is now handled directly in compile_splunk_queries() function
        # to ensure proper query structure with transformation pipelines and | search clause
        # So we skip the post-processing enhancement here for Splunk queries
        # enhanced_splunk_queries = []
        # for query in appended_splunk_queries:
        #     enhanced_query, was_enhanced = enhance_query_with_osint(query, osint_indicators, target_vendor="Splunk")
        #     enhanced_splunk_queries.append(enhanced_query)
        #     splunk_queries_enhanced[enhanced_query] = was_enhanced
        # appended_splunk_queries = enhanced_splunk_queries

        # Count how many queries were actually enhanced
        mde_enhanced_count = sum(1 for enhanced in mde_queries_enhanced.values() if enhanced)
        print(f"  🔧 OSINT Enhancement: Successfully enhanced {mde_enhanced_count}/{len(appended_mde_queries)} MDE queries with datatables")

    all_tactics = additional_tactics(tid, tactic)

    # Writing MDE YAML file
    for query in appended_mde_queries:
        # Extract the table name from the query, skipping comment lines and let statements
        lines = query.split("\n")
        table_name = None
        for line in lines:
            stripped = line.strip()
            # Skip empty lines, comments, and let statements
            if stripped and not stripped.startswith("//") and not stripped.startswith("let "):
                table_name = stripped
                break

        # Fallback if no table name found
        if not table_name:
            table_name = "UnknownTable"

        # Extract query and entity mappings separately
        query_only, entity_mappings_str = map_entities(query)

        """if len(query_with_entities) > 10:
            print(
                f"  {name} ({table_name}) breaches the MDE entityMapping limit of 10.\n   Please review before commiting to production.\n"
            )
            time.sleep(0.5)"""
        # Create filename-safe version of the name (remove spaces and slashes)
        # But keep the original name for writing to the YAML metadata
        name_safe = name.replace(" ", "").replace("/", "")
        # Use the actual MDE table name from the query for the filename
        # NOT the index_name parameter which might be a Splunk index
        filename = f"{name_safe}_{table_name}.yaml"
        yamlfile = os.path.join(GENERATE_DIR, filename)
        if not os.path.exists(yamlfile):
            # Check if THIS specific query was enhanced (not just if enhancement was attempted)
            query_was_enhanced = mde_queries_enhanced.get(query, False)

            write_yaml(
                yamlfile,
                name,  # Pass original name with spaces/slashes preserved
                tid,
                tdesc,
                "MicrosoftThreatProtection",
                all_tactics,
                tag,
                query_only,  # Pass query WITHOUT entity mappings
                indicators=identifiers,  # Pass indicators for YAML metadata
                osint_data=osint_enhancement_data,  # Pass OSINT data dict
                osint_enhanced=query_was_enhanced,    # Pass TRUE only if this query was actually enhanced
                entity_mappings=entity_mappings_str,  # Pass entity mappings separately
            )
        else:
            update_yaml(yamlfile, tag)

    # Writing Splunk YAML file
    for query in appended_splunk_queries:
        index = query.split("\n")[0].split(" earliest=")[0].replace("index=", "").replace(" ", "")
        query = query.replace(" earliest=-1d\n", " earliest=-1d\n  ")
        # Use filename-safe version for Splunk filenames too
        yamlfile = os.path.join(GENERATE_DIR, f"{name_safe}_{index}.yaml")
        if not os.path.exists(yamlfile):
            write_yaml(
                yamlfile,
                name,
                tid,
                tdesc,
                "Splunk",
                all_tactics,
                tag,
                query,
                indicators=identifiers,  # Pass indicators for YAML metadata
                osint_data=osint_enhancement_data,  # Pass OSINT data dict
                osint_enhanced=osint_enhancement,    # Pass enhancement flag
            )
        else:
            update_yaml(yamlfile, tag)

    # Writing Chronicle YAML file (if Chronicle support is enabled)
    # Chronicle uses AI-generated YARA-L detection rules
    try:
        from archer.build.chronicle import ChronicleGenerator

        chronicle_gen = ChronicleGenerator()
        chronicle_rule = chronicle_gen.generate_yaral_rule(
            technique_id=tid,
            technique_name=name,
            tactic=tactic,
            description=tdesc,
            osint_data=osint_enhancement_data,
            group_name=tag
        )

        if chronicle_rule and chronicle_rule.get("yaral_code"):
            # Create Chronicle YAML file
            yamlfile = os.path.join(GENERATE_DIR, f"{name_safe}_Chronicle.yaml")
            if not os.path.exists(yamlfile):
                write_yaml(
                    yamlfile,
                    name,
                    tid,
                    tdesc,
                    "GoogleChronicle",
                    all_tactics,
                    tag,
                    chronicle_rule["yaral_code"],
                    indicators=identifiers,
                    osint_data=osint_enhancement_data,
                    osint_enhanced=osint_enhancement,
                )
                print(f"  ✅ Generated Chronicle YARA-L rule: {chronicle_rule['rule_name']}")
            else:
                update_yaml(yamlfile, tag)
    except Exception as e:
        # Chronicle generation is optional - don't fail if it errors
        print(f"  ⚠️  Chronicle generation failed for {name}: {e}")

    # Writing Elastic YAML file (if Elastic support is enabled)
    # Elastic uses AI-generated Query DSL with ECS field names
    try:
        from archer.build.elastic import ElasticQueryGenerator

        elastic_gen = ElasticQueryGenerator()
        elastic_query_result = elastic_gen.generate_query(
            technique_id=tid,
            technique_name=name,
            tactic=tactic,
            description=tdesc,
            osint_data=osint_enhancement_data,
            group_name=tag
        )

        if elastic_query_result and elastic_query_result.get("query_dsl"):
            # Validate the query
            is_valid, error = elastic_gen.validate_query(elastic_query_result["query_dsl"])

            if is_valid:
                # Format query as JSON string for YAML
                elastic_query_str = elastic_gen.format_query_for_display(elastic_query_result["query_dsl"])

                # Create Elastic YAML file
                yamlfile = os.path.join(GENERATE_DIR, f"{name_safe}_Elastic.yaml")
                if not os.path.exists(yamlfile):
                    write_yaml(
                        yamlfile,
                        name,
                        tid,
                        tdesc,
                        "Elastic",
                        all_tactics,
                        tag,
                        elastic_query_str,
                        indicators=identifiers,
                        osint_data=osint_enhancement_data,
                        osint_enhanced=osint_enhancement,
                    )
                    print(f"  ✅ Generated Elastic Query DSL: {elastic_query_result['query_name']}")
                else:
                    update_yaml(yamlfile, tag)
            else:
                print(f"  ⚠️  Elastic query validation failed for {name}: {error}")
    except Exception as e:
        # Elastic generation is optional - don't fail if it errors
        print(f"  ⚠️  Elastic generation failed for {name}: {e}")
