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
        entities = "\nentityMappings:"
        for entity_type, identifier, column_name in results:
            entities += (
                f"\n- entityType: {entity_type}\n"
                f"  fieldMappings:\n"
                f"    - identifier: {identifier}\n"
                f"      columnName: {column_name}"
            )

    return f"{query}{entities}"


def write_yaml(query_file, name, tid, tdesc, connector_id, tactic, tag, query, osint_data=None, osint_enhanced=False):
    with open(os.path.join("archer", "mappings", "template.yaml")) as queryTemplate:
        template = queryTemplate.read()

    uid = check_id([])
    desc = tdesc.replace("\n  \n", "\n  ").replace("\n* ", "\n  * ")
    desc = re.sub(r"</?code>", r"`", desc)
    datatype = (
        query.split("\n")[0].split(" earliest=")[0].replace("index=", "").replace("_prod", "")
    )
    tactic = str(tactic)[2:-2].replace("', '", "\n  - ")
    query = query.replace("\n| ", "  | ")
    author = getpass.getuser()
    team = get_team(author)

    # Format the threat group tag with (Group) suffix
    formatted_tag = f"{tag} (Group)" if tag else ""

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
        .replace("§ver§", "1.0")
        .replace("§source§", "Archer")
        .replace("§author§", author)
        .replace("§support§", team)
        .replace("query:  |", "query: |")
        .replace("  | ", " | ")
        .replace("\n | ", "\n  | ")
    )
    yaml_content = re.sub(r"\n\n", r"\n  ", yaml_content)
    yaml_content = re.sub(r"(\(Citation: [^\)]+\))", r"", yaml_content)
    yaml_content = yaml_content.replace(" | where ", "\n   | where ").replace("   | ", "  | ")

    # Add OSINT metadata if data was found during comparison
    print(f"🔍 DEBUG write_yaml: osint_data={osint_data is not None}, osint_enhanced={osint_enhanced}")
    if osint_data:
        print(f"   osint_data keys: {osint_data.keys() if isinstance(osint_data, dict) else 'NOT A DICT'}")
        print(f"   osint_compared: {osint_data.get('osint_compared') if isinstance(osint_data, dict) else 'N/A'}")

    if osint_data and osint_data.get("osint_compared"):
        print(f"   ✅ Writing OSINT metadata to YAML")
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
                        yaml_str = yaml_module.dump([value], default_flow_style=False)
                        # Extract just the value part (remove the list syntax)
                        yaml_value = yaml_str.strip().replace('- ', '', 1).strip()
                        osint_section += f'    - {yaml_value}\n'

        if osint_data.get("enrichment_notes"):
            notes = osint_data["enrichment_notes"].replace("\n", "\n  ")
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
    print(f"🔍 DEBUG construct_yaml for {tid}: osint_enhancement_data={osint_enhancement_data is not None}, osint_enhancement={osint_enhancement}")

    appended_mde_queries, appended_splunk_queries = collate_data(
        identifiers, log_sources, procedure_platforms, software_platforms
    )

    # Apply OSINT enhancement if requested (merge OSINT patterns into queries)
    if osint_enhancement and osint_enhancement_data and osint_enhancement_data.get("osint_indicators"):
        from archer.build.osint_query_enhancer import enhance_query_with_osint

        osint_indicators = osint_enhancement_data.get("osint_indicators", {})

        # Enhance MDE queries
        enhanced_mde_queries = []
        for query in appended_mde_queries:
            enhanced_query = enhance_query_with_osint(query, osint_indicators, target_vendor="MDE")
            enhanced_mde_queries.append(enhanced_query)
        appended_mde_queries = enhanced_mde_queries

        # Enhance Splunk queries
        enhanced_splunk_queries = []
        for query in appended_splunk_queries:
            enhanced_query = enhance_query_with_osint(query, osint_indicators, target_vendor="Splunk")
            enhanced_splunk_queries.append(enhanced_query)
        appended_splunk_queries = enhanced_splunk_queries

        print(f"  🔧 OSINT Enhancement: Merged OSINT patterns into {len(appended_mde_queries)} MDE and {len(appended_splunk_queries)} Splunk queries")

    all_tactics = additional_tactics(tid, tactic)

    # Writing MDE YAML file
    for query in appended_mde_queries:
        table = query.split("\n")[0].replace("Device", "")
        query_with_entities = ""
        query_with_entities = map_entities(query)
        """if len(query_with_entities) > 10:
            print(
                f"  {name} ({table}) breaches the MDE entityMapping limit of 10.\n   Please review before commiting to production.\n"
            )
            time.sleep(0.5)"""
        name = name.replace(" ", "").replace("/", "")
        # If index_name is provided, include it in the filename
        # Handle case where index_name might be a dict or other non-string type
        if isinstance(index_name, dict):
            print(f"⚠️ WARNING: index_name is a dict, using 'unknown': {index_name}")
            index_name_str = "unknown"
        elif not isinstance(index_name, str):
            print(
                f"⚠️ WARNING: index_name is type {type(index_name)}, converting to string: {index_name}"
            )
            index_name_str = str(index_name)
        else:
            index_name_str = index_name.replace("=", "").replace(" ", "")
        filename = f"{name}_{index_name_str}.yaml"
        yamlfile = os.path.join(GENERATE_DIR, filename)
        if not os.path.exists(yamlfile):
            write_yaml(
                yamlfile,
                name,
                tid,
                tdesc,
                "MicrosoftThreatProtection",
                all_tactics,
                tag,
                query_with_entities,
                osint_data=osint_enhancement_data,  # Pass OSINT data dict
                osint_enhanced=osint_enhancement,    # Pass enhancement flag
            )
        else:
            update_yaml(yamlfile, tag)

    # Writing Splunk YAML file
    for query in appended_splunk_queries:
        index = query.split("\n")[0].split(" earliest=")[0].replace("index=", "").replace(" ", "")
        query = query.replace(" earliest=-1d\n", " earliest=-1d\n  ")
        yamlfile = os.path.join(GENERATE_DIR, f"{name}_{index}.yaml")
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
                osint_data=osint_enhancement_data,  # Pass OSINT data dict
                osint_enhanced=osint_enhancement,    # Pass enhancement flag
            )
        else:
            update_yaml(yamlfile, tag)
