from archer.build.collate import collate_data

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
                wait_time = 2 ** attempt
                print(f"Warning: Failed to fetch tactics from MITRE (attempt {attempt + 1}/{max_retries}), retrying in {wait_time}s...")
                import time
                time.sleep(wait_time)
            else:
                # Final fallback: use the tactic provided
                print(f"Warning: Could not fetch additional tactics from {url} after {max_retries} attempts, using provided tactic: {tactic}")
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


def write_yaml(query_file, name, tid, tdesc, connector_id, tactic, tag, query):
    with open(os.path.join("archer", "mappings", "template.yaml")) as queryTemplate:
        template = queryTemplate.read()

    uid = check_id([])
    desc = tdesc.replace("\n  \n", "\n  ").replace("\n* ", "\n  * ")
    desc = re.sub(r"</?code>", r"`", desc)
    datatype = (
        query.split("\n")[0]
        .split(" earliest=")[0]
        .replace("index=", "")
        .replace("_prod", "")
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
    yaml_content = yaml_content.replace(" | where ", "\n   | where ").replace(
        "   | ", "  | "
    )

    if "()" in query or "( OR )" in query or "\n  | where \n  | " in query:
        pass
    else:
        with open(query_file, "w") as new_yaml:
            new_yaml.write(yaml_content)

    # Inserting this to create a simple approach for the latest file having been created for the web application to provide progress
    with open(os.path.join("data", "generate", "latest.yaml"), "w") as latest_yaml:
        latest_yaml.write(query_file)


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
        newver = re.sub(
            r"(version: \d+\.)(\d+)((\.\d+)?)", increment_version, added_tags
        )
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
    """
    appended_mde_queries, appended_splunk_queries = collate_data(
        identifiers, log_sources, procedure_platforms, software_platforms
    )

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
        filename = f"{name}_{index_name.replace('=', '').replace(' ', '')}.yaml"
        yamlfile = os.path.join("data", "generate", filename)
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
            )
        else:
            update_yaml(yamlfile, tag)

    # Writing Splunk YAML file
    for query in appended_splunk_queries:
        index = (
            query.split("\n")[0]
            .split(" earliest=")[0]
            .replace("index=", "")
            .replace(" ", "")
        )
        query = query.replace(" earliest=-1d\n", " earliest=-1d\n  ")
        yamlfile = os.path.join("data", "generate", f"{name}_{index}.yaml")
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
            )
        else:
            update_yaml(yamlfile, tag)
