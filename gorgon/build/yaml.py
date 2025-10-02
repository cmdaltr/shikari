from gorgon.build.collate import collate_data
from bs4 import BeautifulSoup

import getpass
import json
import os
import re
import uuid
import requests


def create_id():
    return str(uuid.uuid4())


def check_id(existing_ids):
    if len(existing_ids) > 0:
        for queryfile in os.listdir(os.path.join("data", "queries")):
            with open(os.path.join("data", "queries", queryfile)) as qf:
                existing_ids.append(qf.readline())
    uid = create_id()
    if uid in str(existing_ids):
        check_id(existing_ids)

    return uid


def get_team(author):
    with open(os.path.join("gorgon", "mappings", "members.json")) as membersjson:
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
    def extract_tactics(extract_from):
        extracted_tactics = re.findall(
            "Reconnaissance|Resource Development|Initial Access|Execution|Persistence|Privilege Escalation|Defense Evasion|Credential Access|Discovery|Lateral Movement|Collection|Command and Control|Exfiltration|Impact",
            extract_from,
        )

        return extracted_tactics

    tid_uri = tid.replace(".", "/")
    url = f"https://attack.mitre.org/techniques/{tid_uri}"
    response = requests.get(url, timeout=5)
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
    with open(os.path.join("gorgon", "mappings", "entityMappings.json")) as f:
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
    with open(os.path.join("gorgon", "mappings", "template.yaml")) as queryTemplate:
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

    yaml_content = (
        template.replace("§id§", uid)
        .replace("§name§", name)
        .replace("§tid§", tid)
        .replace("§tdesc§", desc)
        .replace("§severity§", "")
        .replace("§connectorId§", connector_id)
        .replace("§dataTypes§", datatype)
        .replace("§tactic§", tactic)
        .replace("§group§", tag)
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
    yaml_content = yaml_content.replace(" | where ", "\n   | where ")

    if "()" in query or "( OR )" in query or "\n  | where \n  | " in query:
        pass
    else:
        with open(query_file, "w") as new_yaml:
            new_yaml.write(yaml_content)

    # Inserting this to create a simple approach for the latest file having been created for the web application to provide progress
    with open(os.path.join("data", "queries", "latest.yaml"), "w") as latest_yaml:
        latest_yaml.write(query_file)


def update_yaml(yamlfile, tag):

    def increment_version(match):
        major = match.group(1)
        minor = int(match.group(2)) + 1  # increment minor version
        patch = match.group(3)

        return f"{major}{minor}{patch}"

    with open(yamlfile) as yfile:
        old_content = yfile.read()

    if tag not in old_content:
        # Insert new Threat Group
        prefix, suffix = old_content.split("tags:\n  - ")
        added_tags = f"{prefix}tags:\n  - {tag}\n  - {suffix}"

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
):
    appended_mde_queries, appended_splunk_queries = collate_data(
        identifiers, log_sources
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
        yamlfile = os.path.join("data", "queries", f"{name}_{table}.yaml")
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
            .replace("_prod", "")
        )
        query = query.replace(" earliest=-1d\n", " earliest=-1d\n  ")
        yamlfile = os.path.join("data", "queries", f"{name}_{index}.yaml")
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
