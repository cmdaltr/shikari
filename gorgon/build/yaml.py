from gorgon.build.collate import collate_data
from bs4 import BeautifulSoup

import ast
import getpass
import json
import os
import re
import uuid
import requests
import yaml


def create_id():
    return str(uuid.uuid4())


def check_id(existing_ids):
    if len(existing_ids) == 0:
        for queryfile in os.listdir(os.path.join("data", "queries")):
            with open(os.path.join("data", "queries", queryfile)) as qf:
                existing_ids.append(qf.readline())
    uid = create_id()
    if uid in str(existing_ids):
        check_id(existing_ids)

    return uid


def get_team(author):
    with open(os.path.join("gorgon", "static", "members.json")) as membersjson:
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
    url = f"https://attack.mitre.org/techniques/{tid.replace(".", "/")}"
    response = requests.get(url, timeout=5)  # 5 seconds timeout
    soup = BeautifulSoup(response.text, "html.parser")
    text = soup.text

    # Find a specific string
    if "Tactics:" in text:
        extracted_tactics = re.findall(
            "Reconnaissance|Resource Development|Initial Access|Execution|Persistence|Privilege Escalation|Defense Evasion|Credential Access|Discovery|Lateral Movement|Collection|Command and Control|Exfiltration|Impact",
            text.split("Sub-technique of")[1][0:200]
            .split("Platforms:")[0]
            .split("Tactics:")[1],
        )
        return extracted_tactics
    else:
        return list[tactic]


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
    with open(os.path.join("gorgon", "static", "entityMappings.json")) as f:
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
        entities = "\nentityMappings:\n"
        for entity_type, identifier, column_name in results:
            entities += (
                f"\n- entityType: {entity_type}\n"
                f"  fieldMappings:\n"
                f"    - identifier: {identifier}\n"
                f"      columnName: {column_name}"
            )

    return f"{query}{entities}"


def write_yaml(query_file, name, tid, tdesc, connector_id, tactic, tag, query, source):
    with open(os.path.join("gorgon", "static", "template.yaml")) as queryTemplate:
        template = queryTemplate.read()

    uid = check_id([])
    datatype = (
        query.split("\n")[0]
        .split(" earliest=")[0]
        .replace("index=", "")
        .replace("_prod", "")
    )
    tactic = str(tactic)[2:-2].replace("', '", "\n  - ")
    query = query.replace("\n| ", "\n  | ")
    author = getpass.getuser()
    team = get_team(author)

    yaml_content = (
        template.replace("§id§", uid)
        .replace("§name§", name)
        .replace("§tid§", tid)
        .replace("§tdesc§", tdesc)
        .replace("§severity§", "")
        .replace("§connectorId§", connector_id)
        .replace("§dataTypes§", datatype)
        .replace("§tactic§", tactic)
        .replace("§group§", tag)
        .replace("§query§", query)
        .replace("§ver§", "1.0")
        .replace("§source§", source)
        .replace("§author§", author)
        .replace("§support§", team)
    )

    with open(query_file, "w") as new_yaml:
        new_yaml.write(yaml_content)


def update_yaml(yamlfile, tag):
    with open(yamlfile) as yfile:
        ycontent = yfile.read()
        if tag not in ycontent:
            insert = tag


def construct_yaml(
    name,
    tid,
    tdesc,
    tactic,
    tag,
    source,
    operatorGuidance,
    detectionSteps,
):
    appended_mde_queries, appended_splunk_queries = collate_data(
        operatorGuidance, detectionSteps
    )

    all_tactics = additional_tactics(tid, tactic)
    name = name.replace(" ", "").replace("/", "")

    # Writing MDE YAML file
    for query in appended_mde_queries:
        table = query.split("\n")[0].replace("Device", "")
        query_with_entities = map_entities(query)
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
                source,
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
        query = query.replace(" earliest=-1d\n", " earliest=-1d\n  ").replace(
            "\n\n  | table ", "\n  | table "
        )
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
                source,
            )
