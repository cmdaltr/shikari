from gorgon.build.collate import collate_data

import ast
import getpass
import json
import os
import uuid


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

    team = None
    for key, people in members.items():
        for person in people:
            if person["username"].lower() == author.lower():
                team = key
                break
        if team:
            return team


def additional_tactics(name, tactic):
    # need to get the potential additional tactics for technique via the ATT&CK API or web scraping
    return tactic


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
    query = query.replace("\n| ", "\n  | ")
    author = getpass.getuser()
    team = get_team(author)

    yaml_content = template.replace("§id§", uid)
    yaml_content = yaml_content.replace("§name§", name)
    yaml_content = yaml_content.replace("§tid§", tid)
    yaml_content = yaml_content.replace("§tdesc§", tdesc)
    yaml_content = yaml_content.replace("§severity§", "")
    yaml_content = yaml_content.replace("§connectorId§", connector_id)
    yaml_content = yaml_content.replace("§dataTypes§", datatype)
    yaml_content = yaml_content.replace("§tactic§", tactic)
    yaml_content = yaml_content.replace("§group§", tag)
    yaml_content = yaml_content.replace("§query§", query)
    yaml_content = yaml_content.replace("§ver§", "1.0")
    yaml_content = yaml_content.replace("§source§", source)
    yaml_content = yaml_content.replace("§author§", author)
    yaml_content = yaml_content.replace("§support§", team)

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

    all_tactics = additional_tactics(name, tactic)
    name = name.replace(" ", "").replace("/", "")
    tactic_list = ast.literal_eval(all_tactics)
    if (
        isinstance(tactic_list, list)
        and len(tactic_list) > 0
        and "name" in tactic_list[0]
    ):
        all_tactics = tactic_list[0]["name"]

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
