from gorgon.build.queries import compile_mde_queries, compile_splunk_queries

import json
import os


def define_values(payload, technique_descriptions, retrieved_data):
    name = payload["variables"]["input"]["createTestCasedata"][0]["testCaseData"][
        "name"
    ]
    tid = payload["variables"]["input"]["createTestCasedata"][0]["testCaseData"][
        "technique"
    ]
    for description in technique_descriptions:
        if description.startswith(f"{tid}: "):
            tdesc = description.split(f"{tid}: ")[1]
    tactic = payload["variables"]["input"]["createTestCasedata"][0]["testCaseData"][
        "phase"
    ]
    tag = retrieved_data["group_name"]
    source = "example Internal"
    support = "example Internal"

    operatorGuidance = payload["variables"]["input"]["createTestCasedata"][0][
        "testCaseData"
    ]["operatorGuidance"]
    redTools = payload["variables"]["input"]["createTestCasedata"][0]["testCaseData"][
        "redTools"
    ]
    detectionSteps = payload["variables"]["input"]["createTestCasedata"][0][
        "testCaseData"
    ]["detectionSteps"]

    return (
        name,
        tid,
        tdesc,
        tactic,
        tag,
        source,
        support,
        operatorGuidance,
        redTools,
        detectionSteps,
    )


def collate_data(operatorGuidance, detectionSteps):
    # Map identified detectionSteps with the data sources and return the logging table/indexes
    with open(os.path.join("gorgon", "static", "dataSources.json")) as datasourcesjson:
        data_sources = json.load(datasourcesjson)

    mitre_data_sources = data_sources["mitreDataSources"]
    alignment_results = []
    for step in detectionSteps:
        matched_sources = []
        for ds_name, ds_content in mitre_data_sources.items():
            if step.startswith(f"{ds_name} "):
                matched_sources.append(
                    {
                        "data_source": ds_name,
                        "MDE": ds_content.get("MDE", []),
                        "Splunk": ds_content.get("Splunk", []),
                    }
                )
        alignment_results.append({"detection_step": step, "matches": matched_sources})

    # For each indicator type (cmd, evt, reg, sw) in operator_guidance, fetch mapping
    with open(os.path.join("gorgon", "static", "mapSplunkIndecies.json")) as f:
        map_splunk_indices = json.load(f)
    og_dict = json.loads(operatorGuidance.replace("'", '"'))

    with open("gorgon/static/indicatorMapping.json", "r") as f:
        indicator_mapping = json.load(f)

    with open(os.path.join("gorgon", "static", "mapDefenderTables.json")) as f:
        map_defender_tables = json.load(f)

    for step in alignment_results:
        if step["matches"]:
            for match in step["matches"]:
                for mde_table in match["MDE"]:
                    mde_mapping = map_defender_tables.get(mde_table)
                for splunk_index in match["Splunk"]:
                    splunk_mapping = map_splunk_indices.get(splunk_index)

    mde_queries = []
    splunk_queries = []
    for indicator_type, indicators in og_dict.items():
        if indicator_type in indicator_mapping:
            # Mapping and building MDE queries
            mde_queries = compile_mde_queries(
                indicator_mapping, indicators, indicator_type, mde_queries
            )

            appended_mde_queries = []
            for query in mde_queries:
                # Extract the table name from the query string (assumes first line is the table name)
                table_name = query.split("\n")[0].strip()
                mde_mapping = map_defender_tables.get(table_name, "")
                appended_query = f"{query}\n{mde_mapping}"
                appended_mde_queries.append(appended_query)

            # Mapping and building Splunk queries
            splunk_queries = compile_splunk_queries(
                indicator_mapping, indicators, indicator_type, splunk_queries
            )

            appended_splunk_queries = []
            for query in splunk_queries:
                # Extract the index name from the query string
                index_name = None
                if query.startswith("index="):
                    index_name = query.split()[0].replace("index=", "")
                if index_name:
                    splunk_mapping = map_splunk_indices.get(index_name, "")
                    appended_query = f"{query}\n{splunk_mapping}"
                    appended_splunk_queries.append(appended_query)
                else:
                    appended_splunk_queries.append(query)

    return appended_mde_queries, appended_splunk_queries
