#!/usr/bin/env python3
from gorgon.mitre import (
    get_stix_data,
    obtain_all_techniques,
    obtain_technique_descriptions,
    check_group_in_mitre,
    retrieve_group,
    retrieve_techniques,
    retrieve_procedures,
)

from gorgon.build.detections import compile_query
from gorgon.build.progress import write_progress
from gorgon.genai import generate_correlations
import os
from pathlib import Path


def safe_progress_update(group_name, status_data):
    """Helper function to safely update progress"""
    try:
        write_progress(group_name, status_data)
    except Exception:
        pass


def process_group(group_name, output_dir=None, hypothesis=None, manual_data=None):
    # mitre variables
    url = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"
    bundle = get_stix_data(url)
    technique_descriptions = obtain_technique_descriptions(bundle)

    retrieved_data = {
        "group_name": group_name,
        "hypothesis": hypothesis,
    }

    group_in_mitre = check_group_in_mitre(bundle, group_name)

    # initialize a progress file for the group
    safe_progress_update(
        group_name, {"status": "started", "stage": "init", "created_yaml": 0}
    )

    if group_in_mitre == "N":
        # manual_data must be provided
        if not manual_data:
            raise ValueError(
                f"Group '{group_name}' not found in MITRE ATT&CK and no manual data provided. Cannot proceed."
            )
        # compute total expected YAMLs for progress reporting
        total = sum(len(entry.get("techniques", [])) for entry in manual_data)
        safe_progress_update(
            group_name,
            {
                "status": "creating_yamls",
                "stage": "yaml",
                "created_yaml": 0,
                "total_yaml": total,
            },
        )

        created = 0
        for entry in manual_data:
            tactic = entry.get("tactic")
            techniques = entry.get("techniques", [])
            retrieved_data["tactic"] = tactic
            for tech_info in techniques:
                technique = tech_info.get("technique")
                retrieved_data["technique"] = technique
                retrieved_data["op_guidance"] = tech_info.get("op_guidance", "")
                retrieved_data["red_tool"] = tech_info.get("red_tool", "")
                retrieved_data["detect_guidance"] = tech_info.get("detect_guidance", "")

                # Build detection queries and YAML
                compile_query(retrieved_data)
                created += 1
                safe_progress_update(
                    group_name,
                    {
                        "status": "creating_yamls",
                        "stage": "yaml",
                        "created_yaml": created,
                        "total_yaml": total,
                    },
                )

    else:
        # retrieve group id based on group name provided
        group_id = retrieve_group(bundle, group_name)
        retrieved_techniques = retrieve_techniques(bundle, group_id)
        procedures = retrieve_procedures(bundle, retrieved_techniques)

        created = 0
        total = len(procedures)
        safe_progress_update(
            group_name,
            {
                "status": "creating_yamls",
                "stage": "yaml",
                "created_yaml": 0,
                "total_yaml": total,
            },
        )

        for procedure in procedures:
            retrieved_data["technique_id"] = procedure[0]
            retrieved_data["technique"] = procedure[1]
            retrieved_data["tactic"] = procedure[2][0]
            retrieved_data["activity_desc"] = procedure[3]
            retrieved_data["op_guidance"] = procedure[4]
            retrieved_data["red_tool"] = procedure[5]
            retrieved_data["detect_guidance"] = procedure[6][0]

            # Add platform data if available (assuming it's in procedure[7] and procedure[8])
            if len(procedure) > 7:
                retrieved_data["procedure_platforms"] = procedure[7]
                retrieved_data["software_platforms"] = procedure[8]
                # Debug output to see what platforms are detected
                print(f"Procedure platforms: {procedure[7]}")
                print(f"Software platforms: {procedure[8]}")

            compile_query(retrieved_data)
            created += 1
            safe_progress_update(
                group_name,
                {
                    "status": "creating_yamls",
                    "stage": "yaml",
                    "created_yaml": created,
                    "total_yaml": total,
                },
            )

    # After YAMLs are created, run the GenAI correlation generator
    try:
        safe_progress_update(group_name, {"status": "genai_starting"})
        # assume YAMLs are under data/yamls/<group_name> or similar; compile_query should write them
        yaml_dir = os.path.join("data", "yamls", group_name)
        generate_correlations(group_name, yaml_dir)
        safe_progress_update(group_name, {"status": "complete"})
    except Exception:
        safe_progress_update(group_name, {"status": "genai_failed"})


def write_splunk_files(
    queries_by_index, output_dir, procedure_platforms=None, software_platforms=None
):
    """
    Write compiled queries to files.
    """
    from gorgon.build.queries import is_query_applicable

    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    file_paths = []

    # Create debug directory if needed
    debug_dir = Path("./debug_output")
    debug_dir.mkdir(exist_ok=True)

    for index_name, queries in queries_by_index.items():
        for i, query in enumerate(queries):
            # Check if query is applicable for this index based on platforms
            if procedure_platforms and software_platforms:
                if not is_query_applicable(
                    procedure_platforms, software_platforms, index_name
                ):
                    with open(debug_dir / "skipped_queries.log", "a") as f:
                        f.write(f"SKIPPED query for {index_name}\n")
                        f.write(f"Reason: Platform incompatibility\n")
                        f.write(f"{query}\n\n")
                    continue

            # Safe to write
            index_safe = index_name.replace("=", "").replace(" ", "_")
            file_name = f"splunk_{index_safe}.spl"
            file_path = output_path / file_name

            with open(file_path, "w") as f:
                f.write(query)

            file_paths.append(str(file_path))

    return file_paths


def sanitize_output_files(output_dir):
    """
    Final safety check to remove any problematic YAML files.
    """
    if not output_dir:
        return

    yaml_files = list(Path(output_dir).glob("*.yaml"))
    for file_path in yaml_files:
        try:
            with open(file_path, "r") as f:
                content = f.read().lower()

            # Check for Windows commands in AWS files
            if "aws_" in file_path.name.lower() or "aws-" in file_path.name.lower():
                windows_patterns = [
                    "ntds.dit",
                    "ninjacopy",
                    "vssadmin",
                    "wbadmin",
                    "dcsync",
                    "ntdsutil",
                    "powershell",
                    "cmd.exe",
                ]
                if any(pattern in content for pattern in windows_patterns):
                    # Log and remove the file
                    debug_dir = Path("./debug_output")
                    debug_dir.mkdir(exist_ok=True)
                    with open(debug_dir / "removed_files.log", "a") as f:
                        f.write(f"REMOVED: {file_path}\n")
                        f.write(f"Reason: Windows commands in AWS file\n\n")

                    # Delete the problematic file
                    os.remove(file_path)
        except Exception as e:
            # Log errors but continue
            debug_dir = Path("./debug_output")
            debug_dir.mkdir(exist_ok=True)
            with open(debug_dir / "sanitize_errors.log", "a") as f:
                f.write(f"Error processing {file_path}: {str(e)}\n")
