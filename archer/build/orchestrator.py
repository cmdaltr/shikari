#!/usr/bin/env python3
from archer.mitre import (
    get_stix_data,
    obtain_all_techniques,
    obtain_technique_descriptions,
    check_group_in_mitre,
    retrieve_group,
    retrieve_techniques,
    retrieve_procedures,
)

# Apply performance patch for fast tactic lookups
from archer.build import yaml_patch  # This patches yaml.additional_tactics()

from archer.build.detections import compile_query
from archer.build.progress import write_progress
from archer.genai import generate_correlations
from archer.config import GENERATE_DIR, CORRELATE_DIR
import os
from pathlib import Path


def safe_progress_update(group_name, status_data):
    """Helper function to safely update progress"""
    try:
        write_progress(group_name, status_data)
    except Exception:
        pass


def process_group(group_name, output_dir=None, hypothesis=None, manual_data=None, run_correlation=False, osint_enhancement=False):
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
                retrieved_data["technique_id"] = technique  # Add technique ID

                # Handle op_guidance - can be dict (IOCs) or string (description)
                op_guidance_val = tech_info.get("op_guidance", {})
                if isinstance(op_guidance_val, str) and op_guidance_val == "":
                    op_guidance_val = {}  # Empty string becomes empty dict
                retrieved_data["op_guidance"] = op_guidance_val

                # Handle red_tool - should be dict
                red_tool_val = tech_info.get("red_tool", {})
                if isinstance(red_tool_val, str) and red_tool_val == "":
                    red_tool_val = {}  # Empty string becomes empty dict
                retrieved_data["red_tool"] = red_tool_val

                retrieved_data["detect_guidance"] = tech_info.get("detect_guidance", "")

                # Extract procedure_platforms and software_platforms from tech_info (for CVE manual data)
                retrieved_data["procedure_platforms"] = tech_info.get("procedure_platforms", [])
                retrieved_data["software_platforms"] = tech_info.get("software_platforms", {})

                # Get technique description and platforms from MITRE data for better detection generation
                # technique_descriptions is a list of strings like ["T1059: Description...", ...]
                # We need to find the matching technique and extract its description
                tech_desc_str = None
                for desc in technique_descriptions:
                    if desc.startswith(f"{technique}:"):
                        tech_desc_str = desc.split(":", 1)[1].strip() if ":" in desc else ""
                        break

                if tech_desc_str:
                    retrieved_data["technique_description"] = tech_desc_str
                else:
                    # CVE-specific technique without MITRE data (synthetic technique)
                    retrieved_data["technique_description"] = f"CVE exploitation technique: {technique}"

                # Get platforms from STIX bundle directly
                technique_platforms = []
                for obj in bundle.objects:
                    if obj.get("type") == "attack-pattern":
                        external_refs = obj.get("external_references", [])
                        for ref in external_refs:
                            if ref.get("external_id") == technique:
                                technique_platforms = obj.get("x_mitre_platforms", [])
                                break
                        if technique_platforms:
                            break

                retrieved_data["technique_platforms"] = technique_platforms if technique_platforms else ["Windows", "Linux", "macOS"]

                # Add activity_desc - use detect_guidance (string) not op_guidance (dict)
                # For CVEs, op_guidance is the IOC dict, detect_guidance is the description string
                retrieved_data["activity_desc"] = tech_info.get("detect_guidance", "") or f"Detection for {technique}"

                # Build detection queries and YAML
                compile_query(retrieved_data, osint_enhancement=osint_enhancement)
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

            # Add platform data if available (in procedure[7] and procedure[8])
            if len(procedure) > 7:
                retrieved_data["procedure_platforms"] = procedure[7]
                retrieved_data["software_platforms"] = procedure[8]

            # Add technique description and platforms for enhanced validation (procedure[9] and procedure[10])
            if len(procedure) > 9:
                retrieved_data["technique_description"] = procedure[9]
                retrieved_data["technique_platforms"] = procedure[10]

            compile_query(retrieved_data, osint_enhancement=osint_enhancement)
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

    # After YAMLs are created, run the GenAI correlation generator only if requested and YAMLs exist
    if run_correlation and created > 0:
        try:
            safe_progress_update(group_name, {
                "status": "genai_starting",
                "created_yaml": created,
                "total_yaml": total,
            })
            # YAMLs are written to data/generate/ directory
            yaml_dir = GENERATE_DIR
            generate_correlations(group_name, yaml_dir)

            # Generate attack flow visualizations
            try:
                from archer.visualization.attack_flow import generate_all_correlation_flows, generate_actor_flow

                # Generate flows for each correlation
                correlations_file = os.path.join(CORRELATE_DIR, f"{group_name}.json")
                if os.path.exists(correlations_file):
                    print(f"Generating attack flow diagrams for correlations...")
                    generate_all_correlation_flows(group_name, correlations_file)

                # Generate complete actor flow using techniques from procedures
                if group_in_mitre == "Y" and 'procedures' in locals():
                    # Extract technique IDs and tactics from procedures
                    all_techniques = [proc[0] for proc in procedures if proc[0]]  # proc[0] is technique_id
                    tactics_map = {}
                    for proc in procedures:
                        tech_id = proc[0]
                        tactics = proc[2] if len(proc) > 2 else []  # proc[2] is tactics list
                        for tactic in tactics:
                            if tactic:
                                tactics_map.setdefault(tactic, []).append(tech_id)

                    if all_techniques:
                        print(f"Generating complete actor attack flow with {len(all_techniques)} techniques...")
                        generate_actor_flow(group_name, all_techniques, tactics_map)
                elif manual_data:
                    # For manual data, extract from manual_data structure
                    all_techniques = []
                    tactics_map = {}
                    for entry in manual_data:
                        tactic = entry.get("tactic")
                        techniques = entry.get("techniques", [])
                        for tech_info in techniques:
                            tech_id = tech_info.get("technique")
                            if tech_id:
                                all_techniques.append(tech_id)
                                if tactic:
                                    tactics_map.setdefault(tactic, []).append(tech_id)

                    if all_techniques:
                        print(f"Generating complete actor attack flow with {len(all_techniques)} techniques (manual)...")
                        generate_actor_flow(group_name, all_techniques, tactics_map)
            except Exception as flow_error:
                print(f"Attack flow generation warning: {flow_error}")
                import traceback
                traceback.print_exc()
                # Don't fail the entire process if attack flow generation fails

            safe_progress_update(group_name, {
                "status": "complete",
                "created_yaml": created,
                "total_yaml": total,
            })
        except Exception as e:
            print(f"Correlation error: {e}")
            import traceback
            traceback.print_exc()
            safe_progress_update(group_name, {
                "status": "genai_failed",
                "created_yaml": created,
                "total_yaml": total,
            })
    else:
        safe_progress_update(group_name, {
            "status": "complete",
            "created_yaml": created,
            "total_yaml": total,
        })


def write_splunk_files(
    queries_by_index, output_dir, procedure_platforms=None, software_platforms=None
):
    """
    Write compiled queries to files.
    """
    from archer.build.queries import is_query_applicable

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
            # Handle case where index_name might not be a string
            if not isinstance(index_name, str):
                print(f"⚠️ WARNING: index_name is type {type(index_name)}, skipping: {index_name}")
                continue
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
