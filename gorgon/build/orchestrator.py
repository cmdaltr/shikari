#!/usr/bin/env python3
from gorgon.mitre import (
    get_stix_data,
    obtain_all_techniques,
    obtain_technique_descriptions,
    check_group_in_mitre,
)
from gorgon.mitre import (
    retrieve_group,
    retrieve_techniques,
    retrieve_procedures,
)

from gorgon.build.detections import compile_query
from gorgon.build.progress import write_progress
from gorgon.genai import generate_correlations
import os
from gorgon.build.progress import write_progress
from gorgon.genai import generate_correlations


def process_group(group_name, hypothesis, manual_data=None):
    """
    Processes a threat actor group with given inputs.

    Parameters:
    - group_name: str, name of the threat actor group
    - hypothesis: str, hypothesis text
    - manual_data: list of dicts, each dict containing:
        {
            'tactic': str,
            'techniques': list of dicts with keys:
                'technique': str,
                'op_guidance': str,
                'red_tool': str,
                'detect_guidance': str
        }
      If manual_data is None, MITRE lookups will be used.
    """
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
    try:
        write_progress(
            group_name, {"status": "started", "stage": "init", "created_yaml": 0}
        )
    except Exception:
        pass

    if group_in_mitre == "N":
        # manual_data must be provided
        if not manual_data:
            raise ValueError(
                f"Group '{group_name}' not found in MITRE ATT&CK and no manual data provided. Cannot proceed."
            )
        # compute total expected YAMLs for progress reporting
        total = sum(len(entry.get("techniques", [])) for entry in manual_data)
        try:
            write_progress(
                group_name,
                {
                    "status": "creating_yamls",
                    "stage": "yaml",
                    "created_yaml": 0,
                    "total_yaml": total,
                },
            )
        except Exception:
            pass

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
                try:
                    write_progress(
                        group_name,
                        {
                            "status": "creating_yamls",
                            "stage": "yaml",
                            "created_yaml": created,
                            "total_yaml": total,
                        },
                    )
                except Exception:
                    pass

    else:
        # retrieve group id based on group name provided
        group_id = retrieve_group(bundle, group_name)
        # retrieve techniques employed by that group
        retrieved_techniques = retrieve_techniques(bundle, group_id)
        # retrieve every procedure example of each technique
        procedures = retrieve_procedures(bundle, retrieved_techniques)

        created = 0
        total = len(procedures)
        try:
            write_progress(
                group_name,
                {
                    "status": "creating_yamls",
                    "stage": "yaml",
                    "created_yaml": 0,
                    "total_yaml": total,
                },
            )
        except Exception:
            pass

        for procedure in procedures:
            retrieved_data["technique_id"] = procedure[0]
            retrieved_data["technique"] = procedure[1]
            retrieved_data["tactic"] = procedure[2][0]
            retrieved_data["activity_desc"] = procedure[3]
            retrieved_data["op_guidance"] = procedure[4]
            retrieved_data["red_tool"] = procedure[5]
            retrieved_data["detect_guidance"] = procedure[6][0]

            compile_query(retrieved_data)
            created += 1
            try:
                write_progress(
                    group_name,
                    {
                        "status": "creating_yamls",
                        "stage": "yaml",
                        "created_yaml": created,
                        "total_yaml": total,
                    },
                )
            except Exception:
                pass
    # After YAMLs are created, run the GenAI correlation generator
    try:
        write_progress(group_name, {"status": "genai_starting"})
        # assume YAMLs are under data/yamls/<group_name> or similar; compile_query should write them
        yaml_dir = os.path.join("data", "yamls", group_name)
        generate_correlations(group_name, yaml_dir)
        write_progress(group_name, {"status": "complete"})
    except Exception:
        try:
            write_progress(group_name, {"status": "genai_failed"})
        except Exception:
            pass
