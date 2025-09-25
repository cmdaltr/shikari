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

from gorgon.build import compile_query


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

    if group_in_mitre == "N":
        # manual_data must be provided
        if not manual_data:
            raise ValueError(
                f"Group '{group_name}' not found in MITRE ATT&CK and no manual data provided. Cannot proceed."
            )

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
                compile_query(retrieved_data, technique_descriptions)

    else:
        # retrieve group id based on group name provided
        group_id = retrieve_group(bundle, group_name)
        # retrieve techniques employed by that group
        retrieved_techniques = retrieve_techniques(bundle, group_id)
        # retrieve every procedure example of each technique
        procedures = retrieve_procedures(bundle, retrieved_techniques)

        for procedure in procedures:
            retrieved_data["technique_id"] = procedure[0]
            retrieved_data["technique"] = procedure[1]
            retrieved_data["tactic"] = procedure[2][0]
            retrieved_data["activity_desc"] = procedure[3]
            retrieved_data["op_guidance"] = procedure[4]
            retrieved_data["red_tool"] = procedure[5]
            retrieved_data["detect_guidance"] = procedure[6][0]

            compile_query(retrieved_data, technique_descriptions)


def main():
    # Example hard-coded inputs for testing
    group_name = "Example Group"
    hypothesis = "Example hypothesis about the group"

    # Example manual_data structure for a group not in MITRE
    manual_data = [
        {
            "tactic": "Initial Access",
            "techniques": [
                {
                    "technique": "Spearphishing Attachment",
                    "op_guidance": "Use email filters and educate users.",
                    "red_tool": "Phishing toolkit",
                    "detect_guidance": "Monitor email attachments for suspicious content.",
                },
                {
                    "technique": "Drive-by Compromise",
                    "op_guidance": "Keep browsers updated.",
                    "red_tool": "Malicious website simulation",
                    "detect_guidance": "Check web traffic for unusual downloads.",
                },
            ],
        },
        {
            "tactic": "Execution",
            "techniques": [
                {
                    "technique": "PowerShell",
                    "op_guidance": "Restrict PowerShell usage.",
                    "red_tool": "PowerShell Empire",
                    "detect_guidance": "Monitor PowerShell command logs.",
                }
            ],
        },
    ]

    # Call process_group with manual_data to simulate a group not in MITRE
    process_group(group_name, hypothesis, manual_data=manual_data)

    # For a group in MITRE, call without manual_data
    # process_group("APT29", "Hypothesis about APT29")


if __name__ == "__main__":
    main()
