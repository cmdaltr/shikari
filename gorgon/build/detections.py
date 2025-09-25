from .yaml import construct_yaml
from gorgon.mitre.enterprise import (
    get_stix_data,
    obtain_all_techniques,
    obtain_technique_descriptions,
)
from gorgon.mitre.retrieve import retrieve_techniques, retrieve_procedures


def compile_query(retrieved_data, technique_descriptions):
    # Extract values from retrieved_data
    name = retrieved_data.get("technique")
    tid = retrieved_data.get("technique_id")
    tdesc = retrieved_data.get("activity_desc")
    tactic = retrieved_data.get("tactic")
    tag = retrieved_data.get("tactic")
    op_guidance = retrieved_data.get("op_guidance")
    red_tool = retrieved_data.get("red_tool")
    log_sources = retrieved_data.get("detect_guidance")
    # detect_guidance = retrieved_data.get("detect_guidance")

    if type(op_guidance) is not dict and type(red_tool) is not dict:
        identifiers = {}
    elif type(op_guidance) is not dict:
        identifiers = red_tool
    elif type(red_tool) is not dict:
        identifiers = op_guidance
    else:
        identifiers = {**op_guidance, **red_tool}
    op_guidance = None
    red_tool = None

    # Only construct YAML if there is means of detection
    if identifiers:
        construct_yaml(
            name,
            tid,
            tdesc,
            tactic,
            tag,
            identifiers,
            log_sources,
        )


def main():
    # Load MITRE enterprise ATT&CK bundle
    bundle = get_stix_data(
        "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"
    )

    # Get all techniques
    techniques = obtain_all_techniques(bundle)
    technique_descriptions = obtain_technique_descriptions(bundle)

    # Process each technique
    for technique in techniques:
        # Find procedures for the technique
        procedures = retrieve_procedures(bundle, [technique])
        for procedure in procedures:
            compile_query(procedure, technique_descriptions)


if __name__ == "__main__":
    main()
