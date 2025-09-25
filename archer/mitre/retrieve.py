#!/usr/bin/env python3 -tt
 (
    consolidate_tactics,
    find_procedure_evidence,
    merge_detect_guidance,
)


def retrieve_group(bundle, group):
    for obj in bundle.objects:
        if (
            obj.get("type") == "intrusion-set"
            and obj.get("name").lower() == group.lower()
        ):
            return obj["id"]


def retrieve_techniques(bundle, group_id):
    techniques = []
    for obj in bundle.objects:
        if (
            obj.get("type") == "relationship"
            and obj.get("relationship_type") == "uses"
            and obj.get("source_ref") == group_id
        ):
            techniques.append((obj.get("description"), obj.get("target_ref")))

    return techniques


def retrieve_procedures(bundle, retrieved_techniques):
    procedures = []
    for obj in bundle.objects:
        for group_procedure_desc, procedure_ref in retrieved_techniques:
            if obj.get("type") == "attack-pattern" and obj.get("id") == procedure_ref:
                red_info, blue_info = find_procedure_evidence(
                    group_procedure_desc, obj["description"], obj["x_mitre_detection"]
                )
                tactics = consolidate_tactics(obj["kill_chain_phases"])
                op_guidance, red_tools = red_info
                try:  # not all procedures have means of detection
                    detect_guidance = merge_detect_guidance(
                        obj["x_mitre_data_sources"], blue_info
                    )
                except:
                    detect_guidance = [[""]]
                procedures.append(
                    (
                        obj["external_references"][0]["external_id"],
                        obj["name"],
                        tactics,
                        group_procedure_desc,
                        op_guidance,
                        red_tools,
                        detect_guidance,
                    )
                )

    return procedures
