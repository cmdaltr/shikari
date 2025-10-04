#!/usr/bin/env python3 -tt
from .extract import extract_red, extract_blue
import re
import requests
import stix2


def get_stix_data(url):
    response = requests.get(url)
    response.raise_for_status()  # raise error if download failed

    # Load the STIX bundle
    return stix2.parse(response.text, allow_custom=True)


def obtain_all_techniques(bundle):
    techniques = []
    for obj in bundle.objects:
        if obj.get("type") == "attack-pattern":
            technique_name = obj.get("name")
            external_id = [
                ref["external_id"]
                for ref in obj.get("external_references", [])
                if "external_id" in ref
            ]
            techniques.append(f"{external_id[0]}: {technique_name}")
    techniques = sorted(list(set(techniques)))  # Remove duplicates

    return techniques


def obtain_technique_descriptions(bundle):
    descriptions = []
    for obj in bundle.objects:
        if obj.get("type") == "attack-pattern":
            technique_description = obj.get("description")
            external_id = [
                ref["external_id"]
                for ref in obj.get("external_references", [])
                if "external_id" in ref
            ]
            descriptions.append(f"{external_id[0]}: {technique_description}")
    descriptions = sorted(list(set(descriptions)))  # Remove duplicates

    return descriptions


def check_group_in_mitre(bundle, group):
    for obj in bundle.objects:
        if obj.get("type") == "intrusion-set":
            group_name = obj.get("name").lower()
            aliases = str(obj.get("aliases")).lower()
            if group.lower() == group_name or group.lower() in aliases:
                return "Y"

    return "N"


def find_procedure_evidence(group_procedure_desc, procedure_desc, detection):
    combined_desc = f"{group_procedure_desc}\n\n{procedure_desc}"
    # add this information to the red/blue team sections of the Template Test Case
    red_info = extract_red(combined_desc)
    blue_info = extract_blue(combined_desc, detection)

    return red_info, blue_info


def consolidate_tactics(phases):
    tactics = []
    phase_names = re.findall(
        r"kill_chain_name='mitre-attack', phase_name='([^']+)", str(phases)
    )
    for phase_name in phase_names:
        tactics.append(phase_name.title().replace("-", " ").replace("_", " "))

    return sorted(list(set(tactics)))


def merge_detect_guidance(data_source, blue_info):
    data_sources = []
    detection_sources = re.findall(r"'[^:]+: ([^']+)'", str(data_source))
    for source in detection_sources:
        data_sources.append(source)

    return (data_sources, blue_info)
