#!/usr/bin/env python3
"""
Extract MITRE ATT&CK procedure examples with associated techniques, tactics, and groups.

This script downloads the latest MITRE ATT&CK STIX data and extracts:
- Procedure examples (from threat groups only)
- Associated techniques (ID, name, description)
- Associated tactics
- Associated groups (ID, name, description) - only groups with IDs starting with "G"

Output is saved as a CSV file with unique combinations, sorted alphabetically by
technique_id, tactic, and group_id.

Note: This script excludes malware and tools, focusing only on threat actor groups.
"""

import csv
import json
from pathlib import Path
from typing import Dict, List, Set, Tuple
import requests
from stix2 import MemoryStore, Filter


def download_attack_data() -> MemoryStore:
    """Download the latest MITRE ATT&CK Enterprise STIX data."""
    print("Downloading MITRE ATT&CK data...")
    url = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"

    response = requests.get(url)
    response.raise_for_status()

    stix_data = response.json()
    return MemoryStore(stix_data=stix_data["objects"])


def get_technique_info(store: MemoryStore, technique_id: str) -> Dict[str, str]:
    """Get technique information by STIX ID."""
    technique = store.get(technique_id)
    if technique:
        # Extract external references to get ATT&CK ID
        attack_id = ""
        for ref in technique.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                attack_id = ref.get("external_id", "")
                break

        return {
            "id": attack_id,
            "name": technique.get("name", ""),
            "description": technique.get("description", "").replace("\n", " ").replace("\r", " ")
        }
    return {"id": "", "name": "", "description": ""}


def get_group_info(store: MemoryStore, group_id: str) -> Dict[str, str]:
    """Get group information by STIX ID."""
    group = store.get(group_id)
    if group:
        # Extract external references to get ATT&CK ID
        attack_id = ""
        for ref in group.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                attack_id = ref.get("external_id", "")
                break

        return {
            "id": attack_id,
            "name": group.get("name", ""),
            "description": group.get("description", "").replace("\n", " ").replace("\r", " ")
        }
    return {"id": "", "name": "", "description": ""}


def get_tactics_for_technique(store: MemoryStore, technique_id: str) -> List[str]:
    """Get all tactics (kill chain phases) for a technique."""
    technique = store.get(technique_id)
    if technique and "kill_chain_phases" in technique:
        tactics = []
        for phase in technique["kill_chain_phases"]:
            if phase.get("kill_chain_name") == "mitre-attack":
                tactic_name = phase.get("phase_name", "")
                # Convert from kebab-case to Title Case
                tactic_name = tactic_name.replace("-", " ").title()
                tactics.append(tactic_name)
        return tactics
    return []


def extract_procedures(store: MemoryStore) -> List[Dict[str, str]]:
    """Extract all procedure examples with associated information."""
    print("Extracting procedure examples...")

    procedures = []
    seen_combinations: Set[Tuple] = set()

    # Get all relationships where the relationship type is "uses"
    relationships = store.query([Filter("type", "=", "relationship")])

    for rel in relationships:
        if rel.get("relationship_type") != "uses":
            continue

        source_ref = rel.get("source_ref", "")
        target_ref = rel.get("target_ref", "")
        description = rel.get("description", "")

        # We're looking for relationships where:
        # - Source is a group (intrusion-set) or malware/tool
        # - Target is a technique (attack-pattern)
        # - Description contains the procedure example

        if not description:
            continue

        source_obj = store.get(source_ref)
        target_obj = store.get(target_ref)

        if not source_obj or not target_obj:
            continue

        # Only process if target is an attack pattern (technique)
        if target_obj.get("type") != "attack-pattern":
            continue

        # Get technique information
        technique_info = get_technique_info(store, target_ref)

        # Get tactics for this technique
        tactics = get_tactics_for_technique(store, target_ref)
        tactics_str = "; ".join(tactics) if tactics else ""

        # Get group information
        source_type = source_obj.get("type")

        # ONLY process intrusion-sets (groups), skip malware and tools
        if source_type == "intrusion-set":
            # This is a group
            group_info = get_group_info(store, source_ref)

            # Only include if group_id starts with "G"
            if not group_info["id"].startswith("G"):
                continue

            # Create entry for each tactic (or one if no tactics)
            if tactics:
                for tactic in tactics:
                    combination = (
                        description,
                        technique_info["id"],
                        technique_info["name"],
                        tactic,
                        group_info["id"],
                        group_info["name"]
                    )

                    if combination not in seen_combinations:
                        seen_combinations.add(combination)
                        procedures.append({
                            "technique_id": technique_info["id"],
                            "technique_name": technique_info["name"],
                            "technique_description": technique_info["description"],
                            "tactic": tactic,
                            "group_id": group_info["id"],
                            "group_name": group_info["name"],
                            "group_description": group_info["description"],
                            "procedure_example": description.replace("\n", " ").replace("\r", " ")
                        })
            else:
                combination = (
                    description,
                    technique_info["id"],
                    technique_info["name"],
                    "",
                    group_info["id"],
                    group_info["name"]
                )

                if combination not in seen_combinations:
                    seen_combinations.add(combination)
                    procedures.append({
                        "technique_id": technique_info["id"],
                        "technique_name": technique_info["name"],
                        "technique_description": technique_info["description"],
                        "tactic": "",
                        "group_id": group_info["id"],
                        "group_name": group_info["name"],
                        "group_description": group_info["description"],
                        "procedure_example": description.replace("\n", " ").replace("\r", " ")
                    })

    return procedures


def save_to_csv(procedures: List[Dict[str, str]], output_file: str):
    """Save procedures to CSV file with alphabetical sorting."""
    print(f"Sorting and saving {len(procedures)} unique procedure combinations to {output_file}...")

    # Sort alphabetically by technique_id, then tactic, then group_id
    sorted_procedures = sorted(procedures, key=lambda x: (x["technique_id"], x["tactic"], x["group_id"]))

    fieldnames = [
        "technique_id",
        "technique_name",
        "tactic",
        "group_id",
        "group_name",
        "procedure_example",
        "group_description",
        "technique_description"
    ]

    with open(output_file, "w", newline="", encoding="utf-8") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(sorted_procedures)

    print(f"✓ Successfully saved {len(sorted_procedures)} procedures to {output_file}")


def main():
    """Main execution function."""
    try:
        # Download MITRE ATT&CK data
        store = download_attack_data()

        # Extract procedures
        procedures = extract_procedures(store)

        # Save to CSV
        output_dir = Path(__file__).parent.parent / "data"
        output_dir.mkdir(exist_ok=True)
        output_file = output_dir / "mitre_procedures.csv"

        save_to_csv(procedures, str(output_file))

        # Print summary statistics
        print("\n=== Summary ===")
        print(f"Total unique procedure combinations: {len(procedures)}")

        unique_techniques = len(set(p["technique_id"] for p in procedures if p["technique_id"]))
        print(f"Unique techniques: {unique_techniques}")

        unique_tactics = len(set(p["tactic"] for p in procedures if p["tactic"]))
        print(f"Unique tactics: {unique_tactics}")

        unique_groups = len(set(p["group_id"] for p in procedures if p["group_id"]))
        print(f"Unique groups: {unique_groups}")

    except Exception as e:
        print(f"Error: {e}")
        raise


if __name__ == "__main__":
    main()
