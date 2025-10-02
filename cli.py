#!/usr/bin/env python3
"""
Command-line interface for Archer functionality.
Run this script directly to access core features without starting the web server.
"""

import os
import sys
import argparse
from pathlib import Path

# Add the project root to the path so we can import our modules
sys.path.insert(0, str(Path(__file__).parent))


def run_genai(group_name, yaml_dir=None):
    """Run the GenAI correlation processing for a specific group"""
    from gorgon import genai

    if yaml_dir is None:
        yaml_dir = os.path.join("data", "queries")

    print(f"Starting GenAI processing for group: {group_name}")
    print(f"YAML directory: {yaml_dir}")

    result = genai.generate_correlations(group_name, yaml_dir)
    print(
        f"Processing complete. Generated {len(result.get('vendor_correlations', []))} vendor correlations "
        f"and {len(result.get('cross_vendor_correlations', []))} cross-vendor correlations."
    )

    return result


def process_group(group_name, hypothesis=None, manual_data=None):
    """Run the process_group function to generate YAML files"""
    from gorgon.build.orchestrator import process_group

    print(f"Starting process_group for: {group_name}")
    if hypothesis:
        print(f"Hypothesis: {hypothesis}")
    if manual_data:
        print(f"Using manual data with {len(manual_data)} entries")

    process_group(group_name, hypothesis, manual_data)
    print(f"YAML generation complete for {group_name}")


def list_techniques():
    """List all available techniques from MITRE ATT&CK"""
    from gorgon.mitre import get_stix_data, obtain_all_techniques

    print("Fetching MITRE ATT&CK data...")
    bundle = get_stix_data(
        "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"
    )

    techniques = obtain_all_techniques(bundle)
    print(f"Found {len(techniques)} techniques:")

    for i, technique in enumerate(techniques, 1):
        print(f"{i}. {technique}")

    return techniques


def generate_detection(technique_name):
    """Generate a detection for a specific technique"""
    from gorgon.mitre import get_stix_data, obtain_all_techniques
    from gorgon.mitre.retrieve import retrieve_procedures
    from gorgon.build.detections import compile_query

    print(f"Generating detection for technique: {technique_name}")

    bundle = get_stix_data(
        "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"
    )
    techniques = obtain_all_techniques(bundle)

    # Find matching technique
    matching = [t for t in techniques if technique_name.lower() in t.lower()]

    if not matching:
        print(f"Error: No technique found matching '{technique_name}'")
        return

    if len(matching) > 1:
        print(f"Multiple techniques match '{technique_name}':")
        for i, m in enumerate(matching, 1):
            print(f"{i}. {m}")
        try:
            idx = int(input("Enter the number of the technique to use: ")) - 1
            if 0 <= idx < len(matching):
                technique = matching[idx]
            else:
                print("Invalid selection.")
                return
        except (ValueError, IndexError):
            print("Invalid selection.")
            return
    else:
        technique = matching[0]

    print(f"Using technique: {technique}")
    procedures = retrieve_procedures(bundle, [technique])

    if not procedures:
        print(f"No procedures found for {technique}")
        return

    print(f"Found {len(procedures)} procedures. Generating detections...")

    for procedure in procedures:
        compile_query(procedure)

    print("Detection generation complete.")


def main():
    parser = argparse.ArgumentParser(
        description="Archer CLI - Run core functionality without web interface"
    )
    subparsers = parser.add_subparsers(dest="command", help="Command to run")

    # GenAI correlation processing
    genai_parser = subparsers.add_parser(
        "genai", help="Run GenAI correlation processing"
    )
    genai_parser.add_argument("group_name", help="Name of the group to process")
    genai_parser.add_argument(
        "--yaml-dir", help="Directory containing YAML files (default: data/queries)"
    )

    # Process group
    process_parser = subparsers.add_parser(
        "process-group", help="Generate YAML files for a group"
    )
    process_parser.add_argument("group_name", help="Name of the group to process")
    process_parser.add_argument("--hypothesis", help="Hypothesis for the group")

    # List techniques
    list_parser = subparsers.add_parser(
        "list-techniques", help="List all available techniques"
    )

    # Generate detection
    detect_parser = subparsers.add_parser(
        "detect", help="Generate a detection for a specific technique"
    )
    detect_parser.add_argument(
        "technique", help="Name of the technique (partial match supported)"
    )

    args = parser.parse_args()

    if args.command == "genai":
        run_genai(args.group_name, args.yaml_dir)
    elif args.command == "process-group":
        process_group(args.group_name, args.hypothesis)
    elif args.command == "list-techniques":
        list_techniques()
    elif args.command == "detect":
        generate_detection(args.technique)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
