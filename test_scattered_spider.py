#!/usr/bin/env python3
"""
Test script to generate Scattered Spider detections with debug logging
"""
import sys
import os

# Add archer to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from archer.mitre import retrieve_group, retrieve_techniques, retrieve_procedures
from archer.mitre.enterprise import get_stix_data
from archer.build.detections import generate_detections

def main():
    print("=" * 80)
    print("SCATTERED SPIDER DETECTION GENERATION - DEBUG MODE")
    print("=" * 80)

    # Get MITRE ATT&CK data
    print("\n[1] Loading MITRE ATT&CK data...")
    bundle = get_stix_data()
    print(f"    Loaded {len(bundle.objects)} STIX objects")

    # Retrieve group
    print("\n[2] Retrieving Scattered Spider group...")
    group_data = retrieve_group(bundle, "Scattered Spider")
    if not group_data:
        print("    ERROR: Could not find Scattered Spider in MITRE data")
        return

    group_id, group_name, group_description, group_aliases = group_data
    print(f"    Group ID: {group_id}")
    print(f"    Group Name: {group_name}")
    print(f"    Aliases: {group_aliases}")

    # Retrieve techniques
    print("\n[3] Retrieving techniques used by group...")
    techniques = retrieve_techniques(bundle, group_id)
    print(f"    Found {len(techniques)} techniques")
    for tech_id, tech_name in techniques[:5]:  # Show first 5
        print(f"      - {tech_id}: {tech_name}")
    if len(techniques) > 5:
        print(f"      ... and {len(techniques) - 5} more")

    # Retrieve procedures with SOFTWARE TRAVERSAL
    print("\n[4] Retrieving procedures (with software traversal)...")
    print("=" * 80)
    procedures = retrieve_procedures(bundle, group_id)
    print("=" * 80)
    print(f"    Found {len(procedures)} procedures")

    # Show a few procedures with their indicators
    for i, proc in enumerate(procedures[:3]):
        tech_id, tech_name, tactics, desc, op_guidance, red_tools, detect_guidance, proc_platforms, sw_platforms, tech_desc, tech_platforms = proc
        print(f"\n    Procedure {i+1}: {tech_id} - {tech_name}")
        print(f"      Tactics: {tactics}")
        if isinstance(op_guidance, dict):
            print(f"      Indicators found:")
            for ind_type in ["cmd", "api", "sw", "reg", "evt", "network"]:
                if op_guidance.get(ind_type):
                    indicators = op_guidance[ind_type]
                    if isinstance(indicators, list):
                        print(f"        {ind_type}: {len(indicators)} items - {indicators[:2]}...")
                    else:
                        print(f"        {ind_type}: {indicators}")
        else:
            print(f"      op_guidance type: {type(op_guidance)}")

    # Generate detections
    print("\n[5] Generating detections...")
    print("=" * 80)
    detections_data = {
        "detections": [],
        "total_generated": 0,
        "needs_review": []
    }

    results = generate_detections(
        group_id=group_id,
        group_name=group_name,
        group_description=group_description,
        vendor="Splunk",
        include_correlations=False,
        osint_mode="off",
        use_openai=False,
        user_id=1,
        detections_data=detections_data
    )
    print("=" * 80)

    print(f"\n[6] Results:")
    print(f"    Total generated: {results['total_generated']}")
    print(f"    Needs review: {len(results['needs_review'])}")
    print(f"    Detections: {len(results['detections'])}")

    # Show a few generated detection summaries
    for i, det in enumerate(results['detections'][:3]):
        print(f"\n    Detection {i+1}:")
        print(f"      Name: {det.get('name', 'N/A')}")
        print(f"      Severity: {det.get('severity', 'N/A')}")
        print(f"      Tactics: {det.get('tactics', [])}")
        connectors = det.get('requiredDataConnectors', [])
        if connectors:
            for conn in connectors:
                print(f"      Data Source: {conn.get('connectorId', 'N/A')} - {conn.get('dataTypes', [])}")

    print("\n" + "=" * 80)
    print("GENERATION COMPLETE")
    print("=" * 80)

if __name__ == "__main__":
    main()
