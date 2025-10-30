#!/usr/bin/env python3
"""
Direct test of software traversal functionality
"""
from archer.mitre import retrieve_procedures, get_stix_data

# Get MITRE data
url = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"
bundle = get_stix_data(url)

# Scattered Spider group ID
group_id = "intrusion-set--44d37b89-a739-4810-9111-0d2617a8939b"

print("=" * 80)
print("TESTING SOFTWARE TRAVERSAL")
print("=" * 80)

# Retrieve procedures
procedures = retrieve_procedures(bundle, group_id)

print(f"\nRetrieved {len(procedures)} procedures")
print("\nFirst 3 procedures:")
for i, proc in enumerate(procedures[:3]):
    tech_id, tech_name, tactics, desc, op_guidance, red_tools, detect_guidance, proc_platforms, sw_platforms, tech_desc, tech_platforms = proc
    print(f"\n{i+1}. {tech_id} - {tech_name}")
    print(f"   Tactics: {tactics}")
    print(f"   op_guidance type: {type(op_guidance)}")
    if isinstance(op_guidance, dict):
        for key in ["cmd", "api", "sw", "reg"]:
            if op_guidance.get(key):
                val = op_guidance[key]
                if isinstance(val, list):
                    print(f"   {key}: {val[:3]}")
                else:
                    print(f"   {key}: {val}")

print("\n" + "=" * 80)
print("END OF TEST")
print("=" * 80)
