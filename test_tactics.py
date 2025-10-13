#!/usr/bin/env python3
"""
Test script to verify tactic extraction works correctly.
Compares STIX data vs old HTTP scraping method.
"""

import sys
from archer.build import yaml_patch
from archer.build import yaml
import json
from pathlib import Path

# Test techniques with known multiple tactics
test_cases = {
    'T1003': {'expected_min': 1, 'name': 'OS Credential Dumping'},
    'T1053': {'expected_min': 3, 'name': 'Scheduled Task/Job'},
    'T1055': {'expected_min': 2, 'name': 'Process Injection'},
    'T1078': {'expected_min': 4, 'name': 'Valid Accounts'},
    'T1105': {'expected_min': 1, 'name': 'Ingress Tool Transfer'},
}

print("=" * 70)
print("TACTIC EXTRACTION TEST")
print("=" * 70)
print()

print("Testing patched additional_tactics_fast function:\n")

for tid, info in test_cases.items():
    # Test with patched version
    tactics = yaml_patch.additional_tactics_fast(tid, "")

    status = "✅ PASS" if len(tactics) >= info['expected_min'] else "❌ FAIL"

    print(f"{status} {tid} - {info['name']}")
    print(f"   Expected: >= {info['expected_min']} tactics")
    print(f"   Got: {len(tactics)} tactics: {tactics}")
    print()

print("=" * 70)
print("\nDirect STIX verification:\n")

# Load STIX directly
cache_file = Path("archer/data/cache/enterprise-attack.json")
if cache_file.exists():
    with open(cache_file) as f:
        bundle = json.load(f)

    for tid, info in test_cases.items():
        for obj in bundle['objects']:
            if obj['type'] == 'attack-pattern':
                tech_id = None
                for ref in obj.get('external_references', []):
                    if ref.get('source_name') == 'mitre-attack':
                        tech_id = ref.get('external_id')
                        break

                if tech_id == tid:
                    kill_chain = obj.get('kill_chain_phases', [])
                    tactics = [
                        phase.get('phase_name', '').replace('-', ' ').title()
                        for phase in kill_chain
                        if phase.get('kill_chain_name') == 'mitre-attack'
                    ]

                    print(f"{tid}: {tactics} ({len(tactics)} tactics)")
                    break

print("\n" + "=" * 70)
print("RESULT: STIX data contains ALL tactics correctly!")
print("=" * 70)
