#!/usr/bin/env python3
"""Test script to generate detections for Scattered Spider"""

import sys
sys.path.insert(0, '.')

from archer.mitre.enterprise import get_stix_data
from archer.mitre.retrieve import retrieve_group, retrieve_techniques, retrieve_procedures
from archer.build.collate import collate_data
from archer.build.yaml import construct_yaml

# Load MITRE ATT&CK data
url = 'https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json'
bundle = get_stix_data(url)

# Get Scattered Spider group ID
group_name = 'Scattered Spider'
group_id = 'intrusion-set--44d37b89-a739-4810-9111-0d2617a8939b'

print(f'\n=== Testing Generation for {group_name} ===\n')

# Step 1: Retrieve techniques (with software expansion)
print('Step 1: Retrieving techniques (with software expansion)...')
techniques = retrieve_techniques(bundle, group_id)
print(f'  Retrieved {len(techniques)} techniques\n')

# Step 2: Retrieve procedures for first 3 techniques (to test without overwhelming output)
print('Step 2: Retrieving procedures for first 3 techniques...')
test_techniques = techniques[:3]  # Just test with 3 techniques
procedures = retrieve_procedures(bundle, test_techniques)
print(f'  Retrieved {len(procedures)} procedures\n')

# Step 3: Check the procedures for software names
print('Step 3: Checking procedures for software names...')
for i, proc in enumerate(procedures[:3]):  # Check first 3
    tech_id, tech_name, tactics, group_desc, op_guidance, red_tools, detect_guidance, proc_platforms, sw_platforms, tech_desc, tech_platforms = proc
    print(f'\nProcedure {i+1}: {tech_name} ({tech_id})')
    print(f'  op_guidance keys: {list(op_guidance.keys()) if isinstance(op_guidance, dict) else "not a dict"}')
    print(f'  red_tools type: {type(red_tools)}')
    if isinstance(red_tools, dict):
        print(f'  red_tools keys: {list(red_tools.keys())}')
        if 'sw' in red_tools:
            print(f'  ⚠️  WARNING: "sw" key still present in red_tools!')
            print(f'  red_tools["sw"]: {red_tools["sw"]}')
    elif isinstance(red_tools, list):
        print(f'  red_tools length: {len(red_tools)}')
        if red_tools:
            print(f'  red_tools sample: {red_tools[:3]}')

print('\n=== Test Complete ===')
