#!/usr/bin/env python3
"""Full generation test for Scattered Spider with detailed reporting"""

import sys
sys.path.insert(0, '.')

from archer.mitre.enterprise import get_stix_data
from archer.mitre.retrieve import retrieve_group, retrieve_techniques, retrieve_procedures
from archer.build.collate import collate_data
from archer.build.yaml import construct_yaml
from pathlib import Path
import json

# Load MITRE ATT&CK data
url = 'https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json'
bundle = get_stix_data(url)

# Get Scattered Spider
group_name = 'Scattered Spider'
group_id = 'intrusion-set--44d37b89-a739-4810-9111-0d2617a8939b'

print(f'\n{"="*80}')
print(f'FULL GENERATION TEST: {group_name}')
print(f'{"="*80}\n')

# Step 1: Retrieve techniques
print('Step 1: Retrieving techniques (with software expansion)...')
techniques = retrieve_techniques(bundle, group_id)
print(f'  ✓ Retrieved {len(techniques)} techniques\n')

# Step 2: Retrieve procedures
print('Step 2: Retrieving procedures for all techniques...')
procedures = retrieve_procedures(bundle, techniques)
print(f'  ✓ Retrieved {len(procedures)} procedures\n')

# Step 3: Analyze procedures for issues
print('Step 3: Analyzing procedures for software names...')
software_names_found = []
procedures_with_indicators = 0
procedures_without_indicators = 0

for proc in procedures:
    tech_id, tech_name, tactics, group_desc, op_guidance, red_tools, detect_guidance, proc_platforms, sw_platforms, tech_desc, tech_platforms = proc

    # Check if technique name looks like software (has S#### pattern)
    if tech_id.startswith('S'):
        software_names_found.append(f"{tech_name} ({tech_id})")

    # Check if has indicators
    has_indicators = False
    if isinstance(op_guidance, dict):
        if op_guidance.get('cmd') or op_guidance.get('api') or op_guidance.get('reg') or op_guidance.get('evt'):
            has_indicators = True

    if has_indicators:
        procedures_with_indicators += 1
    else:
        procedures_without_indicators += 1

    # Check if red_tools still has 'sw' key
    if isinstance(red_tools, dict) and 'sw' in red_tools:
        print(f"  ⚠️  WARNING: Found 'sw' key in {tech_name} ({tech_id})")
        print(f"      Software names: {red_tools['sw']}")

if software_names_found:
    print(f'  ⚠️  Found {len(software_names_found)} procedures with software IDs:')
    for sw in software_names_found[:5]:  # Show first 5
        print(f'      - {sw}')
    if len(software_names_found) > 5:
        print(f'      ... and {len(software_names_found) - 5} more')
else:
    print(f'  ✓ No software IDs found as technique names')

print(f'\n  Procedures with indicators: {procedures_with_indicators}')
print(f'  Procedures without indicators: {procedures_without_indicators}')

# Step 4: Collate data
print('\nStep 4: Collating data by technique and data source...')
collated = collate_data(procedures)
print(f'  ✓ Collated into {len(collated)} detection rules\n')

# Step 5: Generate YAML files
print('Step 5: Generating YAML detection files...')
output_dir = Path('data/generate')
output_dir.mkdir(exist_ok=True)

# Clear existing files
for f in output_dir.glob('*.yaml'):
    f.unlink()

yaml_files = []
for detection in collated:
    tech_id, tech_name, data_source, tactics, combined_op_guidance, combined_detect_guidance, combined_platforms, combined_sw_platforms = detection

    # Generate YAML
    yaml_content = construct_yaml(
        tech_id=tech_id,
        tech_name=tech_name,
        data_source=data_source,
        tactics=tactics,
        op_guidance=combined_op_guidance,
        detect_guidance=combined_detect_guidance,
        platforms=combined_platforms,
        software_platforms=combined_sw_platforms,
        group_name=group_name
    )

    # Save to file
    filename = f"{tech_name.replace(' ', '')}_{data_source.replace(' ', '_').replace(':', '_')}.yaml"
    filepath = output_dir / filename
    filepath.write_text(yaml_content)
    yaml_files.append((tech_name, data_source, filepath))

print(f'  ✓ Generated {len(yaml_files)} YAML files\n')

# Step 6: Sample and analyze generated files
print('Step 6: Analyzing generated YAML files...')

# Check for CloudTrail
cloudtrail_files = [f for f in yaml_files if 'cloudtrail' in f[1].lower()]
print(f'  CloudTrail detections: {len(cloudtrail_files)}')
if cloudtrail_files:
    print(f'    Sample: {cloudtrail_files[0][0]} -> {cloudtrail_files[0][2].name}')

# Check for software names in queries
print('\n  Checking for software names in detection queries...')
software_keywords = ['BlackCat', 'BoomBox', 'Mimikatz', 'LaZagne', 'ngrok', 'WarzoneRAT']
files_with_software_names = []

for tech_name, data_source, filepath in yaml_files[:20]:  # Check first 20
    content = filepath.read_text()
    for sw_name in software_keywords:
        if sw_name in content:
            files_with_software_names.append((filepath.name, sw_name))

if files_with_software_names:
    print(f'  ⚠️  Found {len(files_with_software_names)} files with software names:')
    for filename, sw_name in files_with_software_names[:5]:
        print(f'      - {filename}: contains "{sw_name}"')
else:
    print(f'  ✓ No software names found in detection queries (checked first 20 files)')

# Step 7: Show sample detection
print('\nStep 7: Sample detection content...')
if yaml_files:
    sample_file = yaml_files[0][2]
    print(f'\n  File: {sample_file.name}')
    print(f'  {"─"*76}')
    content = sample_file.read_text()
    lines = content.split('\n')
    for line in lines[:30]:  # Show first 30 lines
        print(f'  {line}')
    if len(lines) > 30:
        print(f'  ... ({len(lines) - 30} more lines)')

print(f'\n{"="*80}')
print('GENERATION TEST COMPLETE')
print(f'{"="*80}\n')

print('Summary:')
print(f'  - Techniques: {len(techniques)}')
print(f'  - Procedures: {len(procedures)}')
print(f'  - Detection rules: {len(collated)}')
print(f'  - YAML files generated: {len(yaml_files)}')
print(f'  - CloudTrail detections: {len(cloudtrail_files)}')
print(f'  - Procedures with indicators: {procedures_with_indicators}')
print(f'  - Procedures without indicators: {procedures_without_indicators}')
if software_names_found:
    print(f'  - ⚠️  Software IDs as techniques: {len(software_names_found)}')
if files_with_software_names:
    print(f'  - ⚠️  Files with software names: {len(files_with_software_names)}')
