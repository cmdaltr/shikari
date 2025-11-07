#!/usr/bin/env python3
"""Test script to debug OSINT enhancement for MDE queries"""

import sys
import yaml
from archer.build.osint_query_enhancer import enhance_query_with_osint

# Load a sample YAML file with OSINT indicators
yaml_file = "data/generate/ExfiltrationOverUnencryptedNon-C2Protocol_windows_events.yaml"

print(f"Loading {yaml_file}...")
with open(yaml_file, 'r') as f:
    data = yaml.safe_load(f)

# Extract the base query and OSINT indicators
base_query = data.get('query', '')
osint_indicators = data.get('osint_indicators', {})

print("\n=== Base Query ===")
print(base_query)
print("\n=== OSINT Indicators ===")
for key, value in osint_indicators.items():
    if isinstance(value, list):
        print(f"{key}: {len(value)} items")
        for item in value[:3]:  # Show first 3
            print(f"  - {item}")
    else:
        print(f"{key}: {type(value)}")

print("\n=== Running Enhancement ===")
enhanced_query = enhance_query_with_osint(base_query, osint_indicators, target_vendor="MDE")

print("\n=== Enhanced Query ===")
print(enhanced_query)

# Check if datatables were added
if "let OSINT" in enhanced_query:
    print("\n✓ SUCCESS: Datatables were added to the query")
else:
    print("\n✗ FAIL: No datatables found in enhanced query")
