#!/usr/bin/env python3
"""Simple test of OSINT enhancement for MDE queries"""

from archer.build.osint_query_enhancer import enhance_query_with_osint

# Sample base MDE query
base_query = """DeviceEvents
| where Timestamp > ago(1d)
| where AdditionalFields contains "runas"
| summarize by Timestamp, DeviceName, ActionType, AccountName, FolderPath, FileName, SHA256"""

# Sample OSINT indicators (simulating what comes from YAML)
osint_indicators = {
    "cmd": [
        "runas",
        "powershell",
        "cmd.exe"
    ],
    "sw": [
        "\\explorer.exe",
        "\\notepad.exe"
    ],
    "acct": [
        "*SYSTEM",
        "*ADMIN"
    ],
    "query_snippets": [
        "[MDE] some snippet here"
    ]
}

print("=== Base Query ===")
print(base_query)
print("\n=== OSINT Indicators ===")
for key, value in osint_indicators.items():
    print(f"{key}: {value}")

print("\n=== Running Enhancement (MDE) ===")
enhanced_query = enhance_query_with_osint(base_query, osint_indicators, target_vendor="MDE")

print("\n=== Enhanced Query ===")
print(enhanced_query)

# Check if datatables were added
if "let OSINT" in enhanced_query:
    print("\n✓ SUCCESS: Datatables were added to the query")
else:
    print("\n✗ FAIL: No datatables found in enhanced query")

if "datatable(" in enhanced_query:
    print("✓ Found datatable keyword")
else:
    print("✗ No datatable keyword found")
