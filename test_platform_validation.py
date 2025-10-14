#!/usr/bin/env python3
"""
Test script to verify platform validation is working correctly.

This tests that:
1. technique_description and technique_platforms are passed through the pipeline
2. Platform validation prevents illogical detections (e.g., linux_syslog + Windows paths)
"""

import sys
import os

# Test 1: Check that platform_validator_v2 can be imported
try:
    from archer.build.platform_validator_v2 import validate_procedure_for_index
    print("✅ platform_validator_v2 imported successfully")
except ImportError as e:
    print(f"❌ Failed to import platform_validator_v2: {e}")
    sys.exit(1)

# Test 2: Test validation logic with Windows path + unix index
test_cases = [
    {
        "name": "Windows path + linux_syslog (should FAIL)",
        "indicator": "C:\\Windows\\System32\\lsass.exe",
        "technique_desc": "On Windows, adversaries may dump credentials from lsass.exe",
        "technique_platforms": ["Windows"],
        "index_name": "linux_syslog",
        "expected": False
    },
    {
        "name": "Windows path + windows_security (should PASS)",
        "indicator": "C:\\Windows\\System32\\lsass.exe",
        "technique_desc": "On Windows, adversaries may dump credentials from lsass.exe",
        "technique_platforms": ["Windows"],
        "index_name": "windows_security",
        "expected": True
    },
    {
        "name": "Linux command + linux_syslog (should PASS)",
        "indicator": "usermod -aG sudo malicious_user",
        "technique_desc": "On Linux, adversaries may use the usermod command",
        "technique_platforms": ["Linux"],
        "index_name": "linux_syslog",
        "expected": True
    },
    {
        "name": "Registry key + linux_syslog (should FAIL)",
        "indicator": "HKLM\\Software\\Microsoft\\Windows",
        "technique_desc": "On Windows, adversaries modify registry keys",
        "technique_platforms": ["Windows"],
        "index_name": "linux_syslog",
        "expected": False
    },
    {
        "name": "Event log + azure_logs (should FAIL)",
        "indicator": "Event ID 4776 in Security.evtx",
        "technique_desc": "On Windows, monitor event logs for authentication attempts",
        "technique_platforms": ["Windows"],
        "index_name": "azure_logs",
        "expected": False
    }
]

print("\n" + "="*80)
print("PLATFORM VALIDATION TESTS")
print("="*80 + "\n")

passed = 0
failed = 0

for test in test_cases:
    result = validate_procedure_for_index(
        indicator_text=test["indicator"],
        index_name=test["index_name"],
        vendor="Splunk",
        technique_desc=test["technique_desc"],
        technique_platforms=test["technique_platforms"]
    )

    status = "✅ PASS" if result == test["expected"] else "❌ FAIL"
    if result == test["expected"]:
        passed += 1
    else:
        failed += 1

    print(f"{status} - {test['name']}")
    print(f"  Indicator: {test['indicator'][:50]}...")
    print(f"  Index: {test['index_name']}")
    print(f"  Expected: {test['expected']}, Got: {result}\n")

print("="*80)
print(f"Results: {passed} passed, {failed} failed")
print("="*80)

if failed > 0:
    sys.exit(1)
else:
    print("\n✅ All platform validation tests passed!")
    sys.exit(0)
