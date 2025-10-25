#!/usr/bin/env python3
"""
Test OSINT Enrichment with Local Repositories

This script tests the new local repository-based OSINT enrichment.
"""

from archer.build.osint_enrichment import search_osint_for_technique

# Test with a known technique
technique_id = "T1078"
technique_name = "Valid Accounts"
technique_description = "Adversaries may obtain and abuse credentials of existing accounts as a means of gaining Initial Access, Persistence, Privilege Escalation, or Defense Evasion."
platforms = ["Windows", "Linux", "macOS"]

print(f"Testing OSINT Enrichment for {technique_id} ({technique_name})\n")
print("=" * 80)

found, enrichment_data = search_osint_for_technique(
    technique_id=technique_id,
    technique_name=technique_name,
    technique_description=technique_description,
    platforms=platforms
)

print("\n" + "=" * 80)
print(f"\nResults:")
print(f"  Found OSINT data: {found}")
print(f"  OSINT enriched: {enrichment_data.get('osint_enriched')}")
print(f"  Sources found: {len(enrichment_data.get('osint_sources', []))}")
print(f"  Indicators found: {len(enrichment_data.get('osint_indicators', {}))}")

if enrichment_data.get('osint_sources'):
    print(f"\n  Sample sources:")
    for source in enrichment_data['osint_sources'][:3]:
        print(f"    - {source}")

if enrichment_data.get('osint_indicators'):
    print(f"\n  Indicators by type:")
    for indicator_type, indicators in enrichment_data['osint_indicators'].items():
        print(f"    {indicator_type}: {len(indicators)} indicators")
        if indicators:
            print(f"      Example: {indicators[0]}")

print(f"\n  Enrichment notes:")
print(f"    {enrichment_data.get('enrichment_notes', 'None')}")
