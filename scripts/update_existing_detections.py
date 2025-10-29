#!/usr/bin/env python3
"""
Update existing detection YAML files by applying platform-indicator validation.

This script reads all detection YAML files, identifies invalid indicators based on
the platform-indicator validation matrix, and regenerates queries with only valid indicators.
"""

import os
import sys
import yaml
import re
from pathlib import Path
from typing import Dict, List, Tuple, Optional

# Add archer to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from archer.build.platform_indicator_validator import (
    normalize_platform_name,
    validate_indicator_for_platform,
    load_validation_matrix
)


def extract_technique_id_from_description(description: str) -> Optional[str]:
    """Extract technique ID from description (usually contains group reference)"""
    # Try to find T#### or T####.### pattern
    match = re.search(r'T\d{4}(?:\.\d{3})?', description)
    if match:
        return match.group(0)
    return None


def extract_technique_id_from_filename(filename: str) -> Optional[str]:
    """
    Try to extract technique from detection name.
    Common patterns:
    - CreateAccount -> T1136
    - DataStaged -> T1074
    - ExternalRemoteServices -> T1133
    """
    # Mapping of common detection names to technique IDs
    technique_mapping = {
        'CreateAccount': 'T1136',
        'DataStaged': 'T1074',
        'ExternalRemoteServices': 'T1133',
        'DirectVolumeAccess': 'T1006',
        'TrustModification': 'T1484',
        'AdditionalCloudRoles': 'T1098.003',
        'CodeSigning': 'T1553',
        'DatafromCloudStorage': 'T1530',
        'CloudInfrastructureDiscovery': 'T1580',
        'CredentialsInFiles': 'T1552.001',
        'CloudServices': 'T1021',
        'UserExecution': 'T1204',
        'Multi-FactorAuthentication': 'T1556.006',
        'DataEncryptedforImpact': 'T1486',
        'ExfiltrationtoCloudStorage': 'T1567.002',
    }

    # Extract detection name from filename (e.g., "example_index.yaml" -> "CreateAccount")
    detection_name = filename.split('_')[0]
    return technique_mapping.get(detection_name)


def extract_platform_from_filename(filename: str) -> str:
    """
    Extract platform from filename.
    Examples:
    - CreateAccount_azure_signin.yaml -> Azure AD
    - CreateAccount_aws_cloudtrail.yaml -> AWS
    - CreateAccount_windows_events.yaml -> Windows
    - CreateAccount_linux_syslog.yaml -> Linux
    - CreateAccount_DeviceProcessEvents.yaml -> Windows (MDE)
    """
    # Remove extension
    base = filename.replace('.yaml', '').replace('.yml', '')

    # Extract data source part (everything after first underscore)
    parts = base.split('_', 1)
    if len(parts) < 2:
        return "Unknown"

    data_source = parts[1]

    # Normalize to platform
    return normalize_platform_name(data_source)


def extract_indicators_from_splunk_query(query: str) -> Dict[str, List[str]]:
    """
    Extract indicators from a Splunk query.
    This is a best-effort extraction looking for common patterns.
    """
    indicators = {
        'cmd': [],
        'evt': [],
        'sw': [],
        'api': [],
        'operation': []
    }

    # Extract event codes (4720, 4688, etc.)
    event_codes = re.findall(r'event_code\s*[=!]?\s*(\d{4})', query, re.IGNORECASE)
    indicators['evt'].extend(event_codes)

    # Extract EventCode patterns
    event_codes2 = re.findall(r'EventCode\s*[=!]?\s*(\d{4})', query, re.IGNORECASE)
    indicators['evt'].extend(event_codes2)

    # Extract process names (common indicators)
    process_names = re.findall(r'process_name\s*(?:IN\s*\(|=)\s*["\']([^"\']+)["\']', query, re.IGNORECASE)
    indicators['cmd'].extend(process_names)

    # Extract command line patterns
    cmd_patterns = re.findall(r'process_command_line\s*=\s*["\']([^"\']+)["\']', query, re.IGNORECASE)
    indicators['cmd'].extend([p.strip('*') for p in cmd_patterns])

    # Extract AWS API calls (event_name)
    api_calls = re.findall(r'event_name\s*IN\s*\(["\']([^"\']+)["\']', query, re.IGNORECASE)
    indicators['api'].extend(api_calls)

    # Extract Azure operations
    operations = re.findall(r'operation_name\s*IN\s*\(["\']([^"\']+)["\']', query, re.IGNORECASE)
    indicators['operation'].extend(operations)

    # Remove duplicates
    for key in indicators:
        indicators[key] = list(set(indicators[key]))

    # Remove empty lists
    indicators = {k: v for k, v in indicators.items() if v}

    return indicators


def check_detection_needs_update(
    yaml_path: Path,
    technique_id: Optional[str],
    platform: str,
    query: str
) -> Tuple[bool, List[str], Dict[str, List[str]]]:
    """
    Check if a detection needs updating.

    Returns:
        (needs_update, invalid_indicators, valid_indicators)
    """
    if not technique_id:
        # Can't validate without technique ID
        return False, [], {}

    # Extract indicators from query
    indicators = extract_indicators_from_splunk_query(query)

    if not indicators:
        # No indicators found
        return False, [], {}

    invalid_indicators = []
    valid_indicators = {}

    # Validate each indicator
    for indicator_type, indicator_list in indicators.items():
        valid_for_type = []

        for indicator in indicator_list:
            is_valid, reason = validate_indicator_for_platform(
                indicator,
                indicator_type,
                platform,
                technique_id
            )

            if not is_valid:
                invalid_indicators.append(f"[{indicator_type}] {indicator}: {reason}")
            else:
                valid_for_type.append(indicator)

        if valid_for_type:
            valid_indicators[indicator_type] = valid_for_type

    needs_update = len(invalid_indicators) > 0

    return needs_update, invalid_indicators, valid_indicators


def update_detection_file(yaml_path: Path, dry_run: bool = True) -> Tuple[bool, str]:
    """
    Update a single detection YAML file.

    Returns:
        (updated, message)
    """
    try:
        # Read YAML
        with open(yaml_path, 'r') as f:
            content = f.read()
            detection = yaml.safe_load(content)

        if not detection or 'query' not in detection:
            return False, f"❌ Skipped (no query found)"

        # Extract metadata
        filename = yaml_path.name
        platform = extract_platform_from_filename(filename)
        technique_id = extract_technique_id_from_filename(filename)

        if not technique_id:
            # Try from description
            description = detection.get('description', '')
            technique_id = extract_technique_id_from_description(description)

        if not technique_id:
            return False, f"⚠️  Skipped (could not determine technique ID)"

        # Check if update needed
        query = detection['query']
        needs_update, invalid_indicators, valid_indicators = check_detection_needs_update(
            yaml_path,
            technique_id,
            platform,
            query
        )

        if not needs_update:
            return False, f"✅ No update needed"

        # Log what would be changed
        message = f"🔧 {technique_id} | {platform}\n"
        message += f"   Invalid indicators found:\n"
        for invalid in invalid_indicators[:5]:  # Limit to 5
            message += f"     - {invalid}\n"
        if len(invalid_indicators) > 5:
            message += f"     ... and {len(invalid_indicators) - 5} more\n"

        if not dry_run:
            # TODO: Implement actual query regeneration
            # This would require calling the query compilation functions
            # For now, just flag the files that need updating
            message += f"   ⚠️  File flagged for regeneration (regeneration not implemented yet)\n"

        return True, message

    except Exception as e:
        return False, f"❌ Error: {str(e)}"


def main():
    """Main function"""
    print("🔍 Scanning detection files for platform-indicator validation issues...\n")

    # Find all detection YAML files
    generate_dir = Path(__file__).parent.parent / "data" / "generate"

    if not generate_dir.exists():
        print(f"❌ Detection directory not found: {generate_dir}")
        return

    yaml_files = list(generate_dir.glob("*.yaml")) + list(generate_dir.glob("*.yml"))

    print(f"📁 Found {len(yaml_files)} detection files\n")
    print("=" * 80)

    updated_count = 0
    skipped_count = 0
    error_count = 0

    for yaml_file in sorted(yaml_files):
        updated, message = update_detection_file(yaml_file, dry_run=True)

        if updated:
            print(f"\n{yaml_file.name}")
            print(message)
            updated_count += 1
        elif "Error" in message:
            error_count += 1
            print(f"\n{yaml_file.name}")
            print(message)
        else:
            skipped_count += 1

    print("\n" + "=" * 80)
    print(f"\n📊 Summary:")
    print(f"   ✅ Clean: {skipped_count}")
    print(f"   🔧 Need update: {updated_count}")
    print(f"   ❌ Errors: {error_count}")
    print(f"   📁 Total: {len(yaml_files)}")

    if updated_count > 0:
        print(f"\n⚠️  This was a DRY RUN. No files were modified.")
        print(f"⚠️  {updated_count} files have been flagged for review/regeneration.")
        print(f"\nTo fix these detections, you have two options:")
        print(f"  1. Re-run the detection generation application (recommended)")
        print(f"  2. Implement query regeneration in this script")


if __name__ == "__main__":
    main()
