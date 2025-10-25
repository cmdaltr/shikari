#!/usr/bin/env python3
"""
Normalize Splunk schema fields for security detection and threat hunting.
Filters security-relevant fields and normalizes field names across data sources.
"""

import json
import re
from pathlib import Path
from typing import Dict, List, Set

# Field normalization mapping - maps various field names to consistent normalized names
FIELD_NORMALIZATION = {
    # Source IP fields
    'src': 'src_ip',
    'source_ip': 'src_ip',
    'sourceIP': 'src_ip',
    'ClientIP': 'src_ip',
    'ClientIPAddress': 'src_ip',
    'callerIpAddress': 'src_ip',
    'httpRequest.clientIp': 'src_ip',
    'properties.ipAddress': 'src_ip',
    'properties.initiatedBy.user.ipAddress': 'src_ip',
    'service.action.awsApiCallAction.remoteIpDetails.ipAddressV4': 'src_ip',
    'service.action.portProbeAction.portProbeDetails{}.remoteIpDetails.ipAddressV4': 'probe_src_ip',
    'service.additionalInfo.recentCredentials{}.ipAddressV4': 'recent_src_ip',
    'src_translated_ip': 'src_translated_ip',

    # Destination fields - keep separate to avoid conflicts
    'dest': 'dest',
    'dst': 'dest',
    'dhost': 'dest_host',
    'dest_host': 'dest_host',
    'dest_name': 'dest_name',
    'dest_ip': 'dest_ip',
    'dest_ip_address': 'dest_ip',
    'dest_ip_internal': 'dest_ip',

    # Port fields
    'src_port': 'src_port',
    's_port': 'src_port',
    'dest_port': 'dest_port',
    'dst_port': 'dest_port',
    'dpt': 'dest_port',

    # User fields - keep some separate to avoid conflicts
    'user': 'user',
    'suser': 'src_user',
    'duser': 'dest_user',
    'userName': 'user_name',
    'user_name': 'user_name',
    'src_user': 'src_user',
    'src_user_name': 'src_user_name',
    'UserId': 'user_id',
    'user_id': 'user_id',
    'properties.userId': 'user_id',
    'properties.userPrincipalName': 'user_principal_name',
    'properties.userDisplayName': 'user_display_name',
    'resource.accessKeyDetails.userName': 'access_key_user_name',

    # Device fields
    'dvc': 'device',
    'DeviceName': 'device_name',
    'properties.DeviceName': 'device_name',
    'ComputerName': 'computer_name',
    'DeviceDisplayName': 'device_display_name',

    # Domain fields
    'domain': 'domain',
    'dest_domain': 'dest_domain',
    'src_domain': 'src_domain',
    'dest_dns': 'dest_dns',
    'src_dns': 'src_dns',
    'service.action.dnsRequestAction.domain': 'dns_domain',

    # Action fields
    'action': 'action',
    'act': 'action',
    'Action': 'action',

    # Signature/Rule fields
    'signature': 'signature',
    'signatureId': 'signature_id',
    'signature_id': 'signature_id',
    'rule': 'rule',
    'rule_name': 'rule_name',
    'Rule_name': 'rule_name',
    'RuleID': 'rule_id',

    # Severity/Level
    'severity': 'severity',
    'Level': 'log_level',
    'deviceSeverity': 'severity',

    # Protocol
    'proto': 'protocol',
    'protocol': 'protocol',
    'transport': 'protocol',

    # HTTP fields
    'http_method': 'http_method',
    'http_user_agent': 'http_user_agent',
    'UserAgent': 'http_user_agent',
    'user_agent': 'http_user_agent',
    'userAgent': 'http_user_agent',
    'properties.userAgent': 'http_user_agent',
    'uri_path': 'uri_path',
    'uri': 'uri_path',
    'url': 'url',
    'httpRequest.uri': 'uri_path',

    # File fields
    'file_name': 'file_name',
    'fname': 'file_name',
    'FileName': 'file_name',
    'properties.FileName': 'file_name',
    'SourceFileName': 'source_file_name',
    'file_path': 'file_path',
    'file_hash': 'file_hash',
    'Sha256': 'file_hash_sha256',
    'Sha1': 'file_hash_sha1',

    # Process fields
    'process_name': 'process_name',
    'ProcessCommandLine': 'process_command_line',
    'properties.ProcessCommandLine': 'process_command_line',
    'process_command_line_arguments': 'process_command_line',
    'parent_process_name': 'parent_process_name',
    'parent_process_path': 'parent_process_path',
    'properties.InitiatingProcessFileName': 'parent_process_name',
    'properties.InitiatingProcessCommandLine': 'parent_process_command_line',

    # Status/Result
    'status': 'status',
    'result': 'result',
    'ResultStatus': 'result_status',
    'properties.result': 'result',
    'properties.resultType': 'result_type',

    # Category/Type
    'category': 'category',
    'eventtype': 'event_type',
    'EventCode': 'event_code',
    'RecordType': 'record_type',
    'record_type': 'record_type',

    # Geographic
    'country': 'country',
    'src_country': 'src_country',
    'dest_country': 'dest_country',
    'ClientCountry': 'src_country',
    'city': 'city',
    'latitude': 'latitude',
    'lat': 'latitude',
    'longitude': 'longitude',
    'long': 'longitude',
    'lon': 'longitude',
}

# Fields to exclude (not useful for security detection)
EXCLUDE_FIELDS = [
    'app', 'awsresource', 'body', 'ct_user', 'gd_details', 'gd_object',
    'ids_type', 'instanceID', 'partition', 'raw_gd_type',
    'src_intrusion', 'eventtype',
    # HR/Organizational fields
    'src_user_HVT_Flags', 'src_user_LanID', 'src_user_active', 'src_user_aws_acct_number',
    'src_user_employee_number', 'src_user_first', 'src_user_identity', 'src_user_identity_id',
    'src_user_identity_tag', 'src_user_last', 'src_user_location', 'src_user_locked_out',
    'src_user_managedBy', 'src_user_nick', 'src_user_org', 'src_user_phone',
    'src_user_prefix', 'src_user_startDate', 'src_user_supervisor_employee_number',
    'src_user_type', 'src_user_work_country',
    'user_HVT_Flags', 'user_LanID', 'user_active', 'user_aws_acct_number',
    'user_employee_number', 'user_endDate', 'user_first', 'user_identity',
    'user_last', 'user_location', 'user_locked_out', 'user_managedBy',
    'user_nick', 'user_org', 'user_phone', 'user_prefix', 'user_startDate',
    'user_supervisor_employee_number', 'user_type', 'user_work_city', 'user_work_country',
    # Asset management fields
    'dest_HVT_Flags', 'dest_asset', 'dest_bunit', 'dest_business_criticality',
    'dest_netmask', 'dest_owner', 'dest_zone', 'dest_category',
    'src_HVT_Flags', 'src_asset', 'src_asset_id', 'src_asset_tag', 'src_bunit',
    'src_business_criticality', 'src_category', 'src_owner',
    'dvc_asset', 'dvc_asset_id', 'dvc_asset_tag', 'dvc_bunit', 'dvc_category',
    'dvc_is_expected', 'dvc_owner', 'dvc_location',
    'dest_bunit', 'dest_category', 'dest_owner',
    # Other non-security fields
    'AutoID', 'dat_version', 'subject', 'subscriptionExternalId',
    'resource.instanceDetails.outpostArn', 'resource.instanceDetails.platform',
    'resource.instanceDetails.imageDescription',
    'resource.instanceDetails.networkInterfaces{}.privateDnsName',
    'resource.instanceDetails.networkInterfaces{}.privateIpAddresses{}.privateDnsName',
    'resource.instanceDetails.networkInterfaces{}.privateIpAddresses{}.privateIpAddress',
    'service.action.dnsRequestAction.vpcOwnerAccountId',
    'resource.instanceDetails.iamInstanceProfile',
    'resource_type',
    # Azure non-security fields
    'additional_details', 'additional_details_name', 'additional_details_value',
    'properties.authenticationDetails{}.RequestSequence',
    'properties.authenticationDetails{}.StatusSequence',
    'object_from_sites',
    # UI/cosmetic fields
    'ListColor', 'ListIcon', 'ListServerTemplate', 'Application',
    # Redundant fields
    'src_ip_address', 'dest_ip_address', 'dvc_ip_address',
    # GCP non-security fields
    'app',
    # Endpoint non-security
    'src_mac', 'dest_mac',
    # CEF metadata
    'cef_6_header', 'extend_part', 'extend_part_1', 'extend_part_2',
    # Proxy non-security
    'CO_Support', 'Customer', 'Javascript_Support', 'process_desc', 'process_guid',
    # IDS non-security
    'dst_proxy', 'src_proxy', 'l7', 'dst',
    # Citrix non-security
    'dvc_bunit', 'dvc_category', 'dvc_location', 'dvc_owner',
    'syslog_message_1', 'syslog_message_9',
    # Various
    'f_dir', 'f_name', 'hostname', 'orig', 'origin_sic_name', 's_port',
    'granular_identity_type', 'identities', 'identity_type', 'message_type', 'product',
]

def extract_fields_from_query(query: str) -> List[str]:
    """Extract field names from a Splunk query."""
    fields = []

    # Remove leading/trailing whitespace and newlines
    query = query.strip()

    # Extract from | table command
    table_match = re.search(r'\|\s*table\s+(.+?)(?:\n|\||$)', query, re.DOTALL)
    if table_match:
        field_str = table_match.group(1).strip()
        fields = [f.strip() for f in field_str.split()]

    # Extract from | fields command
    fields_match = re.search(r'\|\s*fields\s+(.+?)(?:\n|\||$)', query, re.DOTALL)
    if fields_match:
        field_str = fields_match.group(1).strip()
        fields = [f.strip() for f in field_str.split()]

    return fields

def is_security_relevant(field: str) -> bool:
    """Determine if a field is relevant for security detection."""
    # Always keep _time
    if field == '_time':
        return True

    # Exclude known non-security fields
    if field in EXCLUDE_FIELDS:
        return False

    # Exclude fields matching patterns
    exclude_patterns = [
        r'^user_.*_(employee_number|first|last|identity|location|locked_out|managedBy|nick|org|phone|prefix|startDate|supervisor|work_)',
        r'^src_user_.*_(employee_number|first|last|identity|location|locked_out|managedBy|nick|org|phone|prefix|startDate|supervisor|work_)',
        r'^dest_.*_(asset|bunit|business_criticality|owner|category)',
        r'^src_.*_(asset|bunit|business_criticality|owner|category)',
        r'^dvc_.*_(asset|bunit|category|owner|location)',
    ]

    for pattern in exclude_patterns:
        if re.match(pattern, field):
            return False

    return True

def normalize_field_name(field: str) -> str:
    """Normalize a field name to a consistent format."""
    # Direct mapping
    if field in FIELD_NORMALIZATION:
        return FIELD_NORMALIZATION[field]

    # Keep as-is if not in mapping
    return field

def process_data_source(source_name: str, query: str) -> str:
    """Process a single data source query."""
    print(f"Processing {source_name}...")

    # Extract existing fields
    fields = extract_fields_from_query(query)

    # Filter to security-relevant fields only
    security_fields = [f for f in fields if is_security_relevant(f)]

    print(f"  Original fields: {len(fields)}")
    print(f"  Security-relevant fields: {len(security_fields)}")
    print(f"  Excluded: {len(fields) - len(security_fields)}")

    # Build rename mappings and detect conflicts
    rename_mappings = {}
    normalized_fields = []
    target_field_sources = {}  # Track which source fields map to each target
    conflicts = []

    for field in security_fields:
        if field == '_time':
            normalized_fields.append('_time')
            continue

        normalized = normalize_field_name(field)

        # Track sources mapping to this target
        if normalized not in target_field_sources:
            target_field_sources[normalized] = []
        target_field_sources[normalized].append(field)

        # Only add to rename if field name changes
        if normalized != field:
            rename_mappings[field] = normalized

        if normalized not in normalized_fields:
            normalized_fields.append(normalized)

    # Detect and resolve conflicts - prioritize keeping original field names
    fields_to_exclude = set()
    for target, sources in target_field_sources.items():
        if len(sources) > 1:
            conflicts.append(f"  WARNING: Multiple fields map to '{target}': {sources}")

            # Strategy: Keep the source that equals the target (no rename needed)
            # Otherwise, keep the first one
            field_to_keep = None

            # First check if any source field is already the target name
            for source in sources:
                if source == target:
                    field_to_keep = source
                    break

            # If no direct match, keep the first one
            if not field_to_keep:
                field_to_keep = sources[0]

            # Mark all others for exclusion
            for source in sources:
                if source != field_to_keep:
                    fields_to_exclude.add(source)
                    if source in rename_mappings:
                        del rename_mappings[source]

    # Rebuild normalized_fields without excluded fields
    if fields_to_exclude:
        final_normalized_fields = []
        for field in normalized_fields:
            # Check if this normalized field should be kept
            keep_field = True
            for excluded in fields_to_exclude:
                if normalize_field_name(excluded) == field and excluded != field:
                    keep_field = False
                    break
            if keep_field:
                final_normalized_fields.append(field)
        normalized_fields = final_normalized_fields

    if conflicts:
        print(f"  ⚠️  CONFLICTS DETECTED:")
        for conflict in conflicts:
            print(conflict)
        print(f"  ✓ Resolved: Kept original field names where possible, excluded {len(fields_to_exclude)} conflicting fields")

    # Build the new query
    query_parts = []

    # Add rename clause if there are mappings
    if rename_mappings:
        rename_clause = "| rename "
        rename_items = []
        for orig, norm in rename_mappings.items():
            # Quote fields with special characters
            if any(c in orig for c in ['{', '}', '.', '-']):
                orig = f'\"{orig}\"'
            rename_items.append(f"{orig} AS {norm}")
        rename_clause += " ".join(rename_items)
        query_parts.append(rename_clause)

    # Add fields clause
    fields_clause = "| fields " + " ".join(normalized_fields)
    query_parts.append(fields_clause)

    # Add eval Time clause
    query_parts.append('| eval Time=strftime(_time, "%F %T")')

    # Join with \n
    return "\\n".join(query_parts)

def main():
    """Main execution function."""
    # Read the schema file
    schema_file = Path(__file__).parent.parent / "archer" / "mappings" / "schemaSplunk.json"

    print(f"Reading schema from: {schema_file}")

    with open(schema_file, 'r') as f:
        schema = json.load(f)

    # Process each category and data source
    normalized_schema = {}

    for category_key, sources in schema.items():
        print(f"\n{'='*60}")
        print(f"Processing category: {category_key}")
        print(f"{'='*60}")

        normalized_schema[category_key] = {}

        for source_name, query in sources.items():
            normalized_query = process_data_source(source_name, query)
            normalized_schema[category_key][source_name] = normalized_query

    # Write output
    output_file = schema_file.parent / "schemaSplunk_normalized.json"

    with open(output_file, 'w') as f:
        json.dump(normalized_schema, f, indent=2)

    print(f"\n{'='*60}")
    print(f"✓ Normalized schema written to: {output_file}")
    print(f"{'='*60}")

    # Print summary
    print(f"\nSummary:")
    for category_key, sources in normalized_schema.items():
        print(f"  {category_key}: {len(sources)} data sources")

if __name__ == "__main__":
    main()
