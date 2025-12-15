#!/usr/bin/env python3
"""
Automatic Schema Normalizer for Archer

This module automatically normalizes new indexes/sources added to platform schema files.
It detects unnormalized indexes (those without proper field filtering and normalization)
and applies consistent field naming and security-focused field filtering.

Supported Platforms:
- Splunk: schemaSplunk.json - Applies SPL query normalization
- Google SecOps: schemaGoogleSecOps.json - Uses UDM standard (no normalization needed)
- Elastic: schemaElastic.json - Uses ECS standard (no normalization needed)

Detection Strategy (Splunk):
- Normalized indexes have: | rename ... | fields ... | eval Time=...
- Unnormalized indexes typically have raw SPL queries without the full normalization pattern

The normalizer:
1. Reads schema file (schemaSplunk.json, schemaGoogleSecOps.json, or schemaElastic.json)
2. Identifies which indexes haven't been normalized by Archer
3. Applies field normalization, security filtering, and formatting (Splunk only)
4. Updates only the unnormalized indexes
5. Preserves all other indexes unchanged

Note: Google SecOps and Elastic schemas use standardized field models (UDM and ECS)
and don't require the same normalization approach as Splunk.
"""

import json
import re
from pathlib import Path
from typing import Dict, List, Set, Tuple
from collections import defaultdict


class SplunkSchemaNormalizer:
    """Automatically normalize Splunk schema indexes with consistent field naming and filtering."""

    # Field normalization mappings - map variant names to consistent standard names
    FIELD_NORMALIZATION = {
        # Source IP fields
        'src': 'src_ip',
        'source_ip': 'src_ip',
        'sourceIP': 'src_ip',
        'ClientIP': 'src_ip',
        'ClientIPAddress': 'src_ip',
        'callerIpAddress': 'src_ip',
        'src_ip': 'src_ip',  # Already normalized

        # Destination IP fields
        'dest_ip': 'dest_ip',  # Already normalized
        'destination_ip': 'dest_ip',
        'dest_ip_internal': 'dest_ip',

        # Destination host fields
        'dest_host': 'dest_host',
        'dhost': 'dest_host',

        # Device fields - ALL variations map to 'device' for consistency
        'dvc': 'device',
        'device': 'device',
        'DeviceName': 'device',
        'ComputerName': 'device',
        'device_name': 'device',
        'computer_name': 'device',
        'DeviceDisplayName': 'device_display_name',

        # User fields - keep separate to avoid conflicts
        'user': 'user',
        'suser': 'src_user',
        'duser': 'dest_user',
        'userName': 'user_name',
        'userPrincipalName': 'user_principal_name',

        # Action fields
        'action': 'action',
        'act': 'action',
        'Action': 'action',

        # Protocol fields
        'proto': 'protocol',
        'transport': 'protocol',
        'protocol': 'protocol',

        # File fields
        'fname': 'file_name',
        'FileName': 'file_name',
        'SourceFileName': 'source_file_name',

        # Hash fields
        'Sha1': 'file_hash_sha1',
        'Sha256': 'file_hash_sha256',

        # Process fields
        'ProcessCommandLine': 'process_command_line',
        'process_command_line_arguments': 'process_command_line',
        'InitiatingProcessFileName': 'parent_process_name',
        'InitiatingProcessCommandLine': 'parent_process_command_line',

        # Severity fields
        'deviceSeverity': 'severity',
        'severity': 'severity',

        # User agent fields
        'user_agent': 'http_user_agent',
        'userAgent': 'http_user_agent',
        'UserAgent': 'http_user_agent',

        # Result/Status fields
        'ResultStatus': 'result_status',
        'result': 'result',

        # Geographic fields
        'lat': 'latitude',
        'lon': 'longitude',

        # Event code fields
        'EventCode': 'event_code',

        # CEF/Rule fields
        'Rule_name': 'rule_name',
        'RuleID': 'rule_id',
        'ClientCountry': 'src_country',

        # HTTP Request fields (from aws_waf and similar)
        'httpRequest.uri': 'uri_path',
        'httpRequest.country': 'request_country',
        'httpRequest.headers{}.name': 'header_name',
        'httpRequest.headers{}.value': 'header_value',
        'httpRequest.host': 'request_host',
        'httpRequest.httpVersion': 'http_version',
        'httpRequest.requestId': 'request_id',
        'httpRequest.scheme': 'request_scheme',

        # AWS CloudTrail fields
        'eventTime': 'event_time',
        'recipientAccountId': 'account_id',
        'requestParameters.instanceType': 'instance_type',
        'requestParameters.availabilityZone': 'availability_zone',

        # AWS GuardDuty resource fields
        'resource.accessKeyDetails.userName': 'access_key_user',
        'resource.accessKeyDetails.accessKeyId': 'access_key_id',
        'resource.accessKeyDetails.principalId': 'principal_id',
        'resource.accessKeyDetails.userType': 'user_type',
        'resource.instanceDetails.availabilityZone': 'availability_zone',
        'resource.instanceDetails.instanceId': 'instance_id',
        'resource.instanceDetails.instanceState': 'instance_state',
        'resource.instanceDetails.instanceType': 'instance_type',
        'resource.resourceType': 'resource_type',

        # AWS GuardDuty service fields
        'service.action.dnsRequestAction.domain': 'dns_domain',
        'service.action.actionType': 'action_type',
        'service.action.awsApiCallAction.api': 'api_call',
        'service.action.awsApiCallAction.serviceName': 'service_name',
        'service.additionalInfo.threatListName': 'threat_list',
        'service.additionalInfo.threatName': 'threat_name',
        'service.serviceName': 'service_name_alt',

        # Azure Active Directory properties fields
        'properties.resultType': 'result_type',
        'properties.userAgent': 'http_user_agent',
        'properties.userDisplayName': 'user_display_name',
        'properties.userPrincipalName': 'user_principal_name',
        'properties.activityDateTime': 'activity_time',
        'properties.category': 'event_category',
        'properties.correlationId': 'correlation_id',
        'properties.location.city': 'city',
        'properties.location.countryOrRegion': 'country',
        'properties.location.geoCoordinates.latitude': 'latitude',
        'properties.location.geoCoordinates.longitude': 'longitude',

        # Azure Activity Log identity fields
        'identity.authorization.action': 'authorization_action',
        'identity.claims.appid': 'claim_app_id',
        'identity.claims.aud': 'claim_audience',

        # GCP Audit protoPayload fields
        'protoPayload.@type': 'proto_type',
        'protoPayload.authenticationInfo.principalEmail': 'principal_email',
        'protoPayload.authenticationInfo.principalSubject': 'principal_subject',
        'protoPayload.authorizationInfo{}.granted': 'auth_granted',
        'protoPayload.authorizationInfo{}.permission': 'permission',
        'protoPayload.authorizationInfo{}.permissionType': 'permission_type',
        'protoPayload.resourceName': 'resource_name_full',

        # Microsoft Defender properties fields
        'properties.DeviceName': 'device',
        'properties.FileName': 'file_name',
        'properties.ProcessCommandLine': 'process_command_line',
        'properties.InitiatingProcessFileName': 'parent_process_name',
        'properties.InitiatingProcessCommandLine': 'parent_process_command_line',
        'properties.AccountName': 'account_name',
        'properties.InitiatingProcessAccountName': 'parent_account_name',
        'properties.InitiatingProcessParentFileName': 'grandparent_process_name',
        'properties.LocalIP': 'local_ip',
        'properties.RemoteIP': 'remote_ip',
        'properties.RemoteUrl': 'remote_url',
        'properties.RegistryKey': 'registry_key',
        'properties.RegistryValueData': 'registry_value_data',
        'properties.PreviousRegistryKey': 'previous_registry_key',
        'properties.PreviousRegistryValueData': 'previous_registry_value_data',

        # Microsoft O365 fields with nested objects
        'AffectedItems{}.Attachments': 'affected_attachments',
        'AffectedItems{}.ParentFolder.Path': 'affected_parent_folder',
        'AffectedItems{}.Subject': 'affected_subject',
        'AppAccessContext.ClientAppName': 'client_app_name',
        'CopilotEventData.AISystemPlugin{}.Id': 'ai_plugin_id',
        'CopilotEventData.AISystemPlugin{}.Name': 'ai_plugin_name',
        'Item.Attachments': 'item_attachments',
        'Item.ParentFolder.Path': 'item_parent_folder_path',
        'Item.Subject': 'item_subject',

        # WAF rule fields
        'ruleGroupList{}.excludedRules{}.ruleId': 'excluded_rule_id',
        'ruleGroupList{}.excludedRules{}.ruleMatchDetails': 'rule_match_details',
        'ruleGroupList{}.excludedRules{}.ruleMatchDetails{}.conditionType': 'condition_type',
        'ruleGroupList{}.excludedRules{}.ruleMatchDetails{}.location': 'match_location',
        'ruleGroupList{}.excludedRules{}.ruleMatchDetails{}.matchedData{}': 'matched_data',
        'ruleGroupList{}.ruleGroupId': 'rule_group_id',
        'labels{}.name': 'label_name',
    }

    # Fields to exclude (non-security, HR, organizational, UI, asset management)
    FIELDS_TO_EXCLUDE = {
        # HR and organizational data
        'employee_id', 'employee_number', 'manager', 'department', 'cost_center',
        'business_unit', 'division', 'office_location', 'building', 'floor',
        'phone_number', 'mobile_number', 'personal_email', 'emergency_contact',
        'hire_date', 'termination_date', 'job_title', 'job_level', 'salary',
        'compensation', 'benefits', 'performance_rating',

        # Asset management (non-security)
        'asset_tag', 'serial_number', 'purchase_date', 'warranty_expiration',
        'vendor', 'model', 'manufacturer', 'purchase_order', 'invoice_number',
        'cost', 'depreciation', 'disposal_date', 'owner_department',

        # UI and display fields
        'display_name', 'friendly_name', 'label', 'description', 'notes',
        'comments', 'color', 'icon', 'theme', 'layout', 'view', 'panel',
        'dashboard', 'widget', 'chart_type', 'visualization',

        # Compliance and audit (low security value)
        'audit_id', 'audit_date', 'auditor', 'compliance_status',
        'certification', 'attestation', 'review_date', 'approval_date',
        'approved_by', 'rejected_by',

        # Workflow and process management
        'workflow_id', 'workflow_status', 'workflow_stage', 'task_id',
        'task_status', 'assigned_to', 'due_date', 'priority_non_security',
        'escalation_level', 'sla', 'resolution_time',

        # Generic metadata (low value)
        'created_by_non_security', 'modified_by', 'updated_by', 'deleted_by',
        'created_date', 'modified_date', 'updated_date', 'deleted_date',
        'version', 'revision', 'change_log', 'history',

        # Application-specific UI fields
        'app_version', 'app_build', 'app_release', 'app_environment',
        'app_tier', 'app_instance', 'app_cluster',

        # Non-security configuration
        'config_id', 'config_name', 'config_value', 'setting_id',
        'setting_name', 'setting_value', 'preference', 'option',

        # Reporting and analytics (non-security)
        'report_id', 'report_name', 'report_type', 'report_format',
        'report_schedule', 'report_recipients', 'report_parameters',

        # Integration and sync
        'sync_status', 'sync_date', 'sync_source', 'import_id',
        'export_id', 'integration_id', 'connector_id',
    }

    def __init__(self, schema_path: Path = None):
        """
        Initialize the schema normalizer.

        Args:
            schema_path: Path to schemaSplunk.json (default: data/bespoke/mappings/schemaSplunk.json)
        """
        if schema_path is None:
            # Look in bespoke/mappings directory
            schema_path = Path(__file__).parent.parent.parent / "data" / "bespoke" / "mappings" / "schemaSplunk.json"

        self.schema_path = schema_path
        self.schema = None
        self.stats = {
            'total_indexes': 0,
            'normalized_indexes': 0,
            'new_indexes': 0,
            'updated_indexes': 0,
            'errors': []
        }

    def load_schema(self) -> Dict:
        """Load the Splunk schema from JSON file."""
        with open(self.schema_path, 'r') as f:
            self.schema = json.load(f)
        return self.schema

    def save_schema(self, backup: bool = True) -> None:
        """
        Save the normalized schema back to JSON file.

        Args:
            backup: Create backup of original file (default: True)
        """
        if backup:
            backup_path = self.schema_path.with_suffix('.json.bak')
            with open(self.schema_path, 'r') as f:
                with open(backup_path, 'w') as bak:
                    bak.write(f.read())
            print(f"  Backup created: {backup_path}")

        with open(self.schema_path, 'w') as f:
            json.dump(self.schema, f, indent=2)
        print(f"  Schema saved: {self.schema_path}")

    def is_normalized(self, query: str) -> bool:
        """
        Check if an index query has been normalized by Archer.

        A normalized query has this pattern:
        1. Optional: | rename ...
        2. Required: | fields ...
        3. Required: | eval Time=strftime(_time, "%F %T")

        Args:
            query: SPL query string

        Returns:
            True if query is already normalized, False if it needs normalization
        """
        # Check for the required normalized pattern
        has_fields = '| fields' in query or '\\n| fields' in query
        has_time_eval = '| eval Time=strftime(_time, "%F %T")' in query or \
                       '\\n| eval Time=strftime(_time, "%F %T")' in query

        # A normalized query MUST have both fields and time evaluation
        return has_fields and has_time_eval

    def extract_fields_from_query(self, query: str) -> Set[str]:
        """
        Extract all field names referenced in a query.

        Args:
            query: SPL query string

        Returns:
            Set of field names found in the query
        """
        fields = set()

        # Find field references in common patterns:
        # - | fields field1 field2 field3
        # - | rename old AS new
        # - | eval field=...
        # - | stats ... by field
        # - | where field=value
        # - field in search clauses

        # Extract from | fields command
        fields_match = re.search(r'\|\s*fields\s+([^\|]+)', query)
        if fields_match:
            field_list = fields_match.group(1).strip()
            for field in re.split(r'\s+', field_list):
                field = field.strip()
                if field and not field.startswith('-'):
                    fields.add(field)

        # Extract from | rename command
        rename_matches = re.findall(r'(\S+)\s+AS\s+(\S+)', query)
        for source, target in rename_matches:
            # Clean quoted fields
            source = source.strip('"\'')
            target = target.strip('"\'')
            fields.add(source)
            fields.add(target)

        # Extract from common field patterns (fieldname=, fieldname>, fieldname<, etc.)
        field_patterns = re.findall(r'(\w+(?:\.\w+)*)\s*[=<>!]', query)
        for field in field_patterns:
            if not field.startswith(('NOT', 'AND', 'OR', 'IN')):
                fields.add(field)

        return fields

    def filter_security_fields(self, fields: Set[str]) -> Set[str]:
        """
        Filter fields to keep only security-relevant ones.

        Args:
            fields: Set of all field names

        Returns:
            Set of security-relevant field names
        """
        security_fields = set()

        for field in fields:
            # Skip excluded fields
            if field.lower() in self.FIELDS_TO_EXCLUDE:
                continue

            # Keep security-relevant patterns
            field_lower = field.lower()

            # Security indicators
            security_keywords = [
                'threat', 'attack', 'malware', 'virus', 'exploit', 'vulnerability',
                'cve', 'mitre', 'detection', 'alert', 'incident', 'breach',
                'intrusion', 'anomaly', 'suspicious', 'malicious', 'risk',
                'severity', 'signature', 'rule', 'policy', 'block', 'deny',
                'allow', 'permit', 'drop', 'reject', 'quarantine',

                # Network security
                'src', 'dest', 'source', 'destination', 'ip', 'port', 'protocol',
                'dns', 'domain', 'url', 'uri', 'http', 'https', 'ssl', 'tls',
                'packet', 'flow', 'session', 'connection', 'traffic',

                # Authentication and access
                'auth', 'login', 'logout', 'logon', 'logoff', 'credential',
                'password', 'token', 'key', 'certificate', 'privilege',
                'permission', 'access', 'identity', 'principal', 'role',
                'group', 'membership', 'entitlement',

                # Endpoint security
                'process', 'command', 'execution', 'file', 'registry',
                'service', 'driver', 'module', 'dll', 'executable',
                'script', 'powershell', 'cmd', 'bash', 'shell',

                # Data security
                'hash', 'sha', 'md5', 'checksum', 'encryption', 'decrypt',
                'cipher', 'crypto', 'sign', 'verify',

                # User and entity
                'user', 'account', 'device', 'host', 'computer', 'machine',
                'endpoint', 'asset', 'entity', 'subject', 'object',

                # Operations and events
                'action', 'event', 'operation', 'activity', 'behavior',
                'status', 'result', 'outcome', 'response', 'error',
                'failure', 'success', 'attempt',

                # Time and correlation
                'time', 'timestamp', 'date', 'created', 'modified', 'updated',
                'first', 'last', 'seen', 'occurred',

                # Location and geography
                'location', 'country', 'region', 'city', 'geo', 'latitude',
                'longitude', 'asn', 'org', 'isp',

                # Cloud and infrastructure
                'cloud', 'aws', 'azure', 'gcp', 'tenant', 'subscription',
                'account', 'instance', 'resource', 'arn', 'id',

                # Specific security products
                'guardian', 'defender', 'edr', 'xdr', 'siem', 'ids', 'ips',
                'firewall', 'waf', 'proxy', 'antivirus', 'epp',
            ]

            # Check if field contains any security keyword
            if any(keyword in field_lower for keyword in security_keywords):
                security_fields.add(field)
                continue

            # Keep standard fields
            standard_fields = {'_time', '_raw', 'index', 'sourcetype', 'source', 'host'}
            if field in standard_fields:
                security_fields.add(field)
                continue

        return security_fields

    def normalize_field_names(self, fields: Set[str]) -> Tuple[Dict[str, str], Set[str]]:
        """
        Create field rename mappings and detect conflicts.

        Args:
            fields: Set of field names to normalize

        Returns:
            Tuple of (rename_mappings dict, fields_to_exclude set)
        """
        rename_mappings = {}
        target_field_sources = defaultdict(list)

        # Build initial rename mappings
        for field in fields:
            if field in self.FIELD_NORMALIZATION:
                target = self.FIELD_NORMALIZATION[field]
                rename_mappings[field] = target
                target_field_sources[target].append(field)
            else:
                # Field not in normalization map, keep as-is
                target_field_sources[field].append(field)

        # Detect and resolve conflicts
        fields_to_exclude = set()
        conflicts = []

        for target, sources in target_field_sources.items():
            if len(sources) > 1:
                conflicts.append(f"  WARNING: Multiple fields map to '{target}': {sources}")

                # Resolution strategy: Keep the source that equals the target (no rename needed)
                # Otherwise, keep the first one
                field_to_keep = None

                # Check if any source field is already the target name
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

        if conflicts:
            print("\n".join(conflicts))

        return rename_mappings, fields_to_exclude

    def build_normalized_query(
        self,
        original_query: str,
        rename_mappings: Dict[str, str],
        security_fields: Set[str],
        fields_to_exclude: Set[str]
    ) -> str:
        """
        Build a normalized SPL query with consistent formatting.

        Args:
            original_query: Original SPL query
            rename_mappings: Dict of field renames (source -> target)
            security_fields: Set of security-relevant fields to keep
            fields_to_exclude: Set of fields to exclude due to conflicts

        Returns:
            Normalized SPL query string
        """
        parts = []

        # 1. Add rename clause if there are mappings
        if rename_mappings:
            rename_pairs = []
            for source, target in sorted(rename_mappings.items()):
                if source not in fields_to_exclude:
                    # Handle fields with special characters (dots, braces, etc.)
                    if any(c in source for c in ['.', '{', '}', '[', ']', ' ']):
                        source_escaped = f'"{source}"'
                    else:
                        source_escaped = source

                    rename_pairs.append(f"{source_escaped} AS {target}")

            if rename_pairs:
                parts.append("| rename " + " ".join(rename_pairs))

        # 2. Add fields clause with security-relevant fields only
        final_fields = sorted(security_fields - fields_to_exclude)
        if final_fields:
            parts.append("| fields " + " ".join(final_fields))

        # 3. Add time evaluation
        parts.append('| eval Time=strftime(_time, "%F %T")')

        # Join with \n separator
        return "\\n".join(parts)

    def normalize_index(self, index_name: str, query: str) -> str:
        """
        Normalize a single index query.

        Args:
            index_name: Name of the index
            query: Current SPL query

        Returns:
            Normalized SPL query
        """
        print(f"\n  Processing: {index_name}")

        # Extract all fields from the query
        all_fields = self.extract_fields_from_query(query)
        print(f"    Found {len(all_fields)} fields")

        # Filter to security-relevant fields
        security_fields = self.filter_security_fields(all_fields)
        excluded_count = len(all_fields) - len(security_fields)
        print(f"    Kept {len(security_fields)} security fields (excluded {excluded_count})")

        # Normalize field names and detect conflicts
        rename_mappings, fields_to_exclude = self.normalize_field_names(security_fields)
        print(f"    Created {len(rename_mappings)} field renames")

        if fields_to_exclude:
            print(f"    Excluded {len(fields_to_exclude)} conflicting fields")

        # Build normalized query
        normalized_query = self.build_normalized_query(
            query, rename_mappings, security_fields, fields_to_exclude
        )

        return normalized_query

    def normalize_all(self, force: bool = False) -> Dict:
        """
        Normalize all unnormalized indexes in the schema.

        Args:
            force: Force re-normalization of all indexes (default: False)

        Returns:
            Dict with normalization statistics
        """
        print("="*80)
        print("AUTOMATIC SPLUNK SCHEMA NORMALIZATION")
        print("="*80)

        # Load schema
        print(f"\nLoading schema from: {self.schema_path}")
        self.load_schema()

        # Process each category
        for category, indexes in self.schema.items():
            print(f"\n{category.upper()} Category:")
            print("-" * 80)

            for index_name, query in indexes.items():
                self.stats['total_indexes'] += 1

                # Check if already normalized
                if self.is_normalized(query) and not force:
                    print(f"  ✓ {index_name}: Already normalized (skipping)")
                    self.stats['normalized_indexes'] += 1
                    continue

                # Normalize the index
                try:
                    normalized_query = self.normalize_index(index_name, query)

                    # Update schema
                    self.schema[category][index_name] = normalized_query

                    if not self.is_normalized(query):
                        self.stats['new_indexes'] += 1
                        print(f"  ✅ {index_name}: Normalized (NEW)")
                    else:
                        self.stats['updated_indexes'] += 1
                        print(f"  ✅ {index_name}: Re-normalized (FORCED)")

                except Exception as e:
                    error_msg = f"{index_name}: {str(e)}"
                    self.stats['errors'].append(error_msg)
                    print(f"  ❌ {index_name}: ERROR - {e}")

        # Save updated schema
        print(f"\n{'='*80}")
        print("SAVING NORMALIZED SCHEMA")
        print("="*80)
        self.save_schema(backup=True)

        # Print summary
        print(f"\n{'='*80}")
        print("NORMALIZATION SUMMARY")
        print("="*80)
        print(f"Total indexes: {self.stats['total_indexes']}")
        print(f"Already normalized: {self.stats['normalized_indexes']}")
        print(f"Newly normalized: {self.stats['new_indexes']}")
        print(f"Re-normalized (forced): {self.stats['updated_indexes']}")
        print(f"Errors: {len(self.stats['errors'])}")

        if self.stats['errors']:
            print("\nErrors encountered:")
            for error in self.stats['errors']:
                print(f"  - {error}")

        print(f"\n{'='*80}")
        if self.stats['new_indexes'] > 0:
            print(f"✅ SUCCESS: Normalized {self.stats['new_indexes']} new indexes!")
        elif self.stats['updated_indexes'] > 0:
            print(f"✅ SUCCESS: Re-normalized {self.stats['updated_indexes']} indexes!")
        else:
            print("✅ All indexes already normalized - nothing to do!")
        print("="*80)

        return self.stats


def main():
    """Main entry point for CLI usage."""
    import argparse

    parser = argparse.ArgumentParser(
        description="Automatically normalize Splunk schema indexes in schemaSplunk.json"
    )
    parser.add_argument(
        '--schema',
        type=Path,
        help='Path to schemaSplunk.json (default: data/bespoke/mappings/schemaSplunk.json)'
    )
    parser.add_argument(
        '--force',
        action='store_true',
        help='Force re-normalization of all indexes (default: only normalize new ones)'
    )

    args = parser.parse_args()

    # Initialize normalizer
    normalizer = SplunkSchemaNormalizer(schema_path=args.schema)

    # Run normalization
    stats = normalizer.normalize_all(force=args.force)

    # Exit with error code if there were errors
    if stats['errors']:
        return 1
    return 0


if __name__ == "__main__":
    exit(main())
