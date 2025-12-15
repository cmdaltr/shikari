#!/usr/bin/env python3
"""
OSINT Query Enhancement Module

This module enhances detection queries by incorporating battle-tested detection patterns
from OSINT sources (Elastic, Splunk, Sigma).

The enhancement process:
1. Extract key detection patterns from OSINT query snippets
2. Translate field names to target schema using pySigma pipelines when available
3. Merge patterns into generated queries as additional OR conditions

Uses pySigma for industry-standard field mapping where possible.
"""

import re
import logging
from typing import Dict, List, Any, Optional

logger = logging.getLogger(__name__)

# Try to import pySigma for advanced field mapping
try:
    from sigma.backends.microsoft365defender import KustoBackend
    from sigma.pipelines.microsoft365defender import microsoft_365_defender_pipeline
    from sigma.collection import SigmaCollection
    HAS_PYSIGMA = True
except ImportError:
    HAS_PYSIGMA = False
    logger.warning("pySigma not available - using fallback field mappings")


class OSINTQueryEnhancer:
    """Enhances queries with OSINT detection patterns"""

    def __init__(self, target_vendor="Splunk"):
        self.target_vendor = target_vendor
        self.field_mappings = self._load_field_mappings()
        self.mde_valid_fields = self._load_mde_schema_fields()
        self.pysigma_field_cache = self._load_pysigma_field_mappings()

    def _load_mde_schema_fields(self) -> set:
        """
        Load valid MDE field names from schemaMDE.json

        Returns set of all valid MDE field names across all tables
        """
        try:
            import json
            import os
            schema_path = os.path.join(os.path.dirname(__file__), '..', '..', 'data', 'bespoke', 'mappings', 'schemaMDE.json')
            with open(schema_path, 'r') as f:
                mde_schema = json.load(f)

            # Extract fields from all tables
            valid_fields = set()
            for table, query in mde_schema.items():
                # Extract fields from "summarize by Field1, Field2, ..."
                match = re.search(r'summarize by (.+)', query)
                if match:
                    fields = [f.strip() for f in match.group(1).split(',')]
                    valid_fields.update(fields)

            logger.info(f"Loaded {len(valid_fields)} valid MDE fields from schema")
            return valid_fields
        except Exception as e:
            logger.warning(f"Could not load MDE schema: {e}")
            return set()

    def _load_pysigma_field_mappings(self) -> Dict[str, str]:
        """
        Pre-load pySigma field mappings for common Sigma fields

        This avoids the performance overhead of converting individual fields on-the-fly.
        Returns a dictionary of Sigma field → KQL field mappings.
        """
        if not HAS_PYSIGMA or self.target_vendor != "MDE":
            return {}

        # Common Sigma field names to pre-translate
        common_sigma_fields = [
            "CommandLine", "Image", "ParentImage", "ParentCommandLine",
            "TargetFilename", "FileName", "User", "ParentUser",
            "ProcessId", "ParentProcessId", "DestinationIp", "SourceIp",
            "DestinationPort", "SourcePort", "RegistryKey", "RegistryValueData",
            "TargetObject", "Details", "Hashes", "md5", "sha1", "sha256",
            "IntegrityLevel", "Imphash"
        ]

        field_cache = {}
        try:
            pipeline = microsoft_365_defender_pipeline()
            backend = KustoBackend(processing_pipeline=pipeline)

            for field in common_sigma_fields:
                try:
                    test_rule = f"""
title: Field Mapping Test
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        {field}: test_value
    condition: selection
"""
                    sigma_collection = SigmaCollection.from_yaml(test_rule)
                    result = backend.convert(sigma_collection)

                    if result:
                        kql = result[0]
                        # Extract KQL field name from output
                        match = re.search(r'(\w+)\s+(?:==|contains|endswith|startswith|has_any)', kql)
                        if match:
                            kql_field = match.group(1)
                            field_cache[field] = kql_field
                            logger.debug(f"pySigma: {field} → {kql_field}")
                except Exception:
                    # Field not supported by pySigma - skip
                    field_cache[field] = None

            logger.info(f"Cached {len([v for v in field_cache.values() if v])} pySigma field mappings")
        except Exception as e:
            logger.warning(f"Could not load pySigma field mappings: {e}")

        return field_cache

    def _load_field_mappings(self) -> Dict[str, Dict[str, str]]:
        """
        Load field name mappings for schema translation
        Maps: source_vendor -> {source_field: target_field}

        For OSINT-to-KQL (MDE) mappings:
        - Maps source field names (Splunk/Elastic/Sigma/CAR) to their KQL equivalents
        - Uses None for fields that should be skipped (no KQL equivalent)
        """
        return {
            "Elastic": {
                # Azure/Cloud fields
                "event.dataset": None,  # ECS-specific, no direct KQL mapping
                "event.action": "ActionType",  # Maps to MDE ActionType
                "event.outcome": None,  # Generic field, context-dependent
                "azure.auditlogs.operation_name": "OperationName",
                "azure.auditlogs.properties.category": "Category",
                "azure.auditlogs.properties.target_resources": None,  # Complex nested field
                "azure.activitylogs.properties.requestbody.properties.roleDefinitionId": None,  # Complex nested field

                # Process fields (ECS to KQL/MDE)
                "process.name": "FileName",  # ECS process.name -> MDE FileName
                "process.executable": "FolderPath",  # ECS process.executable -> MDE FolderPath (full path)
                "process.command_line": "ProcessCommandLine",  # ECS -> MDE
                "process.parent.name": "InitiatingProcessFileName",  # ECS parent -> MDE InitiatingProcess
                "process.parent.executable": "InitiatingProcessFolderPath",
                "process.parent.command_line": "InitiatingProcessCommandLine",

                # File fields (ECS to KQL/MDE)
                "file.name": "FileName",
                "file.path": "FolderPath",
                "file.extension": None,  # No direct MDE field, skip
                "file.hash.sha256": "SHA256",
                "file.hash.sha1": "SHA1",
                "file.hash.md5": "MD5",

                # Network fields (ECS to KQL/MDE)
                "destination.ip": "RemoteIP",
                "destination.port": "RemotePort",
                "source.ip": "LocalIP",
                "source.port": "LocalPort",
                "destination.address": "RemoteUrl",
                "source.address": "LocalIP",

                # User/Account fields (ECS to KQL/MDE)
                "user.name": "AccountName",
                "user.domain": "AccountDomain",
                "user.id": None,  # Generic ID, skip
            },
            "Sigma": {
                # Sigma-to-KQL (MDE) field mappings
                # Sigma uses Windows/Sysmon-like field names

                # Process fields
                "CommandLine": "ProcessCommandLine",
                "Image": "FileName",  # Sigma 'Image' (process path) -> MDE FileName
                "ParentImage": "InitiatingProcessFolderPath",  # Sigma ParentImage -> MDE InitiatingProcessFolderPath
                "ParentCommandLine": "InitiatingProcessCommandLine",
                "ParentProcessId": None,  # Not in standard MDE tables
                "ProcessId": None,  # Not in standard MDE tables

                # File fields
                "TargetFilename": "FileName",
                "TargetObject": "RegistryKey",  # For registry operations
                "FileName": "FileName",

                # Network fields
                "DestinationIp": "RemoteIP",
                "DestinationPort": "RemotePort",
                "SourceIp": "LocalIP",
                "SourcePort": "LocalPort",

                # User fields
                "User": "AccountName",
                "LogonId": "LogonId",

                # Registry fields
                "TargetObject": "RegistryKey",
                "Details": "RegistryValueData",

                # Hash fields
                "Hashes": None,  # Sigma uses combined hash field, needs parsing
                "md5": "MD5",
                "sha1": "SHA1",
                "sha256": "SHA256",

                # Fields to SKIP
                "IntegrityLevel": None,  # Sysmon-specific, no MDE equivalent
                "Imphash": None,  # Import hash, not in MDE standard tables
            },
            "Splunk": {
                # Splunk-to-KQL (MDE) field mappings
                # Process fields
                "process": "FileName",  # Splunk 'process' field maps to KQL 'FileName'
                "ParentUser": "InitiatingProcessAccountName",  # Splunk 'ParentUser' maps to KQL 'InitiatingProcessAccountName'
                "parent_process": "InitiatingProcessFolderPath",  # Parent process path
                "parent_process_name": "InitiatingProcessFolderPath",  # Parent process path
                "process_name": "FileName",
                "process_path": "FolderPath",

                # User/Account fields
                "User": "AccountName",
                "src_user": "AccountName",
                "user": "AccountName",
                "dest_user": "AccountName",

                # File fields
                "file_name": "FileName",
                "file_path": "FolderPath",

                # Command fields
                "CommandLine": "ProcessCommandLine",
                "ParentCommandLine": "InitiatingProcessCommandLine",

                # Network fields
                "src_ip": "LocalIP",
                "dest_ip": "RemoteIP",
                "src_port": "LocalPort",
                "dest_port": "RemotePort",

                # Fields to SKIP (Splunk-only, no KQL equivalent)
                # Using None as value means "skip this field"
                "process_integrity_level": None,  # Only in DeviceProcessEvents, not DeviceEvents
                "ProcessIntegrityLevel": None,  # Only in DeviceProcessEvents
                "IntegrityLevel": None,  # Splunk Sysmon field, no direct KQL equivalent
                "SidHistory": None,  # AD-specific, not in MDE tables
                "EnabledPrivilegeList": None,  # No direct KQL equivalent
                "Processes.process": None,  # Splunk data model syntax
                "Processes.user": None,  # Splunk data model syntax
                "Processes.process_integrity_level": None,  # Splunk data model syntax
                "Endpoint.Processes": None,  # Splunk data model
                "signature": None,  # Splunk ES field, context-dependent
            },
            "CAR": {
                # MITRE CAR-to-KQL (MDE) field mappings
                # CAR uses a data model similar to CIM/Splunk

                # Process fields
                "exe": "FolderPath",  # CAR 'exe' -> full executable path
                "command_line": "ProcessCommandLine",
                "parent_exe": "InitiatingProcessFolderPath",
                "parent_command_line": "InitiatingProcessCommandLine",
                "pid": "ProcessId",
                "ppid": "InitiatingProcessId",

                # User fields
                "user": "AccountName",
                "uid": None,  # Unix UID, not applicable to Windows MDE

                # File fields
                "file_name": "FileName",
                "file_path": "FolderPath",

                # Network fields
                "src_ip": "LocalIP",
                "dest_ip": "RemoteIP",
                "src_port": "LocalPort",
                "dest_port": "RemotePort",
                "hostname": "DeviceName",

                # Fields to SKIP
                "sysmon_event_id": None,  # Sysmon-specific
                "event_type": None,  # Generic field
            }
        }

    def extract_patterns_from_query(self, query_snippet: str, source_vendor: str) -> List[Dict[str, Any]]:
        """
        Extract detection patterns from OSINT query snippets

        Returns list of patterns: [
            {
                "field": "OperationName",
                "operator": "=",
                "values": ["Add member to role", "Update role"],
                "logic": "OR"
            }
        ]
        """
        patterns = []

        # Remove vendor prefix like "[Splunk] " or "[Elastic] "
        query_snippet = re.sub(r'^\[.*?\]\s*', '', query_snippet)

        if source_vendor == "Splunk":
            patterns.extend(self._extract_splunk_patterns(query_snippet))
        elif source_vendor == "Elastic":
            patterns.extend(self._extract_elastic_patterns(query_snippet))

        logger.info(f"Extracted {len(patterns)} patterns from {source_vendor} query")
        return patterns

    def _extract_splunk_patterns(self, query: str) -> List[Dict[str, Any]]:
        """Extract patterns from Splunk SPL queries"""
        patterns = []

        # Pattern 1: field="value" or field=value
        field_value_pattern = r'(\w+)\s*=\s*"([^"]+)"'
        for match in re.finditer(field_value_pattern, query):
            field, value = match.groups()
            patterns.append({
                "field": field,
                "operator": "=",
                "values": [value],
                "logic": "OR"
            })

        # Pattern 2: field IN ("val1", "val2")
        in_pattern = r'(\w+)\s+IN\s*\(\s*([^)]+)\s*\)'
        for match in re.finditer(in_pattern, query):
            field, values_str = match.groups()
            values = [v.strip(' "') for v in values_str.split(',')]
            patterns.append({
                "field": field,
                "operator": "IN",
                "values": values,
                "logic": "OR"
            })

        # Pattern 3: | search "field"=value
        search_pattern = r'\|\s*search\s+"([^"]+)"\s*=\s*(\w+)'
        for match in re.finditer(search_pattern, query):
            field, value = match.groups()
            patterns.append({
                "field": field,
                "operator": "=",
                "values": [value],
                "logic": "OR"
            })

        return patterns

    def _extract_elastic_patterns(self, query: str) -> List[Dict[str, Any]]:
        """Extract patterns from Elastic EQL/KQL queries"""
        patterns = []

        # Pattern 1: field: "value" or field:"value"
        field_value_pattern = r'(\w+(?:\.\w+)*)\s*:\s*"([^"]+)"'
        for match in re.finditer(field_value_pattern, query):
            field, value = match.groups()
            patterns.append({
                "field": field,
                "operator": ":",
                "values": [value],
                "logic": "OR"
            })

        # Pattern 2: field:(value1 or value2)
        or_pattern = r'(\w+(?:\.\w+)*)\s*:\s*\(([^)]+)\)'
        for match in re.finditer(or_pattern, query):
            field, values_str = match.groups()
            # Split on 'or' keyword
            values = [v.strip(' "') for v in re.split(r'\s+or\s+', values_str, flags=re.IGNORECASE)]
            patterns.append({
                "field": field,
                "operator": ":",
                "values": values,
                "logic": "OR"
            })

        return patterns

    def translate_field_with_pysigma(self, field: str, source_vendor: str) -> Optional[str]:
        """
        Use pySigma to translate field names (for Sigma rules targeting MDE/KQL)

        Returns:
            - Translated field name if pySigma can map it
            - None if field should be skipped or pySigma not available
        """
        if not HAS_PYSIGMA or self.target_vendor != "MDE" or source_vendor != "Sigma":
            return None

        try:
            # pySigma's microsoft_365_defender pipeline has built-in field mappings
            # We can construct a minimal Sigma rule to test field translation
            test_rule = f"""
title: Field Translation Test
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        {field}: test_value
    condition: selection
"""
            pipeline = microsoft_365_defender_pipeline()
            backend = KustoBackend(processing_pipeline=pipeline)
            sigma_collection = SigmaCollection.from_yaml(test_rule)

            # Convert and extract the field name from the KQL output
            result = backend.convert(sigma_collection)
            if result:
                kql = result[0]
                # Extract field name from pattern like "FieldName == "test_value"" or "FieldName contains "test_value""
                match = re.search(r'(\w+)\s+(?:==|contains|endswith|startswith)', kql)
                if match:
                    return match.group(1)
        except Exception as e:
            # Field not supported by pySigma pipeline - will skip
            logger.debug(f"pySigma field translation failed for {field}: {e}")
            return None

        return None

    def translate_field(self, field: str, source_vendor: str) -> Optional[str]:
        """
        Translate field name from source schema to target schema

        Uses pySigma for Sigma→KQL translation when available, otherwise uses fallback mappings.
        Validates translated fields against schemaMDE.json for MDE target.

        Returns:
            - Translated field name if mapping exists and is valid
            - Original field name if no mapping exists
            - None if field should be skipped (has no equivalent in target schema)
        """
        # Try pySigma cache first for Sigma rules targeting MDE
        if source_vendor == "Sigma" and self.target_vendor == "MDE" and self.pysigma_field_cache:
            if field in self.pysigma_field_cache:
                cached_result = self.pysigma_field_cache[field]
                if cached_result:
                    logger.debug(f"pySigma cache hit: {field} → {cached_result}")
                    return cached_result
                else:
                    # Cached as unsupported
                    logger.debug(f"pySigma cache: {field} is unsupported")
                    return None

        # Fallback to manual mappings
        if source_vendor not in self.field_mappings:
            # If targeting MDE and no mapping, check if field already exists in schema
            if self.target_vendor == "MDE" and self.mde_valid_fields:
                if field in self.mde_valid_fields:
                    return field  # Field name is already valid MDE field
                else:
                    logger.debug(f"Field '{field}' not found in MDE schema - skipping")
                    return None  # Field doesn't exist in MDE schema
            return field

        mapping = self.field_mappings[source_vendor]

        # Check if field exists in mapping
        if field in mapping:
            translated = mapping[field]
            # None means "skip this field"
            if translated is None:
                return None

            # Validate translated field against MDE schema
            if self.target_vendor == "MDE" and self.mde_valid_fields:
                if translated not in self.mde_valid_fields:
                    logger.warning(f"Mapped field '{field}' → '{translated}' not found in MDE schema - skipping")
                    return None

            return translated

        # No mapping found - check if field already valid for target
        if self.target_vendor == "MDE" and self.mde_valid_fields:
            if field in self.mde_valid_fields:
                return field  # Field name is already valid
            else:
                logger.debug(f"Unmapped field '{field}' not found in MDE schema - skipping")
                return None

        # Return original field name
        return field

    def generate_enhancement_conditions(self, patterns: List[Dict[str, Any]], source_vendor: str) -> List[str]:
        """
        Generate query conditions from extracted patterns

        Returns list of condition strings that can be added to the main query
        Skips patterns where the source field has no target equivalent (translates to None)
        """
        conditions = []
        skipped_fields = []

        for pattern in patterns:
            # Translate field name (may return None if field should be skipped)
            translated_field = self.translate_field(pattern["field"], source_vendor)

            # Skip this pattern if field has no target equivalent
            if translated_field is None:
                skipped_fields.append(pattern["field"])
                continue

            field = translated_field
            operator = pattern["operator"]
            values = pattern["values"]

            if self.target_vendor == "Splunk":
                # Generate Splunk SPL conditions
                if operator in ["=", ":"]:
                    if len(values) == 1:
                        conditions.append(f'{field}="{values[0]}"')
                    else:
                        # Multiple values -> use IN
                        values_str = ', '.join([f'"{v}"' for v in values])
                        conditions.append(f'{field} IN ({values_str})')
                elif operator == "IN":
                    values_str = ', '.join([f'"{v}"' for v in values])
                    conditions.append(f'{field} IN ({values_str})')

            elif self.target_vendor == "MDE":
                # Generate KQL conditions
                if operator in ["=", ":"]:
                    if len(values) == 1:
                        conditions.append(f'{field} == "{values[0]}"')
                    else:
                        # Multiple values -> use has_any
                        values_str = ', '.join([f'"{v}"' for v in values])
                        conditions.append(f'{field} has_any ({values_str})')
                elif operator == "IN":
                    values_str = ', '.join([f'"{v}"' for v in values])
                    conditions.append(f'{field} has_any ({values_str})')

        # Log skipped fields if any
        if skipped_fields:
            unique_skipped = list(set(skipped_fields))
            logger.info(f"Skipped {len(unique_skipped)} Splunk-only field(s) with no {self.target_vendor} equivalent: {', '.join(unique_skipped[:5])}")

        return conditions

    def _build_mde_osint_variables(self, osint_indicators: Dict[str, List[str]]) -> str:
        """
        Build KQL let statements for OSINT indicator datatables

        Maps indicator types to KQL datatable variables:
        - cmd → OSINTCommands
        - sw → OSINTSoftware
        - path → OSINTPaths
        - acct → OSINTAccounts
        - reg → OSINTRegistry
        - api → OSINTAPIs
        - op → OSINTOperations
        """
        let_statements = []
        let_statements.append("// OSINT Enhancements")

        # Map indicator types to variable names and datatable column types
        indicator_mappings = {
            "cmd": ("OSINTCommands", "cmds"),
            "sw": ("OSINTSoftware", "software"),
            "path": ("OSINTPaths", "paths"),
            "acct": ("OSINTAccounts", "accounts"),
            "reg": ("OSINTRegistry", "registry"),
            "api": ("OSINTAPIs", "apis"),
            "op": ("OSINTOperations", "operations"),
            "evt": ("OSINTEvents", "events"),
        }

        for indicator_type, (var_name, column_name) in indicator_mappings.items():
            values = osint_indicators.get(indicator_type, [])
            if values and len(values) > 0:
                # Escape quotes in values and format as KQL array
                escaped_values = [f'"{v.replace(chr(34), chr(34)+chr(34))}"' for v in values]
                values_str = ", ".join(escaped_values)
                let_statements.append(f'let {var_name} = datatable({column_name}:string) [{values_str}];')

        return "\n".join(let_statements)

    def _build_mde_osint_conditions(self, osint_indicators: Dict[str, List[str]]) -> str:
        """
        Build KQL where conditions for OSINT enhancement

        Creates conditions that check various MDE fields against OSINT datatables
        """
        conditions = []

        # Commands - check ProcessCommandLine and InitiatingProcessCommandLine
        if osint_indicators.get("cmd"):
            conditions.append("ProcessCommandLine in (OSINTCommands) or InitiatingProcessCommandLine in (OSINTCommands)")

        # Software/Processes - check process names and paths
        if osint_indicators.get("sw"):
            conditions.append("ProcessCommandLine in (OSINTSoftware) or InitiatingProcessCommandLine in (OSINTSoftware) or FolderPath in (OSINTSoftware) or InitiatingProcessFolderPath in (OSINTSoftware)")

        # Paths - check file and process paths
        if osint_indicators.get("path"):
            conditions.append("ProcessCommandLine in (OSINTPaths) or InitiatingProcessCommandLine in (OSINTPaths) or FolderPath in (OSINTPaths) or InitiatingProcessFolderPath in (OSINTPaths)")

        # Accounts - check account names
        if osint_indicators.get("acct"):
            conditions.append("AccountName in (OSINTAccounts) or InitiatingProcessAccountName in (OSINTAccounts)")

        # Registry - check registry keys
        if osint_indicators.get("reg"):
            conditions.append("RegistryKey in (OSINTRegistry) or PreviousRegistryKey in (OSINTRegistry)")

        # APIs - check command lines for API calls
        if osint_indicators.get("api"):
            conditions.append("ProcessCommandLine in (OSINTAPIs) or InitiatingProcessCommandLine in (OSINTAPIs)")

        # Operations - check command lines for operations
        if osint_indicators.get("op"):
            conditions.append("ProcessCommandLine in (OSINTOperations) or InitiatingProcessCommandLine in (OSINTOperations)")

        # Events - check ActionType
        if osint_indicators.get("evt"):
            conditions.append("ActionType in (OSINTEvents)")

        if conditions:
            return "(" + " or\n".join(conditions) + ")"
        return ""

    def enhance_query(self, base_query: str, osint_indicators: Dict[str, List[str]],
                      target_vendor: str = "Splunk") -> tuple:
        """
        Enhance a base query with OSINT detection patterns

        Args:
            base_query: The generated detection query
            osint_indicators: OSINT indicators dict from YAML (contains query_snippets, cmd, sw, etc.)
            target_vendor: Target SIEM vendor (Splunk or MDE)

        Returns:
            tuple: (enhanced_query, was_enhanced) where was_enhanced is True if query was actually modified
        """
        if not osint_indicators:
            logger.debug("No OSINT indicators provided, returning base query")
            return (base_query, False)

        self.target_vendor = target_vendor

        # Debug logging
        logger.info(f"=== OSINT Enhancement Debug ===")
        logger.info(f"Target vendor: {target_vendor}")
        logger.info(f"OSINT indicators keys: {list(osint_indicators.keys())}")
        for key, value in osint_indicators.items():
            if isinstance(value, list):
                logger.info(f"  {key}: {len(value)} items")
            else:
                logger.info(f"  {key}: {type(value)}")

        # For MDE: Use structured datatable approach
        if target_vendor == "MDE":
            # Check if we have any direct indicators (cmd, sw, path, etc.)
            has_direct_indicators = any(
                osint_indicators.get(ind_type)
                for ind_type in ["cmd", "sw", "path", "acct", "reg", "api", "op", "evt"]
            )

            logger.info(f"Has direct indicators: {has_direct_indicators}")
            if has_direct_indicators:
                for ind_type in ["cmd", "sw", "path", "acct", "reg", "api", "op", "evt"]:
                    indicators = osint_indicators.get(ind_type)
                    if indicators:
                        logger.info(f"  - {ind_type}: {len(indicators)} indicators")

            if has_direct_indicators:
                # Build let statements for datatables
                let_statements = self._build_mde_osint_variables(osint_indicators)
                logger.info(f"Built let statements:\n{let_statements}")

                # Build OSINT enhancement conditions
                osint_conditions = self._build_mde_osint_conditions(osint_indicators)
                logger.info(f"Built OSINT conditions:\n{osint_conditions}")

                if osint_conditions:
                    # Parse the base query to find where to inject OSINT enhancements
                    lines = base_query.strip().split("\n")

                    # Find the table name (first non-comment, non-let line)
                    table_line_idx = 0
                    for i, line in enumerate(lines):
                        stripped = line.strip()
                        if stripped and not stripped.startswith("//") and not stripped.startswith("let "):
                            table_line_idx = i
                            break

                    # Find the summarize line (last line typically)
                    summarize_line_idx = len(lines) - 1
                    for i in range(len(lines) - 1, -1, -1):
                        if "summarize by" in lines[i].lower() or "| summarize" in lines[i].lower():
                            summarize_line_idx = i
                            break

                    # Extract existing query body (between table and summarize)
                    existing_query_lines = lines[table_line_idx + 1:summarize_line_idx]

                    # Find the last where clause to append OSINT conditions
                    last_where_idx = -1
                    for i in range(len(existing_query_lines) - 1, -1, -1):
                        if "| where" in existing_query_lines[i]:
                            last_where_idx = i
                            break

                    # Build enhanced query
                    enhanced_parts = []
                    enhanced_parts.append(let_statements)
                    enhanced_parts.append(lines[table_line_idx])  # Table name

                    if last_where_idx >= 0:
                        # Add all lines up to and including the last where clause
                        for i in range(last_where_idx + 1):
                            enhanced_parts.append(existing_query_lines[i])

                        # Wrap existing where condition and add OSINT enhancement
                        last_where_line = existing_query_lines[last_where_idx]
                        # Extract the condition part (everything after "| where")
                        where_condition = last_where_line.split("| where", 1)[1].strip()

                        # Replace the last where with enhanced version
                        enhanced_parts[-1] = f"| where ({where_condition}) or"
                        enhanced_parts.append("// OSINT Enhancement")
                        enhanced_parts.append(osint_conditions)

                        # Add remaining lines after the last where clause
                        for i in range(last_where_idx + 1, len(existing_query_lines)):
                            enhanced_parts.append(existing_query_lines[i])
                    else:
                        # No where clause found, add OSINT as new where clause
                        for line in existing_query_lines:
                            enhanced_parts.append(line)
                        enhanced_parts.append("// OSINT Enhancement")
                        enhanced_parts.append(f"| where {osint_conditions}")

                    enhanced_parts.append(lines[summarize_line_idx])  # Summarize

                    enhanced_query = "\n".join(enhanced_parts)

                    logger.info(f"✓ Enhanced MDE query with OSINT datatables")
                    return (enhanced_query, True)
                else:
                    logger.warning("No OSINT conditions generated, falling back to query_snippets method")

            else:
                logger.info("No direct indicators found, falling back to query_snippets method")

            # Fallback to query_snippets method if no direct indicators
            logger.info("Using _enhance_with_query_snippets fallback method")
            result = self._enhance_with_query_snippets(base_query, osint_indicators, target_vendor)
            # For MDE, if we're using fallback, it means no enhancement was done
            return (result, False)

        # For Splunk: Use existing query_snippets method
        result = self._enhance_with_query_snippets(base_query, osint_indicators, target_vendor)
        # Check if Splunk query was actually enhanced (different from base)
        was_enhanced = result != base_query
        return (result, was_enhanced)

    def _enhance_with_query_snippets(self, base_query: str, osint_indicators: Dict[str, List[str]], target_vendor: str) -> str:
        """
        Original enhancement method using query snippets
        Used as fallback for MDE when no direct indicators, and default for Splunk
        """
        all_conditions = []

        # Extract and process query snippets
        query_snippets = osint_indicators.get("query_snippets", [])
        for snippet_with_url in query_snippets:
            # Parse format: "[Vendor] query|||url"
            parts = snippet_with_url.split("|||")
            if len(parts) < 1:
                continue

            snippet_with_source = parts[0]

            # Extract vendor from "[Vendor] query" format
            vendor_match = re.match(r'\[(Splunk|Elastic|Sigma)\]\s*(.+)', snippet_with_source)
            if not vendor_match:
                continue

            source_vendor = vendor_match.group(1)
            query_snippet = vendor_match.group(2)

            # Extract patterns from this query
            patterns = self.extract_patterns_from_query(query_snippet, source_vendor)

            # Generate conditions for target vendor
            conditions = self.generate_enhancement_conditions(patterns, source_vendor)
            all_conditions.extend(conditions)

        # If we have OSINT conditions, merge them into the base query
        if all_conditions:
            logger.info(f"Adding {len(all_conditions)} OSINT enhancement conditions to query")

            # For Splunk: Add as OR conditions in the where clause
            if target_vendor == "Splunk":
                # Find the main where clause and add OSINT patterns
                osint_filter = " OR " + " OR ".join(all_conditions)
                enhanced_query = base_query + osint_filter
                return enhanced_query

            # For MDE: Use datatable format even for query_snippet-extracted patterns
            elif target_vendor == "MDE":
                # The old method just appended conditions - but we should NOT do that
                # Instead, return the base query and log that we need proper indicators
                logger.warning(f"MDE query has OSINT query_snippets but no direct indicators - enhancement skipped. Query snippets should be converted to direct indicators during OSINT comparison phase.")
                return base_query

        return base_query


def enhance_query_with_osint(base_query: str, osint_indicators: Dict[str, List[str]],
                              target_vendor: str = "Splunk") -> tuple:
    """
    Convenience function to enhance a query with OSINT patterns

    Args:
        base_query: The generated detection query
        osint_indicators: OSINT indicators dict from YAML
        target_vendor: Target SIEM vendor (Splunk or MDE)

    Returns:
        tuple: (enhanced_query, was_enhanced) where was_enhanced is True if query was actually modified
    """
    enhancer = OSINTQueryEnhancer(target_vendor=target_vendor)
    return enhancer.enhance_query(base_query, osint_indicators, target_vendor)
