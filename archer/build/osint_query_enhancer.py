#!/usr/bin/env python3
"""
OSINT Query Enhancement Module

This module enhances detection queries by incorporating battle-tested detection patterns
from OSINT sources (Elastic, Splunk, Sigma).

The enhancement process:
1. Extract key detection patterns from OSINT query snippets
2. Translate field names to target schema (Elastic -> Splunk, etc.)
3. Merge patterns into generated queries as additional OR conditions
"""

import re
import logging
from typing import Dict, List, Any, Optional

logger = logging.getLogger(__name__)


class OSINTQueryEnhancer:
    """Enhances queries with OSINT detection patterns"""

    def __init__(self, target_vendor="Splunk"):
        self.target_vendor = target_vendor
        self.field_mappings = self._load_field_mappings()

    def _load_field_mappings(self) -> Dict[str, Dict[str, str]]:
        """
        Load field name mappings for schema translation
        Maps: source_vendor -> {source_field: target_field}
        """
        return {
            "Elastic": {
                # Azure/Cloud fields
                "event.dataset": "source",
                "event.action": "EventID",
                "event.outcome": "EventResult",
                "azure.auditlogs.operation_name": "OperationName",
                "azure.auditlogs.properties.category": "Category",
                "azure.auditlogs.properties.target_resources": "TargetResources",
                "azure.activitylogs.properties.requestbody.properties.roleDefinitionId": "RoleDefinitionId",

                # Process fields
                "process.name": "Image",
                "process.command_line": "CommandLine",
                "process.executable": "ProcessPath",
                "process.parent.name": "ParentImage",
                "process.parent.command_line": "ParentCommandLine",

                # File fields
                "file.name": "TargetFilename",
                "file.path": "TargetObject",
                "file.extension": "FileExtension",

                # Network fields
                "destination.ip": "DestinationIp",
                "destination.port": "DestinationPort",
                "source.ip": "SourceIp",
                "source.port": "SourcePort",

                # User/Account fields
                "user.name": "User",
                "user.domain": "Domain",
            },
            "Sigma": {
                # Sigma uses generic field names
                "CommandLine": "CommandLine",
                "Image": "Image",
                "ParentImage": "ParentImage",
                "TargetFilename": "TargetFilename",
                "DestinationIp": "DestinationIp",
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

    def translate_field(self, field: str, source_vendor: str) -> str:
        """Translate field name from source schema to target schema"""
        if source_vendor not in self.field_mappings:
            return field

        mapping = self.field_mappings[source_vendor]
        return mapping.get(field, field)

    def generate_enhancement_conditions(self, patterns: List[Dict[str, Any]], source_vendor: str) -> List[str]:
        """
        Generate query conditions from extracted patterns

        Returns list of condition strings that can be added to the main query
        """
        conditions = []

        for pattern in patterns:
            field = self.translate_field(pattern["field"], source_vendor)
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

        return conditions

    def enhance_query(self, base_query: str, osint_indicators: Dict[str, List[str]],
                      target_vendor: str = "Splunk") -> str:
        """
        Enhance a base query with OSINT detection patterns

        Args:
            base_query: The generated detection query
            osint_indicators: OSINT indicators dict from YAML (contains query_snippets, cmd, sw, etc.)
            target_vendor: Target SIEM vendor (Splunk or MDE)

        Returns:
            Enhanced query with OSINT patterns merged in
        """
        if not osint_indicators:
            return base_query

        self.target_vendor = target_vendor
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

            # For MDE: Add as OR conditions in the where clause
            elif target_vendor == "MDE":
                osint_filter = " or " + " or ".join(all_conditions)
                enhanced_query = base_query + osint_filter
                return enhanced_query

        return base_query


def enhance_query_with_osint(base_query: str, osint_indicators: Dict[str, List[str]],
                              target_vendor: str = "Splunk") -> str:
    """
    Convenience function to enhance a query with OSINT patterns

    Args:
        base_query: The generated detection query
        osint_indicators: OSINT indicators dict from YAML
        target_vendor: Target SIEM vendor (Splunk or MDE)

    Returns:
        Enhanced query with OSINT patterns merged in
    """
    enhancer = OSINTQueryEnhancer(target_vendor=target_vendor)
    return enhancer.enhance_query(base_query, osint_indicators, target_vendor)
