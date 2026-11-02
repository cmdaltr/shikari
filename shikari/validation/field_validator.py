"""
Field Validator

Validates that fields used in detection queries exist in the target platform.
Suggests alternatives for missing fields.
"""

import json
import re
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple


class FieldValidator:
    """Validates field usage in detection queries."""

    def __init__(self, knowledge_base_path: str = 'data/external/detections'):
        """
        Initialize field validator.

        Args:
            knowledge_base_path: Path to knowledge base directory
        """
        self.kb_path = Path(knowledge_base_path)
        self.field_mappings_path = self.kb_path / 'field_mappings'
        self.field_catalogs = {}
        self._load_field_catalogs()

    def _load_field_catalogs(self):
        """Load all available field mapping catalogs."""
        if not self.field_mappings_path.exists():
            return

        for catalog_file in self.field_mappings_path.glob('*.json'):
            try:
                with open(catalog_file, 'r', encoding='utf-8') as f:
                    catalog = json.load(f)
                    platform = catalog.get('platform', catalog_file.stem)
                    self.field_catalogs[platform] = catalog
            except Exception as e:
                print(f"Warning: Could not load field catalog {catalog_file}: {e}")

    def validate_query(self, query: str, platform: str) -> Dict:
        """
        Validate fields in a query.

        Args:
            query: The detection query
            platform: Platform name (Splunk, Elastic, etc.)

        Returns:
            Validation result dictionary with:
                - valid: Boolean indicating if all fields are valid
                - missing_fields: List of fields that don't exist
                - suggestions: Dict mapping missing fields to suggested alternatives
                - warnings: List of warning messages
        """
        # Extract fields from query
        fields = self._extract_fields(query, platform)

        # Get field catalog for platform
        catalog = self._get_catalog(platform)

        if not catalog:
            return {
                'valid': None,  # Unknown - no catalog available
                'missing_fields': [],
                'suggestions': {},
                'warnings': [f'No field catalog available for {platform}']
            }

        # Validate each field
        missing_fields = []
        suggestions = {}
        warnings = []

        available_fields = self._get_available_fields(catalog)
        field_aliases = self._get_field_aliases(catalog)

        for field in fields:
            if field not in available_fields:
                # Check if it's an alias
                canonical_field = field_aliases.get(field)
                if canonical_field:
                    warnings.append(
                        f"Field '{field}' is an alias for '{canonical_field}'. "
                        f"Consider using the canonical name."
                    )
                else:
                    missing_fields.append(field)
                    # Find suggestions
                    suggested = self._find_similar_fields(field, available_fields)
                    if suggested:
                        suggestions[field] = suggested

        return {
            'valid': len(missing_fields) == 0,
            'missing_fields': missing_fields,
            'suggestions': suggestions,
            'warnings': warnings
        }

    def _extract_fields(self, query: str, platform: str) -> Set[str]:
        """Extract field names from a query based on platform."""
        fields = set()

        if platform.lower() == 'splunk':
            # Splunk field extraction
            # Pattern 1: field=value or field="value"
            fields.update(re.findall(r'\b(\w+)\s*=', query))
            # Pattern 2: stats/eval/where commands
            fields.update(re.findall(r'(?:by|eval|where)\s+([A-Za-z_][\w.]*)', query))
            # Pattern 3: field IN (...)
            fields.update(re.findall(r'\b(\w+)\s+IN\s*\(', query, re.IGNORECASE))

        elif platform.lower() in ['elastic', 'elasticsearch']:
            # Elastic/KQL field extraction
            # Pattern 1: field:value or field:"value"
            fields.update(re.findall(r'\b([\w.]+)\s*:', query))
            # Pattern 2: field.keyword or field.text
            fields.update(re.findall(r'\b([\w.]+)\.(?:keyword|text)', query))

        elif platform.lower() in ['microsoftthreatprotection', 'microsoft defender', 'kql']:
            # KQL field extraction
            # Pattern 1: field == value or field contains value
            fields.update(re.findall(r'\b(\w+)\s+(?:==|!=|contains|has|startswith|endswith)', query, re.IGNORECASE))
            # Pattern 2: where/project/extend commands
            fields.update(re.findall(r'(?:where|project|extend)\s+([A-Za-z_][\w]*)', query, re.IGNORECASE))

        else:
            # Generic extraction - look for field=value patterns
            fields.update(re.findall(r'\b([A-Za-z_][\w.]*)\s*[=:]', query))

        # Filter out common keywords and operators
        keywords = {
            'and', 'or', 'not', 'in', 'by', 'as', 'from', 'where', 'select',
            'stats', 'eval', 'table', 'search', 'index', 'sourcetype', 'source',
            'true', 'false', 'null', 'count', 'sum', 'avg', 'min', 'max'
        }

        return {f for f in fields if f.lower() not in keywords}

    def _get_catalog(self, platform: str) -> Optional[Dict]:
        """Get field catalog for platform."""
        # Try exact match
        if platform in self.field_catalogs:
            return self.field_catalogs[platform]

        # Try case-insensitive match
        for cat_platform, catalog in self.field_catalogs.items():
            if cat_platform.lower() == platform.lower():
                return catalog

        return None

    def _get_available_fields(self, catalog: Dict) -> Set[str]:
        """Get set of all available fields from catalog."""
        fields = set()
        for field in catalog.get('fields', []):
            fields.add(field['name'])
        return fields

    def _get_field_aliases(self, catalog: Dict) -> Dict[str, str]:
        """Get mapping of aliases to canonical field names."""
        aliases = {}
        for field in catalog.get('fields', []):
            field_name = field['name']
            for alias in field.get('aliases', []):
                aliases[alias] = field_name
        return aliases

    def _find_similar_fields(self, field: str, available_fields: Set[str], max_suggestions: int = 3) -> List[str]:
        """Find similar field names using fuzzy matching."""
        # Simple similarity: Levenshtein-like approach
        suggestions = []

        # Exact substring match
        for available_field in available_fields:
            if field.lower() in available_field.lower() or available_field.lower() in field.lower():
                suggestions.append(available_field)

        if len(suggestions) >= max_suggestions:
            return suggestions[:max_suggestions]

        # Fuzzy match by common prefixes/suffixes
        field_lower = field.lower()
        for available_field in available_fields:
            if available_field in suggestions:
                continue

            available_lower = available_field.lower()

            # Check common prefix
            common_prefix_len = 0
            for i in range(min(len(field_lower), len(available_lower))):
                if field_lower[i] == available_lower[i]:
                    common_prefix_len += 1
                else:
                    break

            # If >50% common prefix, suggest
            if common_prefix_len > len(field_lower) * 0.5:
                suggestions.append(available_field)

            if len(suggestions) >= max_suggestions:
                break

        return suggestions[:max_suggestions]

    def get_field_info(self, field: str, platform: str) -> Optional[Dict]:
        """
        Get detailed information about a field.

        Args:
            field: Field name
            platform: Platform name

        Returns:
            Field information dict or None if not found
        """
        catalog = self._get_catalog(platform)
        if not catalog:
            return None

        for field_info in catalog.get('fields', []):
            if field_info['name'] == field:
                return field_info

            # Check aliases
            if field in field_info.get('aliases', []):
                return field_info

        return None

    def suggest_alternative(self, field: str, platform: str) -> Optional[str]:
        """
        Suggest an alternative field if the given field doesn't exist.

        Args:
            field: Field name that doesn't exist
            platform: Platform name

        Returns:
            Suggested field name or None
        """
        catalog = self._get_catalog(platform)
        if not catalog:
            return None

        available_fields = self._get_available_fields(catalog)
        suggestions = self._find_similar_fields(field, available_fields, max_suggestions=1)

        return suggestions[0] if suggestions else None
