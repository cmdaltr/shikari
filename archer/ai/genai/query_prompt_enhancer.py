"""
Query Prompt Enhancer

Enhances LLM prompts with relevant high-quality query examples to improve
detection rule generation through few-shot learning.

This module injects contextually relevant examples into prompts based on:
- MITRE ATT&CK technique being generated
- Target SIEM platform (Splunk, MDE/KQL, Google SecOps, Elastic)
- Organizational field schema (schemaSplunk.json, schemaMDE.json, schemaGoogleSecOps.json, schemaElastic.json)
"""

import json
from pathlib import Path
from typing import Dict, List, Optional
from .query_examples import get_repository


class QueryPromptEnhancer:
    """Enhances query generation prompts with relevant examples."""

    def __init__(self, schema_dir: str = None):
        """
        Initialize the prompt enhancer.

        Args:
            schema_dir: Directory containing SIEM schema files (default: archer/mappings)
        """
        if schema_dir is None:
            archer_dir = Path(__file__).parent.parent.parent
            schema_dir = archer_dir / "bespoke" / "mappings" / "schemas"

        self.schema_dir = Path(schema_dir)
        self.repository = get_repository()

        # Load organizational schemas
        self.schemas = {}
        self._load_schemas()

    def _load_schemas(self):
        """Load organizational SIEM schemas."""
        schema_files = {
            "splunk": "schemaSplunk.json",
            "mde": "schemaMDE.json",
            "googlesecops": "schemaGoogleSecOps.json",
            "elastic": "schemaElastic.json",
        }

        for vendor, filename in schema_files.items():
            schema_path = self.schema_dir / filename
            if schema_path.exists():
                try:
                    with open(schema_path, "r", encoding="utf-8") as f:
                        self.schemas[vendor] = json.load(f)
                    print(f"Loaded {vendor} schema from {filename}")
                except Exception as e:
                    print(f"Warning: Could not load {vendor} schema: {e}")

    def enhance_query_generation_prompt(
        self,
        technique_id: str,
        technique_name: str,
        technique_description: str,
        vendor: str,
        indicator_type: str,
        indicators: List[str],
        tactic: str = None,
        num_examples: int = 3,
    ) -> str:
        """
        Generate an enhanced prompt for query generation with relevant examples.

        Args:
            technique_id: MITRE ATT&CK technique ID (e.g., "T1003")
            technique_name: Name of the technique
            technique_description: Description of the technique
            vendor: Target SIEM vendor (splunk, mde, elastic)
            indicator_type: Type of indicators (cmd, reg, evt, sw)
            indicators: List of indicators to detect
            tactic: MITRE ATT&CK tactic
            num_examples: Number of examples to include

        Returns:
            Enhanced prompt string ready for LLM
        """
        # Get relevant examples
        examples = self.repository.get_examples_for_technique(
            technique_id, vendor=vendor, limit=num_examples
        )

        # If no technique-specific examples, try tactic-based
        if not examples and tactic:
            examples = self.repository.get_examples_for_tactic(
                tactic, vendor=vendor, limit=num_examples
            )

        # Get schema information for this vendor
        schema_info = self._get_schema_info(vendor, indicator_type)

        # Build the enhanced prompt
        prompt_parts = []

        # 1. Task description
        prompt_parts.append(
            f"""# Task: Generate {vendor.upper()} Detection Query

You are generating a detection query for the following MITRE ATT&CK technique:

**Technique**: {technique_id} - {technique_name}
**Tactic**: {tactic or 'Unknown'}
**Description**: {technique_description}

**Indicators to Detect**:
"""
        )

        for indicator in indicators:
            prompt_parts.append(f"  - {indicator}")

        # 2. Schema information (field names specific to organization)
        if schema_info:
            prompt_parts.append(
                f"""

## Field Schema for {vendor.upper()}

Use these specific field names in your query (organizational schema):
"""
            )
            prompt_parts.append(schema_info)

        # 3. Example queries (few-shot learning)
        if examples:
            prompt_parts.append(
                f"""

## High-Quality Example Queries

Here are {len(examples)} professionally-written detection queries for similar techniques to guide your approach:
"""
            )

            for idx, example in enumerate(examples, 1):
                prompt_parts.append(f"""
### Example {idx}: {example['name']}
**Technique**: {', '.join(example.get('techniques', ['N/A']))}
**Description**: {example.get('description', 'No description')[:200]}

**Query**:
```{vendor}
{example['query'][:1000]}
```

**Key Patterns**:
{self._extract_key_patterns(example['query'], vendor)}
""")

        # 4. Best practices
        prompt_parts.append(
            f"""

## Best Practices for {vendor.upper()} Queries

"""
        )

        if vendor == "splunk":
            prompt_parts.append(
                """
1. **Index Selection**: Always specify the correct index (e.g., index=edr_events, index=windows_events)
2. **Time Window**: Use earliest=-1d for recent events
3. **Wildcard Matching**: Use "*term*" for substring matching in field values
4. **Field Extraction**: Use | fields to select relevant fields early in the pipeline
5. **Aggregation**: Use | stats to group and count matching events
6. **Multi-word Indicators**: For phrases, combine with AND: (field="*word1*" AND field="*word2*")
7. **Performance**: Filter by index and time first, then apply complex logic
8. **Field Names**: Use exact field names from the organizational schema above

**Common Splunk Fields (from schema)**:
- Process execution: process_name, new_process_name, process_command_line_arguments, parent_process_name
- User context: user, AccountName, InitiatingProcessAccountName
- System: ComputerName, DeviceName
- Registry: RegistryKey, RegistryValueData
- Event IDs: EventCode
"""
            )
        elif vendor == "mde":
            prompt_parts.append(
                """
1. **Table Selection**: Start with the appropriate Device* table (DeviceProcessEvents, DeviceFileEvents, etc.)
2. **Time Filtering**: Use | where Timestamp > ago(1d) early in the query
3. **String Matching**: Use has, has_any, has_all for efficient string matching
4. **Field Names**: Use exact field names (e.g., ProcessCommandLine, FileName, AccountName)
5. **Multi-condition**: Combine conditions with and/or operators
6. **Aggregation**: Use | summarize for grouping and counting
7. **Performance**: Filter by Timestamp and DeviceName first
8. **Case Sensitivity**: Use =~ for case-insensitive, == for case-sensitive matching

**Common KQL/MDE Fields**:
- DeviceProcessEvents: FileName, ProcessCommandLine, AccountName, InitiatingProcessFileName
- DeviceFileEvents: FileName, FolderPath, InitiatingProcessFileName
- DeviceRegistryEvents: RegistryKey, RegistryValueData, ActionType
- DeviceNetworkEvents: RemoteIP, RemoteUrl, RemotePort
- All tables: DeviceId, DeviceName, Timestamp
- Note: Do NOT use SHA256, SHA1, MD5, or VersionInfo fields - these are not useful for behavioral detection
"""
            )

        # 5. Generation instructions
        prompt_parts.append(
            f"""

## Your Task

Generate a {vendor.upper()} query that:
1. Detects the indicators listed above for technique {technique_id}
2. Uses the organizational field schema provided
3. Follows the best practices and patterns shown in the examples
4. Combines multiple indicators with appropriate logic (OR for alternatives, AND for required combinations)
5. Filters by relevant time windows and system fields
6. Returns useful fields for security analyst triage

**Important**:
- Use ONLY the field names from the organizational schema
- Follow the query structure patterns from the examples
- Ensure the query is syntactically correct and performant
- Include comments explaining the detection logic

Generate the query now:
"""
        )

        return "\n".join(prompt_parts)

    def _get_schema_info(self, vendor: str, indicator_type: str) -> Optional[str]:
        """
        Get schema information for a specific vendor and indicator type.

        Args:
            vendor: SIEM vendor (splunk, mde)
            indicator_type: Type of indicator (cmd, reg, evt, sw)

        Returns:
            Formatted schema information string
        """
        if vendor not in self.schemas:
            return None

        schema = self.schemas[vendor]

        if indicator_type not in schema:
            return None

        info_parts = []

        # For Splunk: show index -> fields mapping
        if vendor == "splunk":
            for index, fields in schema[indicator_type].items():
                # Extract just the SPL operations, not the full query template
                if isinstance(fields, str):
                    # This is a template string, extract field references
                    field_names = self._extract_field_names_from_spl(fields)
                    if field_names:
                        info_parts.append(
                            f"  **{index}**: {', '.join(field_names)}"
                        )
                else:
                    info_parts.append(f"  **{index}**: {fields}")

        # For MDE: show table -> fields mapping
        elif vendor == "mde":
            if isinstance(schema, dict) and indicator_type in schema:
                for table, fields in schema[indicator_type].items():
                    if isinstance(fields, list):
                        info_parts.append(f"  **{table}**: {', '.join(fields)}")

        return "\n".join(info_parts) if info_parts else None

    def _extract_field_names_from_spl(self, spl: str) -> List[str]:
        """Extract field names from Splunk SPL template."""
        import re

        # Look for field references like: properties.FieldName, FieldName, etc.
        field_pattern = r"\b(?:properties\.)?([A-Z][A-Za-z0-9_]+)\b"
        matches = re.findall(field_pattern, spl)

        # Remove common SPL commands that aren't fields
        spl_commands = {
            "BY",
            "AS",
            "Time",
            "EOF",
            "FillNull",
            "Eval",
            "Stats",
            "Table",
            "Fields",
        }
        fields = [m for m in matches if m not in spl_commands]

        # Deduplicate while preserving order
        seen = set()
        unique_fields = []
        for field in fields:
            if field not in seen:
                seen.add(field)
                unique_fields.append(field)

        return unique_fields

    def _extract_key_patterns(self, query: str, vendor: str) -> str:
        """
        Extract key detection patterns from an example query.

        Args:
            query: The example query
            vendor: SIEM vendor

        Returns:
            Formatted string describing key patterns
        """
        patterns = []

        if vendor == "splunk":
            # Extract index
            import re

            index_match = re.search(r"index\s*=\s*(\w+)", query)
            if index_match:
                patterns.append(f"- Uses index: {index_match.group(1)}")

            # Look for field filters
            field_filters = re.findall(r'(\w+)\s*=\s*["\']([^"\']+)["\']', query)
            if field_filters:
                patterns.append(
                    f"- Filters on fields: {', '.join(set(f[0] for f in field_filters[:3]))}"
                )

            # Check for stats aggregation
            if "| stats" in query:
                patterns.append("- Uses stats for aggregation and grouping")

            # Check for wildcards
            if "*" in query:
                patterns.append("- Uses wildcard matching for flexible detection")

        elif vendor == "mde":
            # Extract table
            import re

            table_match = re.match(r"^\s*(\w+)", query)
            if table_match:
                patterns.append(f"- Queries table: {table_match.group(1)}")

            # Look for has/has_any/has_all
            if "has_any" in query:
                patterns.append("- Uses has_any for efficient multi-term matching")
            elif "has_all" in query:
                patterns.append("- Uses has_all to require all terms present")
            elif "has" in query:
                patterns.append("- Uses has for substring matching")

            # Check for time filtering
            if "ago(" in query:
                patterns.append("- Filters by time window with ago()")

            # Check for aggregation
            if "summarize" in query:
                patterns.append("- Uses summarize for aggregation")

        if not patterns:
            patterns.append("- Standard detection pattern")

        return "\n".join(patterns)

    def get_correlation_examples(
        self, technique_ids: List[str], vendor: str, limit: int = 2
    ) -> List[Dict]:
        """
        Get examples useful for correlation query generation.

        Args:
            technique_ids: List of technique IDs to correlate
            vendor: Target SIEM vendor
            limit: Max examples per technique

        Returns:
            List of relevant examples
        """
        examples = []

        for tech_id in technique_ids:
            tech_examples = self.repository.get_examples_for_technique(
                tech_id, vendor=vendor, limit=limit
            )
            examples.extend(tech_examples)

        return examples


# Singleton instance
_enhancer = None


def get_enhancer() -> QueryPromptEnhancer:
    """Get the global query prompt enhancer instance."""
    global _enhancer
    if _enhancer is None:
        _enhancer = QueryPromptEnhancer()
    return _enhancer


if __name__ == "__main__":
    # Test the enhancer
    enhancer = get_enhancer()

    # Example: Generate prompt for credential dumping
    prompt = enhancer.enhance_query_generation_prompt(
        technique_id="T1003",
        technique_name="OS Credential Dumping",
        technique_description="Adversaries may attempt to dump credentials to obtain account login and credential material.",
        vendor="splunk",
        indicator_type="cmd",
        indicators=["lsass", "procdump", "mimikatz"],
        tactic="Credential Access",
        num_examples=2,
    )

    print(prompt)
