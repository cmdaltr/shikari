"""
Elasticsearch Query Generator
Generates Elastic Query DSL and ECS-based detection queries
"""

from typing import Dict, List, Optional
import json
import os


class ElasticQueryGenerator:
    """Generates Elasticsearch queries for threat detection"""

    def __init__(self, llm_provider=None):
        """
        Initialize Elastic generator with LLM provider

        Args:
            llm_provider: Optional LLMProvider instance. If None, creates default Anthropic provider
        """
        if llm_provider is None:
            from archer.llm.providers import LLMFactory
            provider_name = os.getenv("LLM_PROVIDER", "anthropic")
            model = os.getenv("LLM_MODEL", None)
            llm_provider = LLMFactory.create(provider_name, model=model)

        self.llm_provider = llm_provider

    def generate_query(
        self,
        technique_id: str,
        technique_name: str,
        tactic: str,
        description: str,
        osint_data: Optional[Dict] = None,
        group_name: Optional[str] = None
    ) -> Dict[str, any]:
        """
        Generate Elasticsearch query for technique

        Returns:
            Dict with keys: query_name, query_dsl, description, severity,
                           ecs_fields, data_streams
        """

        prompt = self._build_prompt(
            technique_id, technique_name, tactic, description,
            osint_data, group_name
        )

        response = self.llm_provider.generate(
            prompt=prompt,
            temperature=0.7,
            max_tokens=4096
        )

        return self._parse_response(response.content)

    def _build_prompt(
        self,
        technique_id: str,
        technique_name: str,
        tactic: str,
        description: str,
        osint_data: Optional[Dict],
        group_name: Optional[str]
    ) -> str:
        """Build prompt for Elastic query generation"""

        prompt = f"""Generate an Elasticsearch detection query using ECS (Elastic Common Schema) for the following MITRE ATT&CK technique:

**Technique**: {technique_id} - {technique_name}
**Tactic**: {tactic}
**Description**: {description}
"""

        if group_name:
            prompt += f"\n**Threat Group**: {group_name}\n"

        if osint_data and osint_data.get("indicators"):
            prompt += "\n**OSINT Indicators**:\n"
            for indicator in osint_data["indicators"][:10]:
                prompt += f"- {indicator.get('type', 'Unknown')}: {indicator.get('value', 'N/A')}\n"

        prompt += """

Create an Elasticsearch query that:
1. Uses Elastic Common Schema (ECS) field names
2. Is written in Query DSL (JSON format)
3. Includes appropriate filters and conditions
4. Uses bool queries with must/should/must_not clauses
5. Leverages ECS data streams (logs-*, metrics-*, etc.)

Format your response as:

QUERY_NAME: <concise_query_name>
SEVERITY: <critical|high|medium|low>
ECS_FIELDS: <comma-separated ECS field names used>
DATA_STREAMS: <comma-separated data streams>
DESCRIPTION: <one-line description>

QUERY_DSL:
```json
{
  "query": {
    // Elasticsearch Query DSL here
  }
}
```

DETECTION_NOTES:
<any important notes about detection coverage, false positives, or tuning>
"""
        return prompt

    def _parse_response(self, response_text: str) -> Dict[str, any]:
        """Parse LLM response into structured format"""

        result = {
            "query_name": "",
            "query_dsl": {},
            "description": "",
            "severity": "medium",
            "ecs_fields": [],
            "data_streams": [],
            "detection_notes": ""
        }

        lines = response_text.split("\n")
        in_code_block = False
        code_lines = []

        for line in lines:
            if line.startswith("QUERY_NAME:"):
                result["query_name"] = line.replace("QUERY_NAME:", "").strip()
            elif line.startswith("SEVERITY:"):
                result["severity"] = line.replace("SEVERITY:", "").strip().lower()
            elif line.startswith("ECS_FIELDS:"):
                fields = line.replace("ECS_FIELDS:", "").strip()
                result["ecs_fields"] = [f.strip() for f in fields.split(",")]
            elif line.startswith("DATA_STREAMS:"):
                streams = line.replace("DATA_STREAMS:", "").strip()
                result["data_streams"] = [s.strip() for s in streams.split(",")]
            elif line.startswith("DESCRIPTION:"):
                result["description"] = line.replace("DESCRIPTION:", "").strip()
            elif line.strip().startswith("```json"):
                in_code_block = True
            elif line.strip() == "```" and in_code_block:
                in_code_block = False
            elif in_code_block:
                code_lines.append(line)
            elif line.startswith("DETECTION_NOTES:"):
                # Capture everything after this line
                idx = lines.index(line)
                result["detection_notes"] = "\n".join(lines[idx+1:]).strip()
                break

        # Parse JSON query
        try:
            query_json = "\n".join(code_lines)
            result["query_dsl"] = json.loads(query_json)
        except json.JSONDecodeError as e:
            print(f"Failed to parse Elastic query JSON: {e}")
            result["query_dsl"] = {"error": "Failed to parse query"}

        return result

    def validate_query(self, query_dsl: Dict) -> tuple[bool, Optional[str]]:
        """
        Validate Elasticsearch Query DSL syntax

        Returns:
            Tuple of (is_valid, error_message)
        """

        # Basic validation
        if not isinstance(query_dsl, dict):
            return False, "Query must be a dictionary"

        if "query" not in query_dsl:
            return False, "Query must have a 'query' key"

        query = query_dsl["query"]

        # Validate query structure
        valid_query_types = [
            "match", "match_all", "match_phrase", "multi_match",
            "term", "terms", "range", "exists", "prefix", "wildcard",
            "regexp", "fuzzy", "bool", "dis_max", "function_score",
            "boosting", "constant_score", "nested", "has_child", "has_parent"
        ]

        if not any(qt in query for qt in valid_query_types):
            return False, f"Query must contain a valid query type. Valid types: {', '.join(valid_query_types[:5])}..."

        # Validate bool query structure
        if "bool" in query:
            bool_query = query["bool"]
            valid_bool_keys = ["must", "filter", "should", "must_not", "minimum_should_match", "boost"]

            for key in bool_query.keys():
                if key not in valid_bool_keys:
                    return False, f"Invalid bool query key: {key}"

        return True, None

    def format_query_for_display(self, query_dsl: Dict) -> str:
        """Format query DSL as pretty-printed JSON"""
        return json.dumps(query_dsl, indent=2)

    def generate_correlation_query(
        self,
        techniques: List[Dict],
        group_name: str,
        time_window: str = "5m"
    ) -> Dict[str, any]:
        """Generate multi-event correlation query using Elastic EQL or bool queries"""

        prompt = f"""Generate an Elasticsearch correlation query that detects multiple techniques in sequence.

**Threat Group**: {group_name}
**Time Window**: {time_window}

**Techniques to Correlate**:
"""
        for tech in techniques:
            prompt += f"- {tech['id']} - {tech['name']} ({tech['tactic']})\n"

        prompt += """

Create an Elasticsearch query that:
1. Uses ECS field names
2. Correlates these techniques within the specified time window
3. Uses bool queries with multiple must clauses or EQL sequence query
4. Groups events by common entity (user.name, host.name, source.ip)
5. Produces results when the sequence is detected

You can use either:
- Bool query with date range filters
- EQL (Event Query Language) sequence query

Format your response as before with QUERY_NAME, SEVERITY, etc.
"""

        response = self.llm_provider.generate(
            prompt=prompt,
            temperature=0.7,
            max_tokens=4096
        )

        return self._parse_response(response.content)
