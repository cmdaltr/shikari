"""
Chronicle/Google SecOps YARA-L Detection Generator
Converts MITRE ATT&CK techniques into YARA-L detection rules
"""

import os
from typing import Dict, List, Optional


class ChronicleGenerator:
    def __init__(self, llm_provider=None):
        """
        Initialize Chronicle generator with LLM provider

        Args:
            llm_provider: Optional LLMProvider instance. If None, creates default Anthropic provider
        """
        if llm_provider is None:
            from archer.llm.providers import LLMFactory
            provider_name = os.getenv("LLM_PROVIDER", "anthropic")
            model = os.getenv("LLM_MODEL", None)
            llm_provider = LLMFactory.create(provider_name, model=model)

        self.llm_provider = llm_provider

    def generate_yaral_rule(
        self,
        technique_id: str,
        technique_name: str,
        tactic: str,
        description: str,
        osint_data: Optional[Dict] = None,
        group_name: Optional[str] = None
    ) -> Dict[str, any]:
        """
        Generate YARA-L detection rule for Chronicle

        Returns:
            Dict with keys: rule_name, yaral_code, description, severity,
                           data_sources, event_types
        """

        # Build prompt with OSINT context if available
        prompt = self._build_prompt(
            technique_id, technique_name, tactic, description,
            osint_data, group_name
        )

        # Call LLM provider
        response = self.llm_provider.generate(
            prompt=prompt,
            temperature=0.7,
            max_tokens=4096
        )

        # Parse response into structured format
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
        """Build prompt for YARA-L generation"""

        prompt = f"""Generate a Google SecOps (Chronicle) YARA-L detection rule for the following MITRE ATT&CK technique:

**Technique**: {technique_id} - {technique_name}
**Tactic**: {tactic}
**Description**: {description}
"""

        if group_name:
            prompt += f"\n**Threat Group**: {group_name}\n"

        if osint_data and osint_data.get("indicators"):
            prompt += "\n**OSINT Indicators**:\n"
            for indicator in osint_data["indicators"][:10]:  # Limit to 10
                prompt += f"- {indicator.get('type', 'Unknown')}: {indicator.get('value', 'N/A')}\n"

        prompt += """

Create a YARA-L detection rule that:
1. Uses Chronicle UDM (Unified Data Model) event types
2. Includes proper event filtering and correlation logic
3. Has clear condition statements for detection
4. Uses appropriate outcome sections for alerting
5. Includes metadata (author, description, severity)

Format your response as:

RULE_NAME: <concise_rule_name>
SEVERITY: <HIGH|MEDIUM|LOW>
DATA_SOURCES: <comma-separated UDM event types>
DESCRIPTION: <one-line description>

YARAL_CODE:
```yaral
<full YARA-L rule code here>
```

DETECTION_NOTES:
<any important notes about detection coverage, false positives, or tuning>
"""
        return prompt

    def _parse_response(self, response_text: str) -> Dict[str, any]:
        """Parse Claude's response into structured format"""

        result = {
            "rule_name": "",
            "yaral_code": "",
            "description": "",
            "severity": "MEDIUM",
            "data_sources": [],
            "event_types": [],
            "detection_notes": ""
        }

        lines = response_text.split("\n")
        in_code_block = False
        code_lines = []

        for line in lines:
            if line.startswith("RULE_NAME:"):
                result["rule_name"] = line.replace("RULE_NAME:", "").strip()
            elif line.startswith("SEVERITY:"):
                result["severity"] = line.replace("SEVERITY:", "").strip()
            elif line.startswith("DATA_SOURCES:"):
                sources = line.replace("DATA_SOURCES:", "").strip()
                result["data_sources"] = [s.strip() for s in sources.split(",")]
                result["event_types"] = result["data_sources"]  # Alias
            elif line.startswith("DESCRIPTION:"):
                result["description"] = line.replace("DESCRIPTION:", "").strip()
            elif line.strip().startswith("```yaral"):
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

        result["yaral_code"] = "\n".join(code_lines)
        return result

    def generate_correlation_rule(
        self,
        techniques: List[Dict],
        group_name: str,
        time_window: str = "5m"
    ) -> Dict[str, any]:
        """Generate multi-event correlation YARA-L rule"""

        prompt = f"""Generate a Google SecOps (Chronicle) YARA-L correlation rule that detects multiple techniques in sequence.

**Threat Group**: {group_name}
**Time Window**: {time_window}

**Techniques to Correlate**:
"""
        for tech in techniques:
            prompt += f"- {tech['id']} - {tech['name']} ({tech['tactic']})\n"

        prompt += """

Create a YARA-L rule that:
1. Correlates these techniques within the specified time window
2. Uses Chronicle's multi-event correlation syntax
3. Groups events by common entity (user, hostname, IP)
4. Produces a single alert when the sequence is detected

Format your response as before with RULE_NAME, SEVERITY, etc.
"""

        response = self.llm_provider.generate(
            prompt=prompt,
            temperature=0.7,
            max_tokens=4096
        )

        return self._parse_response(response.content)
