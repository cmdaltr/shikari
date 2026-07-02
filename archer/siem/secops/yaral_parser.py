"""
YARA-L Rule Parser and Executor

Simplified parser for executing YARA-L detection rules against UDM events.
Supports basic event matching and condition evaluation.
"""

import re
from typing import Dict, List, Any, Optional
from dataclasses import dataclass


@dataclass
class YaralRule:
    """Parsed YARA-L rule"""
    name: str
    meta: Dict[str, str]
    events: List[str]
    match: Optional[str]
    condition: str


class YaralParser:
    """Parse and execute YARA-L rules"""

    def parse(self, yaral_code: str) -> YaralRule:
        """
        Parse a YARA-L rule into structured components.

        Args:
            yaral_code: YARA-L rule text

        Returns:
            Parsed YaralRule object
        """
        # Extract rule name
        name_match = re.search(r'rule\s+(\w+)\s*\{', yaral_code)
        if not name_match:
            raise ValueError("Invalid YARA-L: no rule name found")
        name = name_match.group(1)

        # Extract meta section
        meta = {}
        meta_match = re.search(r'meta:\s*(.*?)(?=events:|match:|condition:|$)', yaral_code, re.DOTALL)
        if meta_match:
            meta_text = meta_match.group(1)
            for line in meta_text.strip().split('\n'):
                if '=' in line:
                    key, value = line.split('=', 1)
                    key = key.strip()
                    value = value.strip().strip('"')
                    meta[key] = value

        # Extract events section
        events = []
        events_match = re.search(r'events:\s*(.*?)(?=match:|condition:|$)', yaral_code, re.DOTALL)
        if events_match:
            events_text = events_match.group(1)
            # Parse each event condition line
            for line in events_text.strip().split('\n'):
                line = line.strip()
                if line and not line.startswith('//'):
                    events.append(line)

        # Extract match section (optional)
        match_clause = None
        match_match = re.search(r'match:\s*(.*?)(?=condition:|$)', yaral_code, re.DOTALL)
        if match_match:
            match_clause = match_match.group(1).strip()

        # Extract condition section
        condition = "$e"  # Default
        condition_match = re.search(r'condition:\s*(.*?)(?=\}|$)', yaral_code, re.DOTALL)
        if condition_match:
            condition = condition_match.group(1).strip()

        return YaralRule(
            name=name,
            meta=meta,
            events=events,
            match=match_clause,
            condition=condition,
        )

    def execute(self, rule: YaralRule, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Execute a YARA-L rule against a list of UDM events.

        Args:
            rule: Parsed YARA-L rule
            events: List of UDM-formatted events

        Returns:
            List of matching events
        """
        matches = []

        for event in events:
            if self._event_matches(rule, event):
                matches.append(event)

        return matches

    def _event_matches(self, rule: YaralRule, event: Dict[str, Any]) -> bool:
        """Check if an event matches the rule conditions"""
        # Check each event condition
        for condition in rule.events:
            if not self._evaluate_condition(condition, event):
                return False

        return True

    def _evaluate_condition(self, condition: str, event: Dict[str, Any]) -> bool:
        """
        Evaluate a single YARA-L event condition.

        Supports:
        - $e.field.path = "value"
        - $e.field.path != "value"
        - re.regex($e.field.path, `pattern`) nocase
        - $e.metadata.event_type = "TYPE"
        """
        condition = condition.strip()

        # Skip empty conditions
        if not condition:
            return True

        # Handle regex conditions
        regex_match = re.search(
            r're\.regex\(\$\w+\.([^,]+),\s*`([^`]+)`\)\s*(nocase)?',
            condition
        )
        if regex_match:
            field_path = regex_match.group(1).strip()
            pattern = regex_match.group(2)
            nocase = regex_match.group(3) is not None

            value = self._get_field_value(event, field_path)
            if value is None:
                return False

            flags = re.IGNORECASE if nocase else 0
            try:
                return bool(re.search(pattern, str(value), flags))
            except re.error:
                return False

        # Handle equality conditions
        eq_match = re.search(r'\$\w+\.([^\s=!]+)\s*(=|!=)\s*["\']?([^"\']+)["\']?', condition)
        if eq_match:
            field_path = eq_match.group(1).strip()
            operator = eq_match.group(2)
            expected = eq_match.group(3).strip()

            value = self._get_field_value(event, field_path)
            if value is None:
                return operator == "!="

            str_value = str(value)
            if operator == "=":
                return str_value.lower() == expected.lower()
            else:  # !=
                return str_value.lower() != expected.lower()

        # Handle numeric conditions (port, etc.)
        num_match = re.search(r'\$\w+\.([^\s=]+)\s*=\s*(\d+)', condition)
        if num_match:
            field_path = num_match.group(1).strip()
            expected = int(num_match.group(2))

            value = self._get_field_value(event, field_path)
            try:
                return int(value) == expected
            except (ValueError, TypeError):
                return False

        # Handle OR conditions within parentheses
        if ' or ' in condition.lower():
            parts = re.split(r'\s+or\s+', condition, flags=re.IGNORECASE)
            return any(self._evaluate_condition(part.strip('() '), event) for part in parts)

        # Handle AND conditions
        if ' and ' in condition.lower():
            parts = re.split(r'\s+and\s+', condition, flags=re.IGNORECASE)
            return all(self._evaluate_condition(part.strip('() '), event) for part in parts)

        # Unknown condition format - log and return True to avoid false negatives
        return True

    def _get_field_value(self, event: Dict[str, Any], field_path: str) -> Any:
        """
        Get a nested field value from an event using dot notation.

        Args:
            event: Event dictionary
            field_path: Dot-separated field path (e.g., "target.process.command_line")

        Returns:
            Field value or None if not found
        """
        parts = field_path.split('.')
        current = event

        for part in parts:
            if isinstance(current, dict):
                current = current.get(part)
            else:
                return None

            if current is None:
                return None

        return current
