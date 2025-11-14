"""
Google SecOps YARA-L Detection Generator
Converts MITRE ATT&CK techniques into YARA-L detection rules for Google SecOps (formerly Chronicle)
Uses template-based generation with UDM (Unified Data Model) field mappings
"""

import os
import json
from pathlib import Path
from typing import Dict, List, Optional


class ChronicleGenerator:
    def __init__(self):
        """
        Initialize Google SecOps generator with schema mappings
        """
        # Load Google SecOps schema mappings
        self.schema = self._load_schema()

    def _load_schema(self) -> Dict:
        """Load Google SecOps UDM schema mappings"""
        schema_path = Path(__file__).parent.parent / "mappings" / "schemaGoogleSecOps.json"
        if schema_path.exists():
            with open(schema_path, 'r') as f:
                return json.load(f)
        return {}

    def generate_yaral_rule(
        self,
        technique_id: str,
        technique_name: str,
        tactic: str,
        description: str,
        indicators: Optional[Dict] = None,
        osint_data: Optional[Dict] = None,
        group_name: Optional[str] = None
    ) -> Dict[str, any]:
        """
        Generate YARA-L detection rule for Google SecOps using templates

        Returns:
            Dict with keys: rule_name, yaral_code, description, severity,
                           data_sources, event_types
        """

        # Generate rule name
        rule_name = f"{technique_id.replace('.', '_')}_{technique_name.replace(' ', '_')}"

        # Determine event type based on technique and indicators
        event_type = self._determine_event_type(indicators or {})

        # Build YARA-L query
        yaral_code = self._build_yaral_query(
            technique_id=technique_id,
            technique_name=technique_name,
            indicators=indicators or {},
            event_type=event_type
        )

        # Determine severity
        severity = "MEDIUM"
        if any(keyword in technique_name.lower() for keyword in ['credential', 'privilege', 'persistence', 'lateral']):
            severity = "HIGH"

        return {
            "rule_name": rule_name,
            "yaral_code": yaral_code,
            "description": f"Detects {technique_name} ({technique_id})",
            "severity": severity,
            "data_sources": [event_type],
            "event_types": [event_type]
        }

    def _determine_event_type(self, indicators: Dict) -> str:
        """Determine appropriate UDM event type based on indicators"""
        if "cmd" in indicators or "sw" in indicators:
            return "PROCESS_LAUNCH"
        elif "reg" in indicators:
            return "REGISTRY_MODIFICATION"
        elif "network" in indicators or "url" in indicators:
            return "NETWORK_CONNECTION"
        elif "file" in indicators:
            return "FILE_CREATION"
        else:
            return "PROCESS_LAUNCH"  # Default

    def _build_yaral_query(
        self,
        technique_id: str,
        technique_name: str,
        indicators: Dict,
        event_type: str
    ) -> str:
        """Build YARA-L query using templates"""

        # Basic template structure
        rule_name = technique_id.replace('.', '_')

        # Build condition based on indicators
        conditions = []

        # Process command line indicators
        if "cmd" in indicators:
            cmd_conditions = []
            for cmd in indicators["cmd"][:5]:  # Limit to 5 indicators
                # Escape special characters
                cmd_escaped = cmd.replace('"', '\\"')
                cmd_conditions.append(f're.regex($e.target.process.command_line, `{cmd_escaped}`) nocase')
            if cmd_conditions:
                conditions.append("(" + " or ".join(cmd_conditions) + ")")

        # Process software/file indicators
        if "sw" in indicators:
            sw_conditions = []
            for sw in indicators["sw"][:5]:
                sw_escaped = sw.replace('"', '\\"')
                sw_conditions.append(f're.regex($e.target.process.file.full_path, `{sw_escaped}`) nocase')
            if sw_conditions:
                conditions.append("(" + " or ".join(sw_conditions) + ")")

        # Process port indicators
        if "port" in indicators:
            port_conditions = []
            for port in indicators["port"][:5]:
                port_conditions.append(f'($e.target.port = {port} or $e.principal.port = {port})')
            if port_conditions:
                conditions.append("(" + " or ".join(port_conditions) + ")")

        # Process protocol indicators
        if "protocol" in indicators:
            proto_conditions = []
            for proto in indicators["protocol"][:5]:
                proto_upper = proto.upper()
                proto_conditions.append(f're.regex($e.network.application_protocol, `{proto_upper}`) nocase')
            if proto_conditions:
                conditions.append("(" + " or ".join(proto_conditions) + ")")

        # Process service indicators
        if "service" in indicators:
            svc_conditions = []
            for svc in indicators["service"][:5]:
                svc_escaped = svc.replace('"', '\\"')
                svc_conditions.append(f're.regex($e.target.application, `{svc_escaped}`) nocase')
            if svc_conditions:
                conditions.append("(" + " or ".join(svc_conditions) + ")")

        # If no specific conditions, create a generic one
        if not conditions:
            conditions.append('$e.metadata.event_type = "PROCESS_LAUNCH"')

        condition_str = " and ".join(conditions)

        # Build complete YARA-L rule
        yaral_query = f"""rule {rule_name} {{
  meta:
    author = "Archer Detection Engineering"
    description = "Detects {technique_name} ({technique_id})"
    mitre_attack_technique = "{technique_id}"
    severity = "MEDIUM"

  events:
    $e.metadata.event_type = "{event_type}"
    {condition_str}

  condition:
    $e
}}"""

        return yaral_query

    def generate_correlation_rule(
        self,
        techniques: List[Dict],
        group_name: str,
        time_window: str = "5m"
    ) -> Dict[str, any]:
        """Generate multi-event correlation YARA-L rule"""

        rule_name = f"{group_name.replace(' ', '_')}_correlation"

        # Build multi-event correlation
        events_section = []
        for i, tech in enumerate(techniques[:3]):  # Limit to 3 techniques
            tech_id = tech.get('id', f'T{i}')
            events_section.append(f'    $e{i+1}.metadata.event_type = "PROCESS_LAUNCH"')

        yaral_query = f"""rule {rule_name} {{
  meta:
    author = "Archer Detection Engineering"
    description = "Multi-technique correlation for {group_name}"
    severity = "HIGH"

  events:
{chr(10).join(events_section)}

  match:
    $e1, $e2 over 5m

  condition:
    $e1 and $e2
}}"""

        return {
            "rule_name": rule_name,
            "yaral_code": yaral_query,
            "description": f"Correlation rule for {group_name}",
            "severity": "HIGH"
        }
