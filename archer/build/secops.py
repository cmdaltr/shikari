"""
Google SecOps YARA-L Detection Generator
Converts MITRE ATT&CK techniques into YARA-L detection rules for Google SecOps
Uses template-based generation with UDM (Unified Data Model) field mappings
"""

import os
import json
import re
from pathlib import Path
from typing import Dict, List, Optional


class SecOpsGenerator:
    def __init__(self):
        """
        Initialize Google SecOps generator with schema mappings
        """
        # Load Google SecOps schema mappings
        self.schema = self._load_schema()

    def _load_schema(self) -> Dict:
        """Load Google SecOps UDM schema mappings"""
        schema_path = Path(__file__).parent.parent.parent / "bespoke" / "mappings" / "schemas" / "schemaGoogleSecOps.json"
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



# ── Multi-event correlation ────────────────────────────────────────────────

_SECTION = re.compile(r"^\s*(meta|events|match|outcome|condition|options)\s*:\s*$", re.M)


def _rule_sections(rule: str) -> Dict[str, str]:
    """Split a YARA-L rule body into its sections (meta, events, condition, ...)."""
    body = rule.strip()
    body = body[body.find("{") + 1: body.rfind("}")] if "{" in body else body
    marks = list(_SECTION.finditer(body))
    return {m.group(1): body[m.end(): marks[i + 1].start() if i + 1 < len(marks) else len(body)].strip("\n")
            for i, m in enumerate(marks)}


def _meta_value(meta: str, key: str) -> Optional[str]:
    m = re.search(rf'^\s*{key}\s*=\s*"([^"]*)"', meta, re.M)
    return m.group(1) if m else None


def _event_block(events: str, var: str, grouped: bool) -> str:
    """
    Rebind a single-event rule's $e to `var`. Lines in an events section are ANDed;
    `grouped` folds them into one parenthesised expression so blocks can be ORed.
    """
    lines = [re.sub(r"\$e\b", var, line.strip()) for line in events.splitlines()
             if line.strip() and not line.strip().startswith("//")]
    if not grouped:
        return "\n".join(f"    {line}" for line in lines)
    return "    (" + " and ".join(lines) + ")"


def _event_types(events: str) -> List[str]:
    return re.findall(r'metadata\.event_type\s*=\s*"([A-Z_]+)"', events)


def _side(rules, var: str):
    """events text, technique IDs and event types for one side ($e1 or $e2) of a correlation."""
    rules = [r for r in ([rules] if isinstance(rules, str) else rules) if r and r.strip()]
    parsed = [_rule_sections(r) for r in rules]
    if not parsed or any(not p.get("events") or re.search(r"\$e\d", p["events"]) for p in parsed):
        return None
    tids = [_meta_value(p.get("meta", ""), "mitre_attack_technique") or "?" for p in parsed]
    names = [_technique_name(p.get("meta", "")) for p in parsed]
    blocks = [_event_block(p["events"], var, grouped=len(parsed) > 1) for p in parsed]
    # Alternatives stay on one line: separate statements in events are ANDed
    events = blocks[0] if len(blocks) == 1 else "    (" + " or ".join(b.strip() for b in blocks) + ")"
    types = [t for p in parsed for t in _event_types(p["events"])]
    return events, list(dict.fromkeys(tids)), types, [n for n in dict.fromkeys(names) if n]


def _technique_name(meta: str) -> Optional[str]:
    """'Detects Access Token Manipulation (T1134)' -> 'Access Token Manipulation'."""
    m = re.match(r"Detects (.+?) \(T\d", _meta_value(meta, "description") or "")
    return m.group(1) if m else None


def build_correlation_rule(rules_a, rules_b, label_a: str = "", label_b: str = "",
                           window: str = "1h") -> Optional[str]:
    """
    Combine single-event YARA-L rules into one multi-event correlation rule.

    Mirrors the MDE correlation (same device within an hour): both events must come
    from the same host (principal.hostname, bound to the $host match variable) within
    `window`, and the A event must not be later than the B event. Each side takes one
    rule or a list; a list becomes alternatives (A1 or A2 ...) for that event.
    Returns None when an input isn't a single-event rule this can rebind.
    """
    a, b = _side(rules_a, "$e1"), _side(rules_b, "$e2")
    if not (a and b):
        return None
    events_a, tids_a, types_a, names_a = a
    events_b, tids_b, types_b, names_b = b
    clean = lambda s: s.replace('"', "'")
    # Technique names from each rule's own meta; the caller's label (from the filename) is the fallback
    label_a = clean(" / ".join(names_a) or label_a or " / ".join(tids_a))
    label_b = clean(" / ".join(names_b) or label_b or " / ".join(tids_b))
    extra = len(tids_a) + len(tids_b) - 2
    name = re.sub(r"\W", "_", f"archer_corr_{tids_a[0]}_then_{tids_b[0]}" + (f"_plus{extra}" if extra else ""))

    return f"""rule {name} {{
  meta:
    author = "Archer Detection Engineering"
    description = "{label_a} followed by {label_b} on the same host within {window}"
    mitre_attack_technique = "{', '.join(tids_a + tids_b)}"
    event_types = "{', '.join(sorted(set(types_a + types_b)))}"
    severity = "HIGH"

  events:
    // {label_a}
{events_a}
    $e1.principal.hostname = $host

    // {label_b}
{events_b}
    $e2.principal.hostname = $host

    $host != ""
    $e1.metadata.event_timestamp.seconds <= $e2.metadata.event_timestamp.seconds

  match:
    $host over {window}

  outcome:
    $first_seen = min($e1.metadata.event_timestamp.seconds)
    $last_seen = max($e2.metadata.event_timestamp.seconds)
    $users = array_distinct($e1.principal.user.userid)
    $commands_a = array_distinct($e1.target.process.command_line)
    $commands_b = array_distinct($e2.target.process.command_line)

  condition:
    $e1 and $e2
}}"""
