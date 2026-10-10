"""
Sample Event Generator

Generates realistic sample events for detection validation using LLM.
Creates both malicious events (that should trigger detections) and
benign events (that should not trigger false positives).
"""

import json
import logging
import re
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from datetime import datetime, timedelta
import random
import uuid

logger = logging.getLogger(__name__)


@dataclass
class GeneratedEventSet:
    """Container for generated sample events"""
    malicious_events: List[Dict[str, Any]]
    benign_events: List[Dict[str, Any]]
    technique_id: str
    vendor: str
    generation_metadata: Dict[str, Any] = field(default_factory=dict)


# Event schemas for each vendor
VENDOR_SCHEMAS = {
    "splunk": {
        "process": {
            "required": ["_time", "host", "sourcetype", "EventCode"],
            "optional": ["ComputerName", "NewProcessName", "CommandLine", "ParentProcessName",
                        "User", "ProcessId", "ParentProcessId", "TargetFilename"],
            "sourcetypes": ["WinEventLog:Security", "WinEventLog:Sysmon", "xmlwineventlog"],
        },
        "network": {
            "required": ["_time", "host", "sourcetype"],
            "optional": ["src_ip", "dest_ip", "src_port", "dest_port", "protocol",
                        "action", "bytes_in", "bytes_out", "app"],
            "sourcetypes": ["firewall", "netflow", "zeek:conn"],
        },
        "file": {
            "required": ["_time", "host", "sourcetype"],
            "optional": ["file_path", "file_name", "file_hash", "action",
                        "user", "process_name"],
            "sourcetypes": ["WinEventLog:Sysmon", "endpoint"],
        },
    },
    "elastic": {
        "process": {
            "required": ["@timestamp", "host.name", "event.category"],
            "optional": ["process.name", "process.command_line", "process.executable",
                        "process.pid", "process.parent.name", "process.parent.command_line",
                        "user.name", "user.domain", "process.hash.sha256"],
            "index": "logs-endpoint.events.process-*",
        },
        "network": {
            "required": ["@timestamp", "host.name", "event.category"],
            "optional": ["source.ip", "destination.ip", "source.port", "destination.port",
                        "network.protocol", "network.transport", "process.name"],
            "index": "logs-endpoint.events.network-*",
        },
        "file": {
            "required": ["@timestamp", "host.name", "event.category"],
            "optional": ["file.path", "file.name", "file.hash.sha256", "file.size",
                        "process.name", "event.action"],
            "index": "logs-endpoint.events.file-*",
        },
    },
    "secops": {
        "process": {
            "required": ["metadata.event_type", "metadata.event_timestamp"],
            "optional": ["target.process.command_line", "target.process.file.full_path",
                        "target.process.file.sha256", "target.process.pid",
                        "principal.user.user_display_name", "principal.hostname",
                        "target.process.parent_process.file.full_path"],
            "event_type": "PROCESS_LAUNCH",
        },
        "network": {
            "required": ["metadata.event_type", "metadata.event_timestamp"],
            "optional": ["principal.ip", "target.ip", "principal.port", "target.port",
                        "network.application_protocol", "principal.hostname",
                        "target.process.file.full_path"],
            "event_type": "NETWORK_CONNECTION",
        },
        "file": {
            "required": ["metadata.event_type", "metadata.event_timestamp"],
            "optional": ["target.file.full_path", "target.file.sha256", "target.file.size",
                        "principal.hostname", "principal.user.user_display_name"],
            "event_type": "FILE_CREATION",
        },
    },
    "mde": {
        "process": {
            "required": ["Timestamp", "DeviceId", "DeviceName"],
            "optional": ["FileName", "FolderPath", "ProcessCommandLine", "ProcessId",
                        "AccountName", "AccountDomain", "SHA256", "SHA1", "MD5",
                        "InitiatingProcessFileName", "InitiatingProcessCommandLine",
                        "InitiatingProcessId"],
            "table": "DeviceProcessEvents",
        },
        "network": {
            "required": ["Timestamp", "DeviceId", "DeviceName"],
            "optional": ["RemoteIP", "RemotePort", "LocalIP", "LocalPort", "Protocol",
                        "RemoteUrl", "InitiatingProcessFileName",
                        "InitiatingProcessCommandLine"],
            "table": "DeviceNetworkEvents",
        },
        "file": {
            "required": ["Timestamp", "DeviceId", "DeviceName"],
            "optional": ["FileName", "FolderPath", "SHA256", "SHA1", "MD5", "FileSize",
                        "ActionType", "InitiatingProcessFileName",
                        "InitiatingProcessCommandLine"],
            "table": "DeviceFileEvents",
        },
    },
}

# Benign event templates for realistic noise
BENIGN_TEMPLATES = {
    "process": [
        {"name": "explorer.exe", "path": "C:\\Windows\\explorer.exe", "cmd": "C:\\Windows\\explorer.exe"},
        {"name": "svchost.exe", "path": "C:\\Windows\\System32\\svchost.exe", "cmd": "C:\\Windows\\System32\\svchost.exe -k netsvcs"},
        {"name": "chrome.exe", "path": "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", "cmd": "chrome.exe --type=renderer"},
        {"name": "notepad.exe", "path": "C:\\Windows\\System32\\notepad.exe", "cmd": "notepad.exe document.txt"},
        {"name": "outlook.exe", "path": "C:\\Program Files\\Microsoft Office\\Outlook.exe", "cmd": "outlook.exe"},
        {"name": "code.exe", "path": "C:\\Program Files\\Microsoft VS Code\\Code.exe", "cmd": "code.exe --status"},
        {"name": "msiexec.exe", "path": "C:\\Windows\\System32\\msiexec.exe", "cmd": "msiexec.exe /i update.msi /quiet"},
    ],
    "network": [
        {"dest_ip": "8.8.8.8", "dest_port": 53, "protocol": "UDP"},
        {"dest_ip": "1.1.1.1", "dest_port": 443, "protocol": "TCP"},
        {"dest_ip": "13.107.42.14", "dest_port": 443, "protocol": "TCP"},  # Microsoft
        {"dest_ip": "142.250.185.206", "dest_port": 443, "protocol": "TCP"},  # Google
        {"dest_ip": "192.168.1.1", "dest_port": 80, "protocol": "TCP"},  # Internal
    ],
}


class SampleEventGenerator:
    """Generates realistic sample events for technique validation using LLM"""

    def __init__(self, llm_provider=None):
        """
        Initialize the event generator.

        Args:
            llm_provider: Optional LLM provider for enhanced generation.
                         Falls back to template-based generation if not provided.
        """
        self.llm = llm_provider
        self._init_llm_if_needed()

    def _init_llm_if_needed(self):
        """Initialize default LLM provider if not provided"""
        if self.llm is None:
            try:
                from archer.ai.llm.providers import LLMFactory
                import os
                # Try to create a provider based on available API keys
                if os.getenv("OPENAI_API_KEY"):
                    self.llm = LLMFactory.create("openai")
                elif os.getenv("ANTHROPIC_API_KEY"):
                    self.llm = LLMFactory.create("anthropic")
                elif os.getenv("GOOGLE_API_KEY"):
                    self.llm = LLMFactory.create("google")
                else:
                    logger.info("No LLM API key found, using template-based event generation")
            except Exception as e:
                logger.warning(f"Could not initialize LLM provider: {e}")

    def generate_events(
        self,
        technique_id: str,
        technique_name: str,
        indicators: Dict[str, List[str]],
        vendor: str,
        malicious_count: int = 10,
        benign_count: int = 20,
    ) -> GeneratedEventSet:
        """
        Generate sample events for a technique.

        Args:
            technique_id: MITRE ATT&CK technique ID (e.g., "T1059.001")
            technique_name: Technique name (e.g., "PowerShell")
            indicators: Dict of indicator types to values (cmd, sw, file, network, etc.)
            vendor: Target SIEM vendor (splunk, elastic, secops, mde)
            malicious_count: Number of malicious events to generate
            benign_count: Number of benign events to generate

        Returns:
            GeneratedEventSet with malicious and benign events
        """
        vendor = vendor.lower()
        if vendor not in VENDOR_SCHEMAS:
            raise ValueError(f"Unsupported vendor: {vendor}")

        # Determine event type from indicators
        event_type = self._determine_event_type(indicators)

        # Generate events
        if self.llm:
            malicious = self._generate_with_llm(
                technique_id, technique_name, indicators, vendor, event_type, malicious_count
            )
        else:
            malicious = self._generate_from_templates(
                technique_id, indicators, vendor, event_type, malicious_count
            )

        benign = self._generate_benign_events(vendor, event_type, benign_count)

        return GeneratedEventSet(
            malicious_events=malicious,
            benign_events=benign,
            technique_id=technique_id,
            vendor=vendor,
            generation_metadata={
                "technique_name": technique_name,
                "event_type": event_type,
                "used_llm": self.llm is not None,
                "generated_at": datetime.utcnow().isoformat(),
            }
        )

    def _determine_event_type(self, indicators: Dict[str, List[str]]) -> str:
        """Determine the event type based on indicators"""
        if "cmd" in indicators or "sw" in indicators:
            return "process"
        elif "network" in indicators or "url" in indicators or "port" in indicators:
            return "network"
        elif "file" in indicators or "reg" in indicators:
            return "file"
        return "process"  # Default

    def _generate_with_llm(
        self,
        technique_id: str,
        technique_name: str,
        indicators: Dict[str, List[str]],
        vendor: str,
        event_type: str,
        count: int
    ) -> List[Dict[str, Any]]:
        """Generate events using LLM for realistic, varied samples"""
        schema = VENDOR_SCHEMAS[vendor][event_type]

        # Build prompt
        prompt = self._build_llm_prompt(
            technique_id, technique_name, indicators, vendor, event_type, schema, count
        )

        try:
            response = self.llm.generate(
                prompt=prompt,
                system_prompt=self._get_system_prompt(),
                temperature=0.7,
                max_tokens=4096
            )

            # Parse JSON from response
            events = self._parse_llm_response(response.content)

            # Validate and fix events
            events = [self._validate_and_fix_event(e, vendor, event_type) for e in events]

            logger.info(f"LLM generated {len(events)} malicious events for {technique_id}")
            return events

        except Exception as e:
            logger.warning(f"LLM generation failed, falling back to templates: {e}")
            return self._generate_from_templates(
                technique_id, indicators, vendor, event_type, count
            )

    def _get_system_prompt(self) -> str:
        """Get system prompt for LLM event generation"""
        return """You are a security event generator for detection testing.
Your task is to generate realistic log events that represent specific attack techniques.
The events should:
1. Match the schema of the target SIEM platform exactly
2. Include realistic variations of the attack indicators
3. Use realistic timestamps, hostnames, usernames, and file paths
4. Be syntactically valid JSON

Always output ONLY a JSON array of events, no other text or explanation."""

    def _build_llm_prompt(
        self,
        technique_id: str,
        technique_name: str,
        indicators: Dict[str, List[str]],
        vendor: str,
        event_type: str,
        schema: Dict,
        count: int
    ) -> str:
        """Build the LLM prompt for event generation"""
        indicator_list = []
        for ind_type, values in indicators.items():
            for v in values[:5]:  # Limit indicators
                indicator_list.append(f"- {ind_type}: {v}")

        indicator_text = "\n".join(indicator_list) if indicator_list else "No specific indicators"

        return f"""Generate {count} realistic sample security events for the following:

Technique: {technique_id} - {technique_name}
Target SIEM: {vendor}
Event Type: {event_type}

Indicators to include (vary these realistically):
{indicator_text}

Schema requirements:
- Required fields: {schema.get('required', [])}
- Optional fields: {schema.get('optional', [])}

Additional context:
- For Splunk: Use Unix timestamps for _time, include sourcetype
- For Elastic: Use ISO timestamps for @timestamp, use ECS field naming (dot notation)
- For Google SecOps: Use UDM format with nested objects (metadata.event_type, target.process.command_line)
- For MDE: Use ISO timestamps, include DeviceId as UUID

Generate varied events that would realistically trigger a detection for this technique.
Include slight variations in command lines, file paths, and other fields.

Output ONLY a valid JSON array of {count} events, nothing else:"""

    def _parse_llm_response(self, response: str) -> List[Dict[str, Any]]:
        """Parse LLM response into event list"""
        # Try to extract JSON from response
        response = response.strip()

        # Find JSON array in response
        json_match = re.search(r'\[[\s\S]*\]', response)
        if json_match:
            try:
                return json.loads(json_match.group())
            except json.JSONDecodeError:
                pass

        # Try parsing entire response as JSON
        try:
            result = json.loads(response)
            if isinstance(result, list):
                return result
            return [result]
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse LLM response as JSON: {e}")
            return []

    def _generate_from_templates(
        self,
        technique_id: str,
        indicators: Dict[str, List[str]],
        vendor: str,
        event_type: str,
        count: int
    ) -> List[Dict[str, Any]]:
        """Generate events from templates when LLM is not available"""
        events = []
        schema = VENDOR_SCHEMAS[vendor][event_type]

        for i in range(count):
            event = self._create_base_event(vendor, event_type, schema)

            # Add indicators
            event = self._add_indicators_to_event(event, indicators, vendor, event_type)

            # Add variation
            event = self._add_variation(event, i)

            events.append(event)

        return events

    def _create_base_event(self, vendor: str, event_type: str, schema: Dict) -> Dict[str, Any]:
        """Create a base event with required fields"""
        timestamp = datetime.utcnow() - timedelta(minutes=random.randint(0, 60))
        hostname = f"WORKSTATION-{random.randint(100, 999)}"
        username = random.choice(["jsmith", "auser", "admin", "service"])

        if vendor == "splunk":
            event = {
                "_time": timestamp.timestamp(),
                "host": hostname,
                "sourcetype": schema.get("sourcetypes", ["WinEventLog:Security"])[0],
                "EventCode": "4688" if event_type == "process" else "5156",
                "ComputerName": hostname,
                "User": f"DOMAIN\\{username}",
            }
        elif vendor == "elastic":
            event = {
                "@timestamp": timestamp.isoformat() + "Z",
                "host": {"name": hostname},
                "event": {"category": [event_type]},
                "user": {"name": username, "domain": "DOMAIN"},
            }
        elif vendor == "secops":
            event = {
                "metadata": {
                    "event_type": schema.get("event_type", "PROCESS_LAUNCH"),
                    "event_timestamp": timestamp.isoformat() + "Z",
                },
                "principal": {
                    "hostname": hostname,
                    "user": {"user_display_name": f"DOMAIN\\{username}"},
                },
                "target": {},
            }
        elif vendor == "mde":
            event = {
                "Timestamp": timestamp.isoformat() + "Z",
                "DeviceId": str(uuid.uuid4()),
                "DeviceName": hostname,
                "AccountName": username,
                "AccountDomain": "DOMAIN",
            }

        return event

    def _add_indicators_to_event(
        self,
        event: Dict[str, Any],
        indicators: Dict[str, List[str]],
        vendor: str,
        event_type: str
    ) -> Dict[str, Any]:
        """Add indicators to an event based on vendor format"""
        # Pick a random indicator from each type
        cmd = random.choice(indicators.get("cmd", ["powershell.exe -NoP -W Hidden"]))
        sw = random.choice(indicators.get("sw", ["powershell.exe"]))
        file_path = random.choice(indicators.get("file", ["C:\\Windows\\Temp\\malware.exe"]))

        if vendor == "splunk":
            event["CommandLine"] = cmd
            event["NewProcessName"] = file_path
            event["ParentProcessName"] = "C:\\Windows\\System32\\cmd.exe"
        elif vendor == "elastic":
            event["process"] = {
                "command_line": cmd,
                "name": sw.split("\\")[-1] if "\\" in sw else sw,
                "executable": file_path,
                "pid": random.randint(1000, 65000),
            }
            event["process"]["parent"] = {
                "name": "cmd.exe",
                "command_line": "C:\\Windows\\System32\\cmd.exe",
            }
        elif vendor == "secops":
            event["target"]["process"] = {
                "command_line": cmd,
                "file": {
                    "full_path": file_path,
                    "sha256": "".join(random.choices("0123456789abcdef", k=64)),
                },
                "pid": str(random.randint(1000, 65000)),
            }
        elif vendor == "mde":
            event["ProcessCommandLine"] = cmd
            event["FileName"] = sw.split("\\")[-1] if "\\" in sw else sw
            event["FolderPath"] = "\\".join(file_path.split("\\")[:-1])
            event["ProcessId"] = random.randint(1000, 65000)
            event["InitiatingProcessFileName"] = "cmd.exe"
            event["InitiatingProcessCommandLine"] = "C:\\Windows\\System32\\cmd.exe"

        return event

    def _add_variation(self, event: Dict[str, Any], index: int) -> Dict[str, Any]:
        """Add slight variations to make events more realistic"""
        # Vary timestamp slightly
        if "_time" in event:
            event["_time"] = event["_time"] + random.uniform(-300, 300)
        elif "@timestamp" in event:
            base = datetime.fromisoformat(event["@timestamp"].rstrip("Z"))
            varied = base + timedelta(seconds=random.randint(-300, 300))
            event["@timestamp"] = varied.isoformat() + "Z"

        return event

    def _validate_and_fix_event(
        self,
        event: Dict[str, Any],
        vendor: str,
        event_type: str
    ) -> Dict[str, Any]:
        """Validate and fix an event to ensure it matches the expected schema"""
        schema = VENDOR_SCHEMAS[vendor][event_type]

        # Ensure required fields exist
        for field in schema.get("required", []):
            if "." in field:
                # Nested field
                parts = field.split(".")
                current = event
                for part in parts[:-1]:
                    if part not in current:
                        current[part] = {}
                    current = current[part]
                if parts[-1] not in current:
                    current[parts[-1]] = "unknown"
            elif field not in event:
                event[field] = "unknown"

        return event

    def _generate_benign_events(
        self,
        vendor: str,
        event_type: str,
        count: int
    ) -> List[Dict[str, Any]]:
        """Generate benign events that should not trigger detections"""
        events = []
        templates = BENIGN_TEMPLATES.get(event_type, BENIGN_TEMPLATES["process"])
        schema = VENDOR_SCHEMAS[vendor].get(event_type, VENDOR_SCHEMAS[vendor]["process"])

        for i in range(count):
            template = random.choice(templates)
            event = self._create_base_event(vendor, event_type, schema)

            # Override with benign template data
            if event_type == "process":
                if vendor == "splunk":
                    event["CommandLine"] = template.get("cmd", "explorer.exe")
                    event["NewProcessName"] = template.get("path", "C:\\Windows\\explorer.exe")
                elif vendor == "elastic":
                    event["process"] = {
                        "command_line": template.get("cmd", "explorer.exe"),
                        "name": template.get("name", "explorer.exe"),
                        "executable": template.get("path", "C:\\Windows\\explorer.exe"),
                    }
                elif vendor == "secops":
                    event["target"]["process"] = {
                        "command_line": template.get("cmd", "explorer.exe"),
                        "file": {"full_path": template.get("path", "C:\\Windows\\explorer.exe")},
                    }
                elif vendor == "mde":
                    event["ProcessCommandLine"] = template.get("cmd", "explorer.exe")
                    event["FileName"] = template.get("name", "explorer.exe")
                    event["FolderPath"] = "\\".join(template.get("path", "C:\\Windows").split("\\")[:-1])

            elif event_type == "network":
                if vendor == "splunk":
                    event["dest_ip"] = template.get("dest_ip", "8.8.8.8")
                    event["dest_port"] = template.get("dest_port", 443)
                    event["protocol"] = template.get("protocol", "TCP")
                elif vendor == "elastic":
                    event["destination"] = {
                        "ip": template.get("dest_ip", "8.8.8.8"),
                        "port": template.get("dest_port", 443),
                    }
                    event["network"] = {"protocol": template.get("protocol", "TCP").lower()}
                elif vendor == "secops":
                    event["target"] = {
                        "ip": [template.get("dest_ip", "8.8.8.8")],
                        "port": template.get("dest_port", 443),
                    }
                elif vendor == "mde":
                    event["RemoteIP"] = template.get("dest_ip", "8.8.8.8")
                    event["RemotePort"] = template.get("dest_port", 443)
                    event["Protocol"] = template.get("protocol", "TCP")

            events.append(event)

        return events

    def generate_custom_events(
        self,
        vendor: str,
        event_type: str,
        field_values: Dict[str, Any],
        count: int = 5
    ) -> List[Dict[str, Any]]:
        """
        Generate custom events with specific field values.

        Useful for testing specific edge cases or scenarios.

        Args:
            vendor: Target SIEM vendor
            event_type: Event type (process, network, file)
            field_values: Dict of field names to values to inject
            count: Number of events to generate

        Returns:
            List of generated events
        """
        events = []
        schema = VENDOR_SCHEMAS.get(vendor, {}).get(event_type, VENDOR_SCHEMAS["mde"]["process"])

        for i in range(count):
            event = self._create_base_event(vendor, event_type, schema)

            # Apply custom field values
            for field, value in field_values.items():
                self._set_nested_field(event, field, value)

            events.append(event)

        return events

    def _set_nested_field(self, obj: Dict, path: str, value: Any):
        """Set a nested field using dot notation path"""
        parts = path.split(".")
        current = obj
        for part in parts[:-1]:
            if part not in current:
                current[part] = {}
            current = current[part]
        current[parts[-1]] = value
