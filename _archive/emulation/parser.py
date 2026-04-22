"""
Emulation Result Parser

Parses emulation framework outputs and extracts threat hunting indicators.
"""

import json
import re
from typing import Dict, List, Any
from pathlib import Path


class EmulationParser:
    """Parse emulation results and extract hunting indicators."""

    @staticmethod
    def parse_atomic_results(result_file: Path) -> Dict[str, Any]:
        """
        Parse Atomic Red Team execution results.

        Args:
            result_file: Path to atomic test result JSON

        Returns:
            Dictionary with parsed indicators
        """
        with open(result_file, "r", encoding="utf-8") as f:
            data = json.load(f)

        indicators = {
            "technique_id": data.get("technique_id"),
            "technique_name": data.get("technique_name"),
            "commands": [],
            "processes": [],
            "registry_keys": [],
            "files": [],
            "network": [],
            "other": [],
        }

        # Extract from evidence
        for evidence in data.get("evidence_collected", []):
            etype = evidence.get("type")
            value = evidence.get("value", "")

            if etype == "command_line":
                indicators["commands"].append(
                    {"value": value, "description": evidence.get("description")}
                )

            # Extract process names from commands
            processes = EmulationParser._extract_processes(value)
            for proc in processes:
                if proc not in [p["name"] for p in indicators["processes"]]:
                    indicators["processes"].append({"name": proc, "source": "command"})

            # Extract file paths
            file_paths = EmulationParser._extract_file_paths(value)
            for fpath in file_paths:
                if fpath not in [f["path"] for f in indicators["files"]]:
                    indicators["files"].append({"path": fpath, "source": "command"})

            # Extract registry keys
            reg_keys = EmulationParser._extract_registry_keys(value)
            for key in reg_keys:
                if key not in [r["key"] for r in indicators["registry_keys"]]:
                    indicators["registry_keys"].append(
                        {"key": key, "source": "command"}
                    )

        return indicators

    @staticmethod
    def _extract_processes(command: str) -> List[str]:
        """Extract process names from command string."""
        processes = []

        # Common executables
        exe_pattern = r"\b(\w+\.exe)\b"
        matches = re.findall(exe_pattern, command, re.IGNORECASE)
        processes.extend(matches)

        # PowerShell cmdlets
        if "powershell" in command.lower():
            processes.append("powershell.exe")
            if "-encodedcommand" in command.lower():
                processes.append("powershell.exe (encoded)")

        # Common shells
        shells = ["cmd.exe", "bash", "sh", "zsh", "wscript.exe", "cscript.exe"]
        for shell in shells:
            if shell.lower() in command.lower():
                if shell not in processes:
                    processes.append(shell)

        return processes

    @staticmethod
    def _extract_file_paths(command: str) -> List[str]:
        """Extract file paths from command string."""
        paths = []

        # Windows paths
        win_pattern = r'[A-Za-z]:\\(?:[^\\/:*?"<>|\r\n]+\\)*[^\\/:*?"<>|\r\n]*'
        paths.extend(re.findall(win_pattern, command))

        # Unix paths
        unix_pattern = r'/(?:[^/\s]+/)*[^/\s]+'
        unix_matches = re.findall(unix_pattern, command)
        # Filter out common false positives
        unix_paths = [
            p
            for p in unix_matches
            if not p.startswith("/http") and len(p) > 3
        ]
        paths.extend(unix_paths)

        # Environment variable paths
        env_pattern = r'\$\{?[A-Z_]+\}?[\\\/][\w\\\/\.]+'
        paths.extend(re.findall(env_pattern, command))

        return list(set(paths))

    @staticmethod
    def _extract_registry_keys(command: str) -> List[str]:
        """Extract Windows registry keys from command string."""
        keys = []

        # Registry key patterns
        reg_pattern = r'(HKEY_[A-Z_]+|HKLM|HKCU|HKCR|HKU|HKCC)\\[^\s"\';]+'
        matches = re.findall(reg_pattern, command, re.IGNORECASE)

        for match in matches:
            # Expand abbreviations
            expanded = match.upper()
            expanded = expanded.replace("HKLM\\", "HKEY_LOCAL_MACHINE\\")
            expanded = expanded.replace("HKCU\\", "HKEY_CURRENT_USER\\")
            expanded = expanded.replace("HKCR\\", "HKEY_CLASSES_ROOT\\")
            expanded = expanded.replace("HKU\\", "HKEY_USERS\\")
            expanded = expanded.replace("HKCC\\", "HKEY_CURRENT_CONFIG\\")
            keys.append(expanded)

        return list(set(keys))

    @staticmethod
    def generate_kql_from_indicators(indicators: Dict[str, Any]) -> List[str]:
        """
        Generate KQL queries from parsed indicators.

        Args:
            indicators: Parsed indicators from emulation results

        Returns:
            List of KQL query strings
        """
        queries = []

        # Process execution queries
        if indicators.get("processes"):
            process_names = [p["name"] for p in indicators["processes"]]
            if process_names:
                process_list = '" or ProcessName == "'.join(process_names)
                query = f"""// Generated from Atomic Red Team execution - {indicators.get('technique_id')}
DeviceProcessEvents
| where Timestamp > ago(30d)
| where ProcessName == "{process_list}"
| project Timestamp, DeviceName, ProcessName, ProcessCommandLine, InitiatingProcessFileName"""
                queries.append(query)

        # File creation/modification queries
        if indicators.get("files"):
            file_paths = [f["path"] for f in indicators["files"][:5]]  # Limit to 5
            if file_paths:
                query = f"""// File activity from Atomic Red Team - {indicators.get('technique_id')}
DeviceFileEvents
| where Timestamp > ago(30d)
| where FileName has_any ({json.dumps(file_paths)})
| project Timestamp, DeviceName, FileName, FolderPath, ActionType, InitiatingProcessFileName"""
                queries.append(query)

        # Registry queries
        if indicators.get("registry_keys"):
            reg_keys = [r["key"] for r in indicators["registry_keys"][:5]]
            if reg_keys:
                query = f"""// Registry activity from Atomic Red Team - {indicators.get('technique_id')}
DeviceRegistryEvents
| where Timestamp > ago(30d)
| where RegistryKey has_any ({json.dumps(reg_keys)})
| project Timestamp, DeviceName, RegistryKey, RegistryValueName, ActionType, InitiatingProcessFileName"""
                queries.append(query)

        return queries

    @staticmethod
    def enrich_yaml_with_evidence(
        yaml_path: Path, indicators: Dict[str, Any]
    ) -> bool:
        """
        Enrich existing YAML detection with evidence from emulation.

        Args:
            yaml_path: Path to YAML detection file
            indicators: Parsed indicators to add

        Returns:
            True if enriched successfully
        """
        import yaml

        try:
            with open(yaml_path, "r", encoding="utf-8") as f:
                detection = yaml.safe_load(f)

            # Add emulation evidence section
            if "emulation_evidence" not in detection:
                detection["emulation_evidence"] = {}

            detection["emulation_evidence"]["source"] = "Atomic Red Team"
            detection["emulation_evidence"]["technique_id"] = indicators.get(
                "technique_id"
            )

            # Add indicators
            if indicators.get("processes"):
                detection["emulation_evidence"]["processes"] = [
                    p["name"] for p in indicators["processes"]
                ]

            if indicators.get("commands"):
                detection["emulation_evidence"]["sample_commands"] = [
                    c["value"] for c in indicators["commands"][:3]
                ]

            if indicators.get("registry_keys"):
                detection["emulation_evidence"]["registry_keys"] = [
                    r["key"] for r in indicators["registry_keys"]
                ]

            if indicators.get("files"):
                detection["emulation_evidence"]["file_paths"] = [
                    f["path"] for f in indicators["files"]
                ]

            # Write back to file
            with open(yaml_path, "w", encoding="utf-8") as f:
                yaml.dump(detection, f, default_flow_style=False, sort_keys=False)

            return True

        except Exception as e:
            print(f"Error enriching YAML: {e}")
            return False
