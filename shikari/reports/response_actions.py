"""
Response Actions Generator
Generates triage, investigation, and remediation guidance for detections
"""

from typing import Dict, List, Optional, Any
from datetime import datetime
import re


class ResponseActionsGenerator:
    """Generate context-aware response actions for threat detections"""

    # MITRE ATT&CK Tactic to response priority mapping
    TACTIC_PRIORITY = {
        "Initial Access": "HIGH",
        "Execution": "HIGH",
        "Persistence": "CRITICAL",
        "Privilege Escalation": "CRITICAL",
        "Defense Evasion": "HIGH",
        "Credential Access": "CRITICAL",
        "Discovery": "MEDIUM",
        "Lateral Movement": "CRITICAL",
        "Collection": "HIGH",
        "Command and Control": "CRITICAL",
        "Exfiltration": "CRITICAL",
        "Impact": "CRITICAL",
        "Reconnaissance": "LOW",
        "Resource Development": "MEDIUM",
    }

    def __init__(self):
        """Initialize response actions generator"""
        self.technique_response_db = self._build_technique_response_db()

    def _build_technique_response_db(self) -> Dict[str, Dict[str, Any]]:
        """
        Build a database of response actions for common technique patterns.
        This can be expanded or loaded from an external configuration.
        """
        return {
            # Credential Access patterns
            "credential_dumping": {
                "patterns": ["lsass", "credential", "password", "mimikatz", "procdump", "sekurlsa"],
                "triage": [
                    "Verify the alert is not a false positive from legitimate administrative tools",
                    "Check if the process attempting credential access is signed and from a trusted vendor",
                    "Identify the user account associated with the activity",
                    "Check for recent privilege escalation events on the same host",
                ],
                "detection_validation": [
                    "Review process command line for known credential dumping tools (mimikatz, procdump, etc.)",
                    "Check if LSASS process was accessed by non-system processes",
                    "Verify if memory dump files were created in unusual locations",
                    "Correlate with other suspicious activity from the same user/device",
                ],
                "containment": [
                    "Isolate the affected device from the network immediately",
                    "Disable the compromised user account(s)",
                    "Force password reset for all potentially compromised accounts",
                    "Block any identified malicious executables via endpoint protection",
                ],
                "investigation": [
                    "Review all processes running on the affected system at time of detection",
                    "Check parent-child process relationships for suspicious process spawning",
                    "Search for lateral movement attempts from this host",
                    "Review authentication logs for unusual login patterns",
                    "Check for data exfiltration attempts following credential access",
                ],
                "remediation": [
                    "Wipe and rebuild the compromised system from a known-good backup",
                    "Reset credentials for all accounts that logged into the affected system",
                    "Enable Credential Guard on Windows systems to protect LSASS",
                    "Deploy EDR with memory protection capabilities",
                    "Review and update privileged access management (PAM) controls",
                ],
            },
            # Lateral Movement patterns
            "lateral_movement": {
                "patterns": ["psexec", "remote", "rdp", "wmi", "smb", "admin$", "c$", "winrm"],
                "triage": [
                    "Identify source and destination systems involved in lateral movement",
                    "Verify if the movement aligns with user's normal behavior patterns",
                    "Check if legitimate IT/admin tools are being used",
                    "Determine if credentials used are appropriate for the accessed systems",
                ],
                "detection_validation": [
                    "Verify remote execution tools (PSExec, WMI, PowerShell Remoting) were used",
                    "Check for SMB/RDP connections between internal hosts",
                    "Review network traffic for anomalous internal connections",
                    "Validate if service creation or scheduled tasks occurred on remote systems",
                ],
                "containment": [
                    "Isolate both source and destination systems from the network",
                    "Disable the account used for lateral movement",
                    "Block SMB/RDP traffic between workstations (if not already blocked)",
                    "Terminate any remote sessions from the compromised account",
                ],
                "investigation": [
                    "Map the full scope of lateral movement across the environment",
                    "Identify all systems accessed by the compromised credential",
                    "Review logs on each affected system for malicious activity",
                    "Search for persistence mechanisms on all compromised systems",
                    "Check domain controller logs for unusual authentication patterns",
                ],
                "remediation": [
                    "Rebuild all affected systems from clean images",
                    "Reset domain/local admin credentials used during lateral movement",
                    "Implement network segmentation to limit lateral movement paths",
                    "Deploy Local Administrator Password Solution (LAPS)",
                    "Enable SMB signing and disable SMBv1",
                    "Implement tiered administration model for privileged accounts",
                ],
            },
            # Persistence patterns
            "persistence": {
                "patterns": ["scheduled task", "registry run", "startup", "service", "wmi event", "bootkit"],
                "triage": [
                    "Identify the persistence mechanism used (scheduled task, registry key, service, etc.)",
                    "Determine when the persistence was established",
                    "Check if the persistence mechanism is associated with known malware",
                    "Verify if multiple persistence mechanisms exist on the same host",
                ],
                "detection_validation": [
                    "Review scheduled tasks for suspicious entries (unusual paths, obfuscated commands)",
                    "Check registry Run/RunOnce keys for unauthorized entries",
                    "Examine Windows services for recently created or modified services",
                    "Look for WMI event subscriptions pointing to malicious scripts",
                ],
                "containment": [
                    "Remove the identified persistence mechanism immediately",
                    "Isolate the affected system from the network",
                    "Disable any accounts associated with the persistence mechanism",
                    "Block execution of any identified malicious files",
                ],
                "investigation": [
                    "Determine how the attacker gained initial access to establish persistence",
                    "Review all persistence locations for additional backdoors",
                    "Check for signs of privilege escalation that enabled persistence creation",
                    "Search for similar persistence mechanisms on other systems",
                ],
                "remediation": [
                    "Completely remove all identified persistence mechanisms",
                    "Rebuild the system if rootkit/bootkit persistence is suspected",
                    "Audit and harden registry permissions to prevent unauthorized persistence",
                    "Implement application whitelisting to prevent unauthorized executables",
                    "Enable and monitor advanced audit policies for persistence-related events",
                ],
            },
            # Command and Control patterns
            "command_control": {
                "patterns": ["c2", "beacon", "callback", "http", "dns", "tunnel", "proxy"],
                "triage": [
                    "Identify the external IP/domain the system is communicating with",
                    "Check threat intelligence feeds for known C2 infrastructure",
                    "Determine the protocol and port used for C2 communication",
                    "Verify if the traffic is encrypted/encoded",
                ],
                "detection_validation": [
                    "Review network logs for beaconing patterns (regular intervals)",
                    "Check DNS queries for suspicious domains or DGA patterns",
                    "Analyze packet captures for C2 communication protocols",
                    "Correlate with process execution logs to identify C2 client process",
                ],
                "containment": [
                    "Block the identified C2 IP addresses/domains at the firewall",
                    "Isolate the affected system from the network immediately",
                    "Terminate the process responsible for C2 communication",
                    "Block the malicious executable via endpoint protection",
                ],
                "investigation": [
                    "Identify all systems communicating with the same C2 infrastructure",
                    "Review C2 traffic to understand attacker commands and data exfiltration",
                    "Determine the malware family based on C2 protocol/behavior",
                    "Check for downloaded payloads or tools from the C2 server",
                    "Search for additional C2 channels (backup domains, IPs)",
                ],
                "remediation": [
                    "Maintain blocks on C2 infrastructure at network perimeter",
                    "Rebuild all systems that communicated with C2 infrastructure",
                    "Deploy network monitoring for similar C2 patterns",
                    "Implement DNS filtering to block known malicious domains",
                    "Review and update egress filtering rules to limit outbound connections",
                ],
            },
            # Execution patterns
            "execution": {
                "patterns": ["powershell", "cmd", "wscript", "cscript", "mshta", "rundll32", "regsvr32"],
                "triage": [
                    "Identify the command line arguments used in execution",
                    "Determine if execution is part of a scripting/automation framework",
                    "Check if the execution was initiated by a user or system process",
                    "Verify if encoded/obfuscated commands were used",
                ],
                "detection_validation": [
                    "Review command line for obfuscation, encoding (base64), or download cradles",
                    "Check for unusual parent-child process relationships",
                    "Verify if scripts were executed from unusual locations (temp, appdata)",
                    "Look for bypass techniques (ExecutionPolicy bypass, hidden windows)",
                ],
                "containment": [
                    "Terminate the suspicious process and any child processes",
                    "Isolate the system if malicious execution is confirmed",
                    "Block identified malicious scripts via endpoint protection",
                    "Disable scripting engines if not required for business operations",
                ],
                "investigation": [
                    "Trace the origin of the executed script (email attachment, download, etc.)",
                    "Review all scripts executed on the system in the relevant timeframe",
                    "Check for modifications to script execution policies",
                    "Search for similar execution patterns across the environment",
                ],
                "remediation": [
                    "Implement PowerShell Constrained Language Mode",
                    "Enable PowerShell script block logging and module logging",
                    "Deploy application control policies to limit script execution",
                    "Use Attack Surface Reduction (ASR) rules to block dangerous execution patterns",
                    "Train users to recognize and avoid malicious scripts",
                ],
            },
            # Privilege Escalation patterns
            "privilege_escalation": {
                "patterns": ["uac bypass", "token", "exploit", "elevate", "administrator", "system"],
                "triage": [
                    "Identify the method used for privilege escalation",
                    "Determine the account that escalated privileges",
                    "Check if a known vulnerability or exploit was used",
                    "Verify the legitimacy of privilege escalation request",
                ],
                "detection_validation": [
                    "Review UAC bypass indicators (elevated execution without prompt)",
                    "Check for token manipulation or impersonation techniques",
                    "Look for exploitation of vulnerable services or applications",
                    "Verify integrity level changes in process creation events",
                ],
                "containment": [
                    "Terminate processes running with escalated privileges",
                    "Disable the compromised user account",
                    "Isolate the affected system immediately",
                    "Revoke any tokens or tickets associated with escalated access",
                ],
                "investigation": [
                    "Determine what actions were taken with escalated privileges",
                    "Check for persistence mechanisms created with admin rights",
                    "Review patch status for exploited vulnerabilities",
                    "Search for similar privilege escalation across other systems",
                ],
                "remediation": [
                    "Patch vulnerabilities used for privilege escalation",
                    "Implement least privilege principles for user accounts",
                    "Enable Protected Process Light (PPL) for critical processes",
                    "Deploy EDR with behavioral detection for privilege escalation",
                    "Regularly audit privileged accounts and access",
                ],
            },
        }

    @staticmethod
    def _normalise_indicators(indicators) -> Dict[str, List[str]]:
        """Coerce indicators into {type: [values]}. Accepts a dict, a list, a
        single string, or None, so a caller passing the wrong shape can't crash
        the steps that expect a mapping."""
        if not indicators:
            return {}
        if isinstance(indicators, dict):
            out = {}
            for key, values in indicators.items():
                if isinstance(values, (list, tuple, set)):
                    out[key] = [str(v) for v in values]
                elif values is not None:
                    out[key] = [str(values)]
            return out
        if isinstance(indicators, str):
            return {"other": [indicators]}
        if isinstance(indicators, (list, tuple, set)):
            return {"other": [str(v) for v in indicators]}
        return {}

    def generate_response_actions(
        self,
        technique_name: str,
        technique_id: str,
        tactic: str,
        description: str,
        indicators: Dict[str, List[str]] = None,
        threat_actor: str = None,
        threat_actor_context: Dict[str, Any] = None,
    ) -> Dict[str, Any]:
        """
        Generate comprehensive response actions for a detection.

        Args:
            technique_name: MITRE ATT&CK technique name
            technique_id: MITRE ATT&CK technique ID (e.g., T1003.001)
            tactic: MITRE ATT&CK tactic
            description: Technique description
            indicators: Dictionary of indicators (cmd, sw, api, etc.)
            threat_actor: Name of threat actor (if applicable)
            threat_actor_context: Additional context about threat actor

        Returns:
            Dictionary containing response actions
        """
        # Normalise indicators to the {type: [values]} shape the steps expect.
        # Callers sometimes hand us a bare list (or a comma string); bucket those
        # under "other" so nothing downstream calls .values()/.get() on a list.
        indicators = self._normalise_indicators(indicators)

        # Determine response priority based on tactic
        priority = self.TACTIC_PRIORITY.get(tactic, "MEDIUM")

        # Match technique to response pattern
        response_template = self._match_response_template(technique_name, description, indicators)

        # Generate triage steps
        triage_steps = self._generate_triage_steps(
            technique_name, tactic, response_template, indicators
        )

        # Generate detection validation steps
        validation_steps = self._generate_validation_steps(
            technique_name, response_template, indicators
        )

        # Generate containment actions
        containment_actions = self._generate_containment_actions(
            technique_name, tactic, response_template, threat_actor
        )

        # Generate investigation queries/steps
        investigation_steps = self._generate_investigation_steps(
            technique_name, technique_id, response_template, indicators
        )

        # Generate remediation guidance
        remediation_steps = self._generate_remediation_steps(
            technique_name, tactic, response_template
        )

        # Add threat actor specific guidance if available
        threat_actor_guidance = None
        if threat_actor and threat_actor_context:
            threat_actor_guidance = self._generate_threat_actor_guidance(
                threat_actor, threat_actor_context, technique_name
            )

        return {
            "technique_id": technique_id,
            "technique_name": technique_name,
            "tactic": tactic,
            "priority": priority,
            "response_actions": {
                "triage": {
                    "description": "Initial assessment steps to understand the scope and validity of the alert",
                    "steps": triage_steps,
                },
                "validation": {
                    "description": "Steps to confirm if this is a true positive detection",
                    "steps": validation_steps,
                },
                "containment": {
                    "description": "Immediate actions to limit the impact and prevent further compromise",
                    "steps": containment_actions,
                },
                "investigation": {
                    "description": "Detailed investigation to understand the full scope of the incident",
                    "steps": investigation_steps,
                },
                "remediation": {
                    "description": "Long-term fixes and hardening to prevent recurrence",
                    "steps": remediation_steps,
                },
            },
            "threat_actor_guidance": threat_actor_guidance,
            "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        }

    def _match_response_template(
        self, technique_name: str, description: str, indicators: Dict[str, List[str]] = None
    ) -> Dict[str, Any]:
        """Match the technique to a response template based on patterns"""
        technique_lower = technique_name.lower()
        desc_lower = description.lower() if description else ""

        # Collect all text to search
        search_text = f"{technique_lower} {desc_lower}"

        if indicators:
            for indicator_list in indicators.values():
                if indicator_list:
                    search_text += " " + " ".join(str(i).lower() for i in indicator_list)

        # Try to match against patterns
        best_match = None
        best_match_score = 0

        for category, template in self.technique_response_db.items():
            match_score = sum(
                1 for pattern in template["patterns"] if pattern.lower() in search_text
            )

            if match_score > best_match_score:
                best_match_score = match_score
                best_match = template

        # Return matched template or generic template
        return best_match if best_match else self._get_generic_template()

    def _get_generic_template(self) -> Dict[str, Any]:
        """Return a generic response template for techniques without specific patterns"""
        return {
            "triage": [
                "Review the detection alert and associated metadata",
                "Verify the affected user account and system",
                "Check if this activity aligns with normal business operations",
                "Assess the credibility and severity of the detection",
            ],
            "detection_validation": [
                "Review logs and telemetry data for the specific technique indicators",
                "Correlate with other security alerts from the same timeframe",
                "Check threat intelligence for similar attack patterns",
                "Validate the detection is not a false positive",
            ],
            "containment": [
                "Isolate affected systems if malicious activity is confirmed",
                "Disable compromised user accounts",
                "Block identified malicious artifacts (files, IPs, domains)",
                "Prevent further spread of the attack",
            ],
            "investigation": [
                "Determine the initial access vector",
                "Map the full scope of compromise",
                "Identify all affected systems and accounts",
                "Collect forensic evidence for further analysis",
            ],
            "remediation": [
                "Remove malicious artifacts from affected systems",
                "Rebuild compromised systems from clean images",
                "Reset credentials for affected accounts",
                "Implement controls to prevent similar attacks",
                "Update detection rules based on lessons learned",
            ],
        }

    def _generate_triage_steps(
        self,
        technique_name: str,
        tactic: str,
        template: Dict[str, Any],
        indicators: Dict[str, List[str]] = None,
    ) -> List[str]:
        """Generate triage steps based on template and context"""
        steps = template.get("triage", []).copy()

        # Add indicator-specific triage steps
        if indicators:
            if indicators.get("cmd"):
                steps.append(
                    f"Review command line arguments: {', '.join(indicators['cmd'][:3])}"
                    + ("..." if len(indicators['cmd']) > 3 else "")
                )
            if indicators.get("sw"):
                steps.append(
                    f"Check for suspicious software: {', '.join(indicators['sw'][:3])}"
                    + ("..." if len(indicators['sw']) > 3 else "")
                )

        return steps

    def _generate_validation_steps(
        self, technique_name: str, template: Dict[str, Any], indicators: Dict[str, List[str]] = None
    ) -> List[str]:
        """Generate detection validation steps"""
        steps = template.get("detection_validation", []).copy()

        # Add technique-specific validation
        steps.append(f"Verify the detection aligns with known behaviors of {technique_name}")

        return steps

    def _generate_containment_actions(
        self,
        technique_name: str,
        tactic: str,
        template: Dict[str, Any],
        threat_actor: str = None,
    ) -> List[str]:
        """Generate containment actions"""
        actions = template.get("containment", []).copy()

        # Add urgency note for critical tactics
        if tactic in ["Credential Access", "Lateral Movement", "Exfiltration"]:
            actions.insert(
                0,
                f"⚠️ URGENT: {tactic} detected - immediate containment required to prevent further compromise",
            )

        # Add threat actor specific containment if applicable
        if threat_actor:
            actions.append(
                f"Review threat intelligence for {threat_actor} to identify additional IOCs to block"
            )

        return actions

    def _generate_investigation_steps(
        self,
        technique_name: str,
        technique_id: str,
        template: Dict[str, Any],
        indicators: Dict[str, List[str]] = None,
    ) -> List[str]:
        """Generate investigation steps and queries"""
        steps = template.get("investigation", []).copy()

        # Add technique ID reference
        steps.append(
            f"Reference MITRE ATT&CK {technique_id} for detailed technique information and detection guidance"
        )

        return steps

    def _generate_remediation_steps(
        self, technique_name: str, tactic: str, template: Dict[str, Any]
    ) -> List[str]:
        """Generate remediation and hardening steps"""
        steps = template.get("remediation", []).copy()

        # Add general best practices
        steps.append("Document the incident and update incident response playbooks")
        steps.append("Conduct post-incident review to identify security gaps")

        return steps

    def _generate_threat_actor_guidance(
        self, threat_actor: str, context: Dict[str, Any], technique_name: str
    ) -> Dict[str, Any]:
        """Generate threat actor specific guidance"""
        guidance = {
            "threat_actor": threat_actor,
            "context": f"This technique is associated with {threat_actor}",
            "recommendations": [],
        }

        # Extract context if available
        if context.get("description"):
            guidance["context"] = context["description"]

        if context.get("aliases"):
            guidance["aliases"] = context["aliases"]

        if context.get("target_sectors"):
            guidance["recommendations"].append(
                f"Note: {threat_actor} typically targets {', '.join(context['target_sectors'])} sectors"
            )

        if context.get("known_tools"):
            guidance["recommendations"].append(
                f"Search for other {threat_actor} tools: {', '.join(context['known_tools'][:5])}"
            )

        if context.get("ttps"):
            guidance["recommendations"].append(
                f"Monitor for other {threat_actor} TTPs to identify campaign scope"
            )

        # Generic threat actor recommendations
        guidance["recommendations"].extend(
            [
                f"Review threat intelligence feeds for latest {threat_actor} IOCs",
                f"Check for indicators of other techniques commonly used by {threat_actor}",
                f"Assess if this detection is part of a broader {threat_actor} campaign",
            ]
        )

        return guidance
