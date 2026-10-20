"""
The attack flow in two other lifecycle models: Lockheed Martin's Cyber Kill Chain and
Mandiant's Targeted Attack Lifecycle (Google Cloud). Neither has an official ATT&CK
crosswalk, so these mappings are Archer's: a technique goes by the tactic it sits under
in the flow, except the techniques listed in "techniques", whose tactic says less about
the phase than the technique itself (phishing is Delivery, not just Initial Access).

None of the three models is a strict sequence. ATT&CK tactics are the adversary's goals,
not steps: a group can reach Discovery before Execution, or Credential Access long
after Lateral Movement. The phases are shown in their usual order, not the order a
group used them.
"""

from typing import Dict, List, Optional

# Phases in each model's own order. "cycle" marks the Targeted Attack Lifecycle's
# maintain-presence loop, which repeats as the intruder moves through the estate.
FRAMEWORKS: List[Dict] = [
    {
        "key": "ckc",
        "name": "Cyber Kill Chain",
        "source": "Lockheed Martin",
        "url": "https://www.lockheedmartin.com/en-us/capabilities/cyber/cyber-kill-chain.html",
        "phases": [
            {"name": "Reconnaissance", "about": "Harvesting email addresses, conference information and so on"},
            {"name": "Weaponization", "about": "Coupling an exploit with a backdoor into a deliverable payload"},
            {"name": "Delivery", "about": "Delivering the weaponised bundle via email, web, USB and so on"},
            {"name": "Exploitation", "about": "Exploiting a vulnerability to execute code on the victim's system"},
            {"name": "Installation", "about": "Installing malware on the asset"},
            {"name": "Command & Control", "about": "A command channel for remote manipulation of the victim"},
            {"name": "Actions on Objectives", "about": "With hands-on-keyboard access, intruders accomplish their original goals"},
        ],
        "tactics": {
            "Reconnaissance": "Reconnaissance",
            "Resource Development": "Weaponization",
            "Initial Access": "Delivery",
            "Execution": "Exploitation",
            "Privilege Escalation": "Exploitation",
            "Persistence": "Installation",
            "Defense Evasion": "Installation",
            "Stealth": "Installation",
            "Defense Impairment": "Installation",
            "Command and Control": "Command & Control",
            "Credential Access": "Actions on Objectives",
            "Discovery": "Actions on Objectives",
            "Lateral Movement": "Actions on Objectives",
            "Collection": "Actions on Objectives",
            "Exfiltration": "Actions on Objectives",
            "Impact": "Actions on Objectives",
        },
        "techniques": {
            "T1190": "Exploitation",   # Exploit Public-Facing Application
            "T1203": "Exploitation",   # Exploitation for Client Execution
            "T1204": "Exploitation",   # User Execution: the user triggers the payload
            "T1068": "Exploitation",   # Exploitation for Privilege Escalation
            "T1211": "Exploitation",   # Exploitation for Defense Evasion
            "T1212": "Exploitation",   # Exploitation for Credential Access
            "T1587": "Weaponization",  # Develop Capabilities
            "T1588": "Weaponization",  # Obtain Capabilities
            "T1608": "Delivery",       # Stage Capabilities: hosting the payload for delivery
        },
    },
    {
        "key": "tal",
        "name": "Targeted Attack Lifecycle",
        "source": "Mandiant, Google Cloud",
        "url": "https://cloud.google.com/security/resources/insights/targeted-attack-lifecycle",
        "phases": [
            {"name": "Initial Recon", "about": "Researching systems and employees and preparing the attack"},
            {"name": "Initial Compromise", "about": "Executing malicious code on one or more systems"},
            {"name": "Establish Foothold", "about": "A backdoor and command channel immediately after the compromise"},
            {"name": "Escalate Privileges", "about": "Obtaining greater access, usually by stealing credentials", "cycle": True},
            {"name": "Internal Recon", "about": "Exploring the environment for its layout, structure and trusts", "cycle": True},
            {"name": "Move Laterally", "about": "Using the access to reach other systems in the environment", "cycle": True},
            {"name": "Maintain Presence", "about": "Ensuring continued control over key systems and credentials", "cycle": True},
            {"name": "Complete Mission", "about": "Collecting, staging and exfiltrating data, or disrupting systems"},
        ],
        "tactics": {
            "Reconnaissance": "Initial Recon",
            "Resource Development": "Initial Recon",
            "Initial Access": "Initial Compromise",
            "Execution": "Initial Compromise",
            "Persistence": "Establish Foothold",
            "Command and Control": "Establish Foothold",
            "Privilege Escalation": "Escalate Privileges",
            "Credential Access": "Escalate Privileges",
            "Discovery": "Internal Recon",
            "Lateral Movement": "Move Laterally",
            "Defense Evasion": "Maintain Presence",
            "Stealth": "Maintain Presence",
            "Defense Impairment": "Maintain Presence",
            "Collection": "Complete Mission",
            "Exfiltration": "Complete Mission",
            "Impact": "Complete Mission",
        },
        "techniques": {
            "T1505": "Establish Foothold",   # Server Software Component (web shells)
            "T1078": "Maintain Presence",    # Valid Accounts: continued access with stolen credentials
            "T1133": "Maintain Presence",    # External Remote Services
        },
    },
]

UNMAPPED = "Unmapped"


def framework(key: str) -> Optional[Dict]:
    return next((f for f in FRAMEWORKS if f["key"] == key), None)


def phase_of(key: str, technique_id: str, tactic: str) -> str:
    """The phase a technique sits in for framework `key`: its own mapping, its parent's, then its tactic's."""
    fw = framework(key)
    if fw is None:
        raise KeyError(key)
    tid = technique_id.upper()
    return fw["techniques"].get(tid) or fw["techniques"].get(tid.split(".")[0]) or fw["tactics"].get(tactic, UNMAPPED)
