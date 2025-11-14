#!/usr/bin/env python3
"""
Generate technique_platform_indicators.json validation matrix for ALL MITRE ATT&CK techniques.

This script creates validation rules based on:
1. MITRE ATT&CK Enterprise data (technique platforms)
2. Common indicator patterns for each platform
3. Known invalid indicators (cross-platform contamination)
"""

import json
import sys
from pathlib import Path

# Add archer to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from archer.mitre.enterprise import get_stix_data, obtain_all_techniques


# Platform-specific valid indicators (generic patterns)
PLATFORM_INDICATORS = {
    "Windows": {
        "valid_indicators": {
            "cmd": ["cmd", "powershell", "net ", "reg ", "wmic", "sc ", "tasklist", "netsh", "certutil", "bitsadmin"],
            "evt": ["4688", "4624", "4625", "4672", "4720", "4732", "1", "7045"],
            "sw": [".exe", ".dll", ".sys", "cmd.exe", "powershell.exe", "rundll32.exe"],
            "reg": ["HKLM", "HKCU", "HKEY_"]
        },
        "invalid_indicators": {
            "cmd": ["useradd", "adduser", "usermod", "apt-get", "yum", "brew", "launchctl", "sysadminctl", "dscl"],
            "api": ["CreateUser", "CreateLoginProfile", "AttachUserPolicy", "SetIamPolicy"],
            "operation": ["Add user", "Invite external user"],
            "reason": "These are Linux/macOS/Cloud indicators, not Windows"
        }
    },
    "Linux": {
        "valid_indicators": {
            "cmd": ["bash", "sh", "useradd", "usermod", "groupadd", "chmod", "chown", "sudo", "apt-get", "yum", "systemctl"],
            "file": ["/etc/", "/var/", "/tmp/", "/home/", "/root/"]
        },
        "invalid_indicators": {
            "cmd": ["cmd.exe", "powershell", "net user", "reg ", "wmic", "sysadminctl", "dscl"],
            "evt": ["4688", "4624", "4720"],
            "reg": ["HKLM", "HKCU"],
            "api": ["CreateUser", "AttachUserPolicy"],
            "reason": "These are Windows/macOS/Cloud indicators, not Linux"
        }
    },
    "macOS": {
        "valid_indicators": {
            "cmd": ["bash", "zsh", "launchctl", "sysadminctl", "dscl", "dseditgroup", "defaults", "osascript"],
            "file": ["/Users/", "/Applications/", "/Library/", "/System/Library/"]
        },
        "invalid_indicators": {
            "cmd": ["cmd.exe", "powershell", "net user", "wmic", "useradd", "usermod", "apt-get"],
            "evt": ["4688", "4624", "4720"],
            "reg": ["HKLM", "HKCU"],
            "api": ["CreateUser", "AttachUserPolicy"],
            "reason": "These are Windows/Linux/Cloud indicators, not macOS"
        }
    },
    "Azure AD": {
        "valid_indicators": {
            "operation": ["Add ", "Create ", "Delete ", "Update ", "Invite ", "Remove "],
            "api": ["Microsoft.Aad", "Microsoft.Graph", "Microsoft.Authorization"]
        },
        "invalid_indicators": {
            "cmd": ["cmd", "powershell", "bash", "net user", "useradd", "wmic"],
            "evt": ["4688", "4624", "4720"],
            "sw": [".exe", ".dll"],
            "reg": ["HKLM", "HKCU"],
            "reason": "Cloud platforms use API operations, not command-line or event log indicators"
        }
    },
    "AWS": {
        "valid_indicators": {
            "api": ["Create", "Delete", "Attach", "Detach", "Put", "Get", "List", "Describe"],
            "operation": ["CreateUser", "CreateLoginProfile", "AttachUserPolicy", "CreateAccessKey"]
        },
        "invalid_indicators": {
            "cmd": ["cmd", "powershell", "bash", "net user", "useradd", "wmic"],
            "evt": ["4688", "4624", "4720"],
            "sw": [".exe", ".dll"],
            "reg": ["HKLM", "HKCU"],
            "reason": "Cloud platforms use API calls, not command-line or event log indicators"
        }
    },
    "GCP": {
        "valid_indicators": {
            "api": ["google.iam", "google.compute", "google.storage", "Create", "Delete", "Update", "SetIamPolicy"],
            "operation": ["CreateServiceAccount", "CreateServiceAccountKey", "SetIamPolicy"]
        },
        "invalid_indicators": {
            "cmd": ["cmd", "powershell", "bash", "net user", "useradd", "wmic"],
            "evt": ["4688", "4624", "4720"],
            "sw": [".exe", ".dll"],
            "reg": ["HKLM", "HKCU"],
            "reason": "Cloud platforms use API calls, not command-line or event log indicators"
        }
    },
    "Office 365": {
        "valid_indicators": {
            "operation": ["Add ", "Create ", "Delete ", "Update ", "Set ", "New-"],
            "api": ["Microsoft.Office", "Exchange", "SharePoint"]
        },
        "invalid_indicators": {
            "cmd": ["cmd", "powershell", "bash", "net user", "useradd", "wmic"],
            "evt": ["4688", "4624"],
            "reason": "Cloud platforms use API operations, not command-line or event log indicators"
        }
    },
    "SaaS": {
        "valid_indicators": {
            "operation": ["create", "delete", "update", "add", "remove"],
            "api": ["api", "oauth", "saml"]
        },
        "invalid_indicators": {
            "cmd": ["cmd", "powershell", "bash", "net user", "useradd"],
            "evt": ["4688", "4624"],
            "reason": "SaaS platforms use API operations"
        }
    }
}


def generate_validation_matrix():
    """Generate validation matrix for all MITRE ATT&CK techniques"""

    print("📥 Loading MITRE ATT&CK Enterprise data...")
    mitre_url = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
    stix_data = get_stix_data(mitre_url)

    # Get technique objects from STIX data
    technique_objects = [obj for obj in stix_data.get("objects", []) if obj.get("type") == "attack-pattern"]

    validation_matrix = {}

    print(f"🔍 Processing {len(technique_objects)} techniques...")

    for technique in technique_objects:
        tech_id = None
        for ref in technique.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                tech_id = ref.get("external_id")
                break

        if not tech_id or not tech_id.startswith("T"):
            continue

        tech_name = technique.get("name", "")
        tech_desc = technique.get("description", "")

        # Get platforms for this technique
        platforms = technique.get("x_mitre_platforms", [])

        # Check if this is a sub-technique
        is_sub_technique = "." in tech_id
        parent_id = tech_id.split(".")[0] if is_sub_technique else None

        # Build validation rules for each platform
        platform_rules = {}
        for platform in platforms:
            if platform in PLATFORM_INDICATORS:
                platform_rules[platform] = PLATFORM_INDICATORS[platform].copy()

        if not platform_rules:
            # No platforms or no rules for platforms, skip
            continue

        # Store in matrix
        if is_sub_technique:
            # Sub-technique
            if parent_id not in validation_matrix:
                # Initialize parent if it doesn't exist
                validation_matrix[parent_id] = {
                    "name": tech_name.rsplit(" -", 1)[0] if " -" in tech_name else tech_name,
                    "sub_techniques": {}
                }

            validation_matrix[parent_id]["sub_techniques"][tech_id] = {
                "name": tech_name,
                "description": tech_desc[:200] + "..." if len(tech_desc) > 200 else tech_desc,
                "platforms": platform_rules
            }
        else:
            # Parent technique
            if tech_id in validation_matrix:
                # Already exists (from sub-technique), update
                validation_matrix[tech_id]["name"] = tech_name
                validation_matrix[tech_id]["description"] = tech_desc[:200] + "..." if len(tech_desc) > 200 else tech_desc
                validation_matrix[tech_id]["platforms"] = platform_rules
            else:
                # New entry
                validation_matrix[tech_id] = {
                    "name": tech_name,
                    "description": tech_desc[:200] + "..." if len(tech_desc) > 200 else tech_desc,
                    "platforms": platform_rules,
                    "sub_techniques": {}
                }

        print(f"  ✅ {tech_id}: {tech_name} ({len(platform_rules)} platforms)")

    # Add metadata
    validation_matrix["_metadata"] = {
        "version": "2.0",
        "generated": "2025-10-29",
        "description": "Auto-generated platform-specific indicator validation for all MITRE ATT&CK Enterprise techniques",
        "usage": "Use this matrix to validate that indicators are appropriate for the technique and platform before generating detections",
        "total_techniques": len(validation_matrix) - 1,  # -1 for _metadata
        "platforms_covered": list(PLATFORM_INDICATORS.keys())
    }

    return validation_matrix


def main():
    """Main function"""
    print("🚀 Generating validation matrix for all MITRE ATT&CK techniques...")

    matrix = generate_validation_matrix()

    output_file = Path(__file__).parent.parent / "archer" / "mappings" / "technique_platform_indicators.json"

    print(f"\n💾 Writing validation matrix to {output_file}...")

    with open(output_file, "w") as f:
        json.dump(matrix, f, indent=2)

    print(f"\n✅ Successfully generated validation matrix!")
    print(f"   - Total techniques: {matrix['_metadata']['total_techniques']}")
    print(f"   - Platforms covered: {', '.join(matrix['_metadata']['platforms_covered'])}")
    print(f"   - File size: {output_file.stat().st_size / 1024:.1f} KB")


if __name__ == "__main__":
    main()
