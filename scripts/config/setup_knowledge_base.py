#!/usr/bin/env python3
"""
Setup script for Knowledge Base directory structure.

This script initializes the directory structure and creates
necessary files for the RAG-based fidelity enhancement system.
"""

import os
import sys
from pathlib import Path
import json

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))


def create_directory_structure():
    """Create all necessary directories for the knowledge base."""

    base_dir = Path("data/external/detections")

    directories = [
        # Main KB directories
        base_dir / "detection_examples",
        base_dir / "field_mappings",
        base_dir / "false_positive_patterns",
        base_dir / "embeddings",

        # Tactic subdirectories
        base_dir / "detection_examples" / "credential_access",
        base_dir / "detection_examples" / "execution",
        base_dir / "detection_examples" / "persistence",
        base_dir / "detection_examples" / "privilege_escalation",
        base_dir / "detection_examples" / "defense_evasion",
        base_dir / "detection_examples" / "discovery",
        base_dir / "detection_examples" / "lateral_movement",
        base_dir / "detection_examples" / "collection",
        base_dir / "detection_examples" / "exfiltration",
        base_dir / "detection_examples" / "command_and_control",
        base_dir / "detection_examples" / "initial_access",
        base_dir / "detection_examples" / "impact",
        base_dir / "detection_examples" / "reconnaissance",
        base_dir / "detection_examples" / "resource_development",

        # Validation directories
        Path("data/validation/test_samples"),
        Path("data/validation/validation_results"),

        # External repositories
        Path("data/external"),

        # ML Training
        Path("data/ml_training"),
    ]

    for directory in directories:
        directory.mkdir(parents=True, exist_ok=True)
        print(f"✓ Created: {directory}")


def create_readme():
    """Create README for knowledge base."""

    readme_content = """# Detection Knowledge Base

This directory contains the curated knowledge base for RAG-based detection enhancement.

## Structure

### detection_examples/
High-quality detection examples organized by MITRE ATT&CK tactic.

Each example is a YAML file with:
- Technique ID and name
- Platform (Splunk, MDE, Elastic, etc.)
- Detection query
- Fidelity score
- Validation data
- False positive patterns
- Data source requirements

### field_mappings/
Platform-specific field catalogs that define available fields in each data source.

Format: JSON files with field names, types, aliases, and population statistics.

### false_positive_patterns/
Known false positive patterns to exclude from detections.

Includes:
- Legitimate administrative tools
- Vendor processes
- Common noise sources

### embeddings/
Vector embeddings for similarity search in RAG system.

Files:
- vector_store.faiss: FAISS index with embeddings
- metadata.json: Mapping of vector indices to detection files

## Adding Examples

To add a new detection example:

```bash
python scripts/add_to_kb.py \\
  --technique T1003.001 \\
  --platform splunk \\
  --query-file my_detection.yaml \\
  --fidelity-score 0.90
```

Or manually create a YAML file in the appropriate tactic directory:

```yaml
technique_id: T1003.001
technique_name: "LSASS Memory Dump"
platform: Splunk
fidelity_score: 0.95
validated: true

query: |
  index=windows EventCode=10
  TargetImage="*\\\\lsass.exe"
  | stats count by SourceImage, GrantedAccess

explanation: |
  Detects access to LSASS memory

data_sources:
  - Windows Security Event Log (Event ID 10)
```

## Importing Community Rules

```bash
# Import Splunk Security Content
python scripts/config/import_community_rules.py --source splunk

# Import all sources
python scripts/config/import_community_rules.py --all
```

## Maintenance

### Update Community Repositories

```bash
cd data/external/splunk && git pull
python scripts/config/import_community_rules.py --source splunk --update
```

### Rebuild Embeddings

```bash
python scripts/config/build_embeddings.py --incremental
```

### Check Statistics

```bash
python scripts/kb_stats.py
```

---

For more information, see [FIDELITY_IMPLEMENTATION_GUIDE.md](../../FIDELITY_IMPLEMENTATION_GUIDE.md)
"""

    readme_path = Path("data/external/detections/README.md")
    with open(readme_path, 'w') as f:
        f.write(readme_content)

    print(f"✓ Created: {readme_path}")


def create_sample_field_mapping():
    """Create a sample field mapping file."""

    sample_mapping = {
        "platform": "Splunk",
        "index": "windows_security",
        "sourcetype": "WinEventLog:Security",
        "description": "Windows Security Event Logs via Splunk",
        "fields": [
            {
                "name": "EventCode",
                "type": "integer",
                "description": "Windows Event ID",
                "common_values": [4688, 4689, 4624, 4625, 4672, 5140, 4698, 4702],
                "population": 1.0,
                "required": True
            },
            {
                "name": "CommandLine",
                "type": "string",
                "description": "Process command line arguments",
                "aliases": ["Process_CommandLine", "ProcessCommandLine"],
                "population": 0.95,
                "required": False
            },
            {
                "name": "SourceImage",
                "type": "string",
                "description": "Path to source process executable",
                "aliases": ["Image", "ProcessName", "ParentProcessName"],
                "population": 0.98,
                "required": False
            },
            {
                "name": "TargetImage",
                "type": "string",
                "description": "Path to target process executable",
                "aliases": ["TargetFilename"],
                "population": 0.90,
                "required": False
            },
            {
                "name": "GrantedAccess",
                "type": "string",
                "description": "Access rights granted to process",
                "population": 0.85,
                "required": False
            },
            {
                "name": "User",
                "type": "string",
                "description": "User account associated with event",
                "aliases": ["Account_Name", "SubjectUserName", "TargetUserName"],
                "population": 0.99,
                "required": False
            }
        ],
        "validation_date": "2024-11-28",
        "sample_count": 1000000,
        "notes": "Sample field mapping - update with your actual field names"
    }

    mapping_path = Path("data/external/detections/field_mappings/splunk_windows_security_sample.json")
    with open(mapping_path, 'w') as f:
        json.dump(sample_mapping, f, indent=2)

    print(f"✓ Created: {mapping_path}")


def create_sample_fp_patterns():
    """Create sample false positive pattern file."""

    sample_fp = {
        "name": "Legitimate Administrative Tools",
        "description": "Common administrative tools that may trigger false positives",
        "patterns": [
            {
                "category": "Process Access",
                "description": "Legitimate security software accessing LSASS",
                "processes": [
                    "MsMpEng.exe",
                    "MsSense.exe",
                    "CrowdStrike\\\\CSFalconService.exe",
                    "SentinelOne\\\\SentinelAgent.exe",
                    "Tanium\\\\TaniumClient.exe"
                ],
                "applies_to": ["T1003.001", "T1003.002"]
            },
            {
                "category": "System Processes",
                "description": "Windows system processes",
                "processes": [
                    "wininit.exe",
                    "services.exe",
                    "csrss.exe",
                    "svchost.exe",
                    "lsass.exe"
                ],
                "applies_to": ["T1003.*", "T1055.*"]
            },
            {
                "category": "Monitoring Tools",
                "description": "Legitimate monitoring and management tools",
                "processes": [
                    "procexp.exe",
                    "procexp64.exe",
                    "ProcessHacker.exe",
                    "taskmgr.exe"
                ],
                "note": "May be legitimate in some environments",
                "confidence": "medium"
            }
        ],
        "updated": "2024-11-28"
    }

    fp_path = Path("data/external/detections/false_positive_patterns/legitimate_admin_tools.json")
    with open(fp_path, 'w') as f:
        json.dump(sample_fp, f, indent=2)

    print(f"✓ Created: {fp_path}")


def create_sample_detection():
    """Create a sample detection example."""

    sample_detection = """technique_id: T1003.001
technique_name: "OS Credential Dumping: LSASS Memory"
tactic: credential_access
platform: Splunk
connectorId: Splunk
fidelity_score: 0.92
validated: true
false_positive_rate: low
source: manual_sample

query: |
  index=windows sourcetype=WinEventLog:Security EventCode=10
  TargetImage="*\\\\lsass.exe"
  (GrantedAccess=0x1010 OR GrantedAccess=0x1410 OR GrantedAccess=0x1438 OR GrantedAccess=0x143a)
  | where NOT match(SourceImage, "(?i)(wininit|services|csrss|svchost|vmtoolsd|vssvc|MsMpEng|MsSense)")
  | stats count by _time, Computer, SourceImage, SourceProcessId, TargetImage, GrantedAccess, User
  | where count > 0

explanation: |
  This detection identifies processes accessing LSASS memory with specific access rights commonly
  used for credential dumping. It filters out known legitimate system processes and security software.

  The specific GrantedAccess values indicate:
  - 0x1010: PROCESS_QUERY_INFORMATION | PROCESS_VM_READ
  - 0x1410: PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_DUP_HANDLE
  - 0x1438: Multiple flags including memory read operations
  - 0x143a: Extended memory access rights

  Common attack tools that trigger this:
  - Mimikatz (sekurlsa::logonpasswords)
  - Procdump (procdump -ma lsass.exe)
  - Comsvcs.dll (rundll32 with minidump)
  - Custom credential dumpers

indicators:
  - type: target_process
    value: lsass.exe
    confidence: high
    description: "LSASS is the primary target for credential dumping"

  - type: access_rights
    values: ["0x1010", "0x1410", "0x1438", "0x143a"]
    confidence: high
    description: "Specific access rights used for memory reading"

false_positives:
  - description: "Security software scanning LSASS"
    processes: ["MsMpEng.exe", "MsSense.exe", "CrowdStrike"]
    mitigation: "Already excluded in query"

  - description: "Legitimate administrative tools"
    processes: ["Process Explorer", "Process Hacker"]
    mitigation: "May require additional filtering based on environment"

  - description: "Windows system maintenance"
    processes: ["services.exe", "svchost.exe"]
    mitigation: "Already excluded in query"

data_sources:
  - name: Windows Security Event Log
    event_id: 10
    event_name: "ProcessAccess"
    required_fields:
      - TargetImage
      - SourceImage
      - GrantedAccess
      - SourceProcessId
    optional_fields:
      - User
      - CallTrace
    log_source: "Sysmon or equivalent process monitoring"
    notes: "Requires Sysmon or Windows Defender ATP for Event ID 10"

validation:
  tested_on:
    - "Windows 10 21H2"
    - "Windows 11 22H2"
    - "Windows Server 2019"
    - "Windows Server 2022"

  test_date: "2024-11-15"

  test_results:
    true_positives: 47
    false_positives: 3
    false_negatives: 2
    precision: 0.94
    recall: 0.96
    f1_score: 0.95

  tested_tools:
    - "Mimikatz 2.2.0"
    - "Procdump v10.11"
    - "Custom dumper"

attack_scenarios:
  - name: "Mimikatz Credential Dump"
    description: "Attacker runs Mimikatz to dump credentials from LSASS"
    steps:
      - "Attacker obtains local admin privileges"
      - "Downloads and executes mimikatz.exe"
      - "Runs 'sekurlsa::logonpasswords' command"
      - "LSASS memory is accessed with 0x1410 rights"
    detection_rate: "100%"

  - name: "Procdump LSASS Dump"
    description: "Using Windows Sysinternals Procdump to dump LSASS"
    steps:
      - "Attacker uses legitimate Windows tool"
      - "Executes 'procdump -ma lsass.exe dump.dmp'"
      - "LSASS memory is accessed"
    detection_rate: "100%"

  - name: "Comsvcs.dll Minidump"
    description: "Native Windows DLL used to dump LSASS"
    steps:
      - "Attacker uses rundll32.exe"
      - "Executes comsvcs.dll MiniDump function"
      - "LSASS is dumped to disk"
    detection_rate: "95%"

response_actions:
  - priority: critical
    action: "Isolate endpoint immediately"
  - priority: high
    action: "Review LSASS dump file if created"
  - priority: high
    action: "Check for credential reuse across network"
  - priority: medium
    action: "Review source process for IOCs"
  - priority: medium
    action: "Check for lateral movement from affected host"

related_techniques:
  - T1003.002: "Security Account Manager"
  - T1003.003: "NTDS"
  - T1003.004: "LSA Secrets"
  - T1055: "Process Injection"
  - T1134: "Access Token Manipulation"

references:
  - https://attack.mitre.org/techniques/T1003/001/
  - https://jpcertcc.github.io/ToolAnalysisResultSheet/
  - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1003.001/T1003.001.md
  - https://docs.microsoft.com/en-us/sysinternals/downloads/procdump

metadata:
  created_by: "Shikari Setup Script"
  created_date: "2024-11-28"
  updated_date: "2024-11-28"
  version: "1.0"
  tags:
    - credential-access
    - lsass
    - memory-dump
    - windows
    - high-fidelity
"""

    detection_path = Path("data/external/detections/detection_examples/credential_access/T1003.001_lsass_dump_splunk_sample.yaml")
    with open(detection_path, 'w') as f:
        f.write(sample_detection)

    print(f"✓ Created: {detection_path}")


def create_gitkeep_files():
    """Create .gitkeep files in empty directories."""

    directories = [
        "data/external/detections/embeddings",
        "data/validation/test_samples",
        "data/validation/validation_results",
        "data/ml_training"
    ]

    for directory in directories:
        gitkeep_path = Path(directory) / ".gitkeep"
        gitkeep_path.touch()
        print(f"✓ Created: {gitkeep_path}")


def main():
    """Main setup function."""

    print("=" * 70)
    print("Knowledge Base Setup Script")
    print("=" * 70)
    print()

    print("Creating directory structure...")
    create_directory_structure()
    print()

    print("Creating README and documentation...")
    create_readme()
    print()

    print("Creating sample files...")
    create_sample_field_mapping()
    create_sample_fp_patterns()
    create_sample_detection()
    print()

    print("Creating .gitkeep files...")
    create_gitkeep_files()
    print()

    print("=" * 70)
    print("✓ Knowledge Base setup complete!")
    print("=" * 70)
    print()
    print("Next steps:")
    print("  1. Clone community detection repositories:")
    print("     cd data/external")
    print("     git clone https://github.com/splunk/security_content.git")
    print()
    print("  2. Import community rules:")
    print("     python scripts/config/import_community_rules.py --all")
    print()
    print("  3. Build vector embeddings:")
    print("     python scripts/config/build_embeddings.py")
    print()
    print("See FIDELITY_IMPLEMENTATION_GUIDE.md for detailed instructions.")
    print()


if __name__ == "__main__":
    main()
