# Data Scripts

Data import, OSINT repository management, and MITRE ATT&CK data extraction utilities.

## Scripts

### update_osint.py
Clone/update the OSINT detection rule repositories.

**Usage**:
```bash
python scripts/data/update_osint.py
```

**What it updates**:
- **Elastic Detection Rules**
- **Splunk Security Content**
- **Azure Sentinel** detection rules

**Process**:
1. Clones each repo (shallow, `--depth 1`) or pulls if already cloned
2. Writes a `.last_update` timestamp per repo

This script only fetches the repos — it doesn't build the technique index (see
`build_osint_index.py` below). Standalone/stdlib-only by design so it can run
in air-gapped environments (see the script's own docstring).

**Frequency**:
- Initial setup: Automatic (via Docker entrypoint)
- Updates: Run monthly or when new rules are released

**Example**:
```bash
$ python scripts/data/update_osint.py
Updating OSINT repositories...
✓ elastic repository ready
✓ splunk repository ready
```

---

### build_osint_index.py
Build the prebuilt MITRE ATT&CK technique → OSINT rule index.

**Usage**:
```bash
python scripts/data/build_osint_index.py               # update repos, then build
python scripts/data/build_osint_index.py --skip-clone   # build from what's already on disk
```

**What it does**:
- Walks every cloned OSINT repo (Elastic, Splunk, Azure Sentinel)
  once, extracting every technique ID mentioned in every rule file
- Writes `data/cache/osint_technique_index.json`: `{technique_id: {source: [{name, source_url, query_snippet}, ...]}}`

Without this index, `archer/build/osint_comparison.py` searches live on every
OSINT comparison call — a `grep -r` subprocess per technique per repo. With the
index built, those same lookups become a single dict access. The comparison
functions fall back to the old live search automatically if the index hasn't
been built yet, so this is optional but strongly recommended.

**Frequency**: Run after `update_osint.py`, or on the same schedule — the
index doesn't regenerate itself when the repos change.

---

### extract_mitre_procedures.py
Extract and process MITRE ATT&CK procedures.

**Usage**:
```bash
python scripts/data/extract_mitre_procedures.py
```

**What it does**:
- Runs MITRESaw (included as a git submodule at `MITRESaw/`) with flags `-d -E -R`
- MITRESaw downloads latest MITRE ATT&CK STIX data and extracts all three attribution paths
- Generates a styled XLSX evidence report with atomic indicators and reference material
- Copies output to `data/mitre_procedures.csv` and `data/mitre_procedures.xlsx`

Delegates to `archer.mitre.procedures.run_mitresaw()` — this script is a thin CLI wrapper.
Can also be run as: `python -m archer.mitre.procedures`

**Output**: `data/mitre_procedures.csv` (12 columns) + `data/mitre_procedures.xlsx`

**Use cases**:
- Generating threat-informed detections
- Understanding technique usage by threat groups
- Prioritizing detection development

---

### import_yaml_to_library.py
Import YAML detection files to Archer's detection library.

**Usage**:
```bash
python scripts/data/import_yaml_to_library.py <file_or_directory>
```

**Supported formats**:
- Custom Archer YAML format
- Splunk savedsearches format
- Elastic detection rule format

**Arguments**:
- `<file_or_directory>` - Single YAML file or directory of YAML files

**Example**:
```bash
# Import single file
python scripts/data/import_yaml_to_library.py detections/my_detection.yml

# Import directory
python scripts/data/import_yaml_to_library.py detections/splunk_rules/

# Import with specific platform
python scripts/data/import_yaml_to_library.py --platform splunk detections/
```

**YAML Format Example**:
```yaml
title: Suspicious PowerShell Download
id: a1b2c3d4-e5f6-7890-abcd-ef1234567890
status: stable
description: Detects PowerShell downloading files from the internet
author: Security Team
date: 2024/01/15
modified: 2024/01/20
mitre:
  - technique: T1059.001
    tactic: Execution
platform: windows
data_source: ProcessEvents
query: |
  DeviceProcessEvents
  | where FileName =~ "powershell.exe"
  | where ProcessCommandLine has_any ("DownloadFile", "IEX", "Invoke-WebRequest")
false_positive_rate: low
severity: high
```

---

## Workflows

### Initial Setup

```bash
# 1. Update OSINT repositories (done automatically by Docker)
python scripts/data/update_osint.py

# 2. Extract MITRE procedures
python scripts/data/extract_mitre_procedures.py
```

### Regular Updates

```bash
# Monthly: Update OSINT rules
python scripts/data/update_osint.py

# Quarterly: Update MITRE data
python scripts/data/extract_mitre_procedures.py
```

### Importing Custom Detections

```bash
# Import your team's custom detections
python scripts/data/import_yaml_to_library.py custom_detections/

# Import detections from another source
python scripts/data/import_yaml_to_library.py external_detections/
```

### After Major MITRE ATT&CK Updates

```bash
# 1. Update MITRE procedures
python scripts/data/extract_mitre_procedures.py

# 2. Regenerate validation matrix
python scripts/validation/generate_validation_matrix.py

# 3. Update OSINT rules (they may reference new techniques)
python scripts/data/update_osint.py
```

## Data Locations

**OSINT Repositories**:
```
data/external/repos/
├── elastic/detection_rules/  # elastic/detection-rules
└── splunk/security_content/  # splunk/security_content
```

**Processed Data**:
```
data/
├── mitre_procedures.csv      # Extracted procedures (generated by MITRESaw, 12 columns)
├── mitre_procedures.xlsx     # Styled evidence report (generated by MITRESaw)
├── osint_index.json          # Indexed OSINT rules
└── attack_data.json          # MITRE ATT&CK data
```

**Imported Detections**:
```
data/library/
├── custom/
└── imported/
```

## Related Documentation

- [OSINT Integration](../../docs/features/OSINT_INTEGRATION.md)
- [Data Architecture](../../docs/architecture/ARCHITECTURE.md)
- [Detection Validation](../../docs/features/DETECTION_VALIDATION.md)
