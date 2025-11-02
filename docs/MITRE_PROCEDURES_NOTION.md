# 📝 MITRE ATT&CK Procedure Examples Extractor

This script extracts procedure examples from the MITRE ATT&CK STIX framework along with associated techniques, tactics, and groups.


---

## 📋 Overview

The script downloads the latest MITRE ATT&CK Enterprise data and extracts:

- **Procedure Examples**: Real-world examples of how threat groups use techniques
- **Techniques**: ATT&CK technique ID, name, and description
- **Tactics**: The tactics associated with each technique
- **Groups**: Threat group ID, name, and description (only groups with IDs starting with "G")
- **Software-to-Technique Traversal**: When groups use software (malware/tools), Archer automatically extracts the techniques employed by that software


---

## 📌 Parent Technique to Subtechnique Expansion ⭐ NEW

When a threat group uses a parent technique (e.g., T1136: Create Account), Archer automatically expands to include all relevant subtechniques (T1136.001, T1136.002, T1136.003) and generates detections for each subtechnique that has unique indicators.

**How it works:**
- **Parent Detection**: Generate detection for the parent technique (T1136)
- **Subtechnique Discovery**: Find all subtechniques from MITRE ATT&CK
- **Indicator Analysis**: Compare subtechnique indicators with parent indicators
- **Conditional Generation**: Only create subtechnique detection if indicators are unique
- **Preservation**: Always keep the parent technique detection

**Example:** T1136 (Create Account) expands to:
- T1136: Create Account (parent - always included)
- T1136.001: Local Account (unique indicators: `net user`, `useradd`)
- T1136.002: Domain Account (unique indicators: `dsadd`, `New-ADUser`)
- T1136.003: Cloud Account (unique indicators: `aws iam`, `az ad user`)

**Constraint:** If a group only uses a subtechnique (e.g., T1136.001) **without** the parent, Archer generates **only** that subtechnique detection and does not expand to other subtechniques.

For detailed implementation specifications, see [PARENT_SUBTECHNIQUE_EXPANSION.md](PARENT_SUBTECHNIQUE_EXPANSION.md).


---

## 📌 Software-to-Technique Indicator Extraction

Archer implements **two paths** for indicator extraction when analyzing threat groups:

### 📌 Path 1: Direct Techniques (Traditional)
```bash
Group → Techniques → Procedure Examples → Indicators
```bash
Example: APT29 uses T1059.001 (PowerShell) → Extract PowerShell command indicators

### 📌 Path 2: Software Traversal (Enhanced) ⭐ NEW
```bash
Group → Software (Malware/Tools) → Techniques → Procedure Examples → Indicators
```bash
Example: Scattered Spider uses BlackCat ransomware → BlackCat uses T1083 (File Discovery) → Extract `net use`, `fsutil` commands

**Benefits:**
- **Comprehensive Coverage**: Groups using sophisticated malware generate detections for ALL the malware's techniques
- **Actionable Indicators**: Instead of detecting "BlackCat" as a string, detect the specific commands it runs (`fsutil behavior set`, `vssadmin delete`)
- **Automatic Updates**: As MITRE adds techniques to software profiles, detections automatically include them
- **Deduplication**: Automatically removes duplicate indicators when both group and software use the same technique

**Example:** For Scattered Spider + BlackCat:
- Direct indicators: `net user`, `Get-ADUser` (from group's techniques)
- Software indicators: `net use`, `fsutil`, `vssadmin`, `bcdedit` (from BlackCat's techniques)
- Final detection includes ALL indicators with duplicates removed


---

## 📋 Requirements

- Python 3.7+
- Required packages:
  - `stix2`
  - `requests`


---

## ⚙️ Installation

If using a virtual environment (recommended):

```bash
source .venv/bin/activate
pip install stix2 requests
```bash


---

## 💻 Usage

Run the script:

```bash
python3 scripts/extract_mitre_procedures.py
```bash

The script will:
1. Download the latest MITRE ATT&CK Enterprise STIX data
2. Extract all procedure examples with associated information
3. Save unique combinations to `data/mitre_procedures.csv`


---

## 📌 Output Format

The CSV file contains the following columns (in this order):

| Column | Description |
| -------- | ------------- |
| `technique_id` | MITRE ATT&CK technique ID (e.g., T1003.001) |
| `technique_name` | Name of the technique |
| `tactic` | The tactic name (e.g., Credential Access, Discovery) |
| `group_id` | MITRE ATT&CK group ID (e.g., G0119) - always starts with "G" |
| `group_name` | Name of the threat group |
| `procedure_example` | The procedure description showing how the technique was used |
| `group_description` | Full description of the threat group |
| `technique_description` | Full description of the technique |

**Sorting**: The data is sorted alphabetically by `technique_id`, then `tactic`, then `group_id`.


---

## ✨ Key Features

- **Groups Only**: Only includes procedures from threat groups (IDs starting with "G"), excluding malware and tools
- **Unique Combinations**: The script ensures only unique combinations of procedure, technique, tactic, and group are included
- **Multiple Tactics**: When a technique has multiple tactics, a separate row is created for each tactic
- **Alphabetical Sorting**: Data is sorted by technique_id, tactic, and group_id for easy navigation
- **Clean Data**: Newlines and carriage returns are removed from descriptions for CSV compatibility


---

## 📌 Example Output

```csv
technique_id,technique_name,tactic,group_id,group_name,procedure_example,group_description,technique_description
T1003.001,LSASS Memory,Credential Access,G0119,Indrik Spider,"Indrik Spider used Cobalt Strike to carry out credential dumping using ProcDump.","Indrik Spider is a Russia-based cybercriminal group...","Adversaries may attempt to access credential material..."
```bash


---

## 📌 Statistics

The script provides summary statistics including:
- Total unique procedure combinations
- Number of unique techniques
- Number of unique tactics
- Number of unique threat groups

Recent extraction yielded:
- **4,840** unique procedure combinations
- **458** unique techniques
- **14** unique tactics
- **162** unique threat groups


---

## 📌 Notes

- Only threat groups (IDs starting with "G") are included; malware and tools are excluded
- Techniques can have multiple tactics (kill chain phases), resulting in multiple rows per procedure
- Data is sorted alphabetically by technique_id, then tactic, then group_id
- The script automatically creates the `data/` directory if it doesn't exist


---

## 📌 Data Source

The script downloads data from:
https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json

This is the official MITRE ATT&CK STIX repository.
