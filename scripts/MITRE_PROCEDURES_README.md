# MITRE ATT&CK Procedure Examples Extractor

This script extracts procedure examples from the MITRE ATT&CK STIX framework along with associated techniques, tactics, and groups.

## Overview

The script downloads the latest MITRE ATT&CK Enterprise data and extracts:

- **Procedure Examples**: Real-world examples of how threat groups use techniques
- **Techniques**: ATT&CK technique ID, name, and description
- **Tactics**: The tactics associated with each technique
- **Groups**: Threat group ID, name, and description (only groups with IDs starting with "G")

**Note**: This script focuses exclusively on threat actor groups and excludes malware and tools.

## Requirements

- Python 3.7+
- Required packages:
  - `stix2`
  - `requests`

## Installation

If using a virtual environment (recommended):

```bash
source .venv/bin/activate
pip install stix2 requests
```

## Usage

Run the script:

```bash
python3 scripts/extract_mitre_procedures.py
```

The script will:
1. Download the latest MITRE ATT&CK Enterprise STIX data
2. Extract all procedure examples with associated information
3. Save unique combinations to `data/mitre_procedures.csv`

## Output Format

The CSV file contains the following columns (in this order):

| Column | Description |
|--------|-------------|
| `technique_id` | MITRE ATT&CK technique ID (e.g., T1003.001) |
| `technique_name` | Name of the technique |
| `tactic` | The tactic name (e.g., Credential Access, Discovery) |
| `group_id` | MITRE ATT&CK group ID (e.g., G0119) - always starts with "G" |
| `group_name` | Name of the threat group |
| `procedure_example` | The procedure description showing how the technique was used |
| `group_description` | Full description of the threat group |
| `technique_description` | Full description of the technique |

**Sorting**: The data is sorted alphabetically by `technique_id`, then `tactic`, then `group_id`.

## Key Features

- **Groups Only**: Only includes procedures from threat groups (IDs starting with "G"), excluding malware and tools
- **Unique Combinations**: The script ensures only unique combinations of procedure, technique, tactic, and group are included
- **Multiple Tactics**: When a technique has multiple tactics, a separate row is created for each tactic
- **Alphabetical Sorting**: Data is sorted by technique_id, tactic, and group_id for easy navigation
- **Clean Data**: Newlines and carriage returns are removed from descriptions for CSV compatibility

## Example Output

```csv
technique_id,technique_name,tactic,group_id,group_name,procedure_example,group_description,technique_description
T1003.001,LSASS Memory,Credential Access,G0119,Indrik Spider,"Indrik Spider used Cobalt Strike to carry out credential dumping using ProcDump.","Indrik Spider is a Russia-based cybercriminal group...","Adversaries may attempt to access credential material..."
```

## Statistics

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

## Notes

- Only threat groups (IDs starting with "G") are included; malware and tools are excluded
- Techniques can have multiple tactics (kill chain phases), resulting in multiple rows per procedure
- Data is sorted alphabetically by technique_id, then tactic, then group_id
- The script automatically creates the `data/` directory if it doesn't exist

## Data Source

The script downloads data from:
https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json

This is the official MITRE ATT&CK STIX repository.
