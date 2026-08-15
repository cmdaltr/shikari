# Archer Scripts Reference

Complete guide to utility scripts organized by functionality.

For detailed documentation on each category, see:
- **[scripts/README.md](../scripts/README.md)** - Main scripts index
- **[scripts/ai/LOCAL_LLM.md](../scripts/ai/LOCAL_LLM.md)** - AI & LLM scripts
- **[scripts/admin/WEB_APP.md](../scripts/admin/WEB_APP.md)** - Admin scripts
- **[scripts/deployment/DEPLOY.md](../scripts/deployment/DEPLOY.md)** - Deployment scripts
- **[scripts/validation/VALIDATION.md](../scripts/validation/VALIDATION.md)** - Validation scripts
- **[scripts/data/DATA_SCRIPTS.md](../scripts/data/DATA_SCRIPTS.md)** - Data scripts

---

## Quick Reference

### AI & LLM Configuration (`scripts/ai/`)

| Script | Purpose | Usage |
|--------|---------|-------|
| **setup_local_llm.py** | **Auto-configure local LLM based on system RAM** | `python scripts/ai/setup_local_llm.py` |
| **setup_local_llm.sh** | Shell version (Linux/macOS only) | `bash scripts/ai/setup_local_llm.sh` |
| **train_ai.py** | Unified training data collection (CVE, reports, OSINT, custom queries) | `python scripts/ai/train_ai.py <command> [options]` |

**Documentation**: [scripts/ai/LOCAL_LLM.md](../scripts/ai/LOCAL_LLM.md), [docs/ai/](ai/)

---

### Admin & User Management (`scripts/admin/`)

| Script | Purpose | Usage |
|--------|---------|-------|
| **create_admin.py** | Create administrator accounts | `python scripts/admin/create_admin.py` |
| **reset_password.py** | Reset user passwords | `python scripts/admin/reset_password.py <email>` |

**Documentation**: [scripts/admin/WEB_APP.md](../scripts/admin/WEB_APP.md)

---

### Deployment & Operations (`scripts/deployment/`)

| Script | Purpose | Usage |
|--------|---------|-------|
| **docker_entrypoint.py** | Docker container initialization | Automatic (Dockerfile) |
| **start_clean.py** | Fresh start with database reset | `python scripts/deployment/start_clean.py` |
| **kill-archer.py** | Stop all Archer processes | `python scripts/deployment/kill-archer.py` |

**Documentation**: [scripts/deployment/DEPLOY.md](../scripts/deployment/DEPLOY.md)

---

### Validation & Configuration (`scripts/validation/`)

| Script | Purpose | Usage |
|--------|---------|-------|
| **setup_mappings.py** | Configure SIEM field mappings and index names | `python scripts/validation/setup_mappings.py` |
| **verify_schema.py** | Verify schema definitions | `python scripts/validation/verify_schema.py` |
| **analyze_schema_fields.py** | Analyze schema field usage | `python scripts/validation/analyze_schema_fields.py` |
| **generate_validation_matrix.py** | Generate validation reports | `python scripts/validation/generate_validation_matrix.py` |

**Documentation**: [scripts/validation/VALIDATION.md](../scripts/validation/VALIDATION.md)

---

### Data Import & OSINT (`scripts/data/`)

| Script | Purpose | Usage |
|--------|---------|-------|
| **update_osint.py** | Update OSINT detection repositories | `python scripts/data/update_osint.py` |
| **extract_mitre_procedures.py** | Extract MITRE ATT&CK procedures | `python scripts/data/extract_mitre_procedures.py` |
| **import_yaml_to_library.py** | Import YAML detections to library | `python scripts/data/import_yaml_to_library.py <file_or_dir>` |

**Documentation**: [scripts/data/DATA_SCRIPTS.md](../scripts/data/DATA_SCRIPTS.md)

---

## Common Workflows

### Initial Setup

```bash
# 1. Configure local LLM (optional)
python scripts/ai/setup_local_llm.py

# 2. Configure SIEM mappings
python scripts/validation/setup_mappings.py

# 3. Update OSINT data (done automatically by Docker)
python scripts/data/update_osint.py
```

### Regular Maintenance

```bash
# Monthly: Update OSINT repositories
python scripts/data/update_osint.py

# Quarterly: Update MITRE procedures
python scripts/data/extract_mitre_procedures.py

# As needed: Verify schema
python scripts/validation/verify_schema.py
```

### Admin Tasks

```bash
# Create admin user
python scripts/admin/create_admin.py

# Reset user password
python scripts/admin/reset_password.py user@example.com
```

### AI/LLM Tasks

```bash
# Setup local LLM automatically
python scripts/ai/setup_local_llm.py

# Collect training data from CVEs
python scripts/ai/train_ai.py cve --year 2024 --min-cvss 7.0

# Import custom high-fidelity queries
python scripts/ai/train_ai.py custom --import-dir custom_queries/

# Update OSINT training examples
python scripts/ai/train_ai.py osint --all
```

---

## Detailed Script Information

### AI Scripts

#### setup_local_llm.py
**Purpose**: Automated local LLM setup that auto-selects the best model based on system RAM.

**Features**:
- Auto-detects available RAM (or accepts manual input)
- Recommends optimal model (llama3.1:70b for 64GB+, llama3.1:8b for 16GB+, etc.)
- Installs Ollama if needed (Linux/macOS)
- Downloads selected model
- Configures Archer `.env` file
- Verifies setup works

**Examples**:
```bash
# Auto-detect and configure
python scripts/ai/setup_local_llm.py

# Specify RAM manually
python scripts/ai/setup_local_llm.py --ram 32

# Non-interactive mode
python scripts/ai/setup_local_llm.py --yes
```

**Full documentation**: [scripts/ai/LOCAL_LLM.md](../scripts/ai/LOCAL_LLM.md)

---

#### train_ai.py
**Purpose**: Unified training data collection for AI model fine-tuning.

**Commands**:
- `cve` - Enrich CVE data with blog posts and analysis
- `reports` - Convert PDF threat reports to JSON
- `osint` - Extract detection rules from OSINT repositories
- `custom` - Import custom high-fidelity detection queries

**Examples**:
```bash
# CVE enrichment
python scripts/ai/train_ai.py cve --year 2024 --min-cvss 7.0 --limit 50

# Convert threat reports
python scripts/ai/train_ai.py reports --dir threat_reports/

# Extract OSINT rules
python scripts/ai/train_ai.py osint --all

# Import custom queries
python scripts/ai/train_ai.py custom --import queries.json
```

**Full documentation**: [docs/ai/TRAIN_AI.md](ai/TRAIN_AI.md)

---

### Admin Scripts

#### create_admin.py
**Purpose**: Create administrator user accounts.

**Interactive prompts**:
- Email address
- Password (with confirmation)

**Example**:
```bash
$ python scripts/admin/create_admin.py
Enter email: admin@company.com
Enter password: ••••••••••••
Confirm password: ••••••••••••
✓ Admin user created
```

---

#### reset_password.py
**Purpose**: Reset user passwords.

**Usage**:
```bash
python scripts/admin/reset_password.py user@company.com
```

---

### Deployment Scripts

#### docker_entrypoint.py
**Purpose**: Docker container initialization script.

**What it does**:
1. Checks if OSINT repositories are initialized
2. Downloads detection rule repositories if needed
3. Starts FastAPI application

**Note**: First run takes 15-20 minutes to download OSINT data.

---

#### start_clean.py
**Purpose**: Fresh start with database reset.

**Warning**: ⚠️ Deletes all data (users, detections, correlations)

**Creates default admin**:
```
Email: admin@archer.app
Password: £missary_0f_the_G0rg0nite$
```

---

### Validation Scripts

#### setup_mappings.py
**Purpose**: Interactive SIEM configuration tool.

**Configures**:
- SIEM platform selection
- Index names
- Field mappings
- Data source configurations

**When to run**:
- Initial setup
- After changing SIEM platforms
- When index names change

---

#### verify_schema.py
**Purpose**: Verify schema definitions and field mappings.

**Checks**:
- Schema files are valid
- Required fields present
- Field types valid
- No circular dependencies

---

#### analyze_schema_fields.py
**Purpose**: Analyze schema field usage across detections.

**Reports**:
- Most commonly used fields
- Unused schema fields
- Coverage by data source
- Field usage statistics

---

#### generate_validation_matrix.py
**Purpose**: Generate validation matrix showing detection coverage.

**Output**: HTML matrix at `reports/validation_matrix.html`

**Includes**:
- Coverage by MITRE tactic
- Platform support breakdown
- Gap analysis

---

### Data Scripts

#### update_osint.py
**Purpose**: Update OSINT detection repositories.

**Updates**:
- Elastic Detection Rules
- Splunk Security Content
- Microsoft Defender queries

**Frequency**: Run monthly or when new rules released.

---

#### extract_mitre_procedures.py
**Purpose**: Rebuild `data/mitre_procedures.csv` and `data/mitre_procedures.xlsx` by running MITRESaw.

**Features**:
- Runs MITRESaw (git submodule at `MITRESaw/`) with flags `-d -E -R`
- MITRESaw extracts all three attribution paths from MITRE ATT&CK STIX data
- Generates a styled XLSX evidence report with atomic indicators and reference material
- Thin wrapper — delegates to `archer.mitre.procedures.run_mitresaw()`

Also runnable as: `python -m archer.mitre.procedures [--output]`

**Output**: `data/mitre_procedures.csv` (12 columns) + `data/mitre_procedures.xlsx`

**Statistics** (ATT&CK v18.1):
- 26,068 unique procedure rows
- 575 unique techniques
- 14 unique tactics
- 172 unique threat groups

---

#### import_yaml_to_library.py
**Purpose**: Import YAML detection files to Archer's library.

**Supported formats**:
- Archer custom YAML
- Splunk savedsearches
- Elastic detection rules

**Examples**:
```bash
# Import single file
python scripts/data/import_yaml_to_library.py detections/my_rule.yml

# Import directory
python scripts/data/import_yaml_to_library.py detections/splunk/
```

---

## Requirements

Most scripts require Python 3.11 (requirements.txt pins torch==2.2.2, incompatible with 3.12+):
```bash
pyenv install 3.11.15
pyenv local 3.11.15
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

Some scripts have additional dependencies noted in their documentation.

---

## Related Documentation

- **[scripts/README.md](../scripts/README.md)** - Main scripts index
- **[docs/ai/](ai/)** - AI documentation
- **[Getting Started](../GETTING_STARTED.md)** - Initial setup
- **[Architecture](architecture/ARCHITECTURE.md)** - System architecture
- **[Docker Deployment](features/DOCKER.md)** - Container deployment
