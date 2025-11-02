# ⚙️ Archer Scripts Directory

This directory contains utility scripts for managing and maintaining Archer.


---

## 📋 Script Categories

### 🛠️ Maintenance & Cleanup

#### 📌 cleanup.py
**Purpose**: Clean up repository temporary files, caches, and build artifacts
**Usage**:
```bash
python scripts/cleanup.py              # Clean repository
python scripts/cleanup.py --dry-run    # Preview what will be deleted
python scripts/cleanup.py --help       # Show help
```bash
**What it cleans**:
- Python cache files (`__pycache__`, `*.pyc`, `*.pyo`)
- Build artifacts (`dist/`, `build/`, `*.egg-info`)
- Testing artifacts (`.pytest_cache`, `.coverage`)
- IDE files (`.DS_Store`, `Thumbs.db`)
- Jupyter checkpoints (`.ipynb_checkpoints`)
- Log files (`*.log`)
- Temporary files (`*.tmp`, `*.swp`)
- SQLite journal files (`*.db-journal`)

**Features**:
- Cross-platform (Windows, macOS, Linux)
- Dry-run mode to preview changes
- Excludes important directories (venv, archer/build, archer/data)
- Colored output

---

#### 📌 start_clean.py / start_clean.sh
**Purpose**: Kill all running Archer servers and start fresh
**Usage**:
```bash
# Cross-platform (Windows, macOS, Linux)
python scripts/start_clean.py

# Unix/macOS only
./scripts/start_clean.sh
```bash
**What it does**:
1. Kills all Python/uvicorn processes
2. Clears Python cache
3. Starts fresh Archer server on port 8000

**⚠️ Warning**: This kills ALL Python processes on your system!

**Windows**: Use the `.py` version for full compatibility

---

### 👤 Admin Management

#### 📌 create_admin.py
**Purpose**: Create a new web admin user
**Usage**:
```bash
python scripts/create_admin.py
```bash
**Interactive prompts**:
- Username
- Password (with confirmation)

---

#### 📌 reset_password.py
**Purpose**: Reset an existing admin user's password
**Usage**:
```bash
python scripts/reset_password.py
```bash
**Interactive prompts**:
- Username
- New password (with confirmation)

---

### 🔍 OSINT Management

#### 📌 update_osint_repos.py
**Purpose**: Clone/update OSINT detection repositories for air-gapped deployments
**Usage**:
```bash
python scripts/update_osint_repos.py          # Update all repos
python scripts/update_osint_repos.py --force  # Force update
```bash

**Repositories managed**:
- SigmaHQ (30MB, 3,065 rules)
- Elastic Security (105MB, 1,504 rules)
- MITRE CAR (5MB, 200+ analytics)
- Splunk Security Content (58MB, 1,930 detections)
- Azure Sentinel (256MB, 1,400+ rules)

**Features**:
- Automatic hourly update checks
- 15-minute timeout for large repos
- Progress display with statistics
- Air-gapped deployment support

**Air-gapped workflow**:
```bash
# On internet-connected machine
python scripts/update_osint_repos.py --force
tar -czf osint_repos.tar.gz data/osint_repos/

# Transfer to air-gapped machine
tar -xzf osint_repos.tar.gz
```bash

**See also**: [../docs/OSINT_ENRICHMENT.md](../docs/OSINT_ENRICHMENT.md)

---

#### 📌 test_osint.py
**Purpose**: Test OSINT enrichment functionality
**Usage**:
```bash
python scripts/test_osint.py
```bash
**What it tests**:
- Repository clones exist
- Search functionality works
- OSINT enrichment integration

---

### 📊 Data Processing

#### 📌 extract_mitre_procedures.py
**Purpose**: Extract procedure examples from MITRE ATT&CK
**Usage**:
```bash
python scripts/extract_mitre_procedures.py
```bash
**Output**: Enriched MITRE data with real-world procedure examples

---

#### 📌 import_training_queries.py
**Purpose**: Import vendor-specific queries for LLM training
**Usage**:
```bash
python scripts/import_training_queries.py
```bash
**What it imports**:
- Splunk queries
- Elastic queries
- Microsoft Sentinel queries
- Other vendor detection formats

---

#### 📌 normalize_schema_splunk.py
**Purpose**: Normalize Splunk schema field names
**Usage**:
```bash
python scripts/normalize_schema_splunk.py
```bash
**What it does**:
- Standardizes field naming conventions
- Maps vendor-specific fields to Archer schema
- Validates field mappings

---

#### 📌 normalize_schema_archer.py / normalize_schema_archer.sh
**Purpose**: Normalize Archer's internal schema
**Usage**:
```bash
# Cross-platform (Windows, macOS, Linux)
python scripts/normalize_schema_archer.py
python scripts/normalize_schema_archer.py --force
python scripts/normalize_schema_archer.py --schema /path/to/schema.json

# Unix/macOS only
./scripts/normalize_schema_archer.sh
./scripts/normalize_schema_archer.sh --force
```bash
**What it does**:
- Applies schema normalization across all vendors
- Updates detection queries with normalized fields
- Can normalize custom schema files

**Windows**: Use the `.py` version for full compatibility

---

### 🔬 Schema Analysis

#### 📌 analyze_schema_fields.py
**Purpose**: Analyze schema field usage across detections
**Usage**:
```bash
python scripts/analyze_schema_fields.py
```bash
**Output**:
- Field frequency statistics
- Vendor coverage analysis
- Unused field identification

---

#### 📌 verify_schema.py
**Purpose**: Comprehensive schema verification (combines duplicate checking + normalization validation)
**Usage**:
```bash
python scripts/verify_schema.py
```bash
**What it verifies**:
1. **Normalization status**: All indexes properly normalized
2. **Duplicate checking**: No duplicate field mappings
3. **Field count analysis**: Reasonable field counts per index
4. **Time evaluation**: All queries have Time field
5. **Rename consistency**: Same source fields map to same targets

**Verification checks**:
|  |
- ✅ No duplicate rename targets within queries
- ✅ Field counts between 5-150 (flags outliers)
- ✅ Consistent rename mappings across indexes

---


---

## 🗂️ Script Organization

```bash
scripts/
├── README.md                           # This file
│
├── Maintenance & Cleanup
│   ├── cleanup.py                      # Repository cleanup (cross-platform)
│   ├── start_clean.py                  # Clean start server (cross-platform)
│   └── start_clean.sh                  # Clean start server (Unix only)
│
├── Admin Management
│   ├── create_admin.py                 # Create admin user
│   └── reset_password.py               # Reset admin password
│
├── OSINT Management
│   ├── update_osint_repos.py           # Update OSINT repositories
│   └── test_osint.py                   # Test OSINT functionality
│
├── Data Processing
│   ├── extract_mitre_procedures.py     # Extract MITRE procedures
│   ├── import_training_queries.py      # Import training data
│   ├── normalize_schema_splunk.py      # Normalize Splunk schema
│   ├── normalize_schema_archer.py      # Normalize Archer schema (cross-platform)
│   └── normalize_schema_archer.sh      # Normalize Archer schema (Unix only)
│
└── Schema Analysis
    ├── analyze_schema_fields.py        # Analyze field usage
    └── verify_schema.py                # Comprehensive schema verification
```bash


---

## 📝 Naming Conventions

All scripts now follow consistent naming:
- **Python scripts**: `lowercase_with_underscores.py`
- **Shell scripts**: `lowercase_with_underscores.sh`
- **No hyphens**: Use underscores instead
- **Descriptive names**: Clear indication of purpose


---

## 🔧 Common Tasks

### 📌 Clean up repository before committing
```bash
python scripts/cleanup.py
git status
```bash

### 👨‍💻 Reset development environment
```bash
./scripts/start_clean.sh
```bash

### 🔧 Create admin user for first-time setup
```bash
python scripts/create_admin.py
```bash

### 📌 Update OSINT repositories weekly
```bash
python scripts/update_osint_repos.py --force
```bash

### 📌 Verify schema integrity after changes
```bash
python scripts/verify_schema.py
```bash


---

## 🚀 Best Practices

1. **Always use --dry-run first** when running cleanup scripts
2. **Back up your database** before running admin password resets
3. **Test OSINT updates** in development before deploying to production
4. **Run schema verification** after any schema modifications
5. **Document any new scripts** you add to this directory


---

## 🆘 Getting Help

For detailed help on any script:
```bash
python scripts/<script_name>.py --help
```bash

For OSINT-specific documentation, see:
- [docs/OSINT_ENRICHMENT.md](../docs/OSINT_ENRICHMENT.md) - Complete OSINT guide with troubleshooting


---

## 📋 Change Log

### 📌 2025-10-25
- Reorganized scripts for better clarity
- Removed duplicates:
  - `repo-cleanup.sh` (Python version is cross-platform)
  - `verify_schema_duplicates.py` (merged into verify_schema.py)
  - `docs/README_OSINT_UPDATE.md` (merged into OSINT_ENRICHMENT.md)
  - `docs/SCRIPTS.md` (consolidated into this file)
- Fixed `import_training_queries.py.py` double extension bug
- Renamed scripts for naming consistency:
  - `repo-cleanup.py` → `cleanup.py`
  - `start_repo-clean.sh` → `start_clean.sh`
  - `create_web-admin.py` → `create_admin.py`
  - `reset_web-admin_password.py` → `reset_admin_password.py`
  - `verify_current_normalization.py` → `verify_schema.py`
  - `reset_admin_password.py` → `reset_password.py`
  - `normalize_splunk_schema.py` → `normalize_schema_splunk.py`
  - `normalize_archer_schema.sh` → `normalize_schema_archer.sh`
- Applied consistent naming convention:
|  |
  - **Documentation**: `CAPITALS_WITH_UNDERSCORES.md` - all caps for visibility
- Created cross-platform Python versions of bash scripts for Windows compatibility:
  - `start_clean.py` (cross-platform alternative to `start_clean.sh`)
  - `normalize_schema_archer.py` (cross-platform alternative to `normalize_schema_archer.sh`)
- Consolidated schema verification into single comprehensive script
- Merged OSINT documentation into single authoritative guide
- Added comprehensive documentation and troubleshooting
