# Scripts Directory

Utility scripts for managing, testing, and analyzing Archer functionality.

## Maintenance Scripts

### cleanup.sh / cleanup.py

Clean up temporary files, caches, and build artifacts from the repository.

**Purpose**: Remove Python cache files, build artifacts, test caches, IDE files, and other temporary files.

**Usage (Bash)**:
```bash
# Preview what will be deleted
./scripts/cleanup.sh --dry-run

# Actually clean up files
./scripts/cleanup.sh
```

**Usage (Python - cross-platform)**:
```bash
# Preview what will be deleted
python3 scripts/cleanup.py --dry-run

# Actually clean up files
python3 scripts/cleanup.py

# Disable colored output
python3 scripts/cleanup.py --no-color
```

**What gets cleaned**:
- Python cache (`__pycache__`, `*.pyc`, `*.pyo`)
- Build artifacts (`dist/`, `build/`, `*.egg-info`)
- Test caches (`.pytest_cache`, `.coverage`)
- IDE files (`.DS_Store`, `Thumbs.db`)
- Log files (`*.log`)
- Temporary files (`*.tmp`, `*.swp`, `*~`)
- SQLite journal files

**Note**: Both scripts do the same thing - use `.sh` on Unix/Mac or `.py` for cross-platform support.

### create_admin.py

Create a new admin user for Archer.

**Usage**:
```bash
python3 scripts/create_admin.py
```

Prompts for:
- Email address
- Full name
- Password (with confirmation)

### reset_admin_password.py

Reset an existing admin user's password.

**Usage**:
```bash
python3 scripts/reset_admin_password.py
```

### start_clean.sh

Start Archer with a clean environment (clears logs and caches).

**Usage**:
```bash
./scripts/start_clean.sh
```

## Testing Scripts

### Available Scripts

### genai_smoke_test.py

Smoke test for GenAI correlation generation.

**Purpose**: Test the GenAI correlation engine with sample YAML files.

**Usage**:
```bash
# Run with heuristic mode (default)
python3 scripts/genai_smoke_test.py

# Run with local LLM mode (requires llama-cpp-python and model)
export GENAI_MODE=local_llm
export LLAMA_MODEL_PATH=/path/to/model.bin
python3 scripts/genai_smoke_test.py
```

**Output**: Creates `data/correlate/smoke_test.json` with correlation results.

**Requirements**:
- Sample YAML files in `data/samples/`
- Optional: `llama-cpp-python` for local LLM mode

### summarize_smoke_json.py

Summarize and validate GenAI correlation output.

**Purpose**: Analyze correlation JSON files and display summary statistics.

**Usage**:
```bash
# Summarize default smoke test output
python3 scripts/summarize_smoke_json.py

# Summarize specific file
python3 scripts/summarize_smoke_json.py data/correlate/custom_test.json
```

**Output**: Displays:
- Number of vendor correlations
- Number of cross-vendor correlations
- Example correlations with reasoning
- Schema validation results (if jsonschema installed)

**Optional Dependency**:
```bash
pip install jsonschema  # For schema validation
```

## Running Tests Instead

For comprehensive testing, use pytest:

```bash
# Run all tests
pytest tests/ -v

# Run specific test file
pytest tests/test_api_endpoints.py -v

# Run with coverage
pytest tests/ --cov=archer --cov-report=html
```

## Archived Scripts

Previously, this directory contained duplicate testing scripts that have been removed:
- `debug_templates.py` - Template validation (now in `tests/test_templates.py`)
- `debug_endpoints.py` - Endpoint smoke tests (now in `tests/test_api_endpoints.py`)
- `run_debug_checks.sh` - Test runner wrapper (use `pytest` directly)

These were consolidated into the proper pytest test suite in `/tests/`.
