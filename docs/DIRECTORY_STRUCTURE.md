# Archer Directory Structure

This document explains the organization of directories in the Archer project, particularly the separation between **static data** and **runtime outputs**.

## Overview

Archer uses a clear separation between:
- **Static data and code**: Stored in `archer/` (the Python module)
- **Runtime outputs**: Stored in `data/` (project root)

## Directory Layout

```
/archer/                              # Project root
│
├── archer/                           # Python module (installed package)
│   ├── build/                        # Query building logic
│   ├── emulation/                    # Emulation Python code
│   │   ├── atomic.py                 # Atomic Red Team integration
│   │   ├── enrich.py                 # Evidence enrichment
│   │   ├── parser.py                 # Result parsing
│   │   └── remote.py                 # Remote execution
│   │
│   ├── data/                         # Static/reference data
│   │   ├── cache/                    # Cached external data
│   │   │   ├── .gitkeep              # Preserves directory structure
│   │   │   └── enterprise-attack.json # MITRE ATT&CK data (43MB, cached for 7 days)
│   │   │
│   │   └── emulation/                # Emulation reference data
│   │       ├── .gitkeep
│   │       └── atomic-red-team/      # Atomic Red Team framework (git submodule)
│   │           ├── atomics/          # Test definitions
│   │           └── atomic_red_team/  # Ruby/Python modules
│   │
│   ├── mitre/                        # MITRE ATT&CK utilities
│   ├── parsers/                      # File intelligence parsers
│   ├── genai/                        # GenAI correlation
│   └── app.py                        # FastAPI web application
│
├── data/                             # Runtime outputs (gitignored except examples)
│   ├── correlate/                    # GenAI correlation results
│   │   ├── .gitkeep
│   │   └── *.json                    # Correlation analysis (gitignored)
│   │
│   ├── emulation/                    # Emulation execution results
│   │   ├── .gitkeep
│   │   ├── *.json                    # Test execution results (gitignored)
│   │   └── evidence/                 # Collected evidence
│   │       └── .gitkeep
│   │
│   ├── generate/                     # Generated detection rules
│   │   ├── .gitkeep
│   │   └── *.yaml                    # YAML detection rules (gitignored)
│   │
│   ├── hunt/                         # Hunt packages
│   │   ├── .gitkeep
│   │   └── *.yaml                    # Hunt packages (gitignored)
│   │
│   ├── progress/                     # Progress tracking for long-running tasks
│   │   ├── .gitkeep
│   │   └── *.json                    # Progress files (gitignored)
│   │
│   ├── uploads/                      # Uploaded threat intelligence files
│   │   └── (temporary storage)
│   │
│   └── vectr/                        # VECTR integration outputs
│       ├── .gitkeep
│       ├── campaigns/
│       ├── exports/
│       └── *.json                    # VECTR data (gitignored)
│
├── templates/                        # HTML templates for web UI
├── tests/                            # Test suite
│   ├── test_ui_tabs.py              # Playwright UI tests
│   ├── test_ui_upload.py            # File upload tests
│   └── TEST_DOCUMENTATION.md        # Test documentation
│
└── scripts/                          # Helper scripts
    └── download_mitre_data.sh       # Pre-download MITRE data to cache
```

## Why Two "data" Directories?

### `archer/data/` - Static Reference Data
- **Purpose**: Store external reference data that the application needs to function
- **Contents**:
  - MITRE ATT&CK cache
  - Atomic Red Team framework
- **Version Control**: Directory structure tracked, contents gitignored
- **Lifecycle**: Persists across runs, rarely changes

### `data/` - Runtime Outputs
- **Purpose**: Store generated files, results, and temporary data
- **Contents**:
  - Generated detection queries
  - Emulation test results
  - Correlation analyses
  - Progress tracking files
- **Version Control**: Fully gitignored (except .gitkeep files)
- **Lifecycle**: Created during execution, can be deleted/regenerated

## Why Two "emulation" Directories?

### `archer/emulation/` - Python Code
- **Purpose**: Python modules for emulation functionality
- **Contents**: `.py` files with logic for running tests
- **Type**: Source code

### `archer/data/emulation/` - Static Data
- **Purpose**: Store Atomic Red Team framework (external git repo)
- **Contents**: `atomic-red-team/` git submodule
- **Type**: Reference data

### `data/emulation/` - Runtime Outputs
- **Purpose**: Store emulation test execution results
- **Contents**: JSON files with test results, evidence collected
- **Type**: Generated output

## Key Design Principles

1. **Separation of Concerns**: Code, static data, and runtime outputs are clearly separated
2. **Clean Git History**: Runtime outputs don't pollute git history
3. **Self-Contained**: All application data within project boundaries
4. **Reproducible**: Delete `data/` and regenerate from scratch
5. **Portable**: Move/copy project without losing static references

## Cache Management

The MITRE ATT&CK cache (`archer/data/cache/enterprise-attack.json`):
- **Size**: ~43MB
- **Lifetime**: 7 days
- **Refresh**: Automatic when expired, or run `./scripts/download_mitre_data.sh`
- **Offline**: Falls back to stale cache if network unavailable
- **Benefits**: Faster startup, works offline, reduces network dependency

## Common Operations

### Clear all runtime outputs:
```bash
rm -rf data/*/*.json data/*/*.yaml
# Preserves directory structure via .gitkeep files
```

### Refresh MITRE cache:
```bash
./scripts/download_mitre_data.sh
```

### Clean emulation results:
```bash
rm -rf data/emulation/*.json data/emulation/evidence/*
```

### Check cache age:
```bash
ls -lh archer/data/cache/enterprise-attack.json
```

## For Developers

When adding new features:
- **Python code** → `archer/`
- **Static/reference data** → `archer/data/`
- **Runtime outputs** → `data/`
- **Tests** → `tests/`
- **Scripts** → `scripts/`

Always create `.gitkeep` files in new directories under `data/` to preserve structure.

## Troubleshooting

**"Application startup failed - MITRE data not found"**
- Run: `./scripts/download_mitre_data.sh`
- Check: `ls -lh archer/data/cache/`

**"Too many generated files"**
- Clean up: `rm -rf data/generate/*.yaml`
- Old files don't affect functionality

**"Emulation tests not found"**
- Check: `ls archer/data/emulation/atomic-red-team/atomics/`
- If missing: `git submodule update --init --recursive`

---

**Last Updated**: 2025-10-11
**Related Docs**:
- [TEST_DOCUMENTATION.md](tests/TEST_DOCUMENTATION.md) - Test suite documentation
- [README.md](README.md) - Main project documentation
