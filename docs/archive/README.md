# Archive

This directory contains historical documentation about past changes to the Archer codebase.

## Archived Documents

### CLEANUP_REPORT.md
**Date**: October 4, 2025
**Purpose**: Comprehensive codebase cleanup report

Documents the removal of unused files and improvement of configuration:
- Removed `data/ai_cache/` (empty)
- Removed `.flake8` (empty)
- Updated Docker configuration
- Improved `.gitignore`
- Reorganized `gorgon/genai/` module

### GENAI_RESTRUCTURE.md
**Date**: October 4, 2025
**Purpose**: Module restructure documentation

Documents the reorganization of the GenAI correlation module:
- Renamed `ai_models/` → `genai/`
- Renamed `genai.py` → `genai/engine.py`
- Renamed `generator.py` → `genai/models.py`
- Added proper `__init__.py` exports

---

**Note**: These documents are kept for historical reference. For current documentation, see the main [docs](../) directory.
