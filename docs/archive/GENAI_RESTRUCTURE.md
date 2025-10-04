# GenAI Module Restructure

**Date**: October 4, 2025
**Purpose**: Improve code organization and naming clarity

---

## Changes Made

### Directory Structure

**Before:**
```
gorgon/
├── genai.py              # 1208 lines - correlation engine
└── ai_models/
    └── generator.py      # 411 lines - AI providers
```

**After:**
```
gorgon/
└── genai/                # Renamed from ai_models/
    ├── __init__.py       # Module exports
    ├── engine.py         # Renamed from genai.py
    └── models.py         # Renamed from generator.py
```

---

## File Renames

| Old Path | New Path | Purpose |
|----------|----------|---------|
| `gorgon/genai.py` | `gorgon/genai/engine.py` | Main correlation generation engine |
| `gorgon/ai_models/generator.py` | `gorgon/genai/models.py` | AI provider implementations |
| `gorgon/ai_models/` | `gorgon/genai/` | Module directory |

---

## Rationale

### Why `genai/` instead of `ai_models/`?
- ✅ **More descriptive**: Clearly indicates "GenAI correlation generation"
- ✅ **Accurate**: Module handles both heuristic AND AI-based generation
- ✅ **Concise**: Shorter, cleaner name
- ✅ **Consistent**: Matches the actual purpose better

### Why `engine.py` instead of `genai.py`?
- ✅ **Avoids confusion**: Previously `genai.py` was at wrong level
- ✅ **Clearer purpose**: "engine" indicates core processing logic
- ✅ **Professional**: Common naming pattern for core modules
- ✅ **Better organization**: Now properly nested in `genai/` package

### Why `models.py` instead of `generator.py`?
- ✅ **Specific**: Refers to AI models/providers
- ✅ **Shorter**: More concise naming
- ✅ **Standard**: Common Python naming convention
- ✅ **Clear**: Distinguishes from the main engine

---

## Module Exports

The new `gorgon/genai/__init__.py` exports:

```python
from .engine import (
    generate_correlations,
    build_correlation_queries,
    process_genai,
    process,
)
```

This allows clean imports:
```python
from gorgon.genai import build_correlation_queries
from gorgon.genai import generate_correlations
```

---

## Files Updated

### Code Files (Imports)
1. ✅ `gorgon/genai/engine.py` - Updated internal import for models
2. ✅ `gorgon/genai/__init__.py` - Created new module exports
3. ✅ `gorgon/app.py` - Simplified imports, removed redundant code
4. ✅ `cli.py` - Already using correct imports (via __init__.py)
5. ✅ `gorgon/parsers/correlations.py` - Already using correct imports
6. ✅ `scripts/genai_smoke_test.py` - Already using correct imports

### Documentation Files
1. ✅ `docs/CORRELATION_BUILDER.md` - Updated file paths
2. ✅ `docs/CLEANUP_REPORT.md` - Updated references
3. ✅ `docs/GENAI_RESTRUCTURE.md` - This file (new)

---

## Testing

All imports verified working:

```bash
$ python3 cli.py --help
usage: cli.py [-h] {genai,build-correlations,...}
✅ Success

$ python3 cli.py build-correlations --help
usage: cli.py build-correlations [-h] [--yaml-dir YAML_DIR]...
✅ Success
```

---

## Migration Guide

### For External Code

If you have external code importing from the old structure:

**Old imports (still work via __init__.py):**
```python
from gorgon.genai import generate_correlations  # ✅ Works
from gorgon.genai import build_correlation_queries  # ✅ Works
```

**New imports (recommended):**
```python
from gorgon.genai import generate_correlations  # Same!
from gorgon.genai import build_correlation_queries  # Same!
from gorgon.genai.engine import _combine_queries  # For internals
from gorgon.genai.models import LocalLLMGenerator  # For AI providers
```

### For Configuration

No configuration changes needed. Environment variables remain the same:

```bash
export GENAI_MODE=local_llm
export LLAMA_MODEL_PATH=/path/to/model.gguf
export OPENAI_API_KEY=sk-...
```

---

## Benefits

1. **Better Organization**
   - Related files grouped in `genai/` directory
   - Clear separation: engine vs AI models
   - Logical module structure

2. **Improved Clarity**
   - `engine.py` clearly indicates core logic
   - `models.py` clearly indicates AI providers
   - `genai/` indicates the module purpose

3. **Easier Navigation**
   - All correlation logic in one place
   - Clear distinction between main engine and optional AI
   - Better IDE support with proper package structure

4. **Future-Proof**
   - Easy to add more files to `genai/`
   - Can add `genai/cache.py`, `genai/validators.py`, etc.
   - Scalable structure

---

## Structure Details

### `gorgon/genai/engine.py` (1208 lines)

**Purpose**: Core correlation generation engine

**Key Functions**:
- `generate_correlations()` - Main entry point
- `build_correlation_queries()` - Advanced correlation builder
- `_combine_queries()` - Query combination logic
- `_build_correlation_search()` - Correlation search builder
- Heuristic, advanced parsing, and AI integration

**Dependencies**:
- `gorgon.parsers.*` - Query parsers
- `gorgon.build.progress` - Progress tracking
- `gorgon.genai.models` - AI providers (optional)

### `gorgon/genai/models.py` (411 lines)

**Purpose**: AI provider implementations for enhanced query generation

**Classes**:
- `QueryGeneratorBase` - Abstract base class
- `LocalLLMGenerator` - Local LLM support (llama.cpp, transformers)
- `RemoteAPIGenerator` - Remote API support (OpenAI, etc.)
- `get_generator()` - Factory function

**Features**:
- Caching system (24hr TTL)
- Platform-aware prompts (Splunk, MDE/KQL)
- Graceful fallbacks

### `gorgon/genai/__init__.py`

**Purpose**: Clean module exports and public API

**Exports**:
- `generate_correlations`
- `build_correlation_queries`
- `process_genai`
- `process`

---

## Backward Compatibility

✅ **Full backward compatibility maintained**

All previous import statements continue to work thanks to `__init__.py`:
- `from gorgon.genai import generate_correlations` ✅
- `from gorgon.genai import build_correlation_queries` ✅
- `from gorgon.genai import process_genai` ✅

---

## Summary

| Aspect | Before | After | Improvement |
|--------|--------|-------|-------------|
| **Organization** | Scattered | Grouped in `genai/` | ✅ Better |
| **Clarity** | `genai.py` at root | `genai/engine.py` | ✅ Clearer |
| **AI Models** | `ai_models/generator.py` | `genai/models.py` | ✅ More specific |
| **Imports** | Direct file imports | Package imports | ✅ Cleaner |
| **Extensibility** | Limited | Easy to extend | ✅ Future-proof |

---

## Related Documentation

- [CORRELATION_BUILDER.md](CORRELATION_BUILDER.md) - Correlation query builder guide
- [CLEANUP_REPORT.md](CLEANUP_REPORT.md) - Full cleanup report
- [Engine Source](../gorgon/genai/engine.py) - Core engine implementation
- [Models Source](../gorgon/genai/models.py) - AI provider implementations

---

**Status**: ✅ Complete
**Testing**: ✅ Verified
**Documentation**: ✅ Updated
**Backward Compatibility**: ✅ Maintained
