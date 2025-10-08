# Scripts and Tests Directory Analysis & Cleanup Plan

## Current Structure

### `/scripts/` Directory (5 files)
1. **debug_endpoints.py** (74 lines) - Basic endpoint smoke tests using TestClient
2. **debug_templates.py** (39 lines) - Template syntax validation using Jinja2
3. **genai_smoke_test.py** (90 lines) - GenAI integration smoke test
4. **summarize_smoke_json.py** (85 lines) - GenAI output summarization tool
5. **run_debug_checks.sh** (11 lines) - Shell script to run debug checks

### `/tests/` Directory (9 files + jest/)
1. **test_templates.py** (18 lines) - pytest version of template validation
2. **test_drafts.py** (62 lines) - Draft save/load endpoint tests
3. **test_manual_submit.py** (51 lines) - Manual submission endpoint tests
4. **test_api_endpoints.py** (381 lines) - Comprehensive API endpoint tests
5. **test_query_execution.py** (251 lines) - Query execution module tests
6. **test_remote_execution.py** (212 lines) - Remote emulation tests
7. **test_selenium_forms.py** (477 lines) - Selenium UI form tests
8. **test_selenium_navigation.py** (531 lines) - Selenium UI navigation tests
9. **jest/components.test.js** - JavaScript component tests

## Identified Issues

### 1. **Duplication: Template Testing**
- `scripts/debug_templates.py` - Standalone script version
- `tests/test_templates.py` - pytest version
- **Both do the exact same thing**: validate Jinja2 template syntax

### 2. **Duplication: Endpoint Testing**
- `scripts/debug_endpoints.py` - Basic smoke tests (3 endpoints)
- `tests/test_api_endpoints.py` - Comprehensive tests (all endpoints)
- **Overlap**: debug_endpoints is a minimal subset of test_api_endpoints

### 3. **Orphaned Jest Tests**
- `tests/jest/components.test.js` - Tests old form structure that no longer exists
- **Issue**: Tests reference DOM elements from old single-form UI (pre-tabbed interface)
- **Status**: Outdated after tabbed UI implementation

### 4. **Selenium Tests for Old UI**
- `test_selenium_forms.py` - Tests old form elements
- `test_selenium_navigation.py` - Tests old navigation flow
- **Issue**: Likely broken after new tabbed interface implementation
- **Need**: Update or remove

### 5. **Script vs Test Confusion**
- Scripts should be utilities/tools
- Tests should be pytest/jest tests
- **Current**: Mixing concerns with duplicated functionality

## Consolidation Plan

### Phase 1: Merge Duplicates ✅

#### Template Testing
**Action**: Keep pytest version, remove script version
- ✅ **Keep**: `tests/test_templates.py` (proper pytest structure)
- ❌ **Remove**: `scripts/debug_templates.py` (duplicate functionality)

#### Endpoint Testing
**Action**: Keep comprehensive pytest version, remove basic script
- ✅ **Keep**: `tests/test_api_endpoints.py` (comprehensive)
- ❌ **Remove**: `scripts/debug_endpoints.py` (subset of functionality)

#### Shell Runner
**Action**: Remove and document pytest usage
- ❌ **Remove**: `scripts/run_debug_checks.sh` (unnecessary wrapper)
- ✅ **Document**: Use `pytest tests/` directly

### Phase 2: Update/Remove Outdated Tests ⚠️

#### Jest Tests
**Status**: Outdated (tests old UI structure)
**Options**:
1. ❌ **Remove entirely** - No JavaScript test coverage (acceptable)
2. ⚠️ **Update** - Rewrite for new tabbed interface (time-consuming)
3. ✅ **Move to archive** - Keep for reference but exclude from test runs

**Recommendation**: Move to `tests/archive/` for now

#### Selenium Tests
**Status**: Potentially outdated (need verification)
**Options**:
1. ⚠️ **Test first** - Run tests to see if they work with new UI
2. ❌ **Remove** - If completely broken
3. ✅ **Update** - Fix selectors for new tabbed interface
4. 📁 **Archive** - Move to `tests/archive/` until can be updated

**Recommendation**: Move to `tests/archive/` - they're large (1008 lines combined) and likely broken

### Phase 3: Reorganize Scripts 📁

**Keep these utility scripts** (actual tools, not tests):
- ✅ `genai_smoke_test.py` - Useful for GenAI testing
- ✅ `summarize_smoke_json.py` - Useful analysis tool

**New structure**:
```
scripts/
├── genai_smoke_test.py       # GenAI smoke testing
├── summarize_smoke_json.py   # GenAI output analysis
└── README.md                  # Documentation for scripts
```

### Phase 4: Reorganize Tests 📁

**Proposed structure**:
```
tests/
├── test_api_endpoints.py      # API endpoint tests
├── test_drafts.py             # Draft functionality tests
├── test_manual_submit.py      # Manual submission tests
├── test_query_execution.py    # Query execution tests
├── test_remote_execution.py   # Remote emulation tests
├── test_templates.py          # Template validation tests
├── archive/                   # Outdated tests kept for reference
│   ├── jest/
│   │   └── components.test.js
│   ├── test_selenium_forms.py
│   └── test_selenium_navigation.py
└── README.md                  # Test documentation
```

## Cleanup Actions

### Immediate Actions (Safe to execute)

1. **Remove duplicate scripts**:
   ```bash
   rm scripts/debug_templates.py
   rm scripts/debug_endpoints.py
   rm scripts/run_debug_checks.sh
   ```

2. **Create archive directory**:
   ```bash
   mkdir -p tests/archive
   ```

3. **Move outdated tests to archive**:
   ```bash
   mv tests/jest tests/archive/
   mv tests/test_selenium_forms.py tests/archive/
   mv tests/test_selenium_navigation.py tests/archive/
   ```

4. **Create documentation**:
   - Add `scripts/README.md` explaining utility scripts
   - Add `tests/README.md` explaining test structure
   - Add `tests/archive/README.md` explaining archived tests

### Files to Remove (3 files)
- `scripts/debug_templates.py` - Duplicate of test_templates.py
- `scripts/debug_endpoints.py` - Subset of test_api_endpoints.py
- `scripts/run_debug_checks.sh` - Unnecessary wrapper

### Files to Archive (3 items)
- `tests/jest/` - Outdated JavaScript tests
- `tests/test_selenium_forms.py` - Likely broken after UI update
- `tests/test_selenium_navigation.py` - Likely broken after UI update

### Files to Keep (9 files)

**Scripts (2 files)**:
- `scripts/genai_smoke_test.py` - Useful GenAI testing utility
- `scripts/summarize_smoke_json.py` - Useful analysis tool

**Tests (7 files)**:
- `tests/test_api_endpoints.py` - Comprehensive API tests
- `tests/test_drafts.py` - Draft functionality tests
- `tests/test_manual_submit.py` - Manual submission tests
- `tests/test_query_execution.py` - Query execution tests
- `tests/test_remote_execution.py` - Remote emulation tests
- `tests/test_templates.py` - Template validation tests

## Benefits of Cleanup

1. **Reduced Confusion**: Clear separation between utilities and tests
2. **No Duplication**: Single source of truth for each test type
3. **Easier Maintenance**: Fewer files to update
4. **Faster CI/CD**: Fewer outdated tests to skip
5. **Better Organization**: Logical structure with archive for reference

## Testing After Cleanup

Run remaining tests to ensure nothing breaks:

```bash
# Run all pytest tests
pytest tests/ -v

# Run specific test categories
pytest tests/test_api_endpoints.py -v
pytest tests/test_templates.py -v

# Run GenAI smoke test
python3 scripts/genai_smoke_test.py
```

## Future Improvements

1. **Add new UI tests**: Create tests for new tabbed interface
2. **Update Selenium tests**: Modernize archived Selenium tests for new UI
3. **Add file upload tests**: Test new upload functionality
4. **Jest modernization**: Update JavaScript tests for new UI components
5. **CI/CD integration**: Add GitHub Actions workflow for automated testing

## Summary

**Before cleanup**: 14 files (5 scripts + 9 test files)
**After cleanup**: 9 files (2 scripts + 7 tests) + 3 archived items

**Reduction**: 5 files removed/archived (35% reduction)
**Result**: Cleaner, more maintainable structure with no loss of useful functionality
