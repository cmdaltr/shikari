# Archer Test Suite

Comprehensive test suite for the Archer Detection Generation Platform.

## Test Categories

### Functionality Tests
Quick tests that verify endpoints respond correctly. These run by default and complete in seconds.

| Test Class | What it validates |
|------------|-------------------|
| `TestArcherHealth` | Health endpoint and home page load |
| `TestArcherAPIs` | API endpoints return valid responses |
| `TestArcherPages` | Page routes render correctly |
| `TestArcherLibrary` | Library API search and filtering |
| `TestArcherAdditional` | Emulation and hunt endpoints |

### Feature Tests
End-to-end tests that validate full generation pipelines. These are skipped by default and require the `--run-feature-tests` flag.

| Test Class | What it validates |
|------------|-------------------|
| `TestArcherThreatGroups` | Threat group detection generation |
| `TestArcherCVEs` | CVE processing and detection generation |
| `TestArcherBlogs` | Blog analysis and TTP extraction |
| `TestArcherProfiles` | Company profile generation |

## Running Tests

### Prerequisites
```bash
# Ensure Archer is running
python -m uvicorn archer.app:app --reload

# Install test dependencies
pip install pytest requests
```

### Run Functionality Tests Only (Default)
```bash
pytest tests/test_comprehensive.py -v
```

### Run All Tests (Including Feature Tests)
```bash
pytest tests/test_comprehensive.py -v --run-feature-tests
```

### Run Specific Test Class
```bash
# Functionality tests
pytest tests/test_comprehensive.py::TestArcherHealth -v
pytest tests/test_comprehensive.py::TestArcherAPIs -v

# Feature tests (requires --run-feature-tests)
pytest tests/test_comprehensive.py::TestArcherThreatGroups -v --run-feature-tests
```

## Standalone Runner

The test suite can also be run directly with Python for more control:

```bash
# Run all tests
python tests/test_comprehensive.py

# Skip feature tests
python tests/test_comprehensive.py --skip-feature-tests

# Test specific items
python tests/test_comprehensive.py --group "Scattered Spider"
python tests/test_comprehensive.py --cve "CVE-2025-55182"
python tests/test_comprehensive.py --blog "https://thedfirreport.com/2025/11/17/cats-got-your-files-lynx-ransomware/"
python tests/test_comprehensive.py --profile "example"

# Limit number of items tested
python tests/test_comprehensive.py --groups 2 --cves 2 --blogs 3 --profiles 2

# Output as JSON
python tests/test_comprehensive.py --json

# Custom Archer URL
python tests/test_comprehensive.py --url http://localhost:8080

# Custom timeout (default 900s = 15 minutes)
python tests/test_comprehensive.py --group "Scattered Spider" --timeout 1800
```

## Test Data

### Threat Groups
- Scattered Spider
- APT28
- Lazarus Group
- Salt Typhoon
- Wizard Spider

### CVEs
- CVE-2025-55182
- CVE-2025-5777
- CVE-2025-62221
- CVE-2025-62215

### Blog URLs
- DFIR Report articles
- CrowdStrike blog posts

### Company Profiles
- example
- LMAX
- Deutsche Bank
- BBC

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `ARCHER_BASE_URL` | Archer server URL | `http://127.0.0.1:8000` |

## File Structure

```
tests/
├── README.md              # This file
├── __init__.py            # Package marker
├── conftest.py            # Pytest configuration and fixtures
└── test_comprehensive.py  # Main test suite
```
