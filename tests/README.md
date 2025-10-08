# Tests Directory

Comprehensive test suite for the Archer threat hunting application.

## Test Structure

### API and Backend Tests

#### test_api_endpoints.py (381 lines)
**Purpose**: Comprehensive API endpoint testing
**Coverage**:
- Health endpoints (/, /health)
- Generate endpoint with various options
- Manual submission endpoint
- Draft save/load functionality
- Progress tracking
- Static file serving

**Run**:
```bash
pytest tests/test_api_endpoints.py -v
```

#### test_drafts.py (62 lines)
**Purpose**: Draft management functionality
**Coverage**:
- Save draft data
- Load draft data
- User-scoped drafts
- Draft listing

**Run**:
```bash
pytest tests/test_drafts.py -v
```

#### test_manual_submit.py (51 lines)
**Purpose**: Manual technique submission
**Coverage**:
- Manual data transformation
- Tactic grouping logic
- Procedure parsing

**Run**:
```bash
pytest tests/test_manual_submit.py -v
```

#### test_templates.py (18 lines)
**Purpose**: Jinja2 template validation
**Coverage**:
- All HTML templates compile without syntax errors

**Run**:
```bash
pytest tests/test_templates.py -v
```

### Module Tests

#### test_query_execution.py (251 lines)
**Purpose**: Query execution module testing
**Coverage**:
- MDE (Microsoft Defender) API integration
- Splunk API integration
- OAuth2 authentication
- Query execution and result handling

**Run**:
```bash
pytest tests/test_query_execution.py -v
```

#### test_remote_execution.py (212 lines)
**Purpose**: Remote emulation testing
**Coverage**:
- SSH remote execution
- WinRM remote execution
- Atomic Red Team integration
- Remote platform detection

**Run**:
```bash
pytest tests/test_remote_execution.py -v
```

## Running Tests

### Run All Tests
```bash
pytest tests/ -v
```

### Run Specific Test File
```bash
pytest tests/test_api_endpoints.py -v
```

### Run Specific Test Function
```bash
pytest tests/test_api_endpoints.py::TestHealthEndpoints::test_root_endpoint -v
```

### Run with Coverage
```bash
pytest tests/ --cov=archer --cov-report=html
```

Then open `htmlcov/index.html` in your browser.

### Run with Markers
```bash
# Run only fast tests
pytest tests/ -m "not slow" -v

# Run only integration tests
pytest tests/ -m integration -v
```

## Test Requirements

Install test dependencies:
```bash
pip install pytest pytest-cov
```

Optional dependencies:
```bash
pip install pytest-mock  # For mocking
pip install httpx        # For async HTTP testing
```

## Archived Tests

The `archive/` directory contains outdated tests that are no longer maintained:

### archive/jest/
**Status**: Outdated - Tests old pre-tabbed UI
**Reason**: UI was redesigned with tabbed interface
**Future**: May be updated for new UI components

### archive/test_selenium_forms.py (477 lines)
**Status**: Outdated - Tests old form structure
**Reason**: Form structure changed with tabbed UI
**Future**: Needs rewrite for new interface

### archive/test_selenium_navigation.py (531 lines)
**Status**: Outdated - Tests old navigation flow
**Reason**: Navigation changed with tabbed UI
**Future**: Needs rewrite for new interface

See `archive/README.md` for more details.

## Writing New Tests

### Test File Naming
- Prefix with `test_`
- Use descriptive names: `test_feature_name.py`

### Test Function Naming
- Prefix with `test_`
- Use descriptive names: `test_feature_does_something()`

### Test Structure
```python
import pytest
from fastapi.testclient import TestClient
from archer.app import app

client = TestClient(app)

class TestFeatureName:
    """Test description"""

    def test_specific_behavior(self):
        """Test that specific behavior works correctly"""
        # Arrange
        data = {"key": "value"}

        # Act
        response = client.post("/endpoint", json=data)

        # Assert
        assert response.status_code == 200
        assert response.json()["success"] == True
```

### Fixtures
```python
@pytest.fixture
def sample_data():
    return {"group_name": "APT29"}

def test_with_fixture(sample_data):
    assert "group_name" in sample_data
```

## Continuous Integration

Tests can be run in CI/CD pipelines:

```yaml
# .github/workflows/test.yml
name: Tests
on: [push, pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - uses: actions/setup-python@v2
        with:
          python-version: '3.11'
      - run: pip install -r requirements.txt
      - run: pip install pytest pytest-cov
      - run: pytest tests/ --cov=archer
```

## Test Coverage Goals

- **API Endpoints**: >80% coverage
- **Core Modules**: >70% coverage
- **Utility Functions**: >60% coverage

## Contributing

When adding new features:
1. Write tests first (TDD approach)
2. Ensure all tests pass: `pytest tests/ -v`
3. Check coverage: `pytest tests/ --cov=archer`
4. Update this README if adding new test categories
