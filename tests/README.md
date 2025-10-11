# Tests Directory

Comprehensive test suite for the Archer threat hunting application.

## Test Structure

### UI Tests (Playwright) ⭐ NEW

#### test_ui_tabs.py
**Purpose**: Test tabbed interface functionality
**Coverage**:
- Tab switching and navigation
- Tab content isolation
- Generate tab form validation
- Upload tab interface
- Emulate tab functionality
- Responsive design (mobile, tablet, desktop)

**Run**:
```bash
pytest tests/test_ui_tabs.py -v

# With browser visible
HEADLESS=false pytest tests/test_ui_tabs.py -v
```

#### test_ui_upload.py
**Purpose**: Test file upload functionality
**Coverage**:
- File selection (PDF, TXT, JSON, CSV, YARA)
- Drag and drop interface
- Upload options (OpenAI enhancement, auto-generate, correlation)
- File clearing and replacement
- Upload button state management
- Accessibility features

**Run**:
```bash
pytest tests/test_ui_upload.py -v
```

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

### Run UI Tests Only (Playwright)
```bash
# All UI tests
pytest tests/test_ui_*.py -v

# Specific UI test
pytest tests/test_ui_tabs.py -v

# Run in headed mode (show browser)
HEADLESS=false pytest tests/test_ui_*.py -v

# Slow motion for debugging
SLOW_MO=1000 pytest tests/test_ui_*.py -v
```

### Run by Test Markers
```bash
# Only UI tests
pytest -m ui -v

# Only API tests (fast)
pytest -m api -v

# Exclude slow tests
pytest -m "not slow" -v

# Only integration tests
pytest -m integration -v
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

### Parallel Execution
```bash
# Install pytest-xdist
pip install pytest-xdist

# Run tests in parallel (4 workers)
pytest tests/ -n 4
```

## Test Requirements

### Basic Requirements
```bash
pip install pytest pytest-cov
```

### For UI Testing (Playwright)
```bash
pip install playwright pytest-playwright
playwright install  # Install browsers (Chromium, Firefox, WebKit)

# Or just Chromium
playwright install chromium
```

### Optional Dependencies
```bash
pip install pytest-mock      # For mocking
pip install httpx            # For async HTTP testing
pip install pytest-xdist     # For parallel test execution
pip install pytest-timeout  # For test timeouts
```

## Modern UI Testing with Playwright

Archer now uses **Playwright** for UI testing instead of Selenium.

### Why Playwright?
- ✅ **Faster and more reliable** - Auto-waits for elements, reducing flakiness
- ✅ **Better for modern apps** - Seamlessly handles SPAs, AJAX, dynamic content
- ✅ **Cross-browser** - Test on Chromium, Firefox, and WebKit
- ✅ **Better debugging** - Screenshots, videos, and trace files on failure
- ✅ **Cleaner API** - More intuitive and concise than Selenium
- ✅ **Auto-installation** - Browsers installed automatically

### Quick Start

```bash
# 1. Install Playwright
pip install playwright pytest-playwright

# 2. Install browsers
playwright install chromium

# 3. Run UI tests
pytest tests/test_ui_*.py -v

# 4. Debug with browser visible
HEADLESS=false pytest tests/test_ui_tabs.py::test_tab_switching -v
```

### Comprehensive Documentation

See **[Playwright Testing Guide](../docs/PLAYWRIGHT_TESTING.md)** for:
- Complete API reference
- Best practices
- Debugging techniques
- CI/CD integration
- Migration from Selenium

## Writing New Tests

### Test File Naming
- Prefix with `test_`
- Use descriptive names: `test_feature_name.py`
- UI tests: `test_ui_feature.py`

### Test Function Naming
- Prefix with `test_`
- Use descriptive names: `test_feature_does_something()`

### Test Structure Example

```python
import pytest
from playwright.sync_api import Page, expect

class TestFeatureName:
    """Test description"""

    def test_specific_behavior(self, page: Page, base_url: str):
        """Test that specific behavior works correctly"""
        # Navigate
        page.goto(base_url)

        # Interact
        button = page.locator('#submit-button')
        button.click()

        # Assert
        expect(page.locator('.success-message')).to_be_visible()
```

### Fixtures

Common fixtures available in `conftest.py`:

```python
def test_example(page, base_url, temp_text_file):
    """
    page: Fresh Page instance for each test
    base_url: Application URL (http://localhost:8000)
    temp_text_file: Temporary test file
    """
    page.goto(base_url)
```

## Test Markers

Tests are automatically marked based on their location:

- `@pytest.mark.ui` - UI tests (slow)
- `@pytest.mark.api` - API tests (fast)
- `@pytest.mark.integration` - Integration tests
- `@pytest.mark.slow` - Slow-running tests
- `@pytest.mark.requires_atomic` - Requires Atomic Red Team
- `@pytest.mark.requires_vectr` - Requires VECTR
- `@pytest.mark.requires_openai` - Requires OpenAI API key

## Debugging

### View Test Output
```bash
pytest tests/ -v -s  # -s shows print statements
```

### Run Specific Failing Test
```bash
pytest tests/test_ui_tabs.py::test_tab_switching -v
```

### Debug with Playwright Inspector
```bash
PWDEBUG=1 pytest tests/test_ui_tabs.py::test_tab_switching
```

### View Screenshots
Failed tests automatically capture screenshots:
```
test-results/
├── test-ui-tabs-py-test-page-loads-chromium/
│   ├── test-failed-1.png
│   └── trace.zip
```

### View Trace Files
```bash
playwright show-trace test-results/*/trace.zip
```

## Continuous Integration

Example GitHub Actions workflow:

```yaml
name: Tests
on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-python@v4
        with:
          python-version: '3.11'

      - name: Install dependencies
        run: |
          pip install -r requirements.txt
          playwright install --with-deps chromium

      - name: Run tests
        run: |
          pytest tests/ --cov=archer -v

      - name: Upload test results
        if: failure()
        uses: actions/upload-artifact@v3
        with:
          name: test-results
          path: test-results/
```

## Test Coverage Goals

- **API Endpoints**: >80% coverage ✓
- **Core Modules**: >70% coverage
- **Utility Functions**: >60% coverage
- **UI Critical Paths**: 100% coverage

## Contributing

When adding new features:

1. **Write tests first** (TDD approach)
2. **Ensure all tests pass**: `pytest tests/ -v`
3. **Check coverage**: `pytest tests/ --cov=archer`
4. **Update this README** if adding new test categories
5. **Add test markers** for categorization

## Resources

- [Playwright Documentation](https://playwright.dev/python/)
- [pytest Documentation](https://docs.pytest.org/)
- [Archer Playwright Guide](../docs/PLAYWRIGHT_TESTING.md)
- [pytest-playwright](https://github.com/microsoft/playwright-pytest)
