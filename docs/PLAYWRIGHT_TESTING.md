# Playwright UI Testing Guide

Modern UI testing for Archer using Playwright instead of Selenium.

## Why Playwright?

Playwright offers several advantages over Selenium:
- **Faster**: Auto-waits for elements, reducing flakiness
- **More Reliable**: Better handling of modern web apps (SPAs, AJAX)
- **Cross-Browser**: Tests on Chromium, Firefox, and WebKit
- **Better DevTools**: Screenshots, videos, trace files for debugging
- **Modern API**: Cleaner, more intuitive syntax
- **Auto-Installation**: Browsers installed automatically

## Installation

### 1. Install Python Dependencies

```bash
pip install playwright pytest-playwright
```

### 2. Install Browsers

```bash
playwright install
```

This installs Chromium, Firefox, and WebKit browsers.

For a single browser:
```bash
playwright install chromium
```

## Test Structure

### Test Files

```
tests/
├── conftest.py                 # Shared fixtures
├── test_ui_tabs.py            # Tabbed interface tests
├── test_ui_upload.py          # File upload tests
├── test_api_endpoints.py      # API tests (non-UI)
└── test_*.py                  # Other tests
```

### Test Organization

Tests are organized by feature:
- `test_ui_tabs.py` - Tab switching, UI layout
- `test_ui_upload.py` - File upload functionality

Each test file contains multiple test classes:
```python
class TestTabbedInterface:
    """Test tab navigation and switching"""

class TestGenerateTab:
    """Test Generate tab functionality"""

class TestUploadTab:
    """Test Upload tab functionality"""
```

## Running Tests

### Run All UI Tests

```bash
# All UI tests
pytest tests/test_ui_*.py -v

# Specific test file
pytest tests/test_ui_tabs.py -v

# Specific test class
pytest tests/test_ui_tabs.py::TestTabbedInterface -v

# Specific test function
pytest tests/test_ui_tabs.py::TestTabbedInterface::test_page_loads -v
```

### Run with Markers

```bash
# Only UI tests
pytest -m ui -v

# Only fast tests (exclude UI)
pytest -m "not ui" -v

# Only slow tests
pytest -m slow -v
```

### Headless vs Headed Mode

```bash
# Headless (default - no browser window)
pytest tests/test_ui_*.py

# Headed (show browser window)
HEADLESS=false pytest tests/test_ui_*.py

# Slow motion (for debugging, in milliseconds)
SLOW_MO=1000 pytest tests/test_ui_*.py
```

### Cross-Browser Testing

```bash
# Test on all browsers
pytest tests/test_ui_*.py --browser chromium --browser firefox --browser webkit

# Test on specific browser
pytest tests/test_ui_*.py --browser firefox
```

### Parallel Execution

```bash
# Install pytest-xdist
pip install pytest-xdist

# Run tests in parallel (4 workers)
pytest tests/test_ui_*.py -n 4
```

## Writing Tests

### Basic Test Structure

```python
import pytest
from playwright.sync_api import Page, expect


class TestMyFeature:
    """Test description"""

    def test_something(self, page: Page, base_url: str):
        """Test that something works"""
        # Navigate to page
        page.goto(base_url)

        # Interact with elements
        button = page.locator('#my-button')
        button.click()

        # Assert expectations
        expect(button).to_have_class('active')
```

### Selectors

Playwright supports multiple selector strategies:

```python
# By ID
page.locator('#element-id')

# By class
page.locator('.class-name')

# By attribute
page.locator('[data-tab="upload"]')

# By text
page.locator('text=Click Me')

# By role (accessible)
page.get_by_role('button', name='Submit')

# By label (accessible)
page.get_by_label('Username')

# CSS selectors
page.locator('div.container > button')

# XPath (if needed)
page.locator('xpath=//button[@class="submit"]')
```

### Assertions

Use Playwright's `expect` API:

```python
from playwright.sync_api import expect

# Visibility
expect(element).to_be_visible()
expect(element).not_to_be_visible()
expect(element).to_be_hidden()

# Text content
expect(element).to_contain_text('Hello')
expect(element).to_have_text('Exact text')

# Attributes
expect(element).to_have_attribute('href', 'https://example.com')
expect(element).to_have_class('active')
expect(element).to_have_id('submit-btn')

# State
expect(element).to_be_enabled()
expect(element).to_be_disabled()
expect(element).to_be_checked()
expect(element).to_be_focused()

# Count
expect(page.locator('.item')).to_have_count(5)

# URL
expect(page).to_have_url('http://localhost:8000')
expect(page).to_have_title('My App')
```

### Interactions

```python
# Click
element.click()

# Type text
input_field.fill('text to type')
input_field.type('text letter by letter')

# Check/uncheck
checkbox.check()
checkbox.uncheck()

# Select option
dropdown.select_option('value')
dropdown.select_option(label='Display Text')

# Upload file
file_input.set_input_files('/path/to/file.pdf')
file_input.set_input_files(['/path/to/file1.pdf', '/path/to/file2.pdf'])

# Hover
element.hover()

# Focus
element.focus()

# Press keys
page.keyboard.press('Enter')
page.keyboard.press('Control+A')
```

### Waiting

Playwright auto-waits, but you can explicitly wait:

```python
# Wait for element
element.wait_for(state='visible')
element.wait_for(state='hidden')

# Wait for selector
page.wait_for_selector('#element-id')

# Wait for URL
page.wait_for_url('**/progress')

# Wait for load state
page.wait_for_load_state('networkidle')
page.wait_for_load_state('domcontentloaded')

# Custom timeout
element.click(timeout=5000)  # 5 seconds
```

### Screenshots

```python
# Full page screenshot
page.screenshot(path='screenshot.png')

# Element screenshot
element.screenshot(path='element.png')

# In test (automatic on failure with pytest-playwright)
# Screenshots saved to test-results/
```

### Debugging

```python
# Pause execution and open browser
page.pause()

# Print console logs
page.on('console', lambda msg: print(f'CONSOLE: {msg.text}'))

# Network monitoring
page.on('request', lambda req: print(f'REQUEST: {req.url}'))
page.on('response', lambda res: print(f'RESPONSE: {res.url} {res.status}'))
```

## Fixtures

### Built-in Fixtures

```python
def test_example(page, base_url):
    """
    page: Fresh Page instance for each test
    base_url: Application base URL (default: http://localhost:8000)
    """
    page.goto(base_url)
```

### Custom Fixtures

Located in `tests/conftest.py`:

```python
@pytest.fixture
def authenticated_page(page, base_url):
    """Page with authentication"""
    page.goto(base_url)
    # Perform login
    page.locator('#username').fill('admin')
    page.locator('#password').fill('password')
    page.locator('#login-btn').click()
    return page


@pytest.fixture
def temp_text_file(tmp_path):
    """Create temporary test file"""
    file_path = tmp_path / "test.txt"
    file_path.write_text("Test content")
    return str(file_path)
```

## Best Practices

### 1. Use Semantic Selectors

```python
# Good - semantic, resilient to changes
page.get_by_role('button', name='Submit')
page.get_by_label('Email')
page.get_by_text('Welcome')

# Okay - data attributes
page.locator('[data-testid="submit-button"]')

# Avoid - brittle CSS selectors
page.locator('div > div.container > button:nth-child(3)')
```

### 2. Wait for State, Not Time

```python
# Good - wait for condition
expect(element).to_be_visible()

# Bad - arbitrary delay
import time
time.sleep(2)
```

### 3. Use Page Object Model

```python
# pages/upload_page.py
class UploadPage:
    def __init__(self, page: Page):
        self.page = page
        self.file_input = page.locator('#file-input')
        self.upload_btn = page.locator('#upload_btn')

    def upload_file(self, path: str):
        self.file_input.set_input_files(path)
        self.upload_btn.click()


# In test
def test_upload(page, base_url, temp_file):
    upload_page = UploadPage(page)
    upload_page.upload_file(temp_file)
```

### 4. Keep Tests Independent

```python
# Each test should:
# - Set up its own data
# - Clean up after itself
# - Not depend on other tests

@pytest.fixture(autouse=True)
def reset_state(page, base_url):
    """Reset application state before each test"""
    # Clear cookies/storage
    page.context.clear_cookies()
    page.context.clear_permissions()
```

### 5. Use Descriptive Names

```python
# Good
def test_upload_button_enables_after_file_selection():
    ...

# Bad
def test1():
    ...
```

## Debugging Failed Tests

### 1. Run in Headed Mode

```bash
HEADLESS=false pytest tests/test_ui_tabs.py::test_tab_switching
```

### 2. Slow Down Execution

```bash
SLOW_MO=1000 pytest tests/test_ui_tabs.py
```

### 3. Use Playwright Inspector

```bash
PWDEBUG=1 pytest tests/test_ui_tabs.py
```

This opens the Playwright Inspector for step-by-step debugging.

### 4. View Screenshots

Failed tests automatically capture screenshots:
```
test-results/
├── test-ui-tabs-py-test-page-loads-chromium/
│   ├── test-failed-1.png
│   └── trace.zip
```

### 5. View Trace Files

```bash
playwright show-trace test-results/*/trace.zip
```

## CI/CD Integration

### GitHub Actions

```yaml
# .github/workflows/test.yml
name: Playwright Tests

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
        run: pytest tests/test_ui_*.py -v

      - name: Upload screenshots
        if: failure()
        uses: actions/upload-artifact@v3
        with:
          name: test-results
          path: test-results/
```

## Configuration

### pytest.ini

```ini
[pytest]
# Playwright timeout (milliseconds)
playwright_timeout = 30000

# Browser launch options
playwright_browser_options = {
    "headless": true,
    "slow_mo": 0
}
```

### Environment Variables

```bash
# Base URL
export BASE_URL=http://localhost:8000

# Headless mode
export HEADLESS=true

# Slow motion (ms)
export SLOW_MO=0

# Browser choice
export BROWSER=chromium
```

## Comparison: Selenium vs Playwright

| Feature | Selenium | Playwright |
|---------|----------|------------|
| Auto-wait | ❌ Manual | ✅ Automatic |
| Speed | Slower | Faster |
| Flakiness | Higher | Lower |
| API | Verbose | Concise |
| DevTools | Limited | Excellent |
| Setup | Complex | Simple |
| Cross-browser | ✅ Yes | ✅ Yes |
| Mobile | Limited | ✅ Good |

## Migration from Selenium

### Selector Changes

```python
# Selenium
driver.find_element(By.ID, 'submit')
driver.find_element(By.CLASS_NAME, 'button')
driver.find_element(By.CSS_SELECTOR, '[data-tab="upload"]')

# Playwright
page.locator('#submit')
page.locator('.button')
page.locator('[data-tab="upload"]')
```

### Interaction Changes

```python
# Selenium
element.send_keys('text')
element.click()
checkbox.click()  # to check

# Playwright
element.fill('text')
element.click()
checkbox.check()
```

### Assertion Changes

```python
# Selenium
assert element.is_displayed()
assert element.text == 'Hello'

# Playwright
expect(element).to_be_visible()
expect(element).to_have_text('Hello')
```

## Resources

- [Playwright Documentation](https://playwright.dev/python/)
- [pytest-playwright](https://github.com/microsoft/playwright-pytest)
- [Playwright Selectors](https://playwright.dev/python/docs/selectors)
- [Best Practices](https://playwright.dev/python/docs/best-practices)
