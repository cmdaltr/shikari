# Archived Tests

This directory contains tests that are no longer actively maintained but kept for reference.

## Why Archive?

These tests were written for previous versions of the Archer UI and are now outdated after the tabbed interface redesign (October 2024). Rather than delete them entirely, they're preserved here as:
- Reference for future UI test rewrites
- Examples of Selenium/Jest testing patterns
- Historical documentation of old UI behavior

## Archived Items

### jest/ - JavaScript Component Tests

**Original Purpose**: Test client-side JavaScript components and DOM manipulation

**Status**: ❌ Outdated
**Last Updated**: October 2024
**Issue**: Tests reference old single-form UI structure
**DOM Elements Tested**:
- `#generateForm`
- `#groupName`
- `#correlate`
- `#advancedParsing`
- `#progressContainer`
- `#draftSelect`

**Reason for Archive**: UI redesigned with tabbed interface
- Old: Single form with all options visible
- New: Tabbed interface (Generate/Upload/Emulate)

**To Resurrect**:
1. Update DOM selectors for new tabbed UI
2. Install Jest: `npm install --save-dev jest @testing-library/dom`
3. Update test to match new structure in `templates/index.html`
4. Move back to `tests/jest/`

**Test Count**: 1 file, ~50 test cases

---

### test_selenium_forms.py - UI Form Testing

**Original Purpose**: End-to-end testing of form interactions using Selenium WebDriver

**Status**: ⚠️ Likely Broken
**Last Updated**: October 2024
**Lines**: 477
**Issue**: Tests old form structure and field names

**Tests Included**:
- Form field validation
- Checkbox interactions
- Draft save/load via UI
- Form submission flow
- Error message display

**Selectors Tested**:
```python
group_name_input = driver.find_element(By.ID, "group_name_input")
correlate_checkbox = driver.find_element(By.NAME, "run_correlation")
generate_button = driver.find_element(By.ID, "generate_btn")
```

**Reason for Archive**: Form structure changed with tabbed UI
- Fields moved into tab-specific sections
- New tab navigation required
- New upload form added
- Different checkbox layouts

**To Resurrect**:
1. Install Selenium: `pip install selenium`
2. Update selectors to match new `templates/index.html`
3. Add tab switching logic:
   ```python
   # Click Upload tab
   upload_tab = driver.find_element(By.CSS_SELECTOR, '[data-tab="upload"]')
   upload_tab.click()
   ```
4. Update test expectations for new UI flow
5. Move back to `tests/`

**Dependencies**:
```bash
pip install selenium webdriver-manager
```

---

### test_selenium_navigation.py - UI Navigation Testing

**Original Purpose**: Test navigation flows and page transitions

**Status**: ⚠️ Likely Broken
**Last Updated**: October 2024
**Lines**: 531
**Issue**: Tests old navigation patterns

**Tests Included**:
- Home page to manual form navigation
- Progress page updates
- Back/forward navigation
- Direct URL access
- Session persistence

**Navigation Flows Tested**:
1. `/` → `/manual`
2. `/` → `/generate` → `/progress`
3. `/manual` → `/manual_submit` → `/progress`

**Reason for Archive**: Navigation changed with tabbed UI
- Single-page tab switching (no page loads)
- Different progress tracking
- New upload workflow

**To Resurrect**:
1. Update navigation to use tab switching instead of page loads
2. Update selectors for new UI elements
3. Add tests for new upload workflow
4. Test tab persistence on page reload
5. Move back to `tests/`

---

## General Resurrection Steps

If you want to resurrect these tests:

1. **Start Fresh**: Consider rewriting from scratch for new UI
2. **Reference Only**: Use these as examples, don't copy directly
3. **Modern Tools**: Consider Playwright instead of Selenium
4. **Smaller Scope**: Break into smaller, focused test files

### Example: Modern UI Test with Playwright

```python
# tests/test_ui_tabs.py
import pytest
from playwright.sync_api import Page, expect

def test_tab_switching(page: Page):
    page.goto("http://localhost:8000")

    # Click Upload tab
    page.click('[data-tab="upload"]')

    # Verify tab is active
    upload_tab = page.locator('[data-tab="upload"]')
    expect(upload_tab).to_have_class(/active/)

    # Verify upload pane is visible
    upload_pane = page.locator('#tab-upload')
    expect(upload_pane).to_be_visible()
```

## Deletion Policy

These archived tests will be kept until:
1. New equivalent tests are written for current UI
2. 6 months have passed with no one requesting them
3. Codebase cleanup is needed

## Questions?

If you need to reference or resurrect any of these tests, see:
- Current UI structure: `templates/index.html`
- Current JS: `static/js/tabs.js`
- Current CSS: `static/css/tabs.css`
- Active tests: `tests/README.md`
