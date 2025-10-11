# Playwright Test Suite Documentation

This document provides detailed descriptions of all UI tests in the Archer application, explaining what each test does and how it validates the functionality.

## Test Organization

The test suite is organized into two main files:
- **test_ui_tabs.py** - Tests for tabbed interface, navigation, and individual tab functionality (26 tests)
- **test_ui_upload.py** - Tests for file upload features and workflows (23 tests)

**Total: 49 tests**

---

## test_ui_tabs.py - Tabbed Interface Tests

### TestTabbedInterface (7 tests)
Tests core tabbed interface functionality and navigation.

#### 1. test_page_loads
**Purpose:** Verify the main application page loads correctly
**What it does:**
- Navigates to http://localhost:8000
- Checks that the page title is "Archer Hunting Application"
- Verifies the main heading contains "Archer"

**Why it matters:** This is a smoke test ensuring the basic application loads and renders.

---

#### 2. test_all_tabs_present
**Purpose:** Ensure all three navigation tabs exist in the UI
**What it does:**
- Locates the Generate tab button (`[data-tab="generate"]`)
- Locates the Upload tab button (`[data-tab="upload"]`)
- Locates the Emulate tab button (`[data-tab="emulate"]`)
- Verifies all three are visible

**Why it matters:** Confirms the tabbed interface structure is complete.

---

#### 3. test_generate_tab_active_by_default
**Purpose:** Verify the Generate tab is the default active tab
**What it does:**
- Checks that the Generate tab button has the "active" CSS class
- Verifies the Generate tab pane (`#tab-generate`) is visible

**Why it matters:** Ensures proper default state for user experience.

---

#### 4. test_tab_switching
**Purpose:** Test navigation between tabs works correctly
**What it does:**
1. Clicks the Upload tab button
2. Verifies Upload tab becomes active (has "active" class)
3. Verifies Upload pane becomes visible
4. Verifies Generate pane becomes hidden
5. Clicks the Emulate tab button
6. Verifies Emulate tab becomes active and visible

**Why it matters:** Core navigation functionality - users must be able to switch between different features.

---

#### 5. test_tab_content_isolation
**Purpose:** Ensure only one tab pane is visible at a time
**What it does:**
1. Verifies initial state: Generate visible, Upload/Emulate hidden
2. Switches to Upload tab
3. Verifies: Upload visible, Generate/Emulate hidden
4. Switches to Emulate tab
5. Verifies: Emulate visible, Generate/Upload hidden

**Why it matters:** Prevents UI confusion and ensures clean single-tab display.

---

#### 6. test_tab_icons_present
**Purpose:** Verify each tab has its associated icon
**What it does:**
- Checks Generate tab for search icon (🔍)
- Checks Upload tab for upload icon (📤)
- Checks Emulate tab for play/execute icon (▶️)

**Why it matters:** Visual feedback helps users identify tab purposes quickly.

---

#### 7. test_tab_labels
**Purpose:** Verify tab labels have correct text
**What it does:**
- Confirms Generate tab contains "Generate"
- Confirms Upload tab contains "Upload"
- Confirms Emulate tab contains "Emulate"

**Why it matters:** Ensures clear labeling for accessibility and UX.

---

### TestGenerateTab (6 tests)
Tests the Generate tab functionality for MITRE ATT&CK-based query generation.

#### 8. test_generate_form_present
**Purpose:** Verify the Generate form and its key elements exist
**What it does:**
- Locates the technique input field (`#technique-input`)
- Locates the group input field (`#group-input`)
- Locates the generate button (`#generate-btn`)
- Verifies all are visible

**Why it matters:** Ensures the core form structure is rendered.

---

#### 9. test_generate_button_disabled_initially
**Purpose:** Ensure Generate button is disabled when form is empty
**What it does:**
- Checks that the Generate button has the `disabled` attribute

**Why it matters:** Prevents users from submitting empty forms, reducing errors.

---

#### 10. test_generate_button_enabled_with_input
**Purpose:** Verify Generate button enables when user enters data
**What it does:**
1. Types "T1059" into the technique input field
2. Waits 100ms for JavaScript validation
3. Verifies the Generate button is no longer disabled

**Why it matters:** Confirms form validation allows valid submissions.

---

#### 11. test_group_name_validation
**Purpose:** Test validation messaging for invalid group names
**What it does:**
1. Types "InvalidGroup123" into the group input field
2. Clicks outside the input to trigger validation (blur event)
3. Verifies an error message appears
4. Checks the error message is visible

**Why it matters:** Ensures users get feedback on invalid input.

---

#### 12. test_advanced_options_collapsible
**Purpose:** Verify the advanced options section can expand/collapse
**What it does:**
1. Locates the `<details>` element (collapsible section)
2. Verifies it doesn't have the `open` attribute (is collapsed)
3. Clicks the `<summary>` element to expand
4. Verifies the `open` attribute is now present (is expanded)

**Why it matters:** Advanced options should be hidden by default to avoid overwhelming users.

---

#### 13. test_checkbox_options
**Purpose:** Test that checkbox options are present and functional
**What it does:**
1. Opens the advanced options section
2. Locates the "Run Correlation" checkbox (scoped to `#tab-generate`)
3. Locates the "Semantic" checkbox
4. Verifies both are visible
5. Checks the correlation checkbox
6. Verifies it becomes checked

**Why it matters:** Users need to control optional features like correlation analysis.

---

### TestUploadTab (5 tests)
Tests the Upload tab interface elements.

#### 14. test_upload_form_present
**Purpose:** Verify the Upload form structure exists
**What it does:**
- Switches to Upload tab
- Locates the upload dropzone (`#upload-dropzone`)
- Locates the upload button (`#upload-btn`)
- Verifies both are visible

**Why it matters:** Core upload interface must be present.

---

#### 15. test_upload_dropzone_visible
**Purpose:** Ensure the drag-and-drop area is visible
**What it does:**
- Switches to Upload tab
- Locates the dropzone element
- Verifies it has the `upload-area` class
- Verifies it's visible

**Why it matters:** Users need a clear target area for drag-and-drop uploads.

---

#### 16. test_upload_button_disabled_initially
**Purpose:** Verify Upload button is disabled without a file
**What it does:**
- Switches to Upload tab
- Checks that the Upload button is disabled

**Why it matters:** Prevents users from submitting without selecting a file.

---

#### 17. test_file_selection_button
**Purpose:** Verify the "Select File" button exists
**What it does:**
- Switches to Upload tab
- Locates the Select File button (`#select-file-btn`)
- Verifies it's visible and clickable

**Why it matters:** Provides alternative to drag-and-drop for file selection.

---

#### 18. test_supported_formats_message
**Purpose:** Ensure supported file formats are displayed
**What it does:**
- Switches to Upload tab
- Checks that the dropzone text mentions supported formats (PDF, TXT, JSON, CSV, YARA)

**Why it matters:** Users need to know what file types are accepted.

---

### TestEmulateTab (5 tests)
Tests the Emulate tab functionality for threat emulation.

#### 19. test_emulate_form_present
**Purpose:** Verify the Emulate form structure exists
**What it does:**
- Switches to Emulate tab
- Locates the technique input field
- Locates the group input field
- Locates the emulate button
- Verifies all are visible

**Why it matters:** Core emulation interface must be present.

---

#### 20. test_technique_input_present
**Purpose:** Verify the technique input field works
**What it does:**
- Switches to Emulate tab
- Locates technique input (`#emulate-technique-input`)
- Types "T1059.001"
- Verifies the input value is correct

**Why it matters:** Users must be able to specify which techniques to emulate.

---

#### 21. test_emulate_button_disabled_initially
**Purpose:** Ensure Emulate button is disabled when form is empty
**What it does:**
- Switches to Emulate tab
- Checks that the Emulate button is disabled

**Why it matters:** Prevents empty form submission.

---

#### 22. test_emulate_button_enabled_with_input
**Purpose:** Verify Emulate button enables with valid input
**What it does:**
1. Switches to Emulate tab
2. Types "T1059" into technique input
3. Waits for validation
4. Verifies button is enabled

**Why it matters:** Confirms form validation allows valid submissions.

---

#### 23. test_execution_mode_radios
**Purpose:** Test execution mode radio buttons (Simulate vs Live)
**What it does:**
1. Locates "Simulate" radio button
2. Locates "Live" radio button
3. Verifies "Simulate" is checked by default
4. Verifies "Live" is not checked
5. Clicks "Live" radio button
6. Verifies "Live" becomes checked
7. Verifies "Simulate" becomes unchecked

**Why it matters:** Critical safety feature - users must explicitly choose live execution mode.

---

#### 24. test_remote_execution_toggle
**Purpose:** Test remote execution configuration toggle
**What it does:**
1. Switches to Emulate tab
2. Opens advanced options (with force click to handle obscured element)
3. Locates remote execution checkbox (scoped to `#tab-emulate`)
4. Locates remote config section (`#remote-config`)
5. Verifies remote config is hidden initially
6. Checks the remote execution checkbox
7. Verifies remote config section becomes visible

**Why it matters:** Remote execution options should only appear when needed, keeping UI clean.

---

### TestResponsiveDesign (2 tests)
Tests responsive design across different viewport sizes.

#### 25. test_mobile_viewport
**Purpose:** Verify UI works on mobile screen sizes
**What it does:**
1. Sets viewport to 375x667 pixels (iPhone size)
2. Navigates to the app
3. Verifies tabs are still visible
4. Verifies content remains accessible

**Why it matters:** Many security professionals use mobile devices for monitoring/triage.

---

#### 26. test_tablet_viewport
**Purpose:** Verify UI works on tablet screen sizes
**What it does:**
1. Sets viewport to 768x1024 pixels (iPad size)
2. Navigates to the app
3. Verifies tabs are still visible
4. Verifies content remains accessible

**Why it matters:** Ensures usability across common device sizes.

---

## test_ui_upload.py - File Upload Tests

### TestFileUploadInterface (5 tests)
Tests file upload UI elements.

#### 27. test_upload_tab_has_dropzone
**Purpose:** Verify upload dropzone exists and has correct styling
**What it does:**
- Switches to Upload tab
- Locates dropzone (`#upload-dropzone`)
- Verifies it's visible
- Verifies it has the `upload-area` CSS class

**Why it matters:** Dropzone is the primary upload mechanism.

---

#### 28. test_upload_instructions_visible
**Purpose:** Ensure upload instructions are clear
**What it does:**
- Switches to Upload tab
- Locates upload text element
- Verifies it contains "Choose file"
- Verifies it contains "drag it here"

**Why it matters:** Clear instructions improve user experience.

---

#### 29. test_supported_formats_listed
**Purpose:** Verify supported file formats are displayed
**What it does:**
- Switches to Upload tab
- Checks dropzone text for "PDF", "TXT", "JSON"

**Why it matters:** Users need to know what file types are accepted before attempting upload.

---

#### 30. test_select_file_button_present
**Purpose:** Verify the "Select File" button exists
**What it does:**
- Switches to Upload tab
- Locates select file button
- Verifies it's visible

**Why it matters:** Alternative to drag-and-drop for file selection.

---

#### 31. test_upload_button_disabled_without_file
**Purpose:** Ensure Upload button is disabled until file is selected
**What it does:**
- Switches to Upload tab
- Verifies Upload button is disabled

**Why it matters:** Prevents submission without a file.

---

### TestFileSelection (5 tests)
Tests file selection and display functionality.

#### 32. test_file_input_accepts_pdf
**Purpose:** Verify PDF file selection works
**What it does:**
1. Switches to Upload tab
2. Creates a temporary PDF file (fixture)
3. Sets the file input to the PDF path
4. Verifies file name is displayed ("threat_report.pdf")

**Why it matters:** PDF is a common format for threat intelligence reports.

---

#### 33. test_file_input_accepts_txt
**Purpose:** Verify TXT file selection works
**What it does:**
1. Switches to Upload tab
2. Creates a temporary TXT file with sample threat data (fixture)
3. Sets the file input to the TXT path
4. Verifies file name is displayed

**Why it matters:** Plain text is often used for IOC lists and reports.

---

#### 34. test_file_input_accepts_json
**Purpose:** Verify JSON file selection works
**What it does:**
1. Switches to Upload tab
2. Creates a temporary JSON file with sample IOCs (fixture)
3. Sets the file input to the JSON path
4. Verifies file name is displayed

**Why it matters:** JSON is common for structured threat data.

---

#### 35. test_clear_file_selection
**Purpose:** Test clearing a selected file
**What it does:**
1. Switches to Upload tab
2. Selects a file
3. Verifies file name appears
4. Clicks the clear/remove button
5. Verifies file name disappears
6. Verifies Upload button becomes disabled again

**Why it matters:** Users need ability to change their file selection.

---

#### 36. test_file_icon_displayed
**Purpose:** Verify file type icon appears after selection
**What it does:**
1. Switches to Upload tab
2. Selects a PDF file
3. Verifies a file icon element becomes visible

**Why it matters:** Visual feedback confirms successful file selection.

---

### TestUploadOptions (5 tests)
Tests upload configuration options.

#### 37. test_upload_options_section
**Purpose:** Verify upload options section exists
**What it does:**
- Switches to Upload tab
- Locates options section
- Verifies it's visible

**Why it matters:** Users need to configure upload behavior.

---

#### 38. test_openai_enhancement_option
**Purpose:** Test OpenAI enhancement checkbox
**What it does:**
1. Switches to Upload tab
2. Opens options section
3. Locates "Use OpenAI Enhancement" checkbox
4. Verifies it's visible and unchecked by default
5. Checks the checkbox
6. Verifies it becomes checked

**Why it matters:** Users need control over AI-powered extraction (costs money/requires API key).

---

#### 39. test_auto_generate_option
**Purpose:** Test auto-generate queries checkbox
**What it does:**
1. Switches to Upload tab
2. Opens options section
3. Locates "Auto-generate Queries" checkbox
4. Verifies it's visible
5. Checks the checkbox
6. Verifies it becomes checked

**Why it matters:** Users may want to just extract TTPs or also generate queries automatically.

---

#### 40. test_correlation_option
**Purpose:** Test correlation analysis checkbox
**What it does:**
1. Switches to Upload tab
2. Opens options section
3. Locates "Run Correlation" checkbox (scoped to `#tab-upload`)
4. Verifies it's visible
5. Checks the checkbox
6. Verifies it becomes checked

**Why it matters:** Correlation is optional and resource-intensive.

---

#### 41. test_options_toggle
**Purpose:** Test collapsible options section
**What it does:**
1. Switches to Upload tab
2. Locates options `<details>` element
3. Verifies it's closed initially (no `open` attribute)
4. Clicks to open
5. Verifies `open` attribute is present
6. Verifies options grid is visible
7. Clicks to close
8. Verifies `open` attribute is removed

**Why it matters:** Keeps UI clean by hiding advanced options by default.

---

### TestDragAndDrop (2 tests)
Tests drag-and-drop file upload functionality.

#### 42. test_dropzone_hover_effect
**Purpose:** Verify visual feedback during drag-over
**What it does:**
1. Switches to Upload tab
2. Creates a sample file
3. Simulates dragging file over dropzone (dragover event)
4. Verifies dropzone gets "dragover" CSS class
5. Simulates drag leave
6. Verifies "dragover" class is removed

**Why it matters:** Visual feedback confirms the dropzone is ready to accept the file.

---

#### 43. test_dropzone_click_triggers_file_dialog
**Purpose:** Test clicking dropzone opens file picker
**What it does:**
1. Switches to Upload tab
2. Clicks the dropzone
3. Verifies this triggers the hidden file input click (opens file dialog)

**Why it matters:** Provides intuitive alternative to drag-and-drop.

---

### TestUploadFlow (3 tests)
Tests complete file upload workflows.

#### 44. test_upload_workflow_with_auto_generate
**Purpose:** Test full upload workflow with auto-generation enabled
**What it does:**
1. Switches to Upload tab
2. Selects a TXT file with threat intel
3. Opens options and enables "Auto-generate Queries"
4. Clicks Upload button
5. Waits for processing
6. Verifies success message or redirect to results

**Why it matters:** Tests the complete happy-path workflow users will follow.

---

#### 45. test_upload_workflow_without_auto_generate
**Purpose:** Test upload workflow with just extraction (no query generation)
**What it does:**
1. Switches to Upload tab
2. Selects a file
3. Ensures "Auto-generate Queries" is unchecked
4. Clicks Upload button
5. Verifies extraction results are displayed
6. Verifies no queries are generated

**Why it matters:** Users may want to review extracted TTPs before generating queries.

---

#### 46. test_multiple_file_selections
**Purpose:** Test changing file selection multiple times
**What it does:**
1. Switches to Upload tab
2. Selects file A
3. Verifies file A name is displayed
4. Selects file B (replaces file A)
5. Verifies file B name is displayed
6. Verifies file A is no longer shown

**Why it matters:** Users should be able to change their minds before uploading.

---

### TestAccessibility (3 tests)
Tests accessibility features for screen readers and keyboard navigation.

#### 47. test_form_labels_present
**Purpose:** Verify all form inputs have associated labels
**What it does:**
1. Switches to Upload tab
2. Checks that file input has a label
3. Checks that checkboxes have labels
4. Verifies label text is descriptive

**Why it matters:** Screen readers need labels to describe inputs to visually impaired users.

---

#### 48. test_keyboard_navigation
**Purpose:** Test navigation using only keyboard (Tab key)
**What it does:**
1. Switches to Upload tab
2. Presses Tab key repeatedly
3. Verifies focus moves through: file input → checkboxes → upload button
4. Verifies each element becomes focused in logical order

**Why it matters:** Keyboard-only users (accessibility) must be able to navigate the form.

---

#### 49. test_aria_labels
**Purpose:** Verify ARIA labels exist for screen reader support
**What it does:**
1. Switches to Upload tab
2. Checks dropzone has `aria-label` attribute
3. Checks upload button has `aria-label` attribute
4. Verifies labels are descriptive

**Why it matters:** ARIA labels provide additional context for assistive technologies.

---

## Running the Tests

### Run all tests:
```bash
pytest tests/test_ui_*.py -v
```

### Run specific test class:
```bash
pytest tests/test_ui_tabs.py::TestTabbedInterface -v
```

### Run specific test:
```bash
pytest tests/test_ui_tabs.py::TestTabbedInterface::test_page_loads -v
```

### Run with markers:
```bash
# Run only UI tests
pytest -m ui -v

# Skip slow tests
pytest -m "not slow" -v
```

### Debug mode (show browser):
```bash
pytest tests/test_ui_tabs.py --headed --slowmo=500
```

## Test Fixtures

### Fixtures in conftest.py:
- `browser_context_args` - Browser configuration (viewport, locale, timezone)
- `base_url` - Application URL (http://localhost:8000)
- `page` - Fresh browser page for each test
- `temp_text_file` - Temporary TXT file with sample threat data
- `sample_pdf_path` - Temporary PDF file for upload tests
- `sample_json_path` - Temporary JSON file with sample IOCs

### Temporary Files Created:
All temporary files are created in pytest's `tmp_path` and automatically cleaned up after tests complete.

## Test Coverage Summary

| Category | Tests | Coverage |
|----------|-------|----------|
| Tabbed Interface | 7 | Tab navigation, visibility, isolation |
| Generate Tab | 6 | Form validation, options, buttons |
| Upload Tab | 5 | Dropzone, instructions, buttons |
| Emulate Tab | 5 | Form inputs, execution modes, remote config |
| Responsive Design | 2 | Mobile and tablet viewports |
| File Selection | 5 | PDF, TXT, JSON file handling |
| Upload Options | 5 | Checkboxes, collapsible sections |
| Drag and Drop | 2 | Visual feedback, file dialog |
| Upload Workflow | 3 | End-to-end upload scenarios |
| Accessibility | 3 | Labels, keyboard nav, ARIA |
| **Total** | **49** | **Comprehensive UI coverage** |

## Key Testing Patterns Used

### 1. Locator Scoping
To avoid "strict mode violations" when multiple tabs have similar elements:
```python
# Bad - matches elements in all tabs
page.locator('input[name="run_correlation"]')

# Good - scoped to specific tab
page.locator('#tab-generate input[name="run_correlation"]')
```

### 2. Force Click
For elements that might be partially obscured:
```python
advanced_options.locator('summary').click(force=True)
```

### 3. Regex Pattern Matching
For CSS class assertions:
```python
expect(element).to_have_class(re.compile(r"active"))
```

### 4. Attribute Checking
For HTML boolean attributes:
```python
expect(element).to_have_attribute('open', '')  # Has attribute
expect(element).not_to_have_attribute('open', '')  # Doesn't have attribute
```

---

## Troubleshooting

### Tests fail with "Target page, context or browser has been closed"
**Solution:** Ensure the application is running at http://localhost:8000 before running tests.

### Tests fail with "Timeout exceeded"
**Solution:**
1. Increase timeout in playwright.config.py
2. Check if application is slow to respond
3. Use `--headed --slowmo=500` to debug

### Import errors
**Solution:** Install Playwright: `pip install playwright && playwright install`

### Browser not found
**Solution:** Run `playwright install chromium`

---

**Last Updated:** 2025-01-11
**Test Framework:** Playwright for Python
**Application:** Archer Threat Hunting Platform
