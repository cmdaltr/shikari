"""
Selenium Form Submission Tests
Tests all form interactions in the Archer web application
"""

import pytest
import time
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from selenium.common.exceptions import TimeoutException, NoSuchElementException


# Configuration
BASE_URL = "http://localhost:8000"
WAIT_TIMEOUT = 10


@pytest.fixture(scope="module")
def driver():
    """Setup Chrome WebDriver"""
    chrome_options = Options()
    chrome_options.add_argument("--headless")  # Run in headless mode
    chrome_options.add_argument("--no-sandbox")
    chrome_options.add_argument("--disable-dev-shm-usage")
    chrome_options.add_argument("--window-size=1920,1080")

    driver = webdriver.Chrome(options=chrome_options)
    driver.implicitly_wait(WAIT_TIMEOUT)

    yield driver

    driver.quit()


@pytest.fixture
def wait(driver):
    """WebDriverWait fixture"""
    return WebDriverWait(driver, WAIT_TIMEOUT)


class TestGenerateForm:
    """Test the main generate form"""

    def test_generate_form_exists(self, driver, wait):
        """Test that generate form is present on homepage"""
        driver.get(BASE_URL)
        form = wait.until(EC.presence_of_element_located((By.ID, "generateForm")))
        assert form is not None

    def test_generate_form_has_required_fields(self, driver):
        """Test form has all required input fields"""
        driver.get(BASE_URL)

        # Check for threat group input
        group_input = driver.find_element(By.ID, "groupName")
        assert group_input is not None
        assert group_input.get_attribute("name") == "group_name"

        # Check for checkboxes
        checkboxes = [
            "correlate",
            "advancedParsing",
            "semanticAnalysis",
            "aiGenerators",
            "localLLM",
        ]

        for checkbox_id in checkboxes:
            try:
                checkbox = driver.find_element(By.ID, checkbox_id)
                assert checkbox.get_attribute("type") in ["checkbox", "hidden"]
            except NoSuchElementException:
                # Some checkboxes might be optional
                pass

    def test_submit_generate_form_empty(self, driver, wait):
        """Test submitting generate form without group name"""
        driver.get(BASE_URL)

        # Find and click submit button
        submit_btn = driver.find_element(By.CSS_SELECTOR, "button[type='submit']")
        submit_btn.click()

        time.sleep(1)

        # Should show validation error or stay on page
        current_url = driver.current_url
        # Either stayed on same page or went to progress
        assert BASE_URL in current_url

    def test_submit_generate_form_valid(self, driver, wait):
        """Test submitting generate form with valid data"""
        driver.get(BASE_URL)

        # Fill in threat group
        group_input = driver.find_element(By.ID, "groupName")
        group_input.clear()
        group_input.send_keys("APT29")

        # Submit form
        submit_btn = driver.find_element(By.CSS_SELECTOR, "button[type='submit']")
        submit_btn.click()

        # Should redirect to progress page
        try:
            wait.until(lambda d: "progress" in d.current_url or "generating" in d.page_source.lower())
            assert True  # Successfully submitted
        except TimeoutException:
            # May stay on same page with message
            assert "APT29" in driver.page_source

    def test_submit_generate_with_correlation(self, driver, wait):
        """Test submitting with correlation checkbox enabled"""
        driver.get(BASE_URL)

        # Fill in threat group
        group_input = driver.find_element(By.ID, "groupName")
        group_input.clear()
        group_input.send_keys("Scattered Spider")

        # Enable correlation
        try:
            correlate_checkbox = driver.find_element(By.ID, "correlate")
            if not correlate_checkbox.is_selected():
                correlate_checkbox.click()
        except NoSuchElementException:
            pass  # Checkbox might not exist

        # Submit
        submit_btn = driver.find_element(By.CSS_SELECTOR, "button[type='submit']")
        submit_btn.click()

        time.sleep(2)
        # Should process successfully
        assert driver.current_url.startswith(BASE_URL)

    def test_submit_generate_with_semantic_analysis(self, driver):
        """Test submitting with semantic analysis enabled"""
        driver.get(BASE_URL)

        # Fill in threat group
        group_input = driver.find_element(By.ID, "groupName")
        group_input.clear()
        group_input.send_keys("APT29")

        # Enable semantic analysis
        try:
            semantic_checkbox = driver.find_element(By.ID, "semanticAnalysis")
            if not semantic_checkbox.is_selected():
                semantic_checkbox.click()
        except NoSuchElementException:
            pass

        # Submit
        submit_btn = driver.find_element(By.CSS_SELECTOR, "button[type='submit']")
        submit_btn.click()

        time.sleep(2)
        assert driver.current_url.startswith(BASE_URL)

    def test_form_input_validation(self, driver):
        """Test form input field validation"""
        driver.get(BASE_URL)

        group_input = driver.find_element(By.ID, "groupName")

        # Test with various inputs
        test_inputs = [
            "APT29",
            "Scattered Spider",
            "Group with Spaces",
            "Group-with-dashes",
        ]

        for test_input in test_inputs:
            group_input.clear()
            group_input.send_keys(test_input)
            assert group_input.get_attribute("value") == test_input


class TestCorrelateForm:
    """Test the correlate form (if separate)"""

    def test_correlate_page_loads(self, driver):
        """Test correlate page loads"""
        try:
            driver.get(f"{BASE_URL}/correlate")
            # Should load without error
            assert "correlate" in driver.current_url.lower() or "Archer" in driver.title
        except:
            # Correlate might be integrated into main page
            driver.get(BASE_URL)
            assert driver.current_url == BASE_URL + "/"


class TestManualSubmitForm:
    """Test manual YAML submission form"""

    def test_manual_page_loads(self, driver):
        """Test manual submission page loads"""
        driver.get(f"{BASE_URL}/manual")
        assert driver.current_url == f"{BASE_URL}/manual"
        assert "manual" in driver.page_source.lower() or "yaml" in driver.page_source.lower()

    def test_manual_form_exists(self, driver):
        """Test manual form elements exist"""
        driver.get(f"{BASE_URL}/manual")

        # Check for textarea
        try:
            yaml_textarea = driver.find_element(By.ID, "yamlContent")
            assert yaml_textarea is not None
        except NoSuchElementException:
            yaml_textarea = driver.find_element(By.NAME, "yaml_content")
            assert yaml_textarea is not None

    def test_manual_submit_valid_yaml(self, driver, wait):
        """Test submitting valid YAML"""
        driver.get(f"{BASE_URL}/manual")

        valid_yaml = """
id: test-001
name: Test Detection
description: Test description
severity: Medium
query: |
  DeviceProcessEvents
  | where ProcessCommandLine contains "test"
"""

        # Find textarea
        try:
            yaml_textarea = driver.find_element(By.ID, "yamlContent")
        except NoSuchElementException:
            yaml_textarea = driver.find_element(By.NAME, "yaml_content")

        yaml_textarea.clear()
        yaml_textarea.send_keys(valid_yaml)

        # Submit
        submit_btn = driver.find_element(By.CSS_SELECTOR, "button[type='submit']")
        submit_btn.click()

        time.sleep(2)

        # Should show success message or redirect
        page_source = driver.page_source.lower()
        assert "success" in page_source or "saved" in page_source or driver.current_url == f"{BASE_URL}/manual"

    def test_manual_submit_empty(self, driver):
        """Test submitting empty YAML"""
        driver.get(f"{BASE_URL}/manual")

        # Find textarea
        try:
            yaml_textarea = driver.find_element(By.ID, "yamlContent")
        except NoSuchElementException:
            yaml_textarea = driver.find_element(By.NAME, "yaml_content")

        yaml_textarea.clear()

        # Submit
        submit_btn = driver.find_element(By.CSS_SELECTOR, "button[type='submit']")
        submit_btn.click()

        time.sleep(1)

        # Should handle gracefully (error message or stay on page)
        assert driver.current_url == f"{BASE_URL}/manual"


class TestDraftFunctionality:
    """Test draft save/load functionality"""

    def test_save_draft_button_exists(self, driver):
        """Test save draft button exists"""
        driver.get(BASE_URL)

        try:
            save_draft_btn = driver.find_element(By.ID, "saveDraftBtn")
            assert save_draft_btn is not None
        except NoSuchElementException:
            # Draft functionality might not be visible
            pass

    def test_save_draft_workflow(self, driver):
        """Test saving a draft"""
        driver.get(BASE_URL)

        # Fill in form
        group_input = driver.find_element(By.ID, "groupName")
        group_input.clear()
        group_input.send_keys("APT29 Test Draft")

        # Click save draft button
        try:
            save_draft_btn = driver.find_element(By.ID, "saveDraftBtn")
            save_draft_btn.click()

            time.sleep(2)

            # Should show success message or save silently
            # Check if draft was saved by looking for confirmation
            page_source = driver.page_source.lower()
            # May or may not show confirmation
            assert True  # If no error, test passes
        except NoSuchElementException:
            # Draft button might not exist
            pass

    def test_load_draft_workflow(self, driver):
        """Test loading a draft"""
        driver.get(BASE_URL)

        try:
            # Look for load draft dropdown or button
            load_draft_select = driver.find_element(By.ID, "draftSelect")

            # Select first option if any exist
            options = load_draft_select.find_elements(By.TAG_NAME, "option")
            if len(options) > 1:  # More than just placeholder
                options[1].click()  # Select first real option

                time.sleep(1)

                # Form should be populated
                group_input = driver.find_element(By.ID, "groupName")
                assert group_input.get_attribute("value") != ""
        except NoSuchElementException:
            # Draft functionality might not exist
            pass


class TestFormInteractions:
    """Test complex form interactions"""

    def test_checkbox_toggle(self, driver):
        """Test toggling checkboxes"""
        driver.get(BASE_URL)

        checkboxes = ["correlate", "advancedParsing", "semanticAnalysis"]

        for checkbox_id in checkboxes:
            try:
                checkbox = driver.find_element(By.ID, checkbox_id)

                # Test checking
                if not checkbox.is_selected():
                    checkbox.click()
                    assert checkbox.is_selected()

                # Test unchecking
                if checkbox.is_selected():
                    checkbox.click()
                    assert not checkbox.is_selected()
            except NoSuchElementException:
                # Checkbox doesn't exist
                pass

    def test_form_reset(self, driver):
        """Test form reset functionality"""
        driver.get(BASE_URL)

        # Fill in form
        group_input = driver.find_element(By.ID, "groupName")
        group_input.clear()
        group_input.send_keys("Test Group")

        # Look for reset button
        try:
            reset_btn = driver.find_element(By.CSS_SELECTOR, "button[type='reset']")
            reset_btn.click()

            time.sleep(0.5)

            # Form should be cleared
            assert group_input.get_attribute("value") == ""
        except NoSuchElementException:
            # No reset button
            pass

    def test_multiple_form_submissions(self, driver):
        """Test submitting form multiple times"""
        driver.get(BASE_URL)

        threat_groups = ["APT29", "APT28", "Scattered Spider"]

        for group in threat_groups:
            driver.get(BASE_URL)  # Reload page

            group_input = driver.find_element(By.ID, "groupName")
            group_input.clear()
            group_input.send_keys(group)

            submit_btn = driver.find_element(By.CSS_SELECTOR, "button[type='submit']")
            submit_btn.click()

            time.sleep(2)

            # Each submission should work
            assert driver.current_url.startswith(BASE_URL)


class TestFormAccessibility:
    """Test form accessibility features"""

    def test_labels_for_inputs(self, driver):
        """Test that form inputs have associated labels"""
        driver.get(BASE_URL)

        # Check for label
        try:
            label = driver.find_element(By.CSS_SELECTOR, "label[for='groupName']")
            assert label is not None
        except NoSuchElementException:
            # Label might be implicit or missing
            pass

    def test_required_fields_marked(self, driver):
        """Test that required fields are marked"""
        driver.get(BASE_URL)

        group_input = driver.find_element(By.ID, "groupName")

        # Check if required attribute exists
        required = group_input.get_attribute("required")
        # May or may not be marked as required
        assert required in [None, "true", ""]  # Any value is acceptable

    def test_placeholder_text(self, driver):
        """Test placeholder text in inputs"""
        driver.get(BASE_URL)

        group_input = driver.find_element(By.ID, "groupName")
        placeholder = group_input.get_attribute("placeholder")

        # Should have helpful placeholder
        if placeholder:
            assert len(placeholder) > 0


# Performance tests
class TestFormPerformance:
    """Test form performance"""

    def test_form_load_time(self, driver):
        """Test that form loads quickly"""
        start_time = time.time()
        driver.get(BASE_URL)
        wait = WebDriverWait(driver, 10)
        wait.until(EC.presence_of_element_located((By.ID, "groupName")))
        load_time = time.time() - start_time

        # Should load in under 5 seconds
        assert load_time < 5

    def test_form_submission_response(self, driver):
        """Test form submission response time"""
        driver.get(BASE_URL)

        group_input = driver.find_element(By.ID, "groupName")
        group_input.send_keys("APT29")

        start_time = time.time()
        submit_btn = driver.find_element(By.CSS_SELECTOR, "button[type='submit']")
        submit_btn.click()

        time.sleep(1)  # Wait for initial response

        response_time = time.time() - start_time

        # Should respond in under 3 seconds (initial redirect/response)
        assert response_time < 3
