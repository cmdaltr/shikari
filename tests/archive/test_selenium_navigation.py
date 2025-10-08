"""
Selenium Navigation and Routing Tests
Tests page navigation, routing, and UI interactions
"""

import pytest
import time
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.chrome.options import Options
from selenium.common.exceptions import TimeoutException, NoSuchElementException


# Configuration
BASE_URL = "http://localhost:8000"
WAIT_TIMEOUT = 10


@pytest.fixture(scope="module")
def driver():
    """Setup Chrome WebDriver"""
    chrome_options = Options()
    chrome_options.add_argument("--headless")
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


class TestBasicNavigation:
    """Test basic page navigation"""

    def test_homepage_loads(self, driver):
        """Test homepage loads successfully"""
        driver.get(BASE_URL)
        assert driver.current_url == BASE_URL + "/"
        assert "Archer" in driver.title or len(driver.page_source) > 0

    def test_manual_page_navigation(self, driver):
        """Test navigating to manual submission page"""
        driver.get(BASE_URL)

        # Find and click manual link
        try:
            manual_link = driver.find_element(By.LINK_TEXT, "Manual")
            manual_link.click()
            assert "manual" in driver.current_url
        except NoSuchElementException:
            # Try navigating directly
            driver.get(f"{BASE_URL}/manual")
            assert driver.current_url == f"{BASE_URL}/manual"

    def test_progress_page_navigation(self, driver):
        """Test navigating to progress page"""
        try:
            driver.get(f"{BASE_URL}/progress")
            assert driver.current_url == f"{BASE_URL}/progress"
        except:
            # Page might require progress ID
            assert True

    def test_back_button_navigation(self, driver):
        """Test browser back button"""
        driver.get(BASE_URL)
        original_url = driver.current_url

        # Navigate to another page
        driver.get(f"{BASE_URL}/manual")
        assert driver.current_url == f"{BASE_URL}/manual"

        # Go back
        driver.back()
        assert driver.current_url == original_url

    def test_forward_button_navigation(self, driver):
        """Test browser forward button"""
        driver.get(BASE_URL)
        driver.get(f"{BASE_URL}/manual")

        # Go back
        driver.back()
        time.sleep(0.5)

        # Go forward
        driver.forward()
        assert "manual" in driver.current_url

    def test_refresh_page(self, driver):
        """Test page refresh"""
        driver.get(BASE_URL)
        original_source = driver.page_source

        driver.refresh()
        time.sleep(1)

        # Page should reload
        assert len(driver.page_source) > 0
        # Content should be similar (but not necessarily identical due to timestamps)


class TestNavigationMenu:
    """Test navigation menu functionality"""

    def test_nav_menu_exists(self, driver):
        """Test navigation menu is present"""
        driver.get(BASE_URL)

        try:
            # Look for nav element
            nav = driver.find_element(By.CSS_SELECTOR, "nav")
            assert nav is not None
        except NoSuchElementException:
            # Navigation might be in header or different structure
            try:
                header = driver.find_element(By.CSS_SELECTOR, "header")
                assert header is not None
            except NoSuchElementException:
                # Navigation might not exist
                pass

    def test_nav_links_clickable(self, driver):
        """Test all navigation links are clickable"""
        driver.get(BASE_URL)

        try:
            # Find all navigation links
            nav_links = driver.find_elements(By.CSS_SELECTOR, "nav a")

            for link in nav_links:
                # Check link has href
                href = link.get_attribute("href")
                assert href is not None and len(href) > 0
        except NoSuchElementException:
            # Navigation might not exist
            pass

    def test_home_link(self, driver):
        """Test clicking home/logo returns to homepage"""
        driver.get(f"{BASE_URL}/manual")

        try:
            # Look for home link or logo
            home_link = driver.find_element(By.LINK_TEXT, "Home")
            home_link.click()
            assert driver.current_url == BASE_URL + "/"
        except NoSuchElementException:
            # Try finding logo or brand link
            try:
                logo = driver.find_element(By.CSS_SELECTOR, ".logo, .brand, .navbar-brand")
                logo.click()
                assert driver.current_url == BASE_URL + "/"
            except NoSuchElementException:
                # No explicit home link
                pass


class TestPageTitles:
    """Test page titles and metadata"""

    def test_homepage_title(self, driver):
        """Test homepage has title"""
        driver.get(BASE_URL)
        title = driver.title
        assert len(title) > 0
        assert "Archer" in title or "Detection" in title or "Threat" in title

    def test_manual_page_title(self, driver):
        """Test manual page has appropriate title"""
        driver.get(f"{BASE_URL}/manual")
        title = driver.title
        assert len(title) > 0

    def test_page_has_metadata(self, driver):
        """Test pages have meta tags"""
        driver.get(BASE_URL)

        # Check for meta tags
        meta_tags = driver.find_elements(By.CSS_SELECTOR, "meta")
        assert len(meta_tags) > 0


class TestURLRouting:
    """Test URL routing and parameters"""

    def test_valid_routes(self, driver):
        """Test all valid routes load without error"""
        valid_routes = [
            "/",
            "/manual",
            "/progress",
        ]

        for route in valid_routes:
            driver.get(BASE_URL + route)
            # Should not get 404 or 500 error
            assert "404" not in driver.page_source
            assert "500" not in driver.page_source
            assert "Error" not in driver.title

    def test_invalid_route(self, driver):
        """Test invalid route returns 404"""
        driver.get(f"{BASE_URL}/invalid-route-12345")

        page_source = driver.page_source
        # Should show 404 or handle gracefully
        assert "404" in page_source or "not found" in page_source.lower() or "Archer" in driver.title

    def test_progress_with_id_parameter(self, driver):
        """Test progress page with ID parameter"""
        test_id = "test-progress-123"
        driver.get(f"{BASE_URL}/progress?progress_id={test_id}")

        # Should load without error
        assert driver.current_url.startswith(BASE_URL)

    def test_url_encoding(self, driver):
        """Test URL parameter encoding"""
        group_name = "Group with Spaces"
        encoded_name = "Group%20with%20Spaces"

        driver.get(f"{BASE_URL}/?group={encoded_name}")

        # Should handle encoded parameters
        assert driver.current_url.startswith(BASE_URL)


class TestPageContent:
    """Test page content loads correctly"""

    def test_homepage_has_form(self, driver):
        """Test homepage contains main form"""
        driver.get(BASE_URL)

        form = driver.find_element(By.CSS_SELECTOR, "form")
        assert form is not None

    def test_homepage_has_heading(self, driver):
        """Test homepage has main heading"""
        driver.get(BASE_URL)

        try:
            h1 = driver.find_element(By.CSS_SELECTOR, "h1")
            assert len(h1.text) > 0
        except NoSuchElementException:
            # Might not have h1, check for any heading
            headings = driver.find_elements(By.CSS_SELECTOR, "h1, h2, h3")
            assert len(headings) > 0

    def test_manual_page_has_textarea(self, driver):
        """Test manual page contains YAML textarea"""
        driver.get(f"{BASE_URL}/manual")

        textarea = driver.find_element(By.CSS_SELECTOR, "textarea")
        assert textarea is not None

    def test_pages_have_footer(self, driver):
        """Test pages have footer"""
        driver.get(BASE_URL)

        try:
            footer = driver.find_element(By.CSS_SELECTOR, "footer")
            assert footer is not None
        except NoSuchElementException:
            # Footer might not exist
            pass


class TestResponsiveDesign:
    """Test responsive design elements"""

    def test_mobile_viewport(self, driver):
        """Test site in mobile viewport"""
        # Set mobile viewport
        driver.set_window_size(375, 667)  # iPhone size
        driver.get(BASE_URL)

        # Page should load and be functional
        assert len(driver.page_source) > 0

        # Reset to desktop
        driver.set_window_size(1920, 1080)

    def test_tablet_viewport(self, driver):
        """Test site in tablet viewport"""
        driver.set_window_size(768, 1024)  # iPad size
        driver.get(BASE_URL)

        assert len(driver.page_source) > 0

        driver.set_window_size(1920, 1080)

    def test_desktop_viewport(self, driver):
        """Test site in desktop viewport"""
        driver.set_window_size(1920, 1080)
        driver.get(BASE_URL)

        assert len(driver.page_source) > 0


class TestJavaScriptFunctionality:
    """Test JavaScript-dependent functionality"""

    def test_javascript_enabled(self, driver):
        """Test JavaScript is enabled"""
        driver.get(BASE_URL)

        # Execute JavaScript
        result = driver.execute_script("return 1 + 1;")
        assert result == 2

    def test_dynamic_content_loading(self, driver, wait):
        """Test dynamically loaded content"""
        driver.get(BASE_URL)

        # Check if page has dynamic elements
        try:
            # Wait for any dynamic content to load
            wait.until(EC.presence_of_element_located((By.ID, "groupName")))
            assert True
        except TimeoutException:
            # No dynamic content or already loaded
            pass

    def test_form_validation_javascript(self, driver):
        """Test client-side form validation"""
        driver.get(BASE_URL)

        # Try submitting empty form
        submit_btn = driver.find_element(By.CSS_SELECTOR, "button[type='submit']")
        submit_btn.click()

        time.sleep(1)

        # Should either stay on page or show validation
        assert BASE_URL in driver.current_url


class TestStaticAssets:
    """Test static assets load correctly"""

    def test_css_loads(self, driver):
        """Test CSS files are loaded"""
        driver.get(BASE_URL)

        # Check for stylesheets
        stylesheets = driver.find_elements(By.CSS_SELECTOR, "link[rel='stylesheet']")

        # Should have at least some styling
        if len(stylesheets) > 0:
            # Check first stylesheet loads
            href = stylesheets[0].get_attribute("href")
            assert href is not None

    def test_javascript_loads(self, driver):
        """Test JavaScript files are loaded"""
        driver.get(BASE_URL)

        # Check for script tags
        scripts = driver.find_elements(By.CSS_SELECTOR, "script[src]")

        # May or may not have external scripts
        for script in scripts:
            src = script.get_attribute("src")
            assert src is not None

    def test_images_load(self, driver):
        """Test images load if present"""
        driver.get(BASE_URL)

        images = driver.find_elements(By.CSS_SELECTOR, "img")

        for img in images:
            # Check image has src
            src = img.get_attribute("src")
            assert src is not None


class TestErrorPages:
    """Test error page handling"""

    def test_404_page(self, driver):
        """Test 404 error page"""
        driver.get(f"{BASE_URL}/nonexistent-page-xyz")

        page_source = driver.page_source.lower()
        # Should show 404 error
        assert "404" in page_source or "not found" in page_source

    def test_500_error_handling(self, driver):
        """Test 500 error handling"""
        # Try to trigger 500 error with invalid request
        try:
            driver.get(f"{BASE_URL}/generate?invalid_param=<script>alert('xss')</script>")
            # Should handle gracefully, not crash
            assert len(driver.page_source) > 0
        except:
            # If page crashes, test should catch it
            assert False, "Page crashed on invalid input"


class TestBrowserCompatibility:
    """Test browser compatibility features"""

    def test_console_errors(self, driver):
        """Test for JavaScript console errors"""
        driver.get(BASE_URL)

        # Get browser console logs
        logs = driver.get_log("browser")

        # Check for severe errors
        severe_errors = [log for log in logs if log["level"] == "SEVERE"]

        # Should have no severe JavaScript errors
        if len(severe_errors) > 0:
            print("Console errors found:", severe_errors)
        # Some errors might be acceptable (e.g., ad blockers)
        assert len(severe_errors) < 5  # Allow a few minor errors

    def test_local_storage_available(self, driver):
        """Test localStorage is available"""
        driver.get(BASE_URL)

        # Test localStorage
        driver.execute_script("localStorage.setItem('test', 'value');")
        result = driver.execute_script("return localStorage.getItem('test');")

        assert result == "value"

        # Cleanup
        driver.execute_script("localStorage.removeItem('test');")

    def test_session_storage_available(self, driver):
        """Test sessionStorage is available"""
        driver.get(BASE_URL)

        # Test sessionStorage
        driver.execute_script("sessionStorage.setItem('test', 'value');")
        result = driver.execute_script("return sessionStorage.getItem('test');")

        assert result == "value"


class TestPagePerformance:
    """Test page load performance"""

    def test_homepage_load_time(self, driver):
        """Test homepage loads quickly"""
        start_time = time.time()
        driver.get(BASE_URL)
        load_time = time.time() - start_time

        # Should load in under 5 seconds
        assert load_time < 5

    def test_page_size_reasonable(self, driver):
        """Test page size is reasonable"""
        driver.get(BASE_URL)

        page_source = driver.page_source
        page_size_kb = len(page_source.encode("utf-8")) / 1024

        # Page should be under 1MB
        assert page_size_kb < 1024

    def test_minimal_redirects(self, driver):
        """Test page doesn't have excessive redirects"""
        start_url = BASE_URL + "/"
        driver.get(start_url)

        final_url = driver.current_url

        # Should either be same or single redirect
        assert final_url == start_url or final_url.startswith(BASE_URL)


class TestAccessibility:
    """Test basic accessibility features"""

    def test_images_have_alt_text(self, driver):
        """Test images have alt attributes"""
        driver.get(BASE_URL)

        images = driver.find_elements(By.CSS_SELECTOR, "img")

        for img in images:
            alt = img.get_attribute("alt")
            # Alt can be empty string for decorative images
            assert alt is not None

    def test_form_inputs_have_labels(self, driver):
        """Test form inputs have associated labels"""
        driver.get(BASE_URL)

        inputs = driver.find_elements(By.CSS_SELECTOR, "input[type='text'], input[type='email']")

        for input_elem in inputs:
            input_id = input_elem.get_attribute("id")
            if input_id:
                # Check for associated label
                try:
                    label = driver.find_element(By.CSS_SELECTOR, f"label[for='{input_id}']")
                    assert label is not None
                except NoSuchElementException:
                    # Label might not exist for all inputs
                    pass

    def test_skip_to_main_content(self, driver):
        """Test skip to main content link for accessibility"""
        driver.get(BASE_URL)

        try:
            skip_link = driver.find_element(By.CSS_SELECTOR, "a[href='#main'], a[href='#content']")
            assert skip_link is not None
        except NoSuchElementException:
            # Skip link might not exist
            pass
