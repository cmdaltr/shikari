"""
Playwright UI tests for secondary pages: login, register, library,
coverage, manual editor, how-it-works, progress.
"""
import pytest
import os

pytestmark = pytest.mark.ui


class TestLoginPage:
    """Login page rendering and form elements."""

    def test_login_page_renders(self, page, base_url, screenshot_dir):
        page.goto(f"{base_url}/login")
        page.wait_for_load_state("networkidle")
        page.screenshot(path=os.path.join(screenshot_dir, "40_login_page.png"))

    def test_login_form_elements(self, page, base_url):
        page.goto(f"{base_url}/login")
        page.wait_for_load_state("networkidle")

        assert page.locator('input[type="email"], input[name="email"]').count() > 0
        assert page.locator('input[type="password"]').count() > 0
        assert page.locator('button[type="submit"], input[type="submit"]').count() > 0

    def test_login_with_wrong_credentials(self, page, base_url, screenshot_dir):
        page.goto(f"{base_url}/login")
        page.wait_for_load_state("networkidle")

        page.locator('input[type="email"], input[name="email"]').first.fill("wrong@wrong.com")
        page.locator('input[type="password"]').first.fill("wrongpassword")
        page.locator('button[type="submit"], input[type="submit"]').first.click()
        page.wait_for_timeout(2000)

        page.screenshot(path=os.path.join(screenshot_dir, "41_login_error.png"))


class TestRegisterPage:
    """Registration page rendering."""

    def test_register_page_renders(self, page, base_url, screenshot_dir):
        page.goto(f"{base_url}/register")
        page.wait_for_load_state("networkidle")
        page.screenshot(path=os.path.join(screenshot_dir, "42_register_page.png"))


class TestLibraryPage:
    """Detection Library page."""

    def test_library_page_renders(self, authenticated_page, base_url, screenshot_dir):
        page = authenticated_page
        page.goto(f"{base_url}/library")
        page.wait_for_load_state("networkidle")
        page.screenshot(path=os.path.join(screenshot_dir, "43_library_page.png"))

    def test_library_search(self, authenticated_page, base_url, screenshot_dir):
        page = authenticated_page
        page.goto(f"{base_url}/library")
        page.wait_for_load_state("networkidle")

        search = page.locator('input[type="search"], input[placeholder*="Search"]').first
        if search.is_visible():
            search.fill("PowerShell")
            page.wait_for_timeout(1000)
            page.screenshot(path=os.path.join(screenshot_dir, "44_library_search.png"))


class TestCoveragePage:
    """Coverage dashboard page."""

    def test_coverage_page_renders(self, authenticated_page, base_url, screenshot_dir):
        page = authenticated_page
        page.goto(f"{base_url}/coverage")
        page.wait_for_load_state("networkidle")
        page.screenshot(path=os.path.join(screenshot_dir, "45_coverage_page.png"))


class TestManualEditor:
    """Manual YAML editor page."""

    def test_manual_page_renders(self, authenticated_page, base_url, screenshot_dir):
        page = authenticated_page
        page.goto(f"{base_url}/manual")
        page.wait_for_load_state("networkidle")
        page.screenshot(path=os.path.join(screenshot_dir, "46_manual_editor.png"))


class TestHowItWorks:
    """How It Works page."""

    def test_how_it_works_renders(self, page, base_url, screenshot_dir):
        page.goto(f"{base_url}/how-it-works")
        page.wait_for_load_state("networkidle")
        page.screenshot(path=os.path.join(screenshot_dir, "47_how_it_works.png"))


class TestProgressPage:
    """Progress page rendering."""

    def test_progress_page_renders(self, authenticated_page, base_url, screenshot_dir):
        page = authenticated_page
        page.goto(f"{base_url}/progress?group_name=APT28")
        page.wait_for_load_state("networkidle")
        page.screenshot(path=os.path.join(screenshot_dir, "48_progress_page.png"))
