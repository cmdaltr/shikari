"""
Shared fixtures for Playwright UI tests.

Install: pip install pytest-playwright && playwright install chromium
Run:     pytest tests/ui/ -v --headed  (to see the browser)
         pytest tests/ui/ -v           (headless)
"""
import pytest
import os

BASE_URL = os.getenv("SHIKARI_BASE_URL", "http://127.0.0.1:32453")
SCREENSHOT_DIR = os.path.join(os.path.dirname(__file__), "..", "screenshots")


@pytest.fixture(scope="session")
def browser_context_args():
    return {
        "viewport": {"width": 1440, "height": 900},
        "ignore_https_errors": True,
    }


@pytest.fixture(scope="session")
def base_url():
    return BASE_URL


@pytest.fixture(scope="session", autouse=True)
def ensure_screenshot_dir():
    os.makedirs(SCREENSHOT_DIR, exist_ok=True)


@pytest.fixture
def screenshot_dir():
    return SCREENSHOT_DIR


@pytest.fixture
def authenticated_page(page, base_url):
    """Navigate to login and authenticate, then return the page."""
    page.goto(f"{base_url}/login")
    page.wait_for_load_state("networkidle")

    # Fill login form
    email_field = page.locator('input[name="email"], input[type="email"]').first
    password_field = page.locator('input[name="password"], input[type="password"]').first

    if email_field.is_visible():
        email_field.fill(os.getenv("SHIKARI_TEST_EMAIL", "admin@shikari.app"))
        password_field.fill(os.getenv("SHIKARI_TEST_PASSWORD", "BigGameHunter"))
        page.locator('button[type="submit"], input[type="submit"]').first.click()
        page.wait_for_load_state("networkidle")

    return page
