"""
Playwright Configuration for Shikari UI Tests
"""

from playwright.sync_api import sync_playwright
import pytest


@pytest.fixture(scope="session")
def browser_context_args():
    """
    Configure browser context settings.
    You can override this fixture in your tests for custom settings.
    """
    return {
        "viewport": {"width": 1280, "height": 720},
        "ignore_https_errors": True,
        "locale": "en-US",
        "timezone_id": "America/New_York",
    }


@pytest.fixture(scope="session")
def playwright():
    """Provide Playwright instance"""
    with sync_playwright() as p:
        yield p


@pytest.fixture(scope="session")
def browser_type(playwright):
    """
    Provide browser type (Chromium by default).
    Can be overridden to test other browsers.
    """
    return playwright.chromium


@pytest.fixture(scope="session")
def browser(browser_type):
    """Launch browser for testing"""
    browser = browser_type.launch(
        headless=True,  # Set to False for debugging
        slow_mo=0,  # Set to >0 to slow down operations for debugging
    )
    yield browser
    browser.close()


@pytest.fixture(scope="function")
def context(browser, browser_context_args):
    """Create a new browser context for each test"""
    context = browser.new_context(**browser_context_args)
    yield context
    context.close()


@pytest.fixture(scope="function")
def page(context):
    """Create a new page for each test"""
    page = context.new_page()
    yield page
    page.close()


# Browser-specific fixtures for cross-browser testing
@pytest.fixture(scope="session")
def chromium_browser(playwright):
    """Chromium browser instance"""
    browser = playwright.chromium.launch(headless=True)
    yield browser
    browser.close()


@pytest.fixture(scope="session")
def firefox_browser(playwright):
    """Firefox browser instance"""
    browser = playwright.firefox.launch(headless=True)
    yield browser
    browser.close()


@pytest.fixture(scope="session")
def webkit_browser(playwright):
    """WebKit browser instance"""
    browser = playwright.webkit.launch(headless=True)
    yield browser
    browser.close()


# Helper fixture for authenticated sessions (if needed)
@pytest.fixture
def authenticated_page(context, base_url):
    """
    Create a page with authentication (if your app requires it).
    Modify this fixture based on your authentication mechanism.
    """
    page = context.new_page()

    # Example: Set authentication cookie or token
    # context.add_cookies([{
    #     'name': 'auth_token',
    #     'value': 'your_token',
    #     'domain': 'localhost',
    #     'path': '/'
    # }])

    yield page
    page.close()


# Configuration constants
BROWSER_OPTIONS = {
    "headless": True,
    "slow_mo": 0,
    "args": [
        "--disable-blink-features=AutomationControlled",
    ],
}

VIEWPORT_SIZES = {
    "desktop": {"width": 1280, "height": 720},
    "tablet": {"width": 768, "height": 1024},
    "mobile": {"width": 375, "height": 667},
}
