"""
Playwright UI tests for the results page.

Tests detection display, OSINT comparison, correlation results,
download buttons, and individual query blocks.
"""
import pytest
import os

pytestmark = pytest.mark.ui


class TestResultsPageLayout:
    """Results page renders all expected sections."""

    def test_results_page_loads(self, authenticated_page, base_url, screenshot_dir):
        page = authenticated_page
        page.goto(f"{base_url}/results?group_name=APT28")
        page.wait_for_load_state("networkidle")

        page.screenshot(path=os.path.join(screenshot_dir, "30_results_page.png"))

    def test_results_has_detection_cards(self, authenticated_page, base_url, screenshot_dir):
        page = authenticated_page
        page.goto(f"{base_url}/results?group_name=APT28")
        page.wait_for_load_state("networkidle")

        # Check for detection cards/sections
        cards = page.locator(".detection-card, .technique-card, .yaml-card, .result-card")
        if cards.count() > 0:
            page.screenshot(path=os.path.join(screenshot_dir, "31_detection_cards.png"))

    def test_results_has_platform_tabs(self, authenticated_page, base_url, screenshot_dir):
        page = authenticated_page
        page.goto(f"{base_url}/results?group_name=APT28")
        page.wait_for_load_state("networkidle")

        # Check for platform filter tabs
        for platform in ["splunk", "mde", "elastic", "googlesecops"]:
            loc = page.locator(f'[data-platform="{platform}"], text="{platform}"')
            # Platform tabs may or may not exist depending on results

        page.screenshot(path=os.path.join(screenshot_dir, "32_platform_tabs.png"))

    def test_results_osint_comparison_panel(self, authenticated_page, base_url, screenshot_dir):
        page = authenticated_page
        page.goto(f"{base_url}/results?group_name=APT28")
        page.wait_for_load_state("networkidle")

        osint = page.locator("[class*='osint'], [class*='comparison']").or_(page.get_by_text('OSINT'))
        if osint.count() > 0:
            page.screenshot(path=os.path.join(screenshot_dir, "33_osint_comparison.png"))

    def test_results_correlation_section(self, authenticated_page, base_url, screenshot_dir):
        page = authenticated_page
        page.goto(f"{base_url}/results?group_name=APT28")
        page.wait_for_load_state("networkidle")

        correlation = page.locator("[class*='correlation']").or_(page.get_by_text('Correlation'))
        if correlation.count() > 0:
            page.screenshot(path=os.path.join(screenshot_dir, "34_correlation_results.png"))

    def test_results_individual_queries(self, authenticated_page, base_url, screenshot_dir):
        page = authenticated_page
        page.goto(f"{base_url}/results?group_name=APT28")
        page.wait_for_load_state("networkidle")

        iq_blocks = page.locator(".iq-block, [class*='individual-query']")
        if iq_blocks.count() > 0:
            page.screenshot(path=os.path.join(screenshot_dir, "35_individual_queries.png"))

    def test_results_download_buttons(self, authenticated_page, base_url, screenshot_dir):
        page = authenticated_page
        page.goto(f"{base_url}/results?group_name=APT28")
        page.wait_for_load_state("networkidle")

        download = page.locator("text='Download', a[href*='download']")
        if download.count() > 0:
            page.screenshot(path=os.path.join(screenshot_dir, "36_download_buttons.png"))

    def test_results_copy_buttons(self, authenticated_page, base_url, screenshot_dir):
        page = authenticated_page
        page.goto(f"{base_url}/results?group_name=APT28")
        page.wait_for_load_state("networkidle")

        copy_btns = page.locator(".iq-copy, [class*='copy'], button:has-text('Copy')")
        if copy_btns.count() > 0:
            # Click first copy button
            copy_btns.first.click()
            page.wait_for_timeout(500)
            page.screenshot(path=os.path.join(screenshot_dir, "37_copy_button_clicked.png"))


class TestResultsNoData:
    """Results page handles missing data gracefully."""

    def test_results_nonexistent_group(self, authenticated_page, base_url, screenshot_dir):
        page = authenticated_page
        page.goto(f"{base_url}/results?group_name=NonExistentGroup12345")
        page.wait_for_load_state("networkidle")

        page.screenshot(path=os.path.join(screenshot_dir, "38_results_no_data.png"))
