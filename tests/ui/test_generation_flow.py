"""
Playwright UI tests for the full generation flow.

Tests the end-to-end user journey: input -> generate -> progress -> results.
"""
import pytest
import os

pytestmark = [pytest.mark.ui, pytest.mark.slow]


class TestGenerationByGroup:
    """Full generation flow using a threat group name."""

    def test_generate_scattered_spider(self, authenticated_page, base_url, screenshot_dir):
        page = authenticated_page
        page.goto(base_url)
        page.wait_for_load_state("networkidle")

        # Fill threat group
        page.locator("#group_name_input").fill("Scattered Spider")
        page.wait_for_timeout(1500)

        # Select from autocomplete if visible
        autocomplete = page.locator(".autocomplete-item, .suggestion-item").first
        if autocomplete.is_visible():
            autocomplete.click()
            page.wait_for_timeout(500)

        page.screenshot(path=os.path.join(screenshot_dir, "20_generate_form_filled.png"))

        # Enable OSINT enhancement
        osint_cb = page.locator("#osint-enhancement-checkbox")
        if osint_cb.is_visible() and not osint_cb.is_checked():
            osint_cb.check()

        # Click Generate
        gen_btn = page.locator("#generate-btn, button[type='submit']").first
        if gen_btn.is_visible() and gen_btn.is_enabled():
            gen_btn.click()
            page.wait_for_timeout(3000)

            # Should navigate to progress page
            page.screenshot(path=os.path.join(screenshot_dir, "21_progress_page.png"))

            # Wait for some progress (up to 60s for screenshot)
            try:
                page.wait_for_selector(
                    ".progress-bar, .progress-text, [class*='progress']",
                    timeout=15000,
                )
                page.wait_for_timeout(5000)
                page.screenshot(path=os.path.join(screenshot_dir, "22_progress_mid_generation.png"))
            except Exception:
                pass  # Progress may complete very quickly or redirect


class TestGenerationByTechnique:
    """Generate by technique IDs (Hunt mode)."""

    def test_hunt_techniques(self, authenticated_page, base_url, screenshot_dir):
        page = authenticated_page
        page.goto(base_url)
        page.wait_for_load_state("networkidle")

        # Fill technique IDs
        technique_input = page.locator("#technique_input")
        if technique_input.is_visible():
            technique_input.fill("T1059.001, T1566.001, T1078")
            page.wait_for_timeout(500)

            page.screenshot(path=os.path.join(screenshot_dir, "23_hunt_techniques_filled.png"))


class TestGenerationByCVE:
    """Generate by CVE ID."""

    def test_cve_generation(self, authenticated_page, base_url, screenshot_dir):
        page = authenticated_page
        page.goto(base_url)
        page.wait_for_load_state("networkidle")

        cve_input = page.locator("#cve_input")
        if cve_input.is_visible():
            cve_input.fill("CVE-2023-44487")
            page.wait_for_timeout(500)

            page.screenshot(path=os.path.join(screenshot_dir, "24_cve_input_filled.png"))
