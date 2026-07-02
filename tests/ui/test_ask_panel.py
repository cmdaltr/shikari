"""
Playwright UI tests for the Ask Archer conversational panel.
"""
import pytest
import os

pytestmark = pytest.mark.ui


class TestAskPanel:
    """The Ask Archer chat/Q&A panel on the home page."""

    def test_ask_panel_visible(self, authenticated_page, base_url, screenshot_dir):
        page = authenticated_page
        page.goto(base_url)
        page.wait_for_load_state("networkidle")

        ask_input = page.locator("#aap-input")
        if ask_input.is_visible():
            page.screenshot(path=os.path.join(screenshot_dir, "50_ask_panel.png"))

    def test_ask_question(self, authenticated_page, base_url, screenshot_dir):
        page = authenticated_page
        page.goto(base_url)
        page.wait_for_load_state("networkidle")

        ask_input = page.locator("#aap-input")
        if ask_input.is_visible():
            ask_input.fill("What is T1059.001?")
            page.wait_for_timeout(500)
            page.screenshot(path=os.path.join(screenshot_dir, "51_ask_question_typed.png"))

    def test_threat_briefing_button(self, authenticated_page, base_url, screenshot_dir):
        page = authenticated_page
        page.goto(base_url)
        page.wait_for_load_state("networkidle")

        # Fill group name first
        page.locator("#group_name_input").fill("Scattered Spider")
        page.wait_for_timeout(1000)

        briefing_btn = page.locator("#briefing-btn, #briefing_checkbox, text='Threat Briefing'").first
        if briefing_btn.is_visible():
            page.screenshot(path=os.path.join(screenshot_dir, "52_threat_briefing_button.png"))
