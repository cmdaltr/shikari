"""
Playwright UI tests for Build → Emulate (#22). Needs a running Archer with the recorded
telemetry built. The page only reads; Update isn't pressed.
"""
import os

import pytest

pytestmark = pytest.mark.ui
SHOTS = os.getenv("EMULATE_SHOTS")  # a folder to save screenshots in, when looking at the page


def shot(page, name):
    if SHOTS:
        page.locator("#em-view-card").screenshot(path=os.path.join(SHOTS, f"{name}.png"))


def test_views_filters_and_pages(authenticated_page, base_url):
    page = authenticated_page
    errors = []
    page.on("pageerror", lambda e: errors.append(str(e)))
    page.goto(f"{base_url}/emulate")
    assert page.locator(".em-page").get_attribute("data-signed-in") == "true"
    page.wait_for_selector(".em-check.is-ready, .em-check.is-unavailable", timeout=20000)
    assert page.locator("#em-sources li").count() >= 3
    page.wait_for_selector("tr.em-row")
    assert page.locator("tr.em-row").count() == 20  # a page
    assert page.locator("#em-pager").is_visible()
    shot(page, "technique")

    # A technique, picked by name in its multiselect, then opened
    page.click('.em-ms[data-key="technique"] .em-ms-btn')
    page.fill('.em-ms[data-key="technique"] .em-ms-search', "LSASS")
    page.locator('.em-ms[data-key="technique"] input[value="T1003.001"]').check()
    page.click("h1")
    assert page.locator("tr.em-row").count() == 1
    page.click("tr.em-row")
    page.wait_for_selector(".em-detail .em-sub")
    shot(page, "technique-open")

    # The indicator search finds it in the recorded values
    page.click("#em-clear")
    page.fill("#em-q", "comsvcs")
    page.wait_for_selector(".em-hit")
    assert page.locator('tr.em-row[data-tid="T1003.001"]').count() == 1

    # Native logs only: a technique Sysmon alone recorded is marked as a gap
    page.click("#em-clear")
    page.click('.em-ms[data-key="collection"] .em-ms-btn')
    page.locator('.em-ms[data-key="collection"] input[value="sysmon"]').uncheck()
    page.locator('.em-ms[data-key="collection"] input[value="edr"]').uncheck()
    page.locator('.em-ms[data-key="collection"] input[value="osquery"]').uncheck()
    page.click("h1")
    page.wait_for_selector("tr.em-row")
    page.click('.em-ms[data-key="platform"] .em-ms-btn')
    page.locator('.em-ms[data-key="platform"] input[value="linux"]').check()
    page.click("h1")
    page.wait_for_selector("tr.em-row")
    shot(page, "linux-native")

    # Data sources for the other SIEM
    page.click("#em-clear")
    page.select_option("#em-view", "source")
    page.select_option("#em-siem", "mde")
    page.wait_for_selector("text=DeviceProcessEvents")
    page.select_option("#em-view", "technique")
    page.wait_for_selector("th:has-text('Defender XDR alerts')")
    assert page.locator(".em-ms[data-key='defender']").is_visible()
    shot(page, "technique-mde")
    page.select_option("#em-view", "source")
    assert "T0000" not in page.inner_text("#em-results")
    assert page.locator(".em-ms[data-key='seen']").is_hidden()
    shot(page, "source")

    # A group's detections: the latest hunt unless groups are picked
    page.select_option("#em-view", "group")
    page.wait_for_selector(".em-status, #em-results .ms-note:not(:has-text('Checking'))", timeout=60000)
    assert "Log in" not in page.inner_text("#em-results")
    assert page.locator(".em-ms[data-key='seen']").is_visible()
    shot(page, "group")
    assert not errors, errors
