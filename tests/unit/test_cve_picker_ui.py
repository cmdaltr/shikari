"""The Hunt page's recent-CVE picker, headless: the real markup, CSS and index.js on a blank page, the API stubbed."""

import json
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
CVES = [
    {"cve_id": "CVE-2026-1000", "published": "2026-10-20T10:00:00.000", "description": "FortiOS heap overflow <img src=x onerror=alert(1)>",
     "cvss_v3": {"score": 9.8, "severity": "CRITICAL", "vector": "AV:N"}, "products": ["FortiGate"], "on_stack": ["FortiGate"],
     "kev": {"date_added": "2026-10-21", "due": "2026-11-11", "ransomware": True}, "researched": True},
    {"cve_id": "CVE-2026-1001", "published": "2026-10-19T10:00:00.000", "description": "A kernel bug",
     "cvss_v3": None, "products": ["Linux"], "on_stack": [], "kev": None, "researched": False},
]


def _page_html():
    index = (ROOT / "templates" / "index.html").read_text()
    picker = re.search(r'(<input type="text" name="cve_id".*?</dialog>)', index, re.S).group(1)
    css = (ROOT / "static" / "css" / "home_tabs.css").read_text()
    return f"<html><head><style>{css}</style></head><body><form id='f'>{picker}<input id='group_name'></form></body></html>"


@pytest.fixture
def page():
    sync = pytest.importorskip("playwright.sync_api")
    with sync.sync_playwright() as p:
        try:
            browser = p.chromium.launch()
        except Exception as e:
            pytest.skip(f"no Chromium for Playwright: {e}")
        page = browser.new_page()
        asked = []

        def api(route):
            asked.append(route.request.url)
            q = route.request.url
            rows = [c for c in CVES if "kev=true" not in q or c["kev"]]
            route.fulfill(content_type="application/json", body=json.dumps(
                {"cves": rows, "total": len(rows), "offset": 0, "limit": 50, "has_stack": True, "window_days": 30,
                 "status": {"last_refresh": "2026-10-23T14:12:19+00:00", "refreshing": False}}))

        page.route("**/api/cves/recent*", api)
        page.route("http://archer.test/", lambda r: r.fulfill(content_type="text/html", body=_page_html()))
        page.goto("http://archer.test/")
        page.add_script_tag(content=(ROOT / "static" / "js" / "index.js").read_text())
        page.evaluate("document.dispatchEvent(new Event('DOMContentLoaded'))")
        page.asked = asked
        yield page
        browser.close()


def test_picking_fills_the_cve_field_and_unpicking_empties_it(page):
    page.click("#cve-browse")
    page.wait_for_selector(".cvp-row")
    assert page.locator(".cvp-row").count() == 2
    first = page.locator(".cvp-row").first
    assert "Exploited" in first.inner_text() and "Ransomware" in first.inner_text() and "Researched" in first.inner_text()
    assert "Not scored yet" in page.locator(".cvp-row").nth(1).inner_text()
    # The description is text, never HTML
    assert page.locator(".cvp-desc img").count() == 0

    first.click()
    page.locator(".cvp-row").nth(1).press("Enter")
    assert page.input_value("#cve_input") == "CVE-2026-1000, CVE-2026-1001"
    first.click()
    assert page.input_value("#cve_input") == "CVE-2026-1001"
    page.click("#cvp-done")
    assert not page.evaluate("document.getElementById('cve-picker').open")


def test_filters_ask_the_server_and_enter_in_search_does_not_submit(page):
    submitted = page.evaluate("""() => { window._sub = 0; document.getElementById('f')
        .addEventListener('submit', e => { e.preventDefault(); window._sub++; }); return 0; }""")
    page.click("#cve-browse")
    page.wait_for_selector(".cvp-row")
    page.check("#cvp-kev")
    page.wait_for_function("document.querySelectorAll('.cvp-row').length === 1")
    assert any("kev=true" in u for u in page.asked)
    page.fill("#cvp-search", "fortios")
    page.press("#cvp-search", "Enter")
    page.wait_for_timeout(400)
    assert any("q=fortios" in u for u in page.asked)
    assert page.evaluate("window._sub") == submitted


def test_a_six_digit_cve_goes_into_the_field_whole(page):
    # The CVE field used to cut each ID to 14 characters: CVE-2026-109619 became CVE-2026-10961
    page.add_script_tag(content=re.search(r"<!-- CVE Input Validation Script -->\s*<script>(.*?)</script>",
                                          (ROOT / "templates" / "index.html").read_text(), re.S).group(1))
    page.route("**/api/cves/recent*", lambda r: r.fulfill(content_type="application/json", body=json.dumps(
        {"cves": [{**CVES[0], "cve_id": "CVE-2026-109619"}], "total": 1, "offset": 0, "limit": 50, "has_stack": True,
         "window_days": 30, "status": {"last_refresh": "2026-10-23T14:12:19+00:00"}})))
    page.click("#cve-browse")
    page.wait_for_selector(".cvp-row")
    page.locator(".cvp-row").first.click()
    assert page.input_value("#cve_input") == "CVE-2026-109619"
    assert page.evaluate("document.getElementById('cve_input').checkValidity()")
