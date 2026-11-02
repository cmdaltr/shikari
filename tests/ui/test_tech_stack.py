"""
Playwright UI tests for the technology stack (#21): Profile's picker, the Hunt page's note and
the Threat Feed's "Your stack" filter. Needs a running Shikari.

Saving the stack is intercepted, and the Hunt page and feed are given a stack, so the
account's own settings aren't changed.
"""
import json

import pytest

pytestmark = pytest.mark.ui


def test_profile_picker(authenticated_page, base_url):
    page = authenticated_page
    sent = []
    page.route("**/api/profile/stack", lambda r: (
        r.continue_() if r.request.method == "GET" else
        (sent.append(json.loads(r.request.post_data)),
         r.fulfill(status=200, content_type="application/json",
                   body=json.dumps({"success": True, "stack": json.loads(r.request.post_data)["stack"]})))))
    page.goto(f"{base_url}/profile#tech-stack")
    page.wait_for_selector("#tech-stack-grid .tech-stack-group")
    for box in page.locator("#tech-stack-grid input:checked").all():
        box.uncheck()
    assert "every technique and procedure applies" in page.inner_text("#tech-stack-platforms")

    page.check("#tech-stack-grid input[value='esxi']")
    line = page.inner_text("#tech-stack-platforms")
    assert "ESXi" in line and "No operating system is ticked" in line
    page.check("#tech-stack-grid input[value='windows']")
    assert "No operating system" not in page.inner_text("#tech-stack-platforms")

    page.fill("#tech-stack-filter", "solarw")
    visible = [l for l in page.locator("#tech-stack-grid .industry-option").all() if l.is_visible()]
    assert len(visible) == 1 and "SolarWinds" in visible[0].inner_text()

    page.click("#tech-stack-save")
    page.wait_for_selector("#tech-stack-status.is-ok")
    assert sent == [{"stack": ["windows", "esxi"]}]


def test_hunt_page_says_the_stack_applies(authenticated_page, base_url):
    page = authenticated_page
    page.route("**/api/profile/stack", lambda r: r.fulfill(
        status=200, content_type="application/json", body=json.dumps({"stack": ["windows", "m365"]})))
    page.goto(base_url + "/")
    page.wait_for_selector("#hp-stack-note:not([hidden])")
    assert "2 products" in page.inner_text("#hp-stack-note")
    assert page.locator("#hp-stack-note input[name='ignore_stack']").count() == 1


def test_feed_your_stack_filter(authenticated_page, base_url):
    page = authenticated_page
    post = {"source": "Test", "published": "2026-10-15T00:00:00+00:00", "description": "", "techniques": ["T1190"],
            "cves": [], "iocs": 0, "groups": [], "yours": {}, "opportunistic": ["reported exploitation"], "financial": [],
            "tags": {"industries": [], "nations": [], "motives": ["Opportunistic"]}}
    posts = [{**post, "title": "FortiGate zero-day exploited", "url": "https://example.org/a",
              "stack": ["Fortinet (FortiGate, FortiOS)"], "off_stack": [], "relevant": True},
             {**post, "title": "MOVEit Transfer exploited", "url": "https://example.org/b",
              "stack": [], "off_stack": ["Progress MOVEit"], "relevant": False}]
    page.route("**/api/feed", lambda r: r.fulfill(status=200, content_type="application/json", body=json.dumps({
        "industries": [], "labels": [], "stack": ["Windows", "Fortinet (FortiGate, FortiOS)"], "days": 7,
        "posts": posts, "relevant": 1, "considered": 2, "last_refresh": None, "refreshing": False, "sources": []})))
    page.goto(f"{base_url}/feed")
    page.wait_for_selector("#fd-wall .fd-card")
    assert page.inner_text("#fd-stack") == "2 products"
    assert page.locator("#fd-wall .fd-card").count() == 1  # Both: the MOVEit post is aimed only at a product we don't run

    page.click(".fd-filter[data-show='all']")
    assert page.locator("#fd-wall .fd-card").count() == 2
    assert page.locator(".fd-tag.is-off-stack").count() == 1

    page.click(".fd-filter[data-show='stack']")
    titles = page.locator("#fd-wall .fd-title").all_inner_texts()
    assert titles == ["FortiGate zero-day exploited"]
