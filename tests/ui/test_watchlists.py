"""
Playwright UI tests for Threat Feed watchlists (#18). Needs a running Archer.

The watchlist API is answered here, so the account's own watchlists aren't changed.
"""
import json

import pytest

pytestmark = pytest.mark.ui

MATCH = {"title": "Scattered Spider hits retail again", "url": "https://example.org/spider", "source": "Example",
         "published": "2026-10-15T00:00:00+00:00", "via": "Example"}


def watch_api(page, lists):
    sent = []

    def handle(route):
        req = route.request
        if req.method == "GET":
            body = {"watchlists": lists, "new_count": sum(w["new_count"] for w in lists), "email_available": False}
        else:
            sent.append((req.method, req.url.split("/api/feed/watchlists")[1], json.loads(req.post_data or "null")))
            body = {"watchlist": {**lists[0], "query": "RedSun"}} if req.method == "POST" and req.url.endswith("watchlists") else {}
        route.fulfill(status=200, content_type="application/json", body=json.dumps(body))

    page.route("**/api/feed/watchlists", handle)
    page.route("**/api/feed/watchlists/*", lambda r: r.fulfill(status=200, content_type="application/json",
                                                                 body=json.dumps({"new": 1})) if r.request.url.endswith("/count")
               else handle(r))
    return sent


def test_watchlists_on_the_feed(authenticated_page, base_url):
    page = authenticated_page
    lists = [{"id": "abc", "query": "Scattered Spider", "web": False, "email": False, "created": 0, "checked": 0,
              "new": [MATCH], "new_count": 1}]
    sent = watch_api(page, lists)
    page.goto(f"{base_url}/feed")
    page.wait_for_selector("#fd-watch-list .fd-watch-item")

    assert page.inner_text("#fd-watch-total") == "1 new"
    assert "Scattered Spider hits retail again" in page.inner_text("#fd-watch-list")
    assert page.is_disabled("#fd-watch-email")  # no SMTP here
    # The menu bar's badge on Intel and Feed
    page.wait_for_selector(".global-nav-controls .nav-watch-badge")
    assert page.locator(".global-nav-controls .nav-watch-badge").count() == 2

    page.fill("#fd-watch-q", "RedSun")
    page.check("#fd-watch-web")
    page.click("#fd-watch-add")
    page.wait_for_selector("#fd-watch-msg.is-ok")
    page.click(".fd-watch-item[data-id='abc'] [data-act='seen']")
    page.click(".fd-watch-item[data-id='abc'] [data-act='remove']")
    page.wait_for_timeout(300)
    assert ("POST", "", {"query": "RedSun", "web": True, "email": False}) in sent
    assert ("POST", "/seen", {"id": "abc"}) in sent
    assert ("DELETE", "/abc", None) in sent
