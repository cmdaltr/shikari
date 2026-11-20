"""The one-time link page (templates/reset_access.html) run in a real browser: its script read `api` and
`invite` before declaring them, a ReferenceError that stopped any submit handler attaching, so every
invitation, reset-access and first-admin link failed in the browser while every API test passed. The
page is rendered by the app and served to headless Chromium through page.route, with the API stubbed,
so any script error, and the requests each step makes, are seen."""
import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import shikari.app as app_module

ROOT = Path(__file__).parents[2]
ORIGIN = "http://shikari.test"
PASSWORD = "Brand-new-passw0rd!"


class _Browser:
    """Headless Chromium on a thread of its own: the sync Playwright API refuses to start where an
    asyncio loop is already running, as one is by the time the whole suite gets here. Each call runs
    `fn(browser)` there."""

    def __init__(self, sync_api):
        import concurrent.futures

        self._pool = concurrent.futures.ThreadPoolExecutor(max_workers=1)
        self._sync_api = sync_api
        self._pool.submit(self._start).result()

    def _start(self):
        self._pw = self._sync_api.sync_playwright().start()
        self._browser = self._pw.chromium.launch()

    def run(self, fn):
        return self._pool.submit(fn, self._browser).result()

    def close(self):
        def stop():
            self._browser.close()
            self._pw.stop()
        self._pool.submit(stop).result()
        self._pool.shutdown()


@pytest.fixture(scope="module")
def link_browser():
    sync_api = pytest.importorskip("playwright.sync_api")
    try:
        b = _Browser(sync_api)
    except Exception as e:  # no browser installed: `playwright install chromium`
        pytest.skip(f"Chromium isn't available: {e}")
    yield b
    b.close()


def _run(browser, path: str, answers: dict):
    """Open ORIGIN<path>#the-token with the API answering from `answers` ({endpoint: (status, body)});
    returns (page, errors, posts)."""
    html = TestClient(app_module.app, base_url=ORIGIN).get(path).text
    errors, posts = [], []
    page = browser.new_page()
    page.on("pageerror", lambda e: errors.append(str(e)))

    def handle(route):
        request = route.request
        if not request.url.startswith(ORIGIN):
            return route.fulfill(status=404, body="")  # fonts and the like: nothing leaves the test
        url_path = request.url.split(ORIGIN, 1)[1].split("?", 1)[0].split("#", 1)[0]
        if request.method == "GET" and url_path == path:
            return route.fulfill(status=200, content_type="text/html", body=html)
        if url_path.startswith("/static/"):
            file = ROOT / url_path.lstrip("/")
            if file.is_file():
                kind = "application/javascript" if file.suffix == ".js" else (
                    "text/css" if file.suffix == ".css" else "application/octet-stream")
                return route.fulfill(status=200, content_type=kind, body=file.read_bytes())
            return route.fulfill(status=404, body="")
        if request.method == "POST" and url_path in answers:
            posts.append((url_path, json.loads(request.post_data or "{}")))
            status, body = answers[url_path]
            return route.fulfill(status=status, content_type="application/json", body=json.dumps(body))
        return route.fulfill(status=404, content_type="application/json", body="{}")

    page.route("**/*", handle)
    page.goto(f"{ORIGIN}{path}#the-token")
    return page, errors, posts


QR = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg=="


def _flow(browser, path: str, api: str, invite: bool):
    answers = {
        f"{api}/start": (200, {"success": True, "email": "new.person@example.org", "secret": "JBSWY3DPEHPK3PXP",
                               "qr_code": QR, "csrf_token": "csrf-2"}),
        f"{api}/complete": (200, {"success": True, "backup_codes": ["aaaa-bbbb", "cccc-dddd"]}),
    }
    if invite:
        answers[f"{api}/preview"] = (200, {"success": True, "email": "new.person@example.org", "role": "admin",
                                           "full_name": "Suggested Name"})
    page, errors, posts = _run(browser, path, answers)
    try:
        page.wait_for_selector("#password-step:not([hidden])")
        page.wait_for_load_state("load")
        assert errors == [], f"the page's script failed: {errors}"
        if invite:
            page.wait_for_function("document.getElementById('full_name').value === 'Suggested Name'")
        assert page.url == f"{ORIGIN}{path}", "the token is taken out of the address bar"
        page.fill("#new_password", PASSWORD)
        page.fill("#confirm_password", PASSWORD)
        page.click("#password-step button[type=submit]")
        page.wait_for_selector("#authenticator-step:not([hidden])")
        assert page.text_content("#totp-secret") == "JBSWY3DPEHPK3PXP"
        page.fill("#code", "123456")
        page.click("#authenticator-step button[type=submit]")
        page.wait_for_selector("#codes-step:not([hidden])")
        assert page.locator("#backup-codes li").all_text_contents() == ["aaaa-bbbb", "cccc-dddd"]
    finally:
        page.close()
    assert errors == [], f"the page's script failed: {errors}"
    sent = dict(posts)
    start = sent[f"{api}/start"]
    assert start["token"] == "the-token" and start["new_password"] == PASSWORD and start["csrf_token"]
    if invite:
        assert start["full_name"] == "Suggested Name"
        assert posts[0][0] == f"{api}/preview" and posts[0][1]["token"] == "the-token"
    assert sent[f"{api}/complete"] == {"token": "the-token", "csrf_token": "csrf-2", "code": "123456"}


@pytest.mark.unit
class TestTheLinkPageInABrowser:
    def test_an_invitation_link_goes_all_the_way_through(self, link_browser):
        link_browser.run(lambda b: _flow(b, "/accept-invite", "/api/auth/invitation", invite=True))

    def test_a_reset_access_link_goes_all_the_way_through(self, link_browser):
        link_browser.run(lambda b: _flow(b, "/reset-access", "/api/auth/reset-access", invite=False))

    @pytest.mark.parametrize("status,message", [(410, "This link has expired."), (404, "This link isn't valid.")])
    def test_a_dead_link_shows_why_and_hides_the_forms(self, link_browser, status, message):
        def check(browser):
            page, errors, _ = _run(browser, "/reset-access",
                                   {"/api/auth/reset-access/start": (status, {"success": False, "error": message})})
            try:
                page.wait_for_selector("#password-step:not([hidden])")
                page.fill("#new_password", PASSWORD)
                page.fill("#confirm_password", PASSWORD)
                page.click("#password-step button[type=submit]")
                page.wait_for_selector("#message-container .error-message")
                assert page.text_content("#message-container") == message
                assert page.locator("#password-step").is_hidden() and page.locator("#authenticator-step").is_hidden()
            finally:
                page.close()
            assert errors == []
        link_browser.run(check)

    def test_no_token_says_so(self, link_browser):
        html = TestClient(app_module.app, base_url=ORIGIN).get("/reset-access").text

        def check(browser):
            page = browser.new_page()
            errors = []
            page.on("pageerror", lambda e: errors.append(str(e)))
            page.route("**/*", lambda route: route.fulfill(
                status=200, content_type="text/html", body=html) if route.request.url.endswith("/reset-access")
                else route.fulfill(status=404, body=""))
            try:
                page.goto(f"{ORIGIN}/reset-access")
                page.wait_for_selector("#no-token:not([hidden])")
                assert page.locator("#password-step").is_hidden()
            finally:
                page.close()
            assert errors == []
        link_browser.run(check)
