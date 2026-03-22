"""
Tests for health checks and page rendering.

Validates that every HTML page route loads and returns expected content.
"""
import pytest


class TestHealthEndpoint:
    """Verify /health returns 200 with status ok."""

    def test_health_returns_ok(self, api, ensure_running):
        r = api.get("/health")
        assert r.status_code == 200
        assert r.json()["status"] == "ok"

    def test_health_response_time(self, api, ensure_running):
        import time
        start = time.time()
        api.get("/health")
        assert time.time() - start < 2.0


class TestPageRoutes:
    """Every HTML page should return 200 (or 302 to login)."""

    @pytest.mark.parametrize("path", [
        "/",
        "/how-it-works",
        "/progress",
        "/manual",
        "/coverage",
        "/login",
        "/register",
        "/forgot-password",
    ])
    def test_public_pages_load(self, api, ensure_running, path):
        r = api.get(path, allow_redirects=False)
        assert r.status_code in [200, 302, 303]

    @pytest.mark.parametrize("path", [
        "/results?group_name=APT28",
        "/library",
        "/profile",
    ])
    def test_authenticated_pages_load(self, api, ensure_running, path):
        r = api.get(path, allow_redirects=False)
        assert r.status_code in [200, 302, 303]

    def test_home_page_contains_archer(self, api, ensure_running):
        r = api.get("/")
        assert r.status_code == 200
        assert "Archer" in r.text or "archer" in r.text.lower()

    def test_home_page_has_generate_form(self, api, ensure_running):
        r = api.get("/")
        assert "group_name" in r.text
        assert "Generate" in r.text or "generate" in r.text.lower()

    def test_home_page_has_all_tabs(self, api, ensure_running):
        r = api.get("/")
        for tab in ["generate", "research", "upload", "profile", "emulate"]:
            assert f'data-tab="{tab}"' in r.text, f"Missing tab: {tab}"

    def test_login_page_has_form(self, api, ensure_running):
        r = api.get("/login")
        if r.status_code == 200:
            assert "email" in r.text.lower()
            assert "password" in r.text.lower()

    def test_register_page_has_form(self, api, ensure_running):
        r = api.get("/register")
        if r.status_code == 200:
            assert "email" in r.text.lower()

    def test_favicon_returns(self, api, ensure_running):
        r = api.get("/favicon.ico")
        assert r.status_code in [200, 204, 301, 302, 404]

    def test_404_for_unknown_route(self, api, ensure_running):
        r = api.get("/this-route-does-not-exist-12345")
        assert r.status_code in [404, 405]
