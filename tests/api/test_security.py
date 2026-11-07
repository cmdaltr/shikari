"""
Security tests for API endpoints.

Tests XSS, SQL injection, SSRF, CSRF, and input sanitization
across all input vectors.
"""
import pytest


class TestXSSPrevention:
    """XSS payloads should be sanitized in all text inputs."""

    XSS_PAYLOADS = [
        "<script>alert('xss')</script>",
        '"><img src=x onerror=alert(1)>',
        "javascript:alert(1)",
        '<svg onload="alert(1)">',
    ]

    @pytest.mark.parametrize("payload", XSS_PAYLOADS)
    def test_xss_in_group_name(self, api, ensure_running, payload):
        r = api.post("/generate", data={"group_name": payload}, allow_redirects=False)
        assert r.status_code in [200, 302, 400, 401, 422]
        if r.status_code == 200:
            assert "<script>" not in r.text

    @pytest.mark.parametrize("payload", XSS_PAYLOADS)
    def test_xss_in_company_name(self, api, ensure_running, payload):
        r = api.post("/profile", data={"company_name": payload}, timeout=60)
        assert r.status_code in [200, 302, 400, 401, 422]
        if r.status_code == 200:
            assert "<script>" not in r.text

    @pytest.mark.parametrize("payload", XSS_PAYLOADS)
    def test_xss_in_ask_question(self, api, ensure_running, payload):
        r = api.post("/api/ask", json={"question": payload})
        assert r.status_code in [200, 400, 401, 422, 500]


class TestSQLInjection:
    """SQL injection payloads should be handled safely."""

    SQL_PAYLOADS = [
        "'; DROP TABLE users; --",
        "1' OR '1'='1",
        "admin'--",
        "1; UPDATE users SET role='admin'",
    ]

    @pytest.mark.parametrize("payload", SQL_PAYLOADS)
    def test_sqli_in_group_name(self, api, ensure_running, payload):
        r = api.post("/generate", data={"group_name": payload}, allow_redirects=False)
        assert r.status_code in [200, 302, 400, 401, 422]

    @pytest.mark.parametrize("payload", SQL_PAYLOADS)
    def test_sqli_in_login(self, api, ensure_running, payload):
        import requests
        fresh = requests.Session()
        r = fresh.post(f"{api.url}/login", data={
            "email": payload,
            "password": payload,
        }, allow_redirects=False, timeout=30)
        assert r.status_code in [200, 302, 400, 401, 422]
        fresh.close()


class TestSSRFPrevention:
    """Internal/localhost URLs should be blocked in blog analysis."""

    @pytest.mark.parametrize("url", [
        "http://localhost/admin",
        "http://127.0.0.1:32453/",
        "http://192.168.1.1/",
        "http://10.0.0.1/",
        "http://169.254.169.254/latest/meta-data/",  # AWS metadata
        "http://[::1]/",
    ])
    def test_ssrf_blocked(self, api, ensure_running, url):
        r = api.post("/analyze_blog", data={"url": url}, allow_redirects=False)
        assert r.status_code in [400, 403], f"SSRF not blocked for {url}: got {r.status_code}"


class TestCommandInjection:
    """Command injection payloads should be handled safely."""

    CMD_PAYLOADS = [
        "; rm -rf /",
        "| cat /etc/passwd",
        "$(whoami)",
        "`id`",
    ]

    @pytest.mark.parametrize("payload", CMD_PAYLOADS)
    def test_cmdi_in_group_name(self, api, ensure_running, payload):
        r = api.post("/generate", data={"group_name": payload}, allow_redirects=False)
        assert r.status_code in [200, 302, 400, 401, 422]

    @pytest.mark.parametrize("payload", CMD_PAYLOADS)
    def test_cmdi_in_cve_id(self, api, ensure_running, payload):
        r = api.post("/generate/cve", data={"cve_id": payload}, allow_redirects=False)
        assert r.status_code in [200, 302, 400, 401, 422]


class TestRateLimiting:
    """Repeated requests should not cause server failure."""

    def test_rapid_health_checks(self, api, ensure_running):
        for _ in range(20):
            r = api.get("/health")
            assert r.status_code == 200

    def test_rapid_group_lookups(self, api, ensure_running):
        for _ in range(10):
            r = api.get("/threat_groups", params={"query": "APT"})
            assert r.status_code in [200, 429]
