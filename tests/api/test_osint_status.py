"""
Tests for OSINT repository status and bespoke detection endpoints.
"""
import pytest


class TestOSINTStatus:
    """GET /api/status/osint reports OSINT repo health."""

    def test_osint_status_returns_data(self, api, ensure_running):
        r = api.get("/api/status/osint")
        assert r.status_code in [200, 401]
        if r.status_code == 200:
            data = r.json()
            assert isinstance(data, dict)

    def test_accept_osint_failures(self, api, ensure_running):
        r = api.post("/api/status/osint/accept-failures")
        assert r.status_code in [200, 401]

    def test_retry_failed_osint(self, api, ensure_running):
        r = api.post("/api/status/osint/retry-failed")
        assert r.status_code in [200, 401, 422]


class TestBespokeStatus:
    """GET /api/status/bespoke reports bespoke detection repo health."""

    def test_bespoke_status(self, api, ensure_running):
        r = api.get("/api/status/bespoke")
        assert r.status_code in [200, 401]

    def test_bespoke_sample_searches(self, api, ensure_running):
        r = api.get("/api/bespoke/sample-searches")
        assert r.status_code in [200, 401]

    def test_bespoke_reload(self, api, ensure_running):
        r = api.post("/api/bespoke/reload")
        assert r.status_code in [200, 401, 422]


class TestReferenceCoverage:
    """GET /api/reference/coverage and /api/reference/queries."""

    def test_reference_coverage(self, api, ensure_running):
        r = api.get("/api/reference/coverage")
        assert r.status_code in [200, 401]

    def test_reference_queries(self, api, ensure_running):
        r = api.get("/api/reference/queries")
        assert r.status_code in [200, 401]


class TestCoveragePage:
    """GET /coverage renders coverage dashboard."""

    def test_coverage_page_loads(self, api, ensure_running):
        r = api.get("/coverage")
        assert r.status_code in [200, 302]
