"""
Tests for correlation engine endpoints.
"""
import pytest


class TestCorrelationParams:
    """GET/POST /api/correlation/params manages correlation settings."""

    def test_get_params(self, api, ensure_running):
        r = api.get("/api/correlation/params")
        assert r.status_code in [200, 401]
        if r.status_code == 200:
            data = r.json()
            assert isinstance(data, dict)

    def test_set_params(self, api, ensure_running):
        r = api.post("/api/correlation/params", json={
            "time_window": "15m",
            "min_techniques": 2,
        })
        assert r.status_code in [200, 401, 422]


class TestCorrelationResults:
    """GET /correlations/{group}.json returns correlation data."""

    def test_get_correlations_for_group(self, api, ensure_running):
        r = api.get("/correlations/APT28.json")
        # May not exist yet
        assert r.status_code in [200, 404]
        if r.status_code == 200:
            data = r.json()
            assert isinstance(data, (dict, list))

    def test_nonexistent_group_correlations(self, api, ensure_running):
        r = api.get("/correlations/NonExistentGroup99999.json")
        assert r.status_code in [404, 200]
