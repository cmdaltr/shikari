"""
Tests for the Research tab endpoints.

Covers actor-technique consolidation, keyword/country filtering,
and XLSX export.
"""
import pytest


class TestActorsByKeyword:
    """GET /api/actors/by-keyword returns groups matching filter."""

    def test_keyword_search(self, api, ensure_running):
        r = api.get("/api/actors/by-keyword", params={"keyword": "ransomware"})
        assert r.status_code in [200, 401]
        if r.status_code == 200:
            data = r.json()
            assert isinstance(data, (dict, list))

    def test_country_search(self, api, ensure_running):
        r = api.get("/api/actors/by-keyword", params={"keyword": "Russia"})
        assert r.status_code in [200, 401]

    def test_empty_keyword(self, api, ensure_running):
        r = api.get("/api/actors/by-keyword", params={"keyword": ""})
        assert r.status_code in [200, 400, 401]

    @pytest.mark.parametrize("kw", [
        "China", "Iran", "North Korea", "finance", "energy", "healthcare",
    ])
    def test_various_keywords(self, api, ensure_running, kw):
        r = api.get("/api/actors/by-keyword", params={"keyword": kw})
        assert r.status_code in [200, 401]


class TestActorTechniques:
    """POST /api/actors/techniques returns consolidated techniques."""

    def test_single_actor(self, api, ensure_running):
        r = api.post("/api/actors/techniques", json={
            "actors": ["APT28"]
        })
        assert r.status_code in [200, 401]
        if r.status_code == 200:
            data = r.json()
            assert isinstance(data, (dict, list))

    def test_multiple_actors(self, api, ensure_running):
        r = api.post("/api/actors/techniques", json={
            "actors": ["APT28", "APT29"]
        })
        assert r.status_code in [200, 401]

    def test_empty_actors_list(self, api, ensure_running):
        r = api.post("/api/actors/techniques", json={"actors": []})
        assert r.status_code in [200, 400, 401, 422]


class TestResearchExportXLSX:
    """POST /api/research/export-xlsx generates spreadsheet."""

    def test_export_returns_xlsx(self, api, ensure_running):
        r = api.post("/api/research/export-xlsx", json={
            "actors": ["APT28"],
            "techniques": [{"id": "T1059.001", "name": "PowerShell"}],
        }, timeout=60)
        assert r.status_code in [200, 401, 422]
        if r.status_code == 200:
            assert "spreadsheet" in r.headers.get("content-type", "") or \
                   "octet-stream" in r.headers.get("content-type", "") or \
                   len(r.content) > 0

    def test_export_empty_data(self, api, ensure_running):
        r = api.post("/api/research/export-xlsx", json={
            "actors": [],
            "techniques": [],
        })
        assert r.status_code in [200, 400, 401, 422]
