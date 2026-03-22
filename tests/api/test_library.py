"""
Tests for the Detection Library endpoints.
"""
import pytest


class TestLibraryPage:
    """GET /library page rendering."""

    def test_library_page_loads(self, api, ensure_running):
        r = api.get("/library", allow_redirects=False)
        assert r.status_code in [200, 302]


class TestLibraryAPI:
    """Library detection CRUD and search."""

    def test_list_detections(self, api, ensure_running):
        r = api.get("/api/library/detections")
        assert r.status_code in [200, 401]
        if r.status_code == 200:
            data = r.json()
            assert isinstance(data, (dict, list))

    def test_search_detections(self, api, ensure_running):
        r = api.post("/api/library/search", json={"query": "PowerShell"})
        assert r.status_code in [200, 401]

    def test_search_by_technique(self, api, ensure_running):
        r = api.post("/api/library/search", json={"query": "T1059.001"})
        assert r.status_code in [200, 401]

    def test_search_by_platform(self, api, ensure_running):
        r = api.post("/api/library/search", json={"query": "splunk"})
        assert r.status_code in [200, 401]

    def test_search_empty_query(self, api, ensure_running):
        r = api.post("/api/library/search", json={"query": ""})
        assert r.status_code in [200, 401]

    def test_export_library(self, api, ensure_running):
        r = api.post("/api/library/export", json={"format": "yaml"})
        assert r.status_code in [200, 401, 422]

    def test_save_to_library(self, api, ensure_running):
        r = api.post("/api/library/save", json={
            "detection": {
                "title": "Test Detection",
                "technique_id": "T1059.001",
                "platform": "splunk",
                "query": 'index=* process_name="powershell.exe"',
            }
        })
        assert r.status_code in [200, 401, 422]

    def test_tag_detection(self, api, ensure_running):
        r = api.post("/api/library/tags", json={
            "detection_id": "test-id",
            "tags": ["critical", "powershell"],
        })
        assert r.status_code in [200, 401, 404, 422]

    def test_set_visibility(self, api, ensure_running):
        r = api.post("/api/library/visibility", json={
            "detection_id": "test-id",
            "visibility": "private",
        })
        assert r.status_code in [200, 401, 404, 422]

    def test_delete_detection(self, api, ensure_running):
        r = api.post("/api/library/delete", json={"detection_id": "nonexistent-id"})
        assert r.status_code in [200, 401, 404, 422]
