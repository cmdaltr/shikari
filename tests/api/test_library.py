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

    def test_export_needs_a_selection(self, api, ensure_running):
        r = api.post("/api/library/export", json={"format": "json"})
        assert r.status_code == 400

    def test_save_refuses_a_detection_without_a_query(self, api, ensure_running):
        r = api.post("/api/library/save", json={
            "title": "API test - no query",
            "detection_type": "detection",
            "content": {"technique": "T1059.001", "query": "x"},
            "platform": "splunk",
        })
        assert r.status_code == 400

    @pytest.mark.parametrize("path", ["/api/library/tags", "/api/library/visibility", "/api/library/delete"])
    def test_bulk_actions_need_ids(self, api, ensure_running, path):
        r = api.post(path, json={"ids": [], "tags": ["x"], "visibility": "private"})
        assert r.status_code == 400

    @pytest.mark.parametrize("path", ["/api/library/tags", "/api/library/visibility", "/api/library/delete"])
    def test_bulk_actions_refuse_unknown_ids(self, api, ensure_running, path):
        r = api.post(path, json={"ids": [999999999], "tags": ["x"], "visibility": "private"})
        assert r.status_code == 403


class TestLibraryRoundTrip:
    """Save a detection, tag it, share it, export it and delete it again."""

    TITLE = "T1059.001 - API test: PowerShell encoded command"

    @pytest.fixture
    def detection_id(self, api, ensure_running):
        r = api.post("/api/library/save", json={
            "title": self.TITLE,
            "detection_type": "detection",
            "visibility": "private",
            "content": {
                "technique": "T1059.001",
                "title": "PowerShell encoded command",
                "query": 'index=* process_name="powershell.exe" CommandLine="*-EncodedCommand*"',
            },
            "platform": "splunk",
            "tags": [],
        })
        assert r.status_code == 200 and r.json()["success"]
        detection_id = r.json()["id"]
        yield detection_id
        # Left behind only if a test deleted it already
        api.post("/api/library/delete", json={"ids": [detection_id]})

    def test_tag_detection(self, api, detection_id):
        r = api.post("/api/library/tags", json={"ids": [detection_id], "tags": ["critical", "powershell"]})
        assert r.status_code == 200 and r.json()["count"] == 1

    def test_set_visibility(self, api, detection_id):
        for visibility in ["shared", "private"]:
            r = api.post("/api/library/visibility", json={"ids": [detection_id], "visibility": visibility})
            assert r.status_code == 200 and r.json()["count"] == 1

    def test_export_library(self, api, detection_id):
        r = api.post("/api/library/export", json={"ids": [detection_id], "format": "json"})
        assert r.status_code == 200
        assert self.TITLE in r.text

    def test_delete_detection(self, api, detection_id):
        r = api.post("/api/library/delete", json={"ids": [detection_id]})
        assert r.status_code == 200 and r.json()["deleted_count"] == 1
        r = api.post("/api/library/delete", json={"ids": [detection_id]})
        assert r.status_code == 403
