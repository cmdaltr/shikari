"""
Tests for results page and download endpoints.
"""
import pytest


class TestResultsPage:
    """GET /results renders detection results."""

    def test_results_page_for_group(self, api, ensure_running):
        r = api.get("/results", params={"group_name": "APT28"})
        assert r.status_code in [200, 302, 404]

    def test_results_page_no_group(self, api, ensure_running):
        r = api.get("/results")
        assert r.status_code in [200, 302, 400, 404, 422]


class TestDetectionAPI:
    """GET /api/detection/{filename} returns individual YAML."""

    def test_nonexistent_detection(self, api, ensure_running):
        r = api.get("/api/detection/nonexistent_file_12345.yaml")
        assert r.status_code in [404, 200]


class TestDownloads:
    """Download endpoints for detections and attack flows."""

    def test_download_single_detection(self, api, ensure_running):
        r = api.get("/api/download/detection/nonexistent.yaml")
        assert r.status_code in [200, 404]

    def test_download_all_for_group(self, api, ensure_running):
        r = api.get("/api/download/all/APT28")
        # May or may not have generated files
        assert r.status_code in [200, 404]
        if r.status_code == 200:
            assert "zip" in r.headers.get("content-type", "") or \
                   "octet-stream" in r.headers.get("content-type", "") or \
                   len(r.content) > 0

    def test_download_attack_flow(self, api, ensure_running):
        r = api.get("/api/attack-flow/nonexistent.json")
        assert r.status_code in [200, 404]

    def test_download_flow_file(self, api, ensure_running):
        r = api.get("/api/download/flow/nonexistent.json")
        assert r.status_code in [200, 404]


class TestProgressStatus:
    """GET /progress_status returns generation progress."""

    def test_progress_for_group(self, api, ensure_running):
        r = api.get("/progress_status", params={"group_name": "APT28"})
        assert r.status_code in [200, 401]
        if r.status_code == 200:
            data = r.json()
            assert isinstance(data, dict)

    def test_progress_for_nonexistent_group(self, api, ensure_running):
        r = api.get("/progress_status", params={"group_name": "NoSuchGroup"})
        assert r.status_code in [200, 404]
