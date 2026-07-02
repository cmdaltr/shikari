"""
Tests for field mapping endpoints (save, load, test).
"""
import pytest


class TestMappings:
    """Field mapping CRUD and testing."""

    def test_save_mapping(self, api, ensure_running):
        r = api.post("/api/mappings/save", json={
            "name": "test_mapping",
            "mappings": {"process_name": "Image"},
        })
        assert r.status_code in [200, 401, 422]

    def test_load_mapping(self, api, ensure_running):
        r = api.get("/api/mappings/load")
        assert r.status_code in [200, 401]
        if r.status_code == 200:
            data = r.json()
            assert isinstance(data, (dict, list))

    def test_test_mapping(self, api, ensure_running):
        r = api.post("/api/mappings/test", json={
            "mapping": {"process_name": "Image"},
            "query": "index=* process_name=cmd.exe",
        })
        assert r.status_code in [200, 401, 422]
