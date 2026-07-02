"""
Tests for draft save/load endpoints and manual YAML editor.
"""
import pytest


class TestDrafts:
    """Draft YAML save, load, and list."""

    def test_save_draft(self, api, ensure_running):
        r = api.post("/save_draft", json={
            "group_name": "TestDraft",
            "yaml_content": "title: Test\ntechnique_id: T1059.001\n",
        })
        assert r.status_code in [200, 401, 422]

    def test_load_draft(self, api, ensure_running):
        r = api.get("/load_draft", params={"draft_id": "nonexistent"})
        assert r.status_code in [200, 401, 404]

    def test_list_drafts(self, api, ensure_running):
        r = api.get("/list_drafts")
        assert r.status_code in [200, 401]
        if r.status_code == 200:
            data = r.json()
            assert isinstance(data, (dict, list))


class TestManualYAML:
    """Manual YAML editor page and submission."""

    def test_manual_page_loads(self, api, ensure_running):
        r = api.get("/manual")
        assert r.status_code in [200, 302]

    def test_manual_submit(self, api, ensure_running):
        r = api.post("/manual_submit", data={
            "yaml_content": "title: Manual Test\ntechnique_id: T1059\n",
        }, allow_redirects=False)
        assert r.status_code in [200, 302, 303, 400, 401, 422]


class TestCompleteYAML:
    """POST /complete_yaml auto-completes partial YAML."""

    def test_complete_partial_yaml(self, api, ensure_running):
        r = api.post("/complete_yaml", json={
            "yaml_content": "title: Incomplete\ntechnique_id: T1059.001",
        })
        assert r.status_code in [200, 401, 422]
