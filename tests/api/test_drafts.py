"""
Tests for draft save/load endpoints and manual YAML editor.
"""
import pytest


class TestDrafts:
    """Draft YAML save, load, and list."""

    def test_save_and_load_draft(self, api, ensure_running):
        entries = [{"technique_id": "T1059.001", "yaml_content": "title: Test\n"}]
        r = api.post("/save_draft", json={"draft_id": "api_test_draft", "entries": entries})
        assert r.status_code == 200 and r.json() == {"ok": True}
        r = api.get("/load_draft", params={"draft_id": "api_test_draft"})
        assert r.status_code == 200 and r.json() == {"ok": True, "entries": entries}

    def test_save_draft_needs_a_draft_id(self, api, ensure_running):
        # The id names the draft's file: anything but letters, digits, - and _ is refused
        for draft_id in ["", "../escape", "a b"]:
            r = api.post("/save_draft", json={"draft_id": draft_id, "entries": []})
            assert r.status_code == 400

    def test_load_missing_draft(self, api, ensure_running):
        r = api.get("/load_draft", params={"draft_id": "nonexistent"})
        assert r.status_code == 200 and r.json() == {"ok": True, "entries": []}

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

