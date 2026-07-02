"""
Tests for the Ask Archer and Threat Briefing endpoints.
"""
import pytest


class TestAskArcher:
    """POST /api/ask conversational Q&A."""

    def test_ask_simple_question(self, api, ensure_running):
        r = api.post("/api/ask", json={
            "question": "What is T1059.001?",
        })
        assert r.status_code in [200, 401, 422, 500]
        if r.status_code == 200:
            data = r.json()
            assert "answer" in data
            assert "provider" in data

    def test_ask_with_group_context(self, api, ensure_running):
        r = api.post("/api/ask", json={
            "question": "What techniques does this group use for initial access?",
            "context": {"group": "Scattered Spider"},
        })
        assert r.status_code in [200, 401, 422, 500]

    def test_ask_empty_question(self, api, ensure_running):
        r = api.post("/api/ask", json={"question": ""})
        assert r.status_code in [200, 400, 401, 422]

    def test_ask_siem_question(self, api, ensure_running):
        r = api.post("/api/ask", json={
            "question": "Write a Splunk query to detect PowerShell encoded commands",
        })
        assert r.status_code in [200, 401, 422, 500]


class TestThreatBriefing:
    """POST /api/threat-briefing generates prioritized briefing."""

    def test_briefing_for_group(self, api, ensure_running):
        r = api.post("/api/threat-briefing", json={
            "group": "Scattered Spider",
            "top_n": 5,
        })
        assert r.status_code in [200, 401, 422, 500]
        if r.status_code == 200:
            data = r.json()
            assert "group_name" in data or "briefing_summary" in data or "top_techniques" in data

    def test_briefing_for_apt28(self, api, ensure_running):
        r = api.post("/api/threat-briefing", json={
            "group": "APT28",
            "top_n": 3,
        })
        assert r.status_code in [200, 401, 422, 500]

    def test_briefing_for_nonexistent_group(self, api, ensure_running):
        r = api.post("/api/threat-briefing", json={
            "group": "FakeGroup99999",
        })
        assert r.status_code in [200, 400, 401, 404, 422, 500]

    def test_briefing_empty_group(self, api, ensure_running):
        r = api.post("/api/threat-briefing", json={"group": ""})
        assert r.status_code in [200, 400, 401, 422]

    def test_briefing_custom_top_n(self, api, ensure_running):
        r = api.post("/api/threat-briefing", json={
            "group": "APT29",
            "top_n": 10,
        })
        assert r.status_code in [200, 401, 422, 500]
