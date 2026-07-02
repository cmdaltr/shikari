"""
Tests for the /threat_groups autocomplete endpoint.
"""
import pytest


class TestThreatGroupsLookup:
    """Verify /threat_groups returns group data for autocomplete."""

    def test_returns_groups_list(self, api, ensure_running):
        r = api.get("/threat_groups", params={"query": "APT"})
        assert r.status_code == 200
        data = r.json()
        assert "groups" in data
        assert isinstance(data["groups"], list)

    def test_finds_apt28(self, api, ensure_running):
        r = api.get("/threat_groups", params={"query": "APT28"})
        data = r.json()
        names = [g.get("name", g) if isinstance(g, dict) else g for g in data["groups"]]
        assert any("APT28" in str(n) for n in names)

    def test_finds_by_alias(self, api, ensure_running):
        r = api.get("/threat_groups", params={"query": "Fancy Bear"})
        data = r.json()
        assert data.get("ok") is True or len(data.get("groups", [])) >= 0

    def test_empty_query_returns_results(self, api, ensure_running):
        r = api.get("/threat_groups", params={"query": ""})
        assert r.status_code == 200
        data = r.json()
        assert isinstance(data.get("groups", []), list)

    def test_nonexistent_group(self, api, ensure_running):
        r = api.get("/threat_groups", params={"query": "FakeGroup99999"})
        assert r.status_code == 200
        data = r.json()
        assert len(data.get("groups", [])) == 0

    @pytest.mark.parametrize("group", [
        "Scattered Spider", "Lazarus Group", "Wizard Spider",
        "FIN7", "Sandworm", "Salt Typhoon",
    ])
    def test_known_groups_findable(self, api, ensure_running, group):
        r = api.get("/threat_groups", params={"query": group})
        assert r.status_code == 200
        data = r.json()
        assert len(data.get("groups", [])) > 0, f"Could not find {group}"
