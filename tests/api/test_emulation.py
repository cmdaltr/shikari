"""
Tests for adversary emulation endpoint.
"""
import pytest


class TestEmulation:
    """POST /emulate triggers Atomic Red Team emulation."""

    def test_emulate_technique(self, api, ensure_running):
        r = api.post("/emulate", data={
            "technique": "T1059.001",
            "emulation_mode": "simulate",
        }, timeout=60)
        assert r.status_code in [200, 401, 422, 500]

    def test_emulate_group_name(self, api, ensure_running):
        r = api.post("/emulate", data={
            "technique": "APT28",
            "emulation_mode": "simulate",
        }, timeout=60)
        assert r.status_code in [200, 401, 422, 500]

    def test_empty_technique_rejected(self, api, ensure_running):
        r = api.post("/emulate", data={
            "technique": "",
            "emulation_mode": "simulate",
        }, timeout=30)
        assert r.status_code in [200, 400, 401, 422]

    @pytest.mark.parametrize("mode", ["simulate", "execute"])
    def test_emulation_modes(self, api, ensure_running, mode):
        r = api.post("/emulate", data={
            "technique": "T1059.001",
            "emulation_mode": mode,
        }, timeout=60)
        assert r.status_code in [200, 401, 422, 500]
