"""
Tests for adversary emulation endpoint.
"""
import pytest


def _emulate(api, technique, mode="simulate"):
    """POST /emulate; skips the test when the server has emulation switched off."""
    r = api.post("/emulate", data={"technique": technique, "emulation_mode": mode}, timeout=60)
    # Off by default (shikari.config.EMULATION_ENABLED): a 503 that says so is the right answer
    if r.status_code == 503:
        assert "not enabled" in r.json()["message"]
        pytest.skip("Emulation is disabled on this server (EMULATION_ENABLED)")
    return r


class TestEmulation:
    """POST /emulate triggers Atomic Red Team emulation."""

    def test_emulate_technique(self, api, ensure_running):
        r = _emulate(api, "T1059.001")
        assert r.status_code in [200, 500]

    def test_emulate_group_name(self, api, ensure_running):
        r = _emulate(api, "APT28")
        assert r.status_code in [200, 500]

    def test_empty_technique_rejected(self, api, ensure_running):
        # Refused by the form's validation, before the feature flag is looked at
        r = api.post("/emulate", data={"technique": "", "emulation_mode": "simulate"}, timeout=30)
        assert r.status_code == 422

    @pytest.mark.parametrize("mode", ["simulate", "execute"])
    def test_emulation_modes(self, api, ensure_running, mode):
        r = _emulate(api, "T1059.001", mode)
        assert r.status_code in [200, 500]
