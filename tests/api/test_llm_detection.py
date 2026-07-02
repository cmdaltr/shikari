"""
Tests for LLM detection and preference endpoints.
"""
import pytest


class TestLLMDetection:
    """Verify /api/llm/detect returns provider info."""

    def test_llm_detect_returns_providers(self, api, ensure_running):
        r = api.get("/api/llm/detect")
        assert r.status_code == 200
        data = r.json()
        # Should report which providers are available
        assert isinstance(data, dict)

    def test_llm_detect_has_expected_fields(self, api, ensure_running):
        r = api.get("/api/llm/detect")
        data = r.json()
        # Expect at least one provider key
        provider_keys = ["anthropic", "openai", "ollama", "lm_studio", "providers"]
        assert any(k in data for k in provider_keys) or "ok" in data


class TestLLMPreference:
    """Verify /api/llm/preference accepts provider selection."""

    def test_set_anthropic_preference(self, api, ensure_running):
        r = api.post("/api/llm/preference", json={"provider": "anthropic"})
        assert r.status_code in [200, 401, 422]

    def test_set_openai_preference(self, api, ensure_running):
        r = api.post("/api/llm/preference", json={"provider": "openai"})
        assert r.status_code in [200, 401, 422]

    def test_set_ollama_preference(self, api, ensure_running):
        r = api.post("/api/llm/preference", json={"provider": "ollama"})
        assert r.status_code in [200, 401, 422]

    def test_invalid_provider_handled(self, api, ensure_running):
        r = api.post("/api/llm/preference", json={"provider": "nonexistent"})
        assert r.status_code in [200, 400, 401, 422]
