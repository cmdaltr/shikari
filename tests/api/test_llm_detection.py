"""
Tests for LLM detection and preference endpoints.
"""
import pytest


class TestLLMDetection:
    """Verify /api/llm/detect reports the local LLM (Ollama, LM Studio and the like) Shikari found."""

    def test_llm_detect_returns_providers(self, api, ensure_running):
        r = api.get("/api/llm/detect")
        assert r.status_code == 200
        data = r.json()
        # Should report which providers are available
        assert isinstance(data, dict)

    def test_llm_detect_has_expected_fields(self, api, ensure_running):
        # The first local LLM endpoint found at startup, or {"available": False} with none running
        data = api.get("/api/llm/detect").json()
        assert isinstance(data["available"], bool)
        if data["available"]:
            for key in ["name", "provider", "url", "base_url", "models", "model"]:
                assert key in data
            assert isinstance(data["models"], list)
        else:
            assert data == {"available": False}


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
