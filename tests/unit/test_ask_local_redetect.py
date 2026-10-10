"""
Ask finds a local LLM started after Archer.

Local endpoints were probed only at startup, so the 503's own advice ("start a
local Ollama instance") did nothing until Archer was restarted.
"""
from types import SimpleNamespace
from unittest.mock import patch

from fastapi import FastAPI
from fastapi.testclient import TestClient

from archer import chat

OLLAMA = {"name": "Ollama", "provider": "ollama", "available": True, "model": "qwen3:8b"}


def _client(redetect=None):
    app = FastAPI()
    app.include_router(chat.router)
    app.state.local_llm_endpoints = []
    if redetect:
        app.state.redetect_local_llm = redetect
    return app, TestClient(app)


def _local(endpoints):
    if not endpoints:
        return None, None
    return SimpleNamespace(generate=lambda **k: SimpleNamespace(content="answer")), "Ollama"


def test_ask_reprobes_when_no_provider_was_found_at_startup():
    calls = []

    async def redetect():
        calls.append(1)
        app.state.local_llm_endpoints = [OLLAMA]

    app, client = _client(redetect)
    with patch.object(chat, "_try_cloud_providers", return_value=(None, None)), \
         patch.object(chat, "_try_local_providers", side_effect=_local):
        r = client.post("/api/ask", json={"question": "What is T1059.001?"})
    assert r.status_code == 200 and r.json()["provider"] == "Ollama"
    assert calls == [1]


def test_ask_still_503s_when_nothing_is_running():
    async def redetect():
        pass

    _, client = _client(redetect)
    with patch.object(chat, "_try_cloud_providers", return_value=(None, None)), \
         patch.object(chat, "_try_local_providers", side_effect=_local):
        r = client.post("/api/ask", json={"question": "What is T1059.001?"})
    assert r.status_code == 503
