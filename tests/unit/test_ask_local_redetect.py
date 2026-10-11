"""
Ask finds a local LLM started after Archer.

Local endpoints were probed only at startup, so the 503's own advice ("start a
local Ollama instance") did nothing until Archer was restarted.
"""
from types import SimpleNamespace
from unittest.mock import patch

import pytest

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


def _answers(text):
    return lambda: SimpleNamespace(generate=lambda **k: SimpleNamespace(content=text))


def _local(endpoints):
    return [("Ollama", _answers("answer"))] if endpoints else []


def test_ask_reprobes_when_no_provider_was_found_at_startup():
    calls = []

    async def redetect():
        calls.append(1)
        app.state.local_llm_endpoints = [OLLAMA]

    app, client = _client(redetect)
    with patch.object(chat, "_cloud_candidates", return_value=[]), \
         patch.object(chat, "_local_candidates", side_effect=_local):
        r = client.post("/api/ask", json={"question": "What is T1059.001?"})
    assert r.status_code == 200 and r.json()["provider"] == "Ollama"
    assert calls == [1]


def test_ask_still_503s_when_nothing_is_running():
    async def redetect():
        pass

    _, client = _client(redetect)
    with patch.object(chat, "_cloud_candidates", return_value=[]), \
         patch.object(chat, "_local_candidates", side_effect=_local):
        r = client.post("/api/ask", json={"question": "What is T1059.001?"})
    assert r.status_code == 503


def _fails(message):
    def make():
        def generate(**k):
            raise RuntimeError(message)
        return SimpleNamespace(generate=generate)
    return make


def test_unassigned_ask_falls_back_when_a_provider_errors():
    # A cloud key with no credit used to end Ask Archer even with Ollama running
    _, client = _client()
    cloud = [("Claude (Anthropic)", _fails("Error code: 400 - {'message': 'Your credit balance is too low'}"))]
    with patch.object(chat, "_cloud_candidates", return_value=cloud), \
         patch.object(chat, "_local_candidates", return_value=[("Ollama", _answers("from ollama"))]):
        r = client.post("/api/ask", json={"question": "What is T1059.001?"})
    assert r.status_code == 200
    assert r.json() == {"answer": "from ollama", "provider": "Ollama"}


def test_assigned_ask_reports_its_error_instead_of_falling_back():
    with patch.object(chat, "_local_candidates", return_value=[("Ollama", _answers("from ollama"))]):
        with pytest.raises(chat.HTTPException) as err:
            chat._generate([("Anthropic Claude / x", _fails("Error code: 400 - {'credit balance is too low'}"))],
                           True, "Ask Archer", prompt="q")
    assert err.value.status_code == 502 and "credit balance too low" in err.value.detail


def test_every_failure_is_listed():
    with pytest.raises(chat.HTTPException) as err:
        chat._generate([("A", _fails("boom")), ("B", _fails("bang"))], False, "Ask Archer", prompt="q")
    assert err.value.detail == "A: boom; B: bang"
