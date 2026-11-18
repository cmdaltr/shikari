"""Blank input is refused with a 400 before anything runs: a group name, an upload, a question or a briefing group."""

import io
from types import SimpleNamespace
from unittest.mock import patch

from fastapi import FastAPI
from fastapi.testclient import TestClient

import shikari.app as web
from shikari import chat


def test_an_empty_upload_is_a_400_not_a_500(monkeypatch):
    monkeypatch.setattr(web, "require_auth", lambda request, session: (
        SimpleNamespace(id=1), SimpleNamespace(close=lambda: None)))
    r = TestClient(web.app).post("/upload", files={"file": ("empty.txt", io.BytesIO(b""), "text/plain")})
    assert r.status_code == 400
    assert r.json() == {"success": False, "error": "The file is empty"}


def test_a_blank_group_name_starts_no_blog_search(monkeypatch):
    monkeypatch.setattr(web, "check_group_in_mitre", lambda *a: (_ for _ in ()).throw(AssertionError("looked up")))
    r = TestClient(web.app).post("/generate", data={"group_name": "   "})
    assert r.status_code == 400


def _chat_client():
    app = FastAPI()
    app.include_router(chat.router)
    app.state.local_llm_endpoints = []
    return TestClient(app)


def test_a_blank_question_asks_no_model():
    with patch.object(chat, "_provider_candidates", side_effect=AssertionError("a model was asked")):
        r = _chat_client().post("/api/ask", json={"question": "   "})
    assert r.status_code == 400


def test_a_blank_briefing_group_is_refused_before_the_lookup():
    with patch("shikari.chat.get_db", side_effect=AssertionError("the database was opened")):
        r = _chat_client().post("/api/threat-briefing", json={"group": " "}, cookies={"shikari_session": "x"})
    assert r.status_code == 400
