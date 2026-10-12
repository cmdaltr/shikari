"""Agents on any tool-calling provider (archer/agents/llm.py), which one is picked, and saved sessions."""

import json
import time
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from cryptography.fernet import Fernet
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from archer.agents import agent_llm, store
from archer.agents.runtime import Agent, Tool, start
from archer.ai import assignment
from archer.auth.encryption import encrypt_api_key
from archer.database.models import APIKey, Base, User

KEY = Fernet.generate_key()


@pytest.fixture
def db(tmp_path, monkeypatch):
    engine = create_engine(f"sqlite:///{tmp_path / 't.db'}")
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine)
    session = factory()
    session.add(User(id=1, email="u@x", full_name="u", password_hash="x"))
    session.commit()
    monkeypatch.setattr("archer.database.db.SessionLocal", factory)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    with patch("archer.auth.encryption.get_encryption_key", return_value=KEY):
        yield session
    session.close()


def _key(db, platform, value="sk-test"):
    db.add(APIKey(user_id=1, platform=platform, encrypted_key=encrypt_api_key(value)))
    db.commit()


@pytest.mark.unit
def test_claude_is_preferred_then_the_ask_provider(db):
    assert agent_llm(db, 1) is None
    _key(db, "openai")
    llm = agent_llm(db, 1)
    assert llm["provider"] == "openai" and llm["base_url"] == "https://api.openai.com/v1" and llm["model"]
    _key(db, "anthropic")
    assert agent_llm(db, 1)["provider"] == "anthropic"
    assert agent_llm(db, 1, "openai", "gpt-x")["model"] == "gpt-x"


@pytest.mark.unit
def test_a_local_endpoint_runs_through_its_v1_api(db):
    settings = assignment.load_settings(db, 1)
    settings["local"] = {"endpoint": "http://localhost:11434", "model": "qwen3:8b"}
    assignment.save_settings(db, 1, settings)
    llm = agent_llm(db, 1)
    assert llm == {"provider": "local", "label": "Local (localhost:11434)", "api_key": "",
                   "model": "qwen3:8b", "base_url": "http://localhost:11434/v1"}
    assert agent_llm(db, 1, "anthropic") is None  # asked for, not configured


def _completion(content="", calls=(), finish="stop"):
    tool_calls = [SimpleNamespace(id=f"c{i}", function=SimpleNamespace(name=n, arguments=json.dumps(a)))
                  for i, (n, a) in enumerate(calls)]
    message = SimpleNamespace(content=content, tool_calls=tool_calls or None)
    return SimpleNamespace(choices=[SimpleNamespace(message=message, finish_reason=finish)],
                           usage=SimpleNamespace(prompt_tokens=7, completion_tokens=3))


@pytest.mark.unit
def test_the_loop_runs_on_an_openai_compatible_api_and_is_saved(db):
    seen, sent = [], []
    tool = Tool("lookup", "Look up", {"type": "object", "properties": {"key": {"type": "string"}}},
                lambda key: seen.append(key) or {"value": 42})
    script = [_completion("<think>hmm</think>", [("lookup", {"key": "x"})], "tool_calls"),
              _completion("<think>so</think>It's 42")]

    def create(**kwargs):
        sent.append(kwargs)
        return script.pop(0)

    agent = Agent(name="t", title="T", summary="", system="sys", inputs={}, tools=lambda ctx: [tool],
                  task=lambda i: "hello")
    with patch("openai.OpenAI") as client:
        client.return_value.chat.completions.create.side_effect = create
        session = start(agent, {}, user_id=1, llm={"provider": "local", "base_url": "http://h/v1", "model": "m"},
                        context=None, persist=store.save)
        deadline = time.time() + 5
        while session.status == "running" and time.time() < deadline:
            time.sleep(0.01)

    assert session.status == "done" and session.answer == "It's 42" and seen == ["x"]
    assert sent[0]["tools"][0]["function"]["name"] == "lookup" and sent[0]["messages"][0]["role"] == "system"
    assistant, result = sent[1]["messages"][-2:]
    assert assistant["tool_calls"][0]["function"]["name"] == "lookup"
    assert result == {"role": "tool", "tool_call_id": "c0", "content": '{"value": 42}'}
    assert session.tokens == {"input": 14, "output": 6}

    saved = store.load(session.id, 1)
    assert saved.status == "done" and saved.answer == "It's 42" and saved.view()["turns"] == 2
    assert store.load(session.id, 2) is None  # another user's session
    assert store.recent(1)[0]["session_id"] == session.id


@pytest.mark.unit
def test_a_session_cut_off_by_a_restart_reads_back_as_interrupted(db):
    from archer.database.models import AgentRun

    db.add(AgentRun(id="a" * 32, user_id=1, agent="ask", status="running", events="[]"))
    db.commit()
    saved = store.load("a" * 32, 1)
    assert saved.status == "interrupted" and saved.events[-1]["type"] == "interrupted"
    assert store.recent(1)[0]["status"] == "interrupted"
    assert store.recent(1, live={"a" * 32})[0]["status"] == "running"


@pytest.mark.unit
def test_an_interrupted_session_continues_from_its_saved_conversation(db):
    from archer.agents.runtime import resume
    from archer.database.models import AgentRun

    conversation = [
        {"role": "user", "content": "hello"},
        {"role": "assistant", "content": None, "tool_calls": [
            {"id": "c0", "type": "function", "function": {"name": "lookup", "arguments": "{}"}}]},
        {"role": "tool", "tool_call_id": "c0", "content": '{"value": 42}'},
    ]
    db.add(AgentRun(id="b" * 32, user_id=1, agent="t", status="running", task="hello", turns=1,
                    events=json.dumps([{"n": 0, "type": "task", "text": "hello"}]),
                    provider="local", conversation=json.dumps(conversation)))
    db.commit()
    saved = store.load("b" * 32, 1)
    assert saved.status == "interrupted" and saved.resumable

    sent = []
    agent = Agent(name="t", title="T", summary="", system="sys", inputs={}, tools=lambda ctx: [],
                  task=lambda i: "hello", max_turns=3)
    with patch("openai.OpenAI") as client:
        client.return_value.chat.completions.create.side_effect = lambda **kw: sent.append(kw) or _completion("It's 42")
        session = resume(saved, agent, llm={"provider": "local", "base_url": "http://h/v1", "model": "m"},
                         context=None, persist=store.save)
        deadline = time.time() + 5
        while session.status == "running" and time.time() < deadline:
            time.sleep(0.01)

    assert session.status == "done" and session.answer == "It's 42" and session.turns == 2
    assert sent[0]["messages"][1:] == conversation  # after the system message
    types = [e["type"] for e in store.load("b" * 32, 1).events]
    assert types[:3] == ["task", "interrupted", "resumed"] and types[-1] == "done"
    assert not store.load("b" * 32, 1).resumable
