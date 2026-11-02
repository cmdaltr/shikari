"""The agent loop (shikari/agents/runtime.py) with a scripted model instead of Claude."""

import time
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from shikari.agents.runtime import Agent, Tool, start


def _text(text):
    return SimpleNamespace(type="text", text=text)


def _tool_use(name, args, uid="t1"):
    return SimpleNamespace(type="tool_use", name=name, input=args, id=uid)


def _response(*blocks, stop="end_turn"):
    return SimpleNamespace(content=list(blocks), stop_reason=stop,
                           usage=SimpleNamespace(input_tokens=10, output_tokens=5))


def _agent(tools, max_turns=5):
    return Agent(name="t", title="T", summary="", system="sys", inputs={"q": {"required": True}},
                 tools=lambda ctx: tools, task=lambda i: i["q"], max_turns=max_turns)


def _run(agent, script, inputs=None, auto_approve=False, decide=None):
    calls = []

    def fake_create(client, kwargs):
        calls.append([dict(m) if isinstance(m, dict) else m for m in kwargs["messages"]])
        return script.pop(0)

    with patch("anthropic.Anthropic"), patch("shikari.ai.llm.providers._create_message", side_effect=fake_create):
        session = start(agent, inputs or {"q": "hello"}, user_id=1, llm={"api_key": "k", "model": "m"},
                        context=None, auto_approve=auto_approve)
        deadline = time.time() + 5
        while session.status in ("running", "needs_approval") and time.time() < deadline:
            if session.status == "needs_approval" and decide is not None:
                session.decide(decide)
            time.sleep(0.01)
    return session, calls


@pytest.mark.unit
def test_tools_run_until_the_model_answers():
    seen = []
    tool = Tool("lookup", "Look up", {"type": "object", "properties": {}}, lambda key: seen.append(key) or {"value": 42})
    session, calls = _run(_agent([tool]), [
        _response(_tool_use("lookup", {"key": "x"}), stop="tool_use"),
        _response(_text("It's 42")),
    ])
    assert session.status == "done" and session.answer == "It's 42" and seen == ["x"]
    # The tool result went back to the model on the next turn
    result = calls[1][-1]["content"][0]
    assert result["type"] == "tool_result" and '"value": 42' in result["content"] and not result["is_error"]
    assert [e["type"] for e in session.events] == ["task", "tool_call", "tool_result", "text", "done"]


@pytest.mark.unit
def test_a_changing_tool_waits_for_approval_and_a_refusal_is_reported():
    ran = []
    tool = Tool("hunt", "Start a hunt", {"type": "object", "properties": {}}, lambda: ran.append(1), changes=True)
    session, calls = _run(_agent([tool]), [
        _response(_tool_use("hunt", {}), stop="tool_use"),
        _response(_text("OK, not hunting")),
    ], decide=False)
    assert ran == [] and session.status == "done"
    result = calls[1][-1]["content"][0]
    assert result["is_error"] and "declined" in result["content"]
    assert any(e["type"] == "approval" and e["approved"] is False for e in session.events)


@pytest.mark.unit
def test_auto_approve_runs_changing_tools():
    ran = []
    tool = Tool("hunt", "Start a hunt", {"type": "object", "properties": {}}, lambda: ran.append(1) or "started", changes=True)
    session, _ = _run(_agent([tool]), [_response(_tool_use("hunt", {}), stop="tool_use"), _response(_text("done"))],
                      auto_approve=True)
    assert ran == [1] and session.status == "done"


@pytest.mark.unit
def test_tool_errors_go_back_to_the_model_and_turns_are_capped():
    def boom():
        raise RuntimeError("nope")

    tool = Tool("boom", "Fails", {"type": "object", "properties": {}}, boom)
    script = [_response(_tool_use("boom", {}, uid=f"t{i}"), stop="tool_use") for i in range(3)]
    session, calls = _run(_agent([tool], max_turns=2), script)
    assert session.status == "stopped" and len(calls) == 2
    assert "RuntimeError: nope" in calls[1][-1]["content"][0]["content"]


@pytest.mark.unit
def test_required_inputs_are_checked_before_starting():
    with pytest.raises(ValueError, match="required"):
        start(_agent([]), {"q": " "}, user_id=1, llm={"api_key": "k", "model": "m"}, context=None)
