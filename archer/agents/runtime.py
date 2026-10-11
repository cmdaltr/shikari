"""
The agent loop: a model, a set of tools, and a loop that runs until the model stops
asking for tools.

    messages = [task]
    loop:
        response = model(system, tools, messages)
        if the response asks for no tools: done, its text is the answer
        run each tool it asked for (pausing for approval if the tool changes something)
        append the tool results to messages and go round again

Everything else here is housekeeping: a trace of each step (so a person can watch the
agent work), approval for tools that change things, limits on turns, and sessions that
run in a background thread so the web page, the console and the MCP server can follow
along and answer approval prompts.
"""

import json
import logging
import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger(__name__)

TOOL_RESULT_LIMIT = 20000   # characters of one tool result the model sees
APPROVAL_TIMEOUT = 30 * 60  # an unanswered approval stops the session
SESSION_TTL = 6 * 3600


@dataclass
class Tool:
    """A function the model may call. changes=True: it needs a person's approval first."""

    name: str
    description: str
    input_schema: Dict
    fn: Callable[..., Any]
    changes: bool = False

    def spec(self) -> Dict:
        return {"name": self.name, "description": self.description, "input_schema": self.input_schema}


@dataclass
class Agent:
    """What an agent is: instructions, tools, and how a task becomes its first message."""

    name: str
    title: str
    summary: str
    system: str
    inputs: Dict[str, Dict]                  # form fields: {name: {"label", "required", "placeholder"}}
    tools: Callable[[Any], List[Tool]]       # ToolContext -> tools
    task: Callable[[Dict], str]              # inputs -> the first user message
    max_turns: int = 20
    max_tokens: int = 8000


@dataclass
class Session:
    id: str
    agent: Agent
    user_id: int
    auto_approve: bool
    status: str = "running"                  # running | needs_approval | done | stopped | error
    events: List[Dict] = field(default_factory=list)
    answer: str = ""
    pending: Optional[Dict] = None
    turns: int = 0
    tokens: Dict[str, int] = field(default_factory=lambda: {"input": 0, "output": 0})
    created: float = field(default_factory=time.time)
    _decision: Optional[bool] = None
    _decided: threading.Event = field(default_factory=threading.Event)
    _stop: bool = False

    def emit(self, kind: str, **data) -> None:
        self.events.append({"n": len(self.events), "type": kind, "at": time.time(), **data})

    def view(self, since: int = 0) -> Dict:
        return {"session_id": self.id, "agent": self.agent.name, "status": self.status,
                "events": self.events[since:], "next": len(self.events), "pending": self.pending,
                "answer": self.answer, "turns": self.turns, "tokens": self.tokens}

    def decide(self, approve: bool) -> None:
        self._decision = approve
        self._decided.set()

    def stop(self) -> None:
        self._stop = True
        self.decide(False)


_sessions: Dict[str, Session] = {}
_lock = threading.Lock()


def get_session(session_id: str, user_id: int) -> Optional[Session]:
    session = _sessions.get(session_id)
    return session if session and session.user_id == user_id else None


def start(agent: Agent, inputs: Dict, *, user_id: int, llm: Dict, context: Any, auto_approve: bool = False) -> Session:
    """Start an agent in a background thread. llm: {"api_key", "model"} (Anthropic)."""
    for name, spec in agent.inputs.items():
        if spec.get("required") and not str(inputs.get(name) or "").strip():
            raise ValueError(f"{spec.get('label', name)} is required")
    with _lock:
        now = time.time()
        for sid in [s for s, v in _sessions.items() if now - v.created > SESSION_TTL]:
            _sessions.pop(sid, None)
        session = Session(id=uuid.uuid4().hex, agent=agent, user_id=user_id, auto_approve=auto_approve)
        _sessions[session.id] = session
    threading.Thread(target=_run, args=(session, inputs, llm, context), daemon=True,
                     name=f"agent-{agent.name}-{session.id[:8]}").start()
    return session


def _run(session: Session, inputs: Dict, llm: Dict, context: Any) -> None:
    import anthropic

    from archer.ai.llm.providers import _create_message

    agent = session.agent
    tools = {t.name: t for t in agent.tools(context)}
    client = anthropic.Anthropic(api_key=llm["api_key"])
    task = agent.task(inputs)
    messages: List[Dict] = [{"role": "user", "content": task}]
    session.emit("task", text=task, model=llm["model"], tools=[t.name for t in tools.values()])
    try:
        while not session._stop:
            if session.turns >= agent.max_turns:
                session.emit("limit", text=f"Stopped after {agent.max_turns} turns")
                session.status = "stopped"
                return
            session.turns += 1
            response = _create_message(client, {
                "model": llm["model"], "max_tokens": agent.max_tokens, "system": agent.system,
                "tools": [t.spec() for t in tools.values()], "messages": messages,
            })
            session.tokens["input"] += response.usage.input_tokens
            session.tokens["output"] += response.usage.output_tokens
            # The whole response goes back next turn, thinking blocks included: the API
            # needs them to continue a tool-using turn
            messages.append({"role": "assistant", "content": response.content})
            text = "".join(b.text for b in response.content if b.type == "text").strip()
            calls = [b for b in response.content if b.type == "tool_use"]
            if text:
                session.emit("text", text=text, final=not calls)
            if not calls:
                session.answer = text
                session.status = "done"
                session.emit("done", stop_reason=response.stop_reason, tokens=dict(session.tokens))
                return
            results = [_call(session, tools, call) for call in calls]
            messages.append({"role": "user", "content": results})
        session.status = "stopped"
        session.emit("stopped")
    except Exception as e:
        logger.exception("Agent %s failed", agent.name)
        session.status = "error"
        session.emit("error", text=f"{e.__class__.__name__}: {e}")


def _call(session: Session, tools: Dict[str, Tool], call) -> Dict:
    tool = tools.get(call.name)
    args = call.input or {}
    session.emit("tool_call", tool=call.name, input=args, changes=bool(tool and tool.changes))
    if tool is None:
        return _result(session, call, f"No tool named {call.name}", error=True)
    if tool.changes and not session.auto_approve:
        session.pending = {"tool": call.name, "input": args, "description": tool.description.split(". ")[0]}
        session.status = "needs_approval"
        session._decided.clear()
        session.emit("approval_needed", tool=call.name, input=args)
        answered = session._decided.wait(APPROVAL_TIMEOUT)
        approved = answered and session._decision
        session.pending = None
        session.status = "running"
        session.emit("approval", tool=call.name, approved=bool(approved))
        if session._stop:
            return _result(session, call, "The session was stopped.", error=True)
        if not approved:
            return _result(session, call, "The user declined this action. Don't retry it; carry on without it "
                                          "or explain what it would have done.", error=True)
    try:
        output = tool.fn(**args)
    except TypeError as e:
        return _result(session, call, f"Bad arguments for {call.name}: {e}", error=True)
    except Exception as e:
        return _result(session, call, f"{e.__class__.__name__}: {e}", error=True)
    return _result(session, call, output)


def _result(session: Session, call, output: Any, error: bool = False) -> Dict:
    text = output if isinstance(output, str) else json.dumps(output, default=str)
    if len(text) > TOOL_RESULT_LIMIT:
        text = text[:TOOL_RESULT_LIMIT] + f"\n… truncated ({len(text)} characters); ask for less"
    session.emit("tool_result", tool=call.name, error=error, preview=text[:600], size=len(text))
    return {"type": "tool_result", "tool_use_id": call.id, "content": text, "is_error": error}
