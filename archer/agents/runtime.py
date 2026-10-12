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
along and answer approval prompts. The model calls themselves are in llm.py (Anthropic,
or any OpenAI-compatible API); a session's trace is saved through `persist` (store.py).
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
PERSIST_EVERY = 2.0         # seconds between saves of a running session's trace


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
    model: str = ""
    provider: str = ""
    task: str = ""
    # The model's conversation as of the last complete turn (every tool call answered), so a
    # session the server lost can carry on from there (resume)
    conversation: List[Dict] = field(default_factory=list)
    max_turns: int = 0
    persist: Optional[Callable[["Session"], None]] = None
    _decision: Optional[bool] = None
    _decided: threading.Event = field(default_factory=threading.Event)
    _stop: bool = False
    _saved: float = 0.0

    def emit(self, kind: str, **data) -> None:
        self.events.append({"n": len(self.events), "type": kind, "at": time.time(), **data})
        # Every event a person might act on, or the end, is saved straight away; the rest at most
        # every PERSIST_EVERY seconds
        self.save(force=kind in ("task", "resumed", "approval_needed", "approval", "done", "error", "stopped", "limit"))

    def save(self, force: bool = False) -> None:
        if self.persist is None or (not force and time.time() - self._saved < PERSIST_EVERY):
            return
        self._saved = time.time()
        try:
            self.persist(self)
        except Exception:
            logger.exception("Could not save agent session %s", self.id)

    def view(self, since: int = 0) -> Dict:
        return {"session_id": self.id, "agent": self.agent.name, "status": self.status,
                "events": self.events[since:], "next": len(self.events), "pending": self.pending,
                "answer": self.answer, "turns": self.turns, "tokens": self.tokens, "model": self.model,
                "provider": self.provider,
                "resumable": self.status in ("stopped", "error") and bool(self.conversation)}

    def decide(self, approve: bool) -> None:
        self._decision = approve
        self._decided.set()

    def stop(self) -> None:
        self._stop = True
        self.decide(False)


_sessions: Dict[str, Session] = {}
_lock = threading.Lock()


def get_session(session_id: str, user_id: int) -> Optional[Session]:
    """A session this server is running (sessions from before a restart: store.load)."""
    session = _sessions.get(session_id)
    return session if session and session.user_id == user_id else None


def start(agent: Agent, inputs: Dict, *, user_id: int, llm: Dict, context: Any, auto_approve: bool = False,
          persist: Optional[Callable[[Session], None]] = None) -> Session:
    """
    Start an agent in a background thread. llm: {"provider", "model", "api_key", "base_url"}
    (archer.agents.agent_llm; provider defaults to anthropic).
    """
    for name, spec in agent.inputs.items():
        if spec.get("required") and not str(inputs.get(name) or "").strip():
            raise ValueError(f"{spec.get('label', name)} is required")
    with _lock:
        now = time.time()
        for sid in [s for s, v in _sessions.items() if now - v.created > SESSION_TTL]:
            _sessions.pop(sid, None)
        session = Session(id=uuid.uuid4().hex, agent=agent, user_id=user_id, auto_approve=auto_approve,
                          model=llm["model"], provider=llm.get("provider", "anthropic"),
                          max_turns=agent.max_turns, persist=persist)
        _sessions[session.id] = session
    session.task = agent.task(inputs)
    session.conversation = [{"role": "user", "content": session.task}]
    session.emit("task", text=session.task, model=llm["model"], provider=session.provider,
                 tools=[t.name for t in agent.tools(context)])
    _thread(session, llm, context)
    return session


def resume(saved, agent: Agent, *, llm: Dict, context: Any, auto_approve: bool = False,
           persist: Optional[Callable[[Session], None]] = None) -> Session:
    """
    Carry on a session the server lost (restart), stopped, or that hit its turn limit, from
    its saved conversation (store.SavedSession). llm must be the provider it ran on: the
    conversation is in that API's shape. It gets another max_turns turns.
    """
    with _lock:
        if saved.id in _sessions and _sessions[saved.id].status in ("running", "needs_approval"):
            raise ValueError("This session is still running")
        session = Session(id=saved.id, agent=agent, user_id=saved.user_id, auto_approve=auto_approve,
                          events=list(saved.events), turns=saved.turns, tokens=dict(saved.tokens),
                          created=saved.created, model=llm["model"], provider=saved.provider,
                          task=saved.task, conversation=list(saved.conversation),
                          max_turns=saved.turns + agent.max_turns, persist=persist)
        _sessions[session.id] = session
    session.emit("resumed", text=f"Continued from turn {saved.turns} on {llm['model']}")
    _thread(session, llm, context)
    return session


def _thread(session: Session, llm: Dict, context: Any) -> None:
    threading.Thread(target=_run, args=(session, llm, context), daemon=True,
                     name=f"agent-{session.agent.name}-{session.id[:8]}").start()


def _run(session: Session, llm: Dict, context: Any) -> None:
    from .llm import chat_for

    agent = session.agent
    tools = {t.name: t for t in agent.tools(context)}
    specs = [t.spec() for t in tools.values()]
    messages: List[Dict] = list(session.conversation)
    try:
        chat = chat_for(llm)
        while not session._stop:
            if session.turns >= session.max_turns:
                session.status = "stopped"
                session.emit("limit", text=f"Stopped after {session.turns} turns; continue it for {agent.max_turns} more")
                return
            session.turns += 1
            reply = chat.turn(agent.system, specs, messages, agent.max_tokens)
            session.tokens["input"] += reply.input_tokens
            session.tokens["output"] += reply.output_tokens
            messages.append(reply.message)
            if reply.text:
                session.emit("text", text=reply.text, final=not reply.calls)
            if not reply.calls:
                session.answer = reply.text
                session.status = "done"
                session.emit("done", stop_reason=reply.stop_reason, tokens=dict(session.tokens))
                return
            messages.extend(chat.results([_call(session, tools, call) for call in reply.calls]))
            session.conversation = list(messages)
            session.save(force=True)
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
    return {"id": call.id, "content": text, "error": error}


def live_ids() -> set:
    return {sid for sid, s in _sessions.items() if s.status in ("running", "needs_approval")}
