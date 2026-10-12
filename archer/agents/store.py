"""
Agent sessions in SQLite (agent_runs), so a trace outlives the server process and every
run, including what was allowed or declined, stays on record.

A session that was running when the server stopped reads back as "interrupted". Its
conversation with the model is saved after every complete turn, so it (or one that was
stopped or hit its turn limit) can be continued: runtime.resume.
"""

import json
from datetime import datetime, timezone
from typing import Dict, List, Optional

LIVE = ("running", "needs_approval")


def save(session) -> None:
    from archer.database.db import SessionLocal
    from archer.database.models import AgentRun

    db = SessionLocal()
    try:
        row = db.get(AgentRun, session.id)
        if row is None:
            row = AgentRun(id=session.id, user_id=session.user_id, agent=session.agent.name,
                           created_at=datetime.utcfromtimestamp(session.created))
            db.add(row)
        row.model = session.model or ""
        row.status = session.status
        row.task = session.task or ""
        row.answer = session.answer or ""
        row.events = json.dumps(session.events, default=str)
        row.provider = session.provider or None
        row.conversation = json.dumps(session.conversation, default=str) if session.conversation else None
        row.turns = session.turns
        row.input_tokens = session.tokens["input"]
        row.output_tokens = session.tokens["output"]
        db.commit()
    finally:
        db.close()


class SavedSession:
    """A session read back from the database: viewable, no longer controllable."""

    def __init__(self, row):
        self.id = row.id
        self.agent_name = row.agent
        self.user_id = row.user_id
        self.status = "interrupted" if row.status in LIVE else row.status
        self.events = json.loads(row.events or "[]")
        if self.status == "interrupted" and not any(e.get("type") == "interrupted" for e in self.events):
            self.events.append({"n": len(self.events), "type": "interrupted",
                                "text": "The server restarted while this agent was running; start it again to continue."})
        self.answer = row.answer
        self.turns = row.turns
        self.tokens = {"input": row.input_tokens, "output": row.output_tokens}
        self.model = row.model
        self.provider = row.provider or "anthropic"
        self.task = row.task
        self.created = row.created_at.replace(tzinfo=timezone.utc).timestamp() if row.created_at else 0.0
        self.conversation = json.loads(row.conversation) if row.conversation else []
        # Continue: anything but a finished run, as long as there's a conversation to continue
        self.resumable = bool(self.conversation) and self.status in ("interrupted", "stopped", "error")
        self.pending = None

    def view(self, since: int = 0) -> Dict:
        return {"session_id": self.id, "agent": self.agent_name, "status": self.status,
                "events": self.events[since:], "next": len(self.events), "pending": None,
                "answer": self.answer, "turns": self.turns, "tokens": self.tokens, "model": self.model,
                "resumable": self.resumable, "provider": self.provider}

    def decide(self, approve: bool) -> None:
        pass

    def stop(self) -> None:
        pass


def load(session_id: str, user_id: int) -> Optional[SavedSession]:
    from archer.database.db import SessionLocal
    from archer.database.models import AgentRun

    db = SessionLocal()
    try:
        row = db.get(AgentRun, session_id)
        return SavedSession(row) if row and row.user_id == user_id else None
    finally:
        db.close()


def recent(user_id: int, limit: int = 20, live: Optional[set] = None) -> List[Dict]:
    """The user's latest sessions, newest first. live: ids this server is still running."""
    from archer.database.db import SessionLocal
    from archer.database.models import AgentRun

    db = SessionLocal()
    try:
        rows = (db.query(AgentRun).filter(AgentRun.user_id == user_id)
                .order_by(AgentRun.created_at.desc()).limit(limit).all())
        return [{
            "session_id": r.id, "agent": r.agent, "model": r.model,
            "status": r.status if r.status not in LIVE or (live and r.id in live) else "interrupted",
            "task": (r.task or "")[:200], "turns": r.turns,
            "tokens": {"input": r.input_tokens, "output": r.output_tokens},
            "created": r.created_at.isoformat() + "Z",
        } for r in rows]
    finally:
        db.close()
