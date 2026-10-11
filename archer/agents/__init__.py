"""
Agents: a model in a loop with tools (runtime.py), Archer's tools (tools.py) and three
agents built from them (definitions.py). See docs/agents/README.md.
"""

import os
from typing import Dict, Optional

from .definitions import AGENTS
from .runtime import Agent, Session, Tool, get_session, start

DEFAULT_MODEL = "claude-sonnet-5-5"
NO_KEY = ("Agents use Claude's tool use: add an Anthropic API key in Profile → API Keys "
          "(other providers aren't supported for agents yet)")


def agent_llm(db, user_id: int) -> Optional[Dict]:
    """
    The Claude model and key an agent runs on: the user's Ask assignment when it's
    Anthropic, else their Anthropic key, else the server's ANTHROPIC_API_KEY.
    """
    from archer.ai.assignment import load_settings, stored_keys

    settings = load_settings(db, user_id)
    keys = stored_keys(db, user_id)
    ask = settings.get("ask") or {}
    key = keys.get("anthropic") or os.getenv("ANTHROPIC_API_KEY")
    if not key:
        return None
    model = (ask.get("model") if ask.get("provider") == "anthropic" else "") or \
        (settings.get("models") or {}).get("anthropic") or DEFAULT_MODEL
    return {"api_key": key, "model": model}


__all__ = ["AGENTS", "Agent", "Session", "Tool", "agent_llm", "get_session", "start", "NO_KEY"]
