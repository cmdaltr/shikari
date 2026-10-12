"""
Agents: a model in a loop with tools (runtime.py, llm.py), Archer's tools (tools.py) and
three agents built from them (definitions.py). See docs/agents/README.md.
"""

import os
from typing import Dict, List, Optional

from .definitions import AGENTS
from .runtime import Agent, Session, Tool, get_session, live_ids, resume, start

DEFAULT_MODEL = "claude-sonnet-5-5"
NO_KEY = ("Agents need a model that can call tools: add an API key (Anthropic, OpenAI, DeepSeek, Qwen, "
          "Grok, Gemini) or a local endpoint in Profile → API Keys")
# Tried in this order when nothing is chosen: Claude is the strongest at multi-step tool use
PREFERENCE = ("anthropic", "openai", "google", "deepseek", "qwen", "grok", "local")


def agent_providers(db, user_id: int) -> List[Dict]:
    """The configured providers an agent can run on, preferred first: [{id, label, model}]."""
    from archer.ai.assignment import configured_providers

    available = {p["id"]: p for p in configured_providers(db, user_id)}
    return [{"id": pid, "label": available[pid]["label"], "model": available[pid]["model"]}
            for pid in PREFERENCE if pid in available]


def agent_llm(db, user_id: int, provider: Optional[str] = None, model: Optional[str] = None) -> Optional[Dict]:
    """
    The model and credentials an agent runs on: the provider asked for; otherwise Anthropic
    if the user has a key; otherwise their Ask Archer assignment; otherwise the first
    configured provider. Falls back to the server's ANTHROPIC_API_KEY.
    """
    from archer.ai.assignment import LOCAL, load_settings, resolve

    from .llm import OPENAI_COMPATIBLE

    choices = [p["id"] for p in agent_providers(db, user_id)]
    if not provider:
        ask = (load_settings(db, user_id).get("ask") or {}).get("provider")
        provider = "anthropic" if "anthropic" in choices else ask if ask in choices else \
            (choices[0] if choices else None)
        if provider and provider == ask and not model:
            model = (load_settings(db, user_id).get("ask") or {}).get("model") or None
    resolved = resolve(db, user_id, "ask", provider, model) if provider else None
    if resolved is None:
        key = os.getenv("ANTHROPIC_API_KEY")
        if key and provider in (None, "anthropic"):
            return {"provider": "anthropic", "label": "Anthropic Claude", "model": model or DEFAULT_MODEL, "api_key": key}
        return None
    llm = {"provider": resolved["provider"], "label": resolved["label"], "api_key": resolved.get("api_key"),
           "model": resolved["model"] or (DEFAULT_MODEL if resolved["provider"] == "anthropic" else "")}
    if llm["provider"] == LOCAL:
        endpoint = resolved["endpoint"]
        llm["base_url"] = endpoint if endpoint.endswith("/v1") else endpoint + "/v1"
    elif llm["provider"] != "anthropic":
        env = {"deepseek": "DEEPSEEK_BASE_URL", "qwen": "QWEN_BASE_URL", "grok": "XAI_BASE_URL"}.get(llm["provider"])
        llm["base_url"] = (os.getenv(env) if env else None) or OPENAI_COMPATIBLE[llm["provider"]]
    if not llm["model"]:
        return None
    return llm


__all__ = ["AGENTS", "Agent", "Session", "Tool", "agent_llm", "agent_providers", "get_session",
           "live_ids", "resume", "start", "NO_KEY"]
