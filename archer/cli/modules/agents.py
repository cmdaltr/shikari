"""
The agents (archer/agents) from the console: they run on the server; the console shows
each step as it happens and asks before any action that changes something.
"""

import json
import sys
import textwrap
import time
from typing import Dict

from archer.client import ArcherClient

from .base import ModuleOption
from .server import ServerModule, client


def follow_agent(c: ArcherClient, session_id: str, approve_all: bool = False) -> Dict:
    """Print an agent session's events until it finishes, answering approval prompts."""
    since, view = 0, {}
    while True:
        view = c.agent_session(session_id, since)
        for e in view["events"]:
            print_event(e)
        since = view["next"]
        if view["status"] == "needs_approval" and view.get("pending"):
            p = view["pending"]
            if approve_all:
                answer = "y"
            elif sys.stdin.isatty():
                answer = input(f"\n  ⚠ Allow {p['tool']}({json.dumps(p['input'])})? [y/N] ").strip().lower()
            else:
                answer = "n"
                print(f"\n  ⚠ {p['tool']} needs approval; declined (not interactive; set APPROVE all to allow)")
            c.agent_decision(session_id, answer in ("y", "yes"))
            continue
        if view["status"] in ("done", "stopped", "error"):
            break
        time.sleep(1.5)
    tokens = view.get("tokens") or {}
    print(f"\n  [{view['status']}: {view.get('turns')} turns, {tokens.get('input', 0):,} in / "
          f"{tokens.get('output', 0):,} out tokens]\n")
    return view


def print_event(e: Dict) -> None:
    kind = e["type"]
    if kind == "task":
        print(f"\n  ▶ {e['text']}\n    model {e['model']}; tools: {', '.join(e['tools'])}")
    elif kind == "text":
        body = e["text"] if e.get("final") else textwrap.shorten(e["text"], 400, placeholder=" …")
        print("\n" + textwrap.indent(body, "  " if e.get("final") else "  💭 "))
    elif kind == "tool_call":
        args = json.dumps(e["input"])
        print(f"  → {e['tool']}({args if len(args) < 160 else args[:157] + '…'})")
    elif kind == "tool_result":
        flag = "✗" if e["error"] else "←"
        print(f"    {flag} {textwrap.shorten(e['preview'], 160, placeholder=' …')}")
    elif kind == "approval":
        print(f"    {'✓ approved' if e['approved'] else '✗ declined'}")
    elif kind in ("error", "limit"):
        print(f"  ✗ {e['text']}")


class AgentModule(ServerModule):
    agent = ""
    fields: Dict[str, ModuleOption] = {}

    def _register_options(self):
        self.options = {
            **{k: ModuleOption(name=o.name, description=o.description, required=o.required, default=o.default)
               for k, o in self.fields.items()},
            "APPROVE": ModuleOption(name="APPROVE", description="ask = confirm each action that changes something | all",
                                    default="ask", choices=["ask", "all"]),
        }

    def execute(self):
        c = client()
        inputs = {k.lower(): v.effective_value for k, v in self.options.items()
                  if k != "APPROVE" and v.effective_value not in (None, "")}
        approve_all = self.options["APPROVE"].effective_value == "all"
        session_id = c.start_agent(self.agent, inputs, auto_approve=approve_all)
        try:
            follow_agent(c, session_id, approve_all)
        except KeyboardInterrupt:
            c.stop_agent(session_id)
            print("\n  Agent stopped")


class RepairAgentModule(AgentModule):
    name = "agent/repair"
    description = "Agent: fix a run's queries that won't parse or can't match, checking each fix"
    author = "Archer Team"
    agent = "repair"
    fields = {
        "RUN": ModuleOption(name="RUN", description="Run whose detections to repair (e.g. CVE-2024-3400, FIN7)", required=True),
        "SCOPE": ModuleOption(name="SCOPE", description="errors | all (errors and warnings)", default="errors"),
        "LIMIT": ModuleOption(name="LIMIT", description="Max queries to repair", default="10"),
    }


class AskAgentModule(AgentModule):
    name = "agent/ask"
    description = "Agent: Ask Archer with tools (library, coverage, ATT&CK, hunts)"
    author = "Archer Team"
    agent = "ask"
    fields = {"QUESTION": ModuleOption(name="QUESTION", description="The question", required=True)}


class TriageAgentModule(AgentModule):
    name = "agent/triage"
    description = "Agent: triage a threat report: coverage gaps, hunts, briefing"
    author = "Archer Team"
    agent = "triage"
    fields = {"URL": ModuleOption(name="URL", description="Report URL", required=True)}
