"""Ask Shikari, threat briefings and the profile's AI assignment, from the console."""

import textwrap
from typing import Dict

from .base import ModuleOption
from .server import ServerModule, client, print_results


def print_briefing(b: Dict) -> None:
    print(f"\n  {b.get('group_name')} ({b.get('group_id')}): {b.get('total_techniques')} techniques, "
          f"{b.get('covered_count')} covered, {b.get('gap_count')} gaps  [{b.get('provider')}]")
    if b.get("attack_chain"):
        print(f"  Chain: {' → '.join(b['attack_chain'])}")
    print("\n" + textwrap.indent(textwrap.fill(b.get("briefing_summary") or "", 100), "  "))
    for t in b.get("top_techniques") or []:
        print(f"\n  {t['priority_rank']}. {t['technique_id']} {t['technique_name']} ({t['tactic']})"
              f"{'' if t.get('covered') else '  — GAP'}")
        print(textwrap.indent(textwrap.fill(t.get("priority_reason") or "", 96), "     "))
        if t.get("detection_approach"):
            print(textwrap.indent(textwrap.fill("Detect: " + t["detection_approach"], 96), "     "))
    print()


class AskModule(ServerModule):
    name = "ai/ask"
    description = "Ask Shikari a question (the profile's Ask provider, with fallback)"
    author = "Shikari Team"

    def _register_options(self):
        self.options = {
            "QUESTION": ModuleOption(name="QUESTION", description="The question", required=True),
            "GROUP": ModuleOption(name="GROUP", description="Context: the threat group the question is about"),
        }

    def execute(self):
        context = {"group": self.options["GROUP"].effective_value} if self.options["GROUP"].effective_value else None
        answer = client().ask(self.options["QUESTION"].effective_value, context)
        print(f"\n  [{answer.get('provider')}]\n")
        print(textwrap.indent(answer.get("answer", ""), "  ") + "\n")


class BriefingModule(ServerModule):
    name = "ai/briefing"
    description = "Threat briefing for a group: prioritised techniques and coverage gaps"
    author = "Shikari Team"

    def _register_options(self):
        self.options = {
            "GROUP": ModuleOption(name="GROUP", description="ATT&CK group name or alias", required=True),
            "TOP_N": ModuleOption(name="TOP_N", description="Techniques to prioritise", default=5),
        }

    def execute(self):
        print_briefing(client().threat_briefing(self.options["GROUP"].effective_value,
                                                int(self.options["TOP_N"].effective_value)))


class AISettingsModule(ServerModule):
    name = "ai/settings"
    description = "Show or change which AI provider/model Ask Shikari and detection generation use"
    author = "Shikari Team"

    def _register_options(self):
        self.options = {
            "ASK_PROVIDER": ModuleOption(name="ASK_PROVIDER", description="Provider for Ask Shikari (none = unassign)"),
            "ASK_MODEL": ModuleOption(name="ASK_MODEL", description="Model for Ask Shikari"),
            "DETECTION_PROVIDER": ModuleOption(name="DETECTION_PROVIDER", description="Provider for detection generation (cloud only; none = unassign)"),
            "DETECTION_MODEL": ModuleOption(name="DETECTION_MODEL", description="Model for detection generation"),
            "MAX_CALLS": ModuleOption(name="MAX_CALLS", description="Max LLM calls per run (1-500)"),
            "LOCAL_ENDPOINT": ModuleOption(name="LOCAL_ENDPOINT", description="Local model base URL (e.g. http://localhost:11434; none = remove)"),
            "LOCAL_MODEL": ModuleOption(name="LOCAL_MODEL", description="Local model name (e.g. qwen3:8b)"),
            "REMEMBER": ModuleOption(name="REMEMBER", description="Hunt prompt: forget = ask again each hunt"),
        }

    def execute(self):
        o = {k: v.effective_value for k, v in self.options.items()}
        c = client()
        current = c.ai_settings()
        update = {}
        for job in ("ask", "detection"):
            provider = o[f"{job.upper()}_PROVIDER"]
            if provider:
                update[job] = None if provider == "none" else {"provider": provider, "model": o[f"{job.upper()}_MODEL"] or ""}
        if o["MAX_CALLS"]:
            update["max_detection_calls"] = int(o["MAX_CALLS"])
        if o["LOCAL_ENDPOINT"]:
            update["local"] = ({"endpoint": "", "model": ""} if o["LOCAL_ENDPOINT"] == "none"
                               else {"endpoint": o["LOCAL_ENDPOINT"], "model": o["LOCAL_MODEL"] or ""})
        if o["REMEMBER"] == "forget":
            update["remember"] = None
        if update:
            c.update_ai_settings(update)
            current = c.ai_settings()
            print("  Saved")
        settings = current.get("settings") or {}
        print("\n  Configured providers:")
        for p in current.get("providers") or []:
            print(f"    {p['id']:<10} {p['label']:<28} {p.get('model') or '':<28} {'Ask + detection' if p.get('detection') else 'Ask only'}")
        for job in ("ask", "detection"):
            a = settings.get(job)
            print(f"  {job.capitalize():<10} {(a['provider'] + ' / ' + (a.get('model') or 'default')) if a else 'unassigned'}")
        remember = settings.get("remember")
        print(f"  Hunt prompt: {'remembered: ' + (remember.get('provider') or 'no AI') if remember else 'asks each hunt'}")
        print(f"  Max LLM calls per run: {settings.get('max_detection_calls')}\n")
        print("  API keys are set in the web app (Profile → API Keys)\n")


class ResultsModule(ServerModule):
    name = "results"
    description = "Show a run's detections, correlations and IOC flow; save them as a zip"
    author = "Shikari Team"

    def _register_options(self):
        self.options = {
            "RUN": ModuleOption(name="RUN", description="Run (group, CVE, report or hunt) name", required=True),
            "LATEST": ModuleOption(name="LATEST", description="Only the latest run's files (false = everything for the group)", default=True),
            "QUERIES": ModuleOption(name="QUERIES", description="Print every query", default=False),
            "OUTPUT": ModuleOption(name="OUTPUT", description="Save the detections as a zip to this path"),
        }

    def execute(self):
        o = {k: v.effective_value for k, v in self.options.items()}
        c = client()
        print_results(c.results(o["RUN"], latest=o["LATEST"]), queries=o["QUERIES"])
        print(f"  {c.results_url(o['RUN'])}")
        if o["OUTPUT"]:
            print(f"  Saved: {c.download_all(o['RUN'], o['OUTPUT'])}")
