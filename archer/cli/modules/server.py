"""
Modules that drive a running Archer server (archer.client), so the console runs
exactly what the web app runs. ARCHER_URL / ARCHER_EMAIL / ARCHER_PASSWORD pick the
server and account; the console prompts for whatever is missing.
"""

from collections import Counter
from typing import Dict, Optional

from archer.client import ArcherClient, ArcherError

from .base import BaseModule, ModuleOption

_client: Optional[ArcherClient] = None


def client() -> ArcherClient:
    """One signed-in client per console session."""
    global _client
    if _client is None:
        _client = ArcherClient()
    _client.login(interactive=True)
    return _client


def ai_options() -> Dict[str, ModuleOption]:
    return {
        "PROVIDER": ModuleOption(
            name="PROVIDER",
            description="AI for detection generation: assigned (profile) | none | anthropic | openai | google | deepseek | qwen | grok",
            default="assigned",
        ),
        "MODEL": ModuleOption(name="MODEL", description="Model override (blank = the provider's model in your profile)"),
    }


def run_options() -> Dict[str, ModuleOption]:
    return {
        "WAIT": ModuleOption(name="WAIT", description="Follow the run to completion and summarise it", default=True),
        "OUTPUT": ModuleOption(name="OUTPUT", description="Save the run's detections as a zip to this path"),
    }


class ServerModule(BaseModule):
    """A module whose work happens on the Archer server."""

    def ai_choice(self):
        """(provider, model) for the client: None leaves no AI, as the web prompt's "No"."""
        provider = (self.options["PROVIDER"].effective_value or "assigned").strip().lower()
        model = self.options["MODEL"].effective_value or ""
        if provider == "none":
            return "", ""
        if provider == "assigned":
            assigned = client().assigned_detection()
            if not assigned:
                print("  No AI provider assigned for detection generation (Profile → API Keys); running without AI")
                return "", ""
            return assigned["provider"], model or assigned["model"]
        return provider, model

    def follow(self, run: str) -> None:
        c = client()
        print(f"  Run started: {run}")
        print(f"  Results:     {c.results_url(run)}")
        if not self.options["WAIT"].effective_value:
            return

        def update(progress):
            phase = progress.get("phase") or progress.get("status")
            made = progress.get("created_yaml")
            print(f"  … {phase}{f' ({made} detections)' if made else ''}", flush=True)

        progress = c.wait(run, on_update=update)
        if progress.get("status") != "complete":
            print(f"  Run ended: {progress.get('status')} {progress.get('error') or ''}")
            return
        print_results(c.results(run))
        if self.options["OUTPUT"].effective_value:
            print(f"  Saved: {c.download_all(run, self.options['OUTPUT'].effective_value)}")

    def run(self):
        try:
            self.execute()
        except ArcherError as e:
            print(f"  {e}")

    def execute(self):
        raise NotImplementedError


def print_results(results: Dict, queries: bool = False) -> None:
    detections = results.get("detections") or []
    platforms = Counter(p for d in detections for p in (d.get("platforms") or ["?"]))
    techniques = {t for d in detections for t in d.get("techniques") or [] if t.startswith("T")}
    print(f"\n  {len(detections)} detections across {len(techniques)} techniques"
          f" ({', '.join(f'{p}: {n}' for p, n in platforms.most_common())})")
    sweeps = [d for d in detections if "IOC-SWEEP" in (d.get("techniques") or [])]
    if sweeps:
        print(f"  IOC sweeps: {', '.join(p for d in sweeps for p in d.get('platforms') or [])}")
    print(f"  {len(results.get('correlations') or [])} correlations")
    if results.get("ioc_flow"):
        print_ioc_flow(results["ioc_flow"])
    if queries:
        for d in detections:
            for q in d.get("queries") or []:
                print(f"\n  ── {d.get('name')} [{', '.join(d.get('techniques') or [])}] {q.get('platform')}"
                      f"{' / ' + q['data_source'] if q.get('data_source') else ''}")
                print("  " + (q.get("query") or "").strip().replace("\n", "\n  "))
    print()


def print_ioc_flow(flow: Dict, limit: int = 8) -> None:
    stats = flow.get("stats") or {}
    print(f"\n  IOC flow ({stats.get('iocs', 0)} IOCs, {stats.get('links', 0)} links) from {flow.get('source', '')}")
    ids = {}
    for i, stage in enumerate(flow.get("stages") or []):
        nodes = stage.get("nodes") or []
        print(f"  {'→ ' if i else '  '}{stage.get('label')} ({len(nodes)})")
        for n in nodes[:limit]:
            ids[n["id"]] = n["value"]
            print(f"      {n.get('kind', ''):<7} {n['value']}")
        if len(nodes) > limit:
            print(f"      … {len(nodes) - limit} more")
        for n in nodes[limit:]:
            ids[n["id"]] = n["value"]
    for e in flow.get("edges") or []:
        print(f"      {ids.get(e['from'], e['from'])} ⇢ {ids.get(e['to'], e['to'])}")
