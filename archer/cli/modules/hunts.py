"""Hunts run on the Archer server: threat group, CVE, ATT&CK techniques."""

from .base import ModuleOption
from .server import ServerModule, ai_options, client, run_options


class GroupHuntModule(ServerModule):
    name = "hunt/group"
    description = "Hunt a threat group as the web app does (OSINT, AI, correlations, briefing)"
    author = "Archer Team"

    def _register_options(self):
        self.options = {
            "GROUP": ModuleOption(name="GROUP", description="ATT&CK group name or alias (e.g. APT29, Scattered Spider)", required=True),
            **ai_options(),
            "CORRELATE": ModuleOption(name="CORRELATE", description="Build correlation queries", default=True),
            "LOL": ModuleOption(name="LOL", description="LOLBAS, LOLDrivers and LOLRMM for tools the group is seen using", default=True),
            "OSINT": ModuleOption(name="OSINT", description="OSINT enhancement", default=False),
            "OSINT_COMPARE": ModuleOption(name="OSINT_COMPARE", description="OSINT comparison (reference only)", default=False),
            "MERGE_BY_TACTIC": ModuleOption(name="MERGE_BY_TACTIC", description="Merge detections by tactic", default=False),
            "MERGE_BY_PARENT": ModuleOption(name="MERGE_BY_PARENT", description="Merge sub-techniques into their parent", default=False),
            "EXCLUDE": ModuleOption(name="EXCLUDE", description="SIEMs to leave out: secops,mde,splunk,elastic", default=""),
            "VALIDATE": ModuleOption(name="VALIDATE", description="Validate queries against the Docker SIEMs", default=False),
            "EMULATION": ModuleOption(name="EMULATION", description="Atomic Red Team after generation: off | simulate | live",
                                      default="off", choices=["off", "simulate", "live"]),
            "BRIEFING": ModuleOption(name="BRIEFING", description="Print a threat briefing (Ask Archer's AI) first", default=False),
            **run_options(),
        }

    def execute(self):
        o = {k: v.effective_value for k, v in self.options.items()}
        if o["BRIEFING"]:
            from .ai import print_briefing
            print_briefing(client().threat_briefing(o["GROUP"]))
        provider, model = self.ai_choice()
        run = client().hunt_group(
            o["GROUP"], provider=provider, model=model, correlate=o["CORRELATE"], lol=o["LOL"], osint=o["OSINT"],
            osint_compare=o["OSINT_COMPARE"], merge_by_tactic=o["MERGE_BY_TACTIC"],
            merge_by_parent=o["MERGE_BY_PARENT"], validate=o["VALIDATE"],
            exclude=[s.strip() for s in (o["EXCLUDE"] or "").split(",") if s.strip()],
            emulation=None if o["EMULATION"] == "off" else o["EMULATION"])
        self.follow(run)


class CveHuntModule(ServerModule):
    name = "hunt/cve"
    description = "Hunt a CVE: exploitation detections plus IOC sweeps from its references"
    author = "Archer Team"

    def _register_options(self):
        self.options = {
            "CVE": ModuleOption(name="CVE", description="CVE ID(s), comma-separated (e.g. CVE-2024-3400)", required=True),
            **ai_options(),
            "CORRELATE": ModuleOption(name="CORRELATE", description="Build correlation queries", default=True),
            **run_options(),
        }

    def execute(self):
        provider, model = self.ai_choice()
        run = client().hunt_cve(self.options["CVE"].effective_value, provider=provider, model=model,
                                correlate=self.options["CORRELATE"].effective_value)
        self.follow(run)


class TechniqueHuntModule(ServerModule):
    name = "hunt/technique"
    description = "Hunt ATT&CK techniques across every group that uses them"
    author = "Archer Team"

    def _register_options(self):
        self.options = {
            "TECHNIQUES": ModuleOption(name="TECHNIQUES", description="Technique IDs, comma-separated (e.g. T1003.001,T1021)", required=True),
            **ai_options(),
            "MERGE_BY_TACTIC": ModuleOption(name="MERGE_BY_TACTIC", description="Merge detections by tactic", default=False),
            "MERGE_BY_PARENT": ModuleOption(name="MERGE_BY_PARENT", description="Merge sub-techniques into their parent", default=False),
            "LOL": ModuleOption(name="LOL", description="LOLBAS, LOLDrivers and LOLRMM for tools the group is seen using", default=True),
            "OSINT": ModuleOption(name="OSINT", description="OSINT enhancement", default=False),
            "OSINT_COMPARE": ModuleOption(name="OSINT_COMPARE", description="OSINT comparison (reference only)", default=False),
            "MIN_RELEVANCE": ModuleOption(name="MIN_RELEVANCE", description="Minimum correlation relevance, 0-1 (blank = configured)"),
            **run_options(),
        }

    def execute(self):
        o = {k: v.effective_value for k, v in self.options.items()}
        provider, model = self.ai_choice()
        ids = [t.strip().upper() for t in o["TECHNIQUES"].split(",") if t.strip()]
        doomed = client().technique_yield(ids, ai=bool(provider), osint=o["OSINT"] or o["OSINT_COMPARE"])["no_detection"]
        for tid, d in doomed.items():
            print(f"  {tid} will produce nothing: {d['text']}")
        if len(doomed) == len(ids):
            print("  Not started: set PROVIDER to an AI model, or OSINT true")
            return
        run = client().hunt_techniques(
            ids, provider=provider, model=model,
            merge_by_tactic=o["MERGE_BY_TACTIC"], merge_by_parent=o["MERGE_BY_PARENT"], lol=o["LOL"], osint=o["OSINT"],
            osint_compare=o["OSINT_COMPARE"], min_relevance=float(o["MIN_RELEVANCE"]) if o["MIN_RELEVANCE"] else None)
        self.follow(run)
