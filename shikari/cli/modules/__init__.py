"""Module registry for shikari console."""

from .generate import GenerateModule
from .correlate import CorrelateModule
from .hunt import HuntModule
from .hunts import CveHuntModule, GroupHuntModule, TechniqueHuntModule
from .intel import CompanyModule, FeedModule, ReportModule
from .research import ResearchModule
from .ai import AISettingsModule, AskModule, BriefingModule, ResultsModule
from .agents import (AgentHistoryModule, AskAgentModule, AuditAgentModule, BriefAgentModule,
                     InvestigateAgentModule, RepairAgentModule, SweepAgentModule, TriageAgentModule,
                     TuneAgentModule)
from .lab import CalderaModule
from shikari.config import EMULATION_ENABLED

# generate, correlate, hunt, lab/caldera and emulate run in this process (lab/caldera talks to the
# CALDERA server directly); the rest drive a running Shikari server (shikari.client), so they run
# exactly what the web app runs
MODULE_REGISTRY = {
    "generate": GenerateModule,
    "correlate": CorrelateModule,
    "hunt": HuntModule,
    "lab/caldera": CalderaModule,
    "hunt/group": GroupHuntModule,
    "hunt/cve": CveHuntModule,
    "hunt/technique": TechniqueHuntModule,
    "intel/report": ReportModule,
    "intel/company": CompanyModule,
    "intel/feed": FeedModule,
    "research/actors": ResearchModule,
    "ai/ask": AskModule,
    "ai/briefing": BriefingModule,
    "ai/settings": AISettingsModule,
    "results": ResultsModule,
    "agent/repair": RepairAgentModule,
    "agent/ask": AskAgentModule,
    "agent/triage": TriageAgentModule,
    "agent/sweep": SweepAgentModule,
    "agent/audit": AuditAgentModule,
    "agent/tune": TuneAgentModule,
    "agent/brief": BriefAgentModule,
    "agent/investigate": InvestigateAgentModule,
    "agent/history": AgentHistoryModule,
}

if EMULATION_ENABLED:
    from .emulate import EmulateModule
    MODULE_REGISTRY["emulate"] = EmulateModule
