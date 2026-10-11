"""Module registry for the ADF console."""

from .generate import GenerateModule
from .correlate import CorrelateModule
from .hunt import HuntModule
from .hunts import CveHuntModule, GroupHuntModule, TechniqueHuntModule
from .intel import CompanyModule, ReportModule
from .research import ResearchModule
from .ai import AISettingsModule, AskModule, BriefingModule, ResultsModule
from .agents import AskAgentModule, RepairAgentModule, TriageAgentModule
from archer.config import EMULATION_ENABLED

# generate, correlate, hunt and emulate run in this process; the rest drive a running
# Archer server (archer.client), so they run exactly what the web app runs
MODULE_REGISTRY = {
    "generate": GenerateModule,
    "correlate": CorrelateModule,
    "hunt": HuntModule,
    "hunt/group": GroupHuntModule,
    "hunt/cve": CveHuntModule,
    "hunt/technique": TechniqueHuntModule,
    "intel/report": ReportModule,
    "intel/company": CompanyModule,
    "research/actors": ResearchModule,
    "ai/ask": AskModule,
    "ai/briefing": BriefingModule,
    "ai/settings": AISettingsModule,
    "results": ResultsModule,
    "agent/repair": RepairAgentModule,
    "agent/ask": AskAgentModule,
    "agent/triage": TriageAgentModule,
}

if EMULATION_ENABLED:
    from .emulate import EmulateModule
    MODULE_REGISTRY["emulate"] = EmulateModule
