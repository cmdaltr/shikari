"""
Adversary Emulation Module

This optional module integrates adversary emulation frameworks to enhance
threat hunting detections with real attack execution data.

Supported Frameworks:
- Atomic Red Team: Local test execution
- MITRE CALDERA: Autonomous adversary emulation
- MACAT: Mapped Attack Chain Analysis Tool

Enable with: ENABLE_EMULATION=true
"""

from .atomic import AtomicRedTeam
from .parser import EmulationParser
from .enrich import enrich_detections_with_emulation

__all__ = [
    "AtomicRedTeam",
    "EmulationParser",
    "enrich_detections_with_emulation",
]
