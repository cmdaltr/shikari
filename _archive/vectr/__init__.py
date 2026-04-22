"""
VECTR Integration Module

This optional module integrates with VECTR (https://vectr.io) for threat hunt
tracking, documentation, and purple team collaboration.

VECTR provides:
- Campaign management for hunt operations
- Test case tracking with MITRE ATT&CK mapping
- Environment-based assessment organization
- Operator guidance and red team tool documentation
- Detection validation and coverage tracking

Enable with: ENABLE_VECTR=true
Configure: VECTR_URL, VECTR_API_TOKEN
"""

from .client import VECTRClient
from .campaigns import CampaignManager
from .testcases import TestCaseManager
from .export import export_to_vectr, import_from_vectr

__all__ = [
    "VECTRClient",
    "CampaignManager",
    "TestCaseManager",
    "export_to_vectr",
    "import_from_vectr",
]
