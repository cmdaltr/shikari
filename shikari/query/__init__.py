"""
Query execution: run a generated detection read-only against a live SIEM to measure how often it fires.

- SplunkClient (splunk.py): SPL via Splunk's search jobs REST API.
- MDEClient (mde.py): KQL via Microsoft Graph's runHuntingQuery, reusing shikari/telemetry/mde.py (#16).

Validation harness and a local Splunk live in scripts/siem-validation/.
"""

from .mde import MDEClient
from .splunk import SplunkClient

__all__ = ["SplunkClient", "MDEClient"]
