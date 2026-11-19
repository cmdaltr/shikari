"""
Query execution: run a generated detection read-only against a live SIEM to measure how often it fires.
Each client is a thin front on samarkand.siem, the clients Ostraka shares.

- SplunkClient (splunk.py): SPL via Splunk's search jobs REST API.
- ElasticClient (elastic.py): ES|QL via Elasticsearch's query API (#50).
- MDEClient (mde.py): KQL via Microsoft Graph's runHuntingQuery, with shikari/telemetry/mde.py's app registration (#16).

Validation harness and a local Splunk live in scripts/siem-validation/.
"""

from .elastic import ElasticClient
from .mde import MDEClient
from .splunk import SplunkClient

__all__ = ["SplunkClient", "ElasticClient", "MDEClient"]
