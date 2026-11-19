"""Defender XDR query execution for hit counts (#16).

Runs a detection's KQL read-only against Defender XDR Advanced Hunting (Microsoft Graph
``runHuntingQuery``) and reports how many rows it returns — a false-positive signal before the rule is
deployed. Uses samarkand.siem.Defender, the client Ostraka shares, with the app registration
``shikari.telemetry.mde`` reads (``ThreatHunting.Read.All`` and the ``SHIKARI_MDE_*`` environment).

    from shikari.query.mde import MDEClient
    client = MDEClient()
    hits = client.hit_count(detection_kql)      # how often the rule would fire over the hunt window
"""
from typing import Dict, Optional

from samarkand import siem

from shikari.telemetry.mde import client as defender


class MDEClient:
    """Read-only Advanced Hunting client for measuring how often a detection fires."""

    def __init__(self, client: Optional[siem.Defender] = None):
        # Read the environment on first use, so constructing the client never needs credentials
        self._client = client

    @property
    def client(self) -> siem.Defender:
        if self._client is None:
            self._client = defender()
        return self._client

    def execute_query(self, query: str, max_results: int = 0) -> Dict:
        """Run a KQL hunting query. Returns ``{status, results, stats: {row_count}}`` or ``{status, error}``."""
        try:
            result = self.client.query(query, max_rows=max_results)
        except (siem.SiemProblem, RuntimeError) as e:
            return {"status": "error", "error": str(e)}
        return {"status": "success", "results": result.rows,
                "stats": {"row_count": len(result.rows), "truncated": result.truncated}}

    def hit_count(self, query: str) -> Optional[int]:
        """How many rows the detection returns over the Advanced Hunting window, or None if it failed.

        Appends ``| count`` (KQL's count operator returns a single ``Count`` row) and reads it back,
        falling back to counting rows directly if a query resists the appended operator.
        """
        r = self.execute_query(f"{query}\n| count")
        if r["status"] == "success" and r["results"] and "Count" in r["results"][0]:
            return int(r["results"][0]["Count"])
        r = self.execute_query(query)
        return r["stats"]["row_count"] if r["status"] == "success" else None

    def test_connection(self) -> bool:
        """True if the app registration works and Advanced Hunting answers a trivial query."""
        try:
            self.client.check()
            return True
        except (siem.SiemProblem, RuntimeError) as e:
            print(f"Defender XDR connection test failed: {e}")
            return False
