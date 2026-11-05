"""Defender XDR query execution for hit counts (#16).

Runs a detection's KQL read-only against Microsoft Defender XDR Advanced Hunting (Microsoft Graph
``runHuntingQuery``) and reports how many rows it returns — a false-positive signal before the rule is
deployed. Reuses the app-registration token and the Graph call already in ``shikari.telemetry.mde``
(same ``ThreatHunting.Read.All`` application permission and ``SHIKARI_MDE_*`` environment), so there is
one place that talks to Graph.

    from shikari.query.mde import MDEClient
    client = MDEClient()
    hits = client.hit_count(detection_kql)      # how often the rule would fire over the hunt window
"""
from typing import Dict, List, Optional

from shikari.telemetry.mde import hunt, token


class MDEClient:
    """Read-only Advanced Hunting client for measuring how often a detection fires."""

    def __init__(self, bearer: Optional[str] = None):
        # Defer auth until first use so constructing the client never needs credentials.
        self._bearer = bearer

    @property
    def bearer(self) -> str:
        if self._bearer is None:
            self._bearer = token()
        return self._bearer

    def execute_query(self, query: str) -> Dict:
        """Run a KQL hunting query. Returns ``{status, results, stats: {row_count}}``."""
        rows: List[Dict] = hunt(self.bearer, query)
        return {"status": "success", "results": rows, "stats": {"row_count": len(rows)}}

    def hit_count(self, query: str) -> int:
        """How many rows the detection returns over the Advanced Hunting window.

        Appends ``| count`` (KQL's count operator returns a single ``Count`` row) and reads it back,
        falling back to counting rows directly if a query resists the appended operator.
        """
        rows = hunt(self.bearer, f"{query}\n| count")
        if rows and "Count" in rows[0]:
            return int(rows[0]["Count"])
        return len(hunt(self.bearer, query))

    def test_connection(self) -> bool:
        """True if the token works and Advanced Hunting answers a trivial query."""
        try:
            hunt(self.bearer, "DeviceInfo | take 1")
            return True
        except Exception as e:  # noqa: BLE001 - surfaced to the caller as a bool + message
            print(f"Defender XDR connection test failed: {e}")
            return False
