"""
Splunk API client for query execution.

Runs SPL through Splunk's search jobs API with samarkand.siem.Splunk, the client Ostraka shares.
Authenticates with a token (Settings > Tokens; sent as a Bearer token) or a username and password (a
session key from /services/auth/login, renewed once if it expires). Never raises on a failed search:
bad SPL, an expired token or a busy Splunk come back as {"status": "error", "error": ...}.
"""

import os
from typing import Dict, Optional

from samarkand import siem


class SplunkClient:
    """Splunk REST API client"""

    def __init__(
        self,
        host: str = None,
        port: int = None,
        username: str = None,
        password: str = None,
        use_https: bool = True,
        token: str = None,
        verify: Optional[bool] = None,
    ):
        """
        Environment variables, for anything not passed:
            SPLUNK_HOST, SPLUNK_PORT (8089)
            SPLUNK_TOKEN, or SPLUNK_USERNAME and SPLUNK_PASSWORD
            SPLUNK_VERIFY=1 to check the management port's certificate (off by default: a lab
            Splunk's is self-signed)
        """
        self.host = host or os.getenv("SPLUNK_HOST")
        self.port = int(port or os.getenv("SPLUNK_PORT", "8089"))
        self.token = token or os.getenv("SPLUNK_TOKEN")
        self.username = username or os.getenv("SPLUNK_USERNAME")
        self.password = password or os.getenv("SPLUNK_PASSWORD")
        self.verify = verify if verify is not None else os.getenv("SPLUNK_VERIFY", "") in ("1", "true", "yes")

        if not self.host or not (self.token or (self.username and self.password)):
            raise ValueError(
                "Splunk credentials required. Set SPLUNK_HOST and SPLUNK_TOKEN, "
                "or SPLUNK_USERNAME and SPLUNK_PASSWORD"
            )

        protocol = "https" if use_https else "http"
        self.client = siem.Splunk(
            f"{protocol}://{self.host}:{self.port}",
            token=self.token or "", username=self.username or "", password=self.password or "",
            verify=self.verify,
        )
        self.base_url = self.client.base

    search_string = staticmethod(siem.Splunk.search_string)

    def execute_query(
        self,
        query: str,
        earliest_time: str = "-24h",
        latest_time: str = "now",
        max_results: int = 1000,
        timeout: int = 300,
    ) -> Dict:
        """
        Run SPL and read its results back.

        Args:
            query: SPL; a time term inside it (earliest=-1d) overrides earliest_time
            earliest_time, latest_time: the search window, in Splunk's words or epoch seconds
            max_results: how many results to read, 0 for all of them
            timeout: seconds to wait for the job

        Returns:
            {"status": "success", "results": [...], "stats": {...}} or {"status": "error", "error": "..."}
        """
        try:
            result = self.client.query(query, start=earliest_time, end=latest_time,
                                       max_rows=max_results, timeout=timeout)
        except siem.SiemProblem as e:
            return {"status": "error", "error": str(e)}
        except (KeyError, ValueError, TypeError) as e:
            return {"status": "error", "error": f"Unexpected response from Splunk: {e}"}
        stats = dict(result.stats)
        return {
            "status": "success",
            "results": result.rows,
            "sid": stats.pop("sid", None),
            "stats": {"row_count": len(result.rows), "truncated": result.truncated, **stats},
        }

    def test_connection(self) -> bool:
        """Whether the credentials work and a search runs"""
        return self.execute_query("| makeresults", max_results=1).get("status") == "success"
