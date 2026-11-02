"""
Splunk API client for query execution.

Uses Splunk REST API to execute SPL queries.
"""

import os
import requests
import time
from typing import Dict, List, Optional
from urllib.parse import urljoin


class SplunkClient:
    """Splunk REST API client"""

    def __init__(
        self,
        host: str = None,
        port: int = 8089,
        username: str = None,
        password: str = None,
        use_https: bool = True,
    ):
        """
        Initialize Splunk client.

        Args:
            host: Splunk server hostname/IP
            port: Splunk management port (default: 8089)
            username: Splunk username
            password: Splunk password
            use_https: Use HTTPS (default: True)

        Environment variables:
            SPLUNK_HOST
            SPLUNK_PORT
            SPLUNK_USERNAME
            SPLUNK_PASSWORD
        """
        self.host = host or os.getenv("SPLUNK_HOST")
        self.port = port or int(os.getenv("SPLUNK_PORT", "8089"))
        self.username = username or os.getenv("SPLUNK_USERNAME")
        self.password = password or os.getenv("SPLUNK_PASSWORD")

        if not all([self.host, self.username, self.password]):
            raise ValueError(
                "Splunk credentials required. Set SPLUNK_HOST, SPLUNK_USERNAME, SPLUNK_PASSWORD"
            )

        protocol = "https" if use_https else "http"
        self.base_url = f"{protocol}://{self.host}:{self.port}/services"
        self.session_key = None

    def _login(self) -> str:
        """Authenticate and get session key"""
        if self.session_key:
            return self.session_key

        url = urljoin(self.base_url, "/auth/login")
        data = {"username": self.username, "password": self.password, "output_mode": "json"}

        response = requests.post(url, data=data, verify=False)  # Disable cert verification for lab
        response.raise_for_status()

        self.session_key = response.json()["sessionKey"]
        return self.session_key

    def execute_query(
        self,
        query: str,
        earliest_time: str = "-24h",
        latest_time: str = "now",
        max_results: int = 1000,
    ) -> Dict:
        """
        Execute SPL query against Splunk.

        Args:
            query: SPL query string
            earliest_time: Start time (e.g., "-24h", "-7d", "2024-01-01")
            latest_time: End time (e.g., "now", "2024-01-02")
            max_results: Maximum results to return

        Returns:
            Dict with 'results' (list of events) and 'stats' (execution metadata)
        """
        session_key = self._login()

        headers = {"Authorization": f"Splunk {session_key}"}

        # Create search job
        url = urljoin(self.base_url, "/search/jobs")
        data = {
            "search": f"search {query}",
            "earliest_time": earliest_time,
            "latest_time": latest_time,
            "output_mode": "json",
        }

        response = requests.post(url, headers=headers, data=data, verify=False)
        response.raise_for_status()

        job_sid = response.json()["sid"]

        # Wait for job to complete
        job_url = urljoin(self.base_url, f"/search/jobs/{job_sid}")
        timeout = 300  # 5 minutes
        start_time = time.time()

        while time.time() - start_time < timeout:
            response = requests.get(
                job_url, headers=headers, params={"output_mode": "json"}, verify=False
            )
            response.raise_for_status()

            job_status = response.json()["entry"][0]["content"]

            if job_status["isDone"]:
                # Get results
                results_url = urljoin(self.base_url, f"/search/jobs/{job_sid}/results")
                response = requests.get(
                    results_url,
                    headers=headers,
                    params={"output_mode": "json", "count": max_results},
                    verify=False,
                )
                response.raise_for_status()

                results = response.json()["results"]

                return {
                    "status": "success",
                    "results": results,
                    "stats": {
                        "row_count": len(results),
                        "scan_count": job_status.get("scanCount", 0),
                        "event_count": job_status.get("eventCount", 0),
                        "run_duration": job_status.get("runDuration", 0),
                    },
                }

            time.sleep(1)

        return {"status": "error", "error": "Query timeout"}

    def test_connection(self) -> bool:
        """Test if Splunk API credentials are valid"""
        try:
            session_key = self._login()
            # Simple query to test
            result = self.execute_query("index=* | head 1")
            return result["status"] == "success"
        except Exception as e:
            print(f"Splunk connection test failed: {e}")
            return False
