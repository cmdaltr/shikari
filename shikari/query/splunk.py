"""
Splunk API client for query execution.

Runs SPL through Splunk's search jobs API (/services/search/jobs) and reads the results back a page
at a time. Authenticates with a token (Settings > Tokens; sent as a Bearer token) or a username and
password (a session key from /services/auth/login). Never raises on a failed search: bad SPL, an
expired token or a busy Splunk come back as {"status": "error", "error": ...}.
"""

import os
import time
from typing import Dict, Optional

import requests


class SplunkClient:
    """Splunk REST API client"""

    RETRIES = 3  # for 429 and 503: Splunk's search concurrency and rate limits

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
        self.base_url = f"{protocol}://{self.host}:{self.port}/services"
        self.session_key = None
        if not self.verify:
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    def _url(self, path: str) -> str:
        # Not urljoin: an absolute path would replace /services
        return f"{self.base_url}/{path.lstrip('/')}"

    def _login(self) -> str:
        """A session key from the username and password"""
        if self.session_key:
            return self.session_key
        response = requests.post(
            self._url("auth/login"),
            data={"username": self.username, "password": self.password, "output_mode": "json"},
            verify=self.verify, timeout=30,
        )
        response.raise_for_status()
        self.session_key = response.json()["sessionKey"]
        return self.session_key

    def _headers(self) -> Dict[str, str]:
        if self.token:
            return {"Authorization": f"Bearer {self.token}"}
        return {"Authorization": f"Splunk {self._login()}"}

    def _request(self, method: str, path: str, **kwargs) -> requests.Response:
        """A call that waits out 429 and 503 and logs in again once if a session key expired"""
        relogged = False
        for attempt in range(self.RETRIES + 1):
            response = requests.request(method, self._url(path), headers=self._headers(),
                                        verify=self.verify, timeout=60, **kwargs)
            if response.status_code in (429, 503) and attempt < self.RETRIES:
                time.sleep(float(response.headers.get("Retry-After") or 2 ** attempt))
                continue
            if response.status_code == 401 and not self.token and not relogged:
                self.session_key, relogged = None, True
                continue
            return response
        return response

    @staticmethod
    def _messages(response: requests.Response) -> str:
        """Splunk's own words for a failure: {"messages": [{"type": "ERROR", "text": ...}]}"""
        try:
            body = response.json()
        except ValueError:
            return response.text[:300] or f"HTTP {response.status_code}"
        texts = [m.get("text", "") for m in body.get("messages", []) if m.get("text")]
        return "; ".join(dict.fromkeys(texts)) or f"HTTP {response.status_code}"  # Splunk repeats a parser error

    @staticmethod
    def search_string(query: str) -> str:
        """A search job needs a leading command: `search` for a bare search, nothing for `| tstats ...`"""
        q = query.strip()
        return q if q.startswith("|") or q.lower().startswith("search ") else f"search {q}"

    def execute_query(
        self,
        query: str,
        earliest_time: str = "-24h",
        latest_time: str = "now",
        max_results: int = 1000,
        page_size: int = 1000,
        timeout: int = 300,
    ) -> Dict:
        """
        Run SPL and read its results back.

        Args:
            query: SPL; a time term inside it (earliest=-1d) overrides earliest_time
            earliest_time, latest_time: the search window
            max_results: how many results to read, 0 for all of them
            page_size: results per request while paging
            timeout: seconds to wait for the job

        Returns:
            {"status": "success", "results": [...], "stats": {...}} or {"status": "error", "error": "..."}
        """
        try:
            return self._execute(query, earliest_time, latest_time, max_results, page_size, timeout)
        except requests.RequestException as e:
            return {"status": "error", "error": f"Splunk unreachable: {e}"}
        except (KeyError, ValueError) as e:
            return {"status": "error", "error": f"Unexpected response from Splunk: {e}"}

    def _execute(self, query, earliest_time, latest_time, max_results, page_size, timeout) -> Dict:
        if not self.token:
            try:
                self._login()
            except requests.HTTPError as e:
                return {"status": "error", "error": f"Login failed: {self._messages(e.response)}"}

        response = self._request("POST", "search/jobs", data={
            "search": self.search_string(query), "earliest_time": earliest_time,
            "latest_time": latest_time, "output_mode": "json",
        })
        if response.status_code == 401:
            return {"status": "error", "error": f"Not authorised (token expired or wrong?): {self._messages(response)}"}
        if response.status_code >= 400:
            # Bad SPL is refused here, at dispatch, with Splunk's parser message
            return {"status": "error", "error": self._messages(response)}
        sid = response.json()["sid"]

        start = time.time()
        while True:
            response = self._request("GET", f"search/jobs/{sid}", params={"output_mode": "json"})
            if response.status_code >= 400:
                return {"status": "error", "error": self._messages(response), "sid": sid}
            job = response.json()["entry"][0]["content"]
            if job.get("dispatchState") == "FAILED" or job.get("isFailed"):
                texts = [m.get("text", "") for m in job.get("messages", [])] if isinstance(job.get("messages"), list) else []
                return {"status": "error", "error": "; ".join(t for t in texts if t) or "Search failed", "sid": sid}
            if job.get("isDone"):
                break
            if time.time() - start > timeout:
                self._request("POST", f"search/jobs/{sid}/control", data={"action": "cancel"})
                return {"status": "error", "error": f"Query timeout after {timeout}s", "sid": sid}
            time.sleep(1)

        results, offset = [], 0
        total = int(job.get("resultCount", 0))
        wanted = total if not max_results else min(max_results, total)
        while offset < wanted:
            count = min(page_size, wanted - offset)
            response = self._request("GET", f"search/jobs/{sid}/results",
                                     params={"output_mode": "json", "count": count, "offset": offset})
            if response.status_code >= 400:
                return {"status": "error", "error": self._messages(response), "sid": sid}
            page = response.json().get("results", [])
            if not page:
                break
            results.extend(page)
            offset += len(page)

        return {
            "status": "success",
            "results": results,
            "sid": sid,
            "stats": {
                "row_count": len(results),
                "result_count": total,
                "truncated": len(results) < total,
                "scan_count": job.get("scanCount", 0),
                "event_count": job.get("eventCount", 0),
                "run_duration": job.get("runDuration", 0),
            },
        }

    def test_connection(self) -> bool:
        """Whether the credentials work and a search runs"""
        return self.execute_query("| makeresults", max_results=1).get("status") == "success"
