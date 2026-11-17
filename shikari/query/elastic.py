"""
Elasticsearch client for query execution (#50).

Runs ES|QL, as shikari/build/elastic.py writes it, through Elasticsearch's query API (POST /_query)
and reads the rows back. Authenticates with an API key (sent as `Authorization: ApiKey`) or a
username and password. Never raises on a failed query: bad ES|QL, an expired key or a busy cluster
come back as {"status": "error", "error": ...}, as SplunkClient's do.

ES|QL has no cursor: a query returns at most its LIMIT (1,000 when it sets none, and never more than
the cluster's esql.query.result_truncation_max_size, 10,000 by default). A query that returns events
(no STATS, no LIMIT of its own) is paged by its timestamp and document ID, so max_results can go past
that; a summarised one (STATS), one with its own LIMIT, or one that picks its columns (KEEP, DROP,
RENAME) is run as written, and stats.truncated says when it came back full.
"""

import os
import re
import time
from typing import Dict, List, Optional, Tuple

import requests

DEFAULT_LIMIT = 1000  # what ES|QL returns when a query sets no LIMIT
_STATS = re.compile(r"\|\s*STATS\b", re.I)
_RESHAPES = re.compile(r"\|\s*(KEEP|DROP|RENAME)\b", re.I)  # can drop the _id and @timestamp paging needs
_TRAILING_LIMIT = re.compile(r"\|\s*LIMIT\s+(\d+)\s*$", re.I)
_FROM = re.compile(r"^\s*FROM\s+([^|]+?)(\s+METADATA\s+([^|]+?))?(?=\s*(?:\||$))", re.I)


def _literal(value: str) -> str:
    return '"' + str(value).replace("\\", "\\\\").replace('"', '\\"') + '"'


class ElasticClient:
    """Elasticsearch ES|QL client"""

    RETRIES = 3  # for 429 and 503: search queue full, or the cluster still starting

    def __init__(
        self,
        url: str = None,
        api_key: str = None,
        username: str = None,
        password: str = None,
        verify: Optional[bool] = None,
    ):
        """
        Environment variables, for anything not passed:
            ELASTIC_URL (https://host:9200), or ELASTIC_HOST and ELASTIC_PORT (9200)
            ELASTIC_API_KEY (the encoded key Kibana or POST /_security/api_key gives), or
            ELASTIC_USERNAME and ELASTIC_PASSWORD
            ELASTIC_VERIFY=1 to check the certificate (off by default: a lab's is self-signed)
        """
        host = os.getenv("ELASTIC_HOST")
        self.url = (url or os.getenv("ELASTIC_URL")
                    or (f"https://{host}:{os.getenv('ELASTIC_PORT', '9200')}" if host else "")).rstrip("/")
        self.api_key = api_key or os.getenv("ELASTIC_API_KEY")
        self.username = username or os.getenv("ELASTIC_USERNAME")
        self.password = password or os.getenv("ELASTIC_PASSWORD")
        self.verify = verify if verify is not None else os.getenv("ELASTIC_VERIFY", "") in ("1", "true", "yes")

        if not self.url or not (self.api_key or (self.username and self.password)):
            raise ValueError(
                "Elasticsearch credentials required. Set ELASTIC_URL and ELASTIC_API_KEY, "
                "or ELASTIC_USERNAME and ELASTIC_PASSWORD"
            )
        self.session = requests.Session()
        self.session.verify = self.verify
        if self.api_key:
            self.session.headers["Authorization"] = f"ApiKey {self.api_key}"
        else:
            self.session.auth = (self.username, self.password)
        if not self.verify:
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    def _request(self, method: str, path: str, timeout: int = 60, **kwargs) -> requests.Response:
        """A call that waits out 429 and 503, honouring Retry-After"""
        for attempt in range(self.RETRIES + 1):
            response = self.session.request(method, f"{self.url}/{path.lstrip('/')}", timeout=timeout, **kwargs)
            if response.status_code in (429, 503) and attempt < self.RETRIES:
                time.sleep(float(response.headers.get("Retry-After") or 2 ** attempt))
                continue
            return response
        return response

    @staticmethod
    def _reason(response: requests.Response) -> str:
        """Elasticsearch's own words: {"error": {"root_cause": [{"reason": ...}], "reason": ...}}"""
        try:
            error = response.json().get("error")
        except ValueError:
            return response.text[:300] or f"HTTP {response.status_code}"
        if isinstance(error, str):
            return error
        if not isinstance(error, dict):
            return f"HTTP {response.status_code}"
        causes = [c.get("reason", "") for c in error.get("root_cause") or [] if c.get("reason")]
        return "; ".join(dict.fromkeys(causes)) or error.get("reason") or f"HTTP {response.status_code}"

    @staticmethod
    def pageable(query: str) -> bool:
        """Whether the query returns events (paged) rather than a summary or its own LIMIT (run once)"""
        q = query.strip()
        return (bool(_FROM.match(q)) and not _STATS.search(q) and not _TRAILING_LIMIT.search(q)
                and not _RESHAPES.search(q))

    @staticmethod
    def page_query(query: str, size: int, after: Optional[Tuple[str, str]] = None) -> str:
        """The query with _id in its METADATA, a keyset WHERE past the last row, sorted, limited"""
        q = query.strip()
        m = _FROM.match(q)
        sources, metadata = m.group(1).strip(), [s.strip() for s in (m.group(3) or "").split(",") if s.strip()]
        if "_id" not in metadata:
            metadata.append("_id")
        head = f"FROM {sources} METADATA {', '.join(metadata)}"
        rest = q[m.end():]
        if after:
            ts, doc = after
            rest += (f"\n| WHERE @timestamp > TO_DATETIME({_literal(ts)})"
                     f" OR (@timestamp == TO_DATETIME({_literal(ts)}) AND _id > {_literal(doc)})")
        return f"{head}{rest}\n| SORT @timestamp ASC, _id ASC\n| LIMIT {size}"

    def _run(self, query: str, timeout: int) -> Dict:
        response = self._request("POST", "_query", timeout=timeout, json={"query": query},
                                 params={"format": "json"})
        if response.status_code == 401:
            return {"status": "error", "error": f"Not authorised (API key expired or wrong?): {self._reason(response)}"}
        if response.status_code == 403:
            return {"status": "error", "error": f"Not allowed to read these indices: {self._reason(response)}"}
        if response.status_code >= 400:
            # Bad ES|QL is refused here with Elasticsearch's parser or verifier message
            return {"status": "error", "error": self._reason(response)}
        body = response.json()
        names = [c["name"] for c in body.get("columns", [])]
        rows = [dict(zip(names, values)) for values in body.get("values", [])]
        return {"status": "success", "rows": rows, "took": body.get("took", 0),
                "partial": bool(body.get("is_partial"))}

    def execute_query(self, query: str, max_results: int = 1000, page_size: int = 1000,
                      timeout: int = 300) -> Dict:
        """
        Run ES|QL and read its rows back.

        Args:
            query: ES|QL; its own time filter (WHERE @timestamp >= NOW() - 1 day) is the window
            max_results: how many rows to read from an event query, 0 for all of them
            page_size: rows per request while paging (at most the cluster's truncation size)
            timeout: seconds to wait for each request

        Returns:
            {"status": "success", "results": [...], "stats": {...}} or {"status": "error", "error": "..."}
        """
        try:
            return self._execute(query, max_results, page_size, timeout)
        except requests.Timeout:
            return {"status": "error", "error": f"Query timeout after {timeout}s"}
        except requests.RequestException as e:
            return {"status": "error", "error": f"Elasticsearch unreachable: {e}"}
        except (KeyError, ValueError, TypeError) as e:
            return {"status": "error", "error": f"Unexpected response from Elasticsearch: {e}"}

    def _execute(self, query: str, max_results: int, page_size: int, timeout: int) -> Dict:
        if not query or not query.strip():
            return {"status": "error", "error": "Empty query"}
        start = time.time()
        if not self.pageable(query):
            run = self._run(query, timeout)
            if run["status"] != "success":
                return run
            m = _TRAILING_LIMIT.search(query.strip())
            limit = int(m.group(1)) if m else DEFAULT_LIMIT
            rows = run["rows"]
            return self._result(rows, len(rows) >= limit, run["partial"], run["took"], start, pages=1)

        rows: List[Dict] = []
        after, pages, partial, took = None, 0, False, 0
        while True:
            size = page_size if not max_results else min(page_size, max_results - len(rows))
            run = self._run(self.page_query(query, size, after), timeout)
            if run["status"] != "success":
                return run
            pages += 1
            partial, took = partial or run["partial"], took + run["took"]
            page = run["rows"]
            rows.extend(page)
            if len(page) < size:
                return self._result(rows, False, partial, took, start, pages)
            if max_results and len(rows) >= max_results:
                return self._result(rows, True, partial, took, start, pages)  # more may be there
            last = page[-1]
            if last.get("@timestamp") is None or last.get("_id") is None:
                return {"status": "error", "error": "Can't page: the rows have no @timestamp or _id"}
            after = (last["@timestamp"], last["_id"])

    @staticmethod
    def _result(rows, truncated, partial, took, start, pages) -> Dict:
        return {
            "status": "success",
            "results": rows,
            "stats": {
                "row_count": len(rows),
                "truncated": truncated,
                "partial": partial,  # a shard or cluster didn't answer: fewer rows than there are
                "pages": pages,
                "took_ms": took,
                "run_duration": round(time.time() - start, 3),
            },
        }

    def hit_count(self, query: str) -> Optional[int]:
        """How many rows the detection returns over its own window, or None if it failed"""
        r = self.execute_query(query, max_results=0)
        return r["stats"]["row_count"] if r["status"] == "success" else None

    def test_connection(self) -> bool:
        """Whether the credentials work and ES|QL runs"""
        return self.execute_query("ROW ok = 1").get("status") == "success"
