"""
Elasticsearch client for query execution (#50).

Runs ES|QL, as shikari/build/elastic.py writes it, through Elasticsearch's query API (POST /_query) with
samarkand.siem.Elastic, the client Ostraka shares. Authenticates with an API key (sent as
`Authorization: ApiKey`) or a username and password. Never raises on a failed query: bad ES|QL, an
expired key or a busy cluster come back as {"status": "error", "error": ...}, as SplunkClient's do.

ES|QL has no cursor: a query returns at most its LIMIT (1,000 when it sets none). A query that returns
events (no STATS, no LIMIT of its own, no KEEP, DROP or RENAME) is paged by its timestamp and document
ID, so max_results can go past that; any other is run as written, and stats.truncated says when it came
back full.
"""

import os
from typing import Dict, Optional

from samarkand import siem


class ElasticClient:
    """Elasticsearch ES|QL client"""

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
        self.client = siem.Elastic(self.url, api_key=self.api_key or "", username=self.username or "",
                                   password=self.password or "", verify=self.verify)

    pageable = staticmethod(siem.Elastic.pageable)
    page_query = staticmethod(siem.Elastic.page_query)

    def execute_query(self, query: str, max_results: int = 1000, timeout: int = 300) -> Dict:
        """
        Run ES|QL and read its rows back.

        Args:
            query: ES|QL; its own time filter (WHERE @timestamp >= NOW() - 1 day) is the window
            max_results: how many rows to read from an event query, 0 for all of them
            timeout: seconds to wait for each request

        Returns:
            {"status": "success", "results": [...], "stats": {...}} or {"status": "error", "error": "..."}
        """
        try:
            result = self.client.query(query, max_rows=max_results, timeout=timeout)
        except siem.SiemProblem as e:
            return {"status": "error", "error": str(e)}
        except (KeyError, ValueError, TypeError) as e:
            return {"status": "error", "error": f"Unexpected response from Elasticsearch: {e}"}
        return {
            "status": "success",
            "results": result.rows,
            # partial: a shard or cluster didn't answer, so fewer rows than there are
            "stats": {"row_count": len(result.rows), "truncated": result.truncated, **result.stats},
        }

    def hit_count(self, query: str) -> Optional[int]:
        """How many rows the detection returns over its own window, or None if it failed"""
        r = self.execute_query(query, max_results=0)
        return r["stats"]["row_count"] if r["status"] == "success" else None

    def test_connection(self) -> bool:
        """Whether the credentials work and ES|QL runs"""
        return self.execute_query("ROW ok = 1").get("status") == "success"
