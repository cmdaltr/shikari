"""The Elasticsearch ES|QL client (#50): requests are faked here; the live run is in
docs/features/QUERY_EXECUTION.md."""
import base64
import json
import os
import socket
from unittest.mock import patch

import pytest
from samarkand._http import Response

from shikari.query.elastic import ElasticClient


def Reply(status=200, body=None, headers=None):
    return Response(status, json.dumps(body or {}).encode(), {k.lower(): v for k, v in (headers or {}).items()})


def rows(*values, columns=("@timestamp", "_id", "process.name")):
    return Reply(body={"columns": [{"name": c, "type": "keyword"} for c in columns],
                       "values": [list(v) for v in values], "took": 3})


class Fake:
    """samarkand's HTTP faked with scripted replies (an exception is raised instead)"""

    def __init__(self, replies, sent=None):
        self.queue, self.sent, self.waits = list(replies), sent, []

    def request(self, method, url, **kw):
        if self.sent is not None:
            self.sent.append(json.loads(kw["body"])["query"])
        r = self.queue.pop(0)
        if isinstance(r, BaseException):
            raise r
        return r


def run(replies, query, sent=None, **kw):
    fake = Fake(replies, sent)
    with patch("samarkand._http.request", fake.request), patch("samarkand.siem.time.sleep", fake.waits.append):
        r = ElasticClient(url="http://es:9200", api_key="k").execute_query(query, **kw)
    return r, fake


def client(replies, sent=None):
    """Something with execute_query that runs against the replies"""
    class Runner:
        def execute_query(self, query, **kw):
            return run(replies, query, sent, **kw)[0]
    return Runner()


def test_credentials_required():
    with patch.dict(os.environ, {}, clear=True), pytest.raises(ValueError, match="credentials required"):
        ElasticClient()


def test_api_key_and_basic_auth():
    with patch.dict(os.environ, {"ELASTIC_HOST": "es", "ELASTIC_API_KEY": "abc"}, clear=True):
        c = ElasticClient()
    assert c.url == "https://es:9200" and c.client.auth == "ApiKey abc"
    c = ElasticClient(url="http://es:9200/", username="elastic", password="pw")
    assert c.url == "http://es:9200" and c.client.auth == "Basic " + base64.b64encode(b"elastic:pw").decode()


def test_summary_query_runs_once_and_says_when_full():
    q = "FROM logs-endpoint.events.process-*\n| STATS Events = COUNT(*) BY host.name\n| LIMIT 2"
    sent = []
    r = client([rows(("a", 1), ("b", 2), columns=("host.name", "Events"))], sent).execute_query(q)
    assert sent == [q] and r["status"] == "success"
    assert r["results"] == [{"host.name": "a", "Events": 1}, {"host.name": "b", "Events": 2}]
    assert r["stats"]["truncated"] is True and r["stats"]["pages"] == 1


def test_event_query_is_paged_by_timestamp_and_id():
    q = 'FROM logs-endpoint.events.process-*\n| WHERE process.name == "whoami.exe"'
    sent = []
    first = rows(*[("t1", f"a{i:04}", "x") for i in range(1000)])
    r = client([first, rows(("t2", "c", "x"))], sent).execute_query(q, max_results=0)
    assert len(r["results"]) == 1001 and r["results"][-1]["_id"] == "c"
    assert r["stats"] == {**r["stats"], "row_count": 1001, "truncated": False, "pages": 2}
    assert sent[0].startswith("FROM logs-endpoint.events.process-* METADATA _id")
    assert sent[0].endswith("| SORT @timestamp ASC, _id ASC\n| LIMIT 1000") and "TO_DATETIME" not in sent[0]
    assert '@timestamp > TO_DATETIME("t1") OR (@timestamp == TO_DATETIME("t1") AND _id > "a0999")' in sent[1]


def test_max_results_stops_paging_and_marks_truncated():
    q = "FROM logs-*"
    r = client([rows(("t1", "a", "x"), ("t1", "b", "x"))]).execute_query(q, max_results=2)
    assert r["stats"]["row_count"] == 2 and r["stats"]["truncated"] is True


def test_existing_metadata_keeps_its_fields():
    assert ElasticClient.page_query("FROM a, b METADATA _index | KEEP x", 10).startswith(
        "FROM a, b METADATA _index, _id | KEEP x")


@pytest.mark.parametrize("reply,expected", [
    (Reply(400, {"error": {"root_cause": [{"type": "parsing_exception",
                                           "reason": "line 1:6: mismatched input"}]}}), "mismatched input"),
    (Reply(401, {"error": {"reason": "unable to authenticate with provided credentials"}}), "refused the credentials"),
    (Reply(403, {"error": {"reason": "action [indices:data/read/esql] is unauthorized"}}), "Not allowed"),
    (socket.timeout("timed out"), "timed out"),
    (ConnectionRefusedError("refused"), "couldn't reach es:9200"),
])
def test_failures_come_back_as_errors(reply, expected):
    r = client([reply]).execute_query("FROM logs-* | STATS c = COUNT(*)")
    assert r["status"] == "error" and expected.lower() in r["error"].lower()


def test_busy_cluster_is_retried_honouring_retry_after():
    r, fake = run([Reply(429, headers={"Retry-After": "7"}), Reply(503), rows(("a",), columns=("ok",))], "ROW ok = 1")
    assert r["status"] == "success" and fake.waits == [7.0, 2.0]


def test_gives_up_after_the_retries():
    r, _ = run([Reply(429)] * 4, "ROW ok = 1")
    assert r["status"] == "error"


def test_empty_query_refused():
    assert client([]).execute_query("  ")["status"] == "error"


@pytest.mark.parametrize("q,paged", [
    ("FROM logs-*", True),
    ("FROM logs-* | WHERE a == 1", True),
    ("FROM logs-* | STATS c = COUNT(*)", False),
    ("FROM logs-* | LIMIT 50", False),
    ("FROM logs-* | KEEP @timestamp", False),   # a live run: KEEP drops the _id paging sorts on
    ("ROW ok = 1", False),
])
def test_which_queries_are_paged(q, paged):
    assert ElasticClient.pageable(q) is paged
