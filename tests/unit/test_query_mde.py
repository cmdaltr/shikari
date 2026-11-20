"""Mocked tests for the Defender XDR execution client (#16).

No live tenant in CI, so samarkand's HTTP is faked; these pin the client's contract: credentials read
on first use, hit_count via `| count` with a row-count fallback, failures as errors, and the
connection test.
"""
import json
from unittest.mock import patch
from urllib.parse import parse_qs

import pytest
from samarkand._http import Response

from shikari.query.mde import MDEClient

ENV = {"SHIKARI_MDE_TENANT_ID": "t", "SHIKARI_MDE_CLIENT_ID": "c", "SHIKARI_MDE_CLIENT_SECRET": "s"}


def ok(body, status=200):
    return Response(status, json.dumps(body).encode(), {})


@pytest.fixture
def graph(monkeypatch):
    """Answers each token request with a token and each hunt with graph.rows(query); keeps the hunts"""
    for k, v in ENV.items():
        monkeypatch.setenv(k, v)

    class Graph:
        def __init__(self):
            self.hunts, self.status = [], 200
            self.rows = lambda query: []

        def request(self, method, url, **kw):
            if "login.microsoftonline.com" in url:
                assert parse_qs(kw["body"].decode())["client_secret"] == ["s"]
                return ok({"access_token": "T"})
            query = json.loads(kw["body"])["Query"]
            self.hunts.append(query)
            if self.status != 200:
                return ok({"error": {"message": "Semantic error"}}, self.status)
            return ok({"results": self.rows(query), "schema": []})

    g = Graph()
    with patch("samarkand._http.request", g.request):
        yield g


def test_credentials_read_on_first_use(monkeypatch):
    for k in ENV:
        monkeypatch.delenv(k, raising=False)
    client = MDEClient()  # constructing the client must not need credentials
    assert "SHIKARI_MDE_TENANT_ID" in client.execute_query("DeviceInfo | take 1")["error"]


def test_execute_query_shape(graph):
    graph.rows = lambda q: [{"a": 1}, {"a": 2}, {"a": 3}]
    out = MDEClient().execute_query("Q")
    assert out["status"] == "success"
    assert out["stats"]["row_count"] == 3
    assert len(out["results"]) == 3


def test_refused_query_is_an_error(graph):
    graph.status = 400
    assert MDEClient().execute_query("Q") == {"status": "error", "error": "Semantic error"}


def test_hit_count_reads_count_row(graph):
    graph.rows = lambda q: [{"Count": 42}]
    assert MDEClient().hit_count("DeviceProcessEvents | where x == 1") == 42
    assert graph.hunts[-1].endswith("| count")   # appends the count operator


def test_hit_count_falls_back_to_row_count(graph):
    # A query whose `| count` yields no Count field: fall back to counting rows of the bare query.
    graph.rows = lambda q: [] if q.endswith("| count") else [{"r": 1}, {"r": 2}]
    assert MDEClient().hit_count("Q") == 2


def test_hit_count_of_a_failed_query_is_none(graph):
    graph.status = 400
    assert MDEClient().hit_count("Q") is None
    assert len(graph.hunts) == 1   # a refused count isn't retried as the whole query, unbounded


def test_token_answer_without_a_token_is_an_error(graph):
    real = graph.request
    graph.request = lambda method, url, **kw: ok({}) if "login.microsoftonline.com" in url else real(method, url, **kw)
    with patch("samarkand._http.request", graph.request):
        assert MDEClient().execute_query("Q")["status"] == "error"


def test_connection_ok_and_fail(graph):
    graph.rows = lambda q: [{"ok": 1}]
    assert MDEClient().test_connection() is True
    graph.status = 401
    assert MDEClient().test_connection() is False
