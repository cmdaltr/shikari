"""Mocked tests for the Defender XDR execution client (#16).

No live tenant in CI, so the Graph call (shikari.telemetry.mde.hunt) and token acquisition are patched;
these pin the client's contract — lazy auth, hit_count via `| count` with a row-count fallback, and the
connection test.
"""
import shikari.query.mde as mde
from shikari.query.mde import MDEClient


def test_lazy_auth_no_token_until_used(monkeypatch):
    calls = {"token": 0}
    monkeypatch.setattr(mde, "token", lambda: calls.__setitem__("token", calls["token"] + 1) or "T")
    monkeypatch.setattr(mde, "hunt", lambda b, q: [])
    client = MDEClient()
    assert calls["token"] == 0          # constructing the client must not authenticate
    client.execute_query("DeviceInfo | take 1")
    assert calls["token"] == 1          # first use authenticates once
    client.execute_query("DeviceInfo | take 1")
    assert calls["token"] == 1          # token is cached


def test_execute_query_shape(monkeypatch):
    monkeypatch.setattr(mde, "token", lambda: "T")
    monkeypatch.setattr(mde, "hunt", lambda b, q: [{"a": 1}, {"a": 2}, {"a": 3}])
    out = MDEClient(bearer="T").execute_query("Q")
    assert out["status"] == "success"
    assert out["stats"]["row_count"] == 3
    assert len(out["results"]) == 3


def test_hit_count_reads_count_row(monkeypatch):
    seen = {}

    def fake_hunt(bearer, query):
        seen["query"] = query
        return [{"Count": 42}]

    monkeypatch.setattr(mde, "hunt", fake_hunt)
    assert MDEClient(bearer="T").hit_count("DeviceProcessEvents | where x == 1") == 42
    assert seen["query"].endswith("| count")   # appends the count operator


def test_hit_count_falls_back_to_row_count(monkeypatch):
    # A query whose `| count` yields no Count field: fall back to counting rows of the bare query.
    def fake_hunt(bearer, query):
        return [] if query.endswith("| count") else [{"r": 1}, {"r": 2}]

    monkeypatch.setattr(mde, "hunt", fake_hunt)
    assert MDEClient(bearer="T").hit_count("Q") == 2


def test_connection_ok_and_fail(monkeypatch):
    monkeypatch.setattr(mde, "hunt", lambda b, q: [{"ok": 1}])
    assert MDEClient(bearer="T").test_connection() is True

    def boom(b, q):
        raise RuntimeError("401")

    monkeypatch.setattr(mde, "hunt", boom)
    assert MDEClient(bearer="T").test_connection() is False
