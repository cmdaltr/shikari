"""MCP over HTTP at /mcp: refused without a valid API token, and each call runs as the token's owner."""

import pytest
from fastapi.testclient import TestClient

from shikari import mcp_server

HEADERS = {"Accept": "application/json, text/event-stream", "Authorization": "Bearer shik_good"}


class FakeClient:
    def __init__(self, token):
        self.token = token

    def search_library(self, query):
        return [{"id": 1, "title": f"{query} as {self.token}", "platform": "splunk"}]


def rpc(http, method, params=None, headers=HEADERS):
    return http.post("/mcp", headers=headers, json={"jsonrpc": "2.0", "id": 1, "method": method, "params": params or {}})


@pytest.fixture
def http(monkeypatch):
    import shikari.app as app_module
    import shikari.auth.tokens as tokens

    monkeypatch.setattr(tokens, "session_for", lambda t: "session-1" if t == "shik_good" else None)
    monkeypatch.setattr(mcp_server, "_request_client",
                        lambda request: FakeClient(request.headers["authorization"][7:]))
    return TestClient(app_module.app)


@pytest.mark.unit
def test_refused_without_a_valid_token(http):
    assert rpc(http, "tools/list", headers={"Accept": HEADERS["Accept"]}).status_code == 401
    assert rpc(http, "tools/list", headers={**HEADERS, "Authorization": "Bearer shik_bad"}).status_code == 401


@pytest.mark.unit
def test_initialise_list_and_call_as_the_token_owner(http):
    r = rpc(http, "initialize", {"protocolVersion": "2025-06-18", "capabilities": {},
                                 "clientInfo": {"name": "test", "version": "1"}})
    assert r.status_code == 200 and r.json()["result"]["serverInfo"]["name"] == "shikari"

    names = [t["name"] for t in rpc(http, "tools/list").json()["result"]["tools"]]
    assert "search_library" in names and "hunt_group" in names

    r = rpc(http, "tools/call", {"name": "search_library", "arguments": {"query": "APT29"}})
    assert "APT29 as shik_good" in r.json()["result"]["content"][0]["text"]
