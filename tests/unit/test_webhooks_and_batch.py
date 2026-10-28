"""Webhooks, batch hunts and streamed progress (#35)."""
import asyncio
import hashlib
import hmac
import json

import pytest

from archer import runs_api, webhooks


@pytest.fixture
def home(tmp_path, monkeypatch):
    monkeypatch.setattr(webhooks.paths, "DATA", tmp_path)
    monkeypatch.setattr(runs_api.paths, "DATA", tmp_path)
    return tmp_path


class Response:
    def __init__(self, status):
        self.status_code = status


def test_a_delivery_is_signed_so_the_receiver_can_check_it(home, monkeypatch):
    sent = {}

    def post(url, data, headers, timeout):
        sent.update(url=url, body=data, headers=headers)
        return Response(204)

    monkeypatch.setattr(webhooks.requests, "post", post)
    hook = webhooks.add("https://hooks.example/archer", ["run.completed"], secret="s3cret")
    result = webhooks.deliver(hook, "run.completed", {"run": "APT29"})
    assert result["ok"] and result["tries"] == 1
    expected = "sha256=" + hmac.new(b"s3cret", sent["body"], hashlib.sha256).hexdigest()
    assert sent["headers"]["X-Archer-Signature"] == expected
    assert json.loads(sent["body"])["data"] == {"run": "APT29"}
    assert webhooks._load()[0]["deliveries"][0]["ok"]


def test_server_errors_are_retried_but_a_refusal_is_not(home, monkeypatch):
    statuses = iter([503, 503, 200])
    monkeypatch.setattr(webhooks.requests, "post", lambda *a, **k: Response(next(statuses)))
    hook = webhooks.add("https://hooks.example/a", ["run.completed"])
    assert webhooks.deliver(hook, "run.completed", {}, backoff=0)["tries"] == 3

    calls = []
    monkeypatch.setattr(webhooks.requests, "post", lambda *a, **k: calls.append(1) or Response(404))
    result = webhooks.deliver(hook, "run.completed", {}, backoff=0)
    assert not result["ok"] and len(calls) == 1


def test_only_webhooks_that_want_the_event_get_it(home, monkeypatch):
    got = []
    monkeypatch.setattr(webhooks, "deliver", lambda hook, event, data: got.append((hook["url"], event)))
    monkeypatch.setattr(webhooks.threading, "Thread",
                        lambda target, args, **k: type("T", (), {"start": lambda self: target(*args)})())
    webhooks.add("https://a.example/", ["run.completed"])
    webhooks.add("https://b.example/", ["run.failed"])
    off = webhooks.add("https://c.example/", ["run.completed"])
    webhooks.update(off["id"], enabled=False)
    webhooks.emit_run("APT29", {"phase": "complete", "created_yaml": 12})
    webhooks.emit_run("FIN7", {"status": "error", "error": "boom"})
    assert got == [("https://a.example/", "run.completed"), ("https://b.example/", "run.failed")]


def test_bad_webhooks_are_refused():
    assert webhooks.validate("ftp://x", ["run.completed"])
    assert webhooks.validate("https://x.example", ["run.started"])
    assert webhooks.validate("https://x.example", ["watchlist.match"]) is None


def test_a_finished_run_fires_its_webhook(tmp_path, monkeypatch):
    from archer.build import progress

    monkeypatch.setattr(progress, "PROGRESS_DIR", str(tmp_path))
    monkeypatch.setattr(progress, "_finish_run", lambda *a: None)
    fired = []
    monkeypatch.setattr(progress, "_notify", lambda run, p: fired.append((run, p.get("phase"), p.get("status"))))
    progress.write_progress("APT29", {"status": "running", "phase": "generating"})
    progress.write_progress("APT29", {"phase": "complete"})
    progress.write_progress("APT29", {"phase": "complete"})
    assert fired == [("APT29", "complete", "running")]


class FakeClient:
    def __init__(self, fail=()):
        self.calls, self.fail = [], set(fail)

    def hunt_group(self, group, correlate, osint):
        self.calls.append(("group", group))
        if group in self.fail:
            raise RuntimeError("Not a known ATT&CK group")
        return group

    def hunt_cve(self, cve, correlate):
        self.calls.append(("cve", cve))
        return cve

    def wait(self, run, timeout):
        return {"status": "complete", "created_yaml": 3}


def test_a_batch_hunts_each_item_in_turn_and_carries_on_past_a_failure(home):
    items = runs_api.items_from({"groups": ["APT29", "apt29", "Nope"], "cves": ["cve-2024-3400"]})
    assert [i["target"] for i in items] == ["APT29", "Nope", "CVE-2024-3400"]
    client = FakeClient(fail={"Nope"})
    batch = runs_api.run_batch({"id": "abc123", "user_id": 1, "correlate": True, "items": items}, client)
    assert client.calls == [("group", "APT29"), ("group", "Nope"), ("cve", "CVE-2024-3400")]
    assert [i["status"] for i in batch["items"]] == ["complete", "failed", "complete"]
    assert batch["status"] == "partial"
    assert runs_api.load("abc123")["status"] == "partial"
    assert runs_api.load("../etc") is None


def test_progress_streams_each_change_then_done():
    states = iter([{"phase": "generating", "processed": 1}, {"phase": "generating", "processed": 1},
                   {"phase": "generating", "processed": 2}, {"phase": "complete"}])

    async def collect():
        return [frame async for frame in runs_api.progress_events("APT29", lambda run: next(states), poll=0)]

    frames = asyncio.run(collect())
    assert [f.split("\n")[0] for f in frames] == ["event: progress"] * 3 + ["event: done"]
