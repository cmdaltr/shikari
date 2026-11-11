"""Webhooks, batch hunts and streamed progress (#35)."""
import asyncio
import hashlib
import hmac
import json

import pytest

from shikari import runs_api, webhooks


@pytest.fixture
def home(tmp_path, monkeypatch):
    monkeypatch.setattr(webhooks.paths, "DATA", tmp_path)
    monkeypatch.setattr(runs_api.paths, "DATA", tmp_path)
    # These tests exercise delivery itself; licensing is covered in test_licence_gates_webhook_delivery.
    monkeypatch.setattr(webhooks, "_automation_on", lambda: True)
    return tmp_path


def test_a_delivery_is_signed_so_the_receiver_can_check_it(home, monkeypatch):
    sent = {}

    def post(url, data, headers, timeout):
        sent.update(url=url, body=data, headers=headers)
        return 204

    monkeypatch.setattr(webhooks, "_post", post)
    hook = webhooks.add("https://hooks.example/shikari", ["run.completed"], secret="s3cret")
    result = webhooks.deliver(hook, "run.completed", {"run": "APT29"})
    assert result["ok"] and result["tries"] == 1
    expected = "sha256=" + hmac.new(b"s3cret", sent["body"], hashlib.sha256).hexdigest()
    assert sent["headers"]["X-Shikari-Signature"] == expected
    assert json.loads(sent["body"])["data"] == {"run": "APT29"}
    assert webhooks._load()[0]["deliveries"][0]["ok"]


def test_server_errors_are_retried_but_a_refusal_is_not(home, monkeypatch):
    statuses = iter([503, 503, 200])
    monkeypatch.setattr(webhooks, "_post", lambda *a, **k: next(statuses))
    hook = webhooks.add("https://hooks.example/a", ["run.completed"])
    assert webhooks.deliver(hook, "run.completed", {}, backoff=0)["tries"] == 3

    calls = []
    monkeypatch.setattr(webhooks, "_post", lambda *a, **k: calls.append(1) or 404)
    result = webhooks.deliver(hook, "run.completed", {}, backoff=0)
    assert not result["ok"] and len(calls) == 1


def test_only_webhooks_that_want_the_event_get_it(home, monkeypatch):
    got = []
    monkeypatch.setattr(webhooks, "deliver", lambda hook, event, data: got.append((hook["url"], event)))
    monkeypatch.setattr(webhooks, "_automation_on", lambda: True)
    monkeypatch.setattr(webhooks.threading, "Thread",
                        lambda target, args, **k: type("T", (), {"start": lambda self: target(*args)})())
    webhooks.add("https://a.example/", ["run.completed"])
    webhooks.add("https://b.example/", ["run.failed"])
    off = webhooks.add("https://c.example/", ["run.completed"])
    webhooks.update(off["id"], enabled=False)
    webhooks.emit_run("APT29", {"phase": "complete", "created_yaml": 12})
    webhooks.emit_run("FIN7", {"status": "error", "error": "boom"})
    assert got == [("https://a.example/", "run.completed"), ("https://b.example/", "run.failed")]


def test_licence_gates_webhook_delivery_but_not_registration(tmp_path, monkeypatch):
    """`automation` is checked at the send: a Free install keeps its webhook, it just doesn't fire;
    a Pro install sends. The webhook survives a lapse back to Free (docs/LICENSING_MODEL.md)."""
    from shikari import licensing

    monkeypatch.setattr(webhooks.paths, "DATA", tmp_path)  # the real _automation_on runs here
    posted = []
    monkeypatch.setattr(webhooks, "_post", lambda *a, **k: posted.append(1) or 204)

    # Free: registering is open, but the send is held and says why.
    monkeypatch.setattr(licensing, "has_feature", lambda f: False)
    hook = webhooks.add("https://hooks.example/x", ["run.completed"])
    free = webhooks.deliver(hook, "run.completed", {"run": "APT29"})
    assert free.get("skipped") and not free["ok"] and not posted
    assert webhooks.emit("run.completed", {"run": "APT29"}) == 0
    assert webhooks.licence_note().startswith("Webhooks need Pro or Services")

    # Pro: the same, still-registered webhook now fires.
    monkeypatch.setattr(licensing, "has_feature", lambda f: f == licensing.FEATURE_AUTOMATION)
    assert webhooks._load() and webhooks._load()[0]["url"] == "https://hooks.example/x"
    assert webhooks.deliver(hook, "run.completed", {"run": "APT29"})["ok"] and posted
    assert webhooks.licence_note() == ""

    # Lapsed back to Free: nothing deleted, delivery held again.
    monkeypatch.setattr(licensing, "has_feature", lambda f: False)
    assert webhooks._load()[0]["url"] == "https://hooks.example/x"
    assert webhooks.deliver(hook, "run.completed", {})["skipped"]


def test_bad_webhooks_are_refused():
    assert webhooks.validate("ftp://x", ["run.completed"])
    assert webhooks.validate("https://x.example", ["run.started"])
    assert webhooks.validate("https://x.example", ["watchlist.match"]) is None


def test_webhook_urls_follow_the_suite_rules():
    # samarkand's rules (its docs/DIFFERENCES.md): plain http only to this machine or a private
    # address, never link-local, never credentials in the URL
    assert webhooks.validate("http://192.168.1.10/hook", ["run.completed"]) is None
    assert webhooks.validate("http://hooks.example/hook", ["run.completed"])
    assert webhooks.validate("https://169.254.169.254/latest", ["run.completed"])
    assert webhooks.validate("https://user:pw@hooks.example/", ["run.completed"])


def test_a_delivery_says_when_it_was_sent_in_iso_8601(home, monkeypatch):
    from datetime import datetime

    sent = {}
    monkeypatch.setattr(webhooks, "_post", lambda url, body, headers, timeout: sent.update(body=body) or 204)
    hook = webhooks.add("https://hooks.example/at", ["run.completed"])
    result = webhooks.deliver(hook, "run.completed", {})
    assert datetime.fromisoformat(json.loads(sent["body"])["sent_at"]).tzinfo is not None
    assert isinstance(result["at"], float)  # the stored record keeps epoch seconds for the admin page


def test_a_finished_run_fires_its_webhook(tmp_path, monkeypatch):
    from shikari.build import progress

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
