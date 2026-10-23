"""The Hunt page's technique field posts to /hunt/technique: the route takes the form and starts a run."""

from types import SimpleNamespace

from fastapi.testclient import TestClient

import archer.app as web


def test_the_form_starts_a_technique_hunt(monkeypatch):
    started, progress = [], []
    monkeypatch.setattr(web, "require_auth", lambda request, session: (
        SimpleNamespace(id=1, tech_stack=None), SimpleNamespace(close=lambda: None)))
    monkeypatch.setattr(web, "start_progress", lambda name, data: progress.append((name, data)))
    monkeypatch.setattr(web, "threading", SimpleNamespace(Thread=lambda target, daemon=None, **kw: SimpleNamespace(
        start=lambda: started.append(target))))  # archer.app's only: nothing runs, nothing lands in data/
    client = TestClient(web.app)  # no startup

    r = client.post("/hunt/technique", data={"technique_ids": "t1003, T1021.001", "osint_enhancement": "true",
                                             "lol_datasets": "true"}, headers={"X-Requested-With": "XMLHttpRequest"})

    assert r.status_code == 200 and r.json()["redirect_url"].startswith("/progress?group_name=")
    assert started and progress


def test_a_malformed_technique_is_refused(monkeypatch):
    monkeypatch.setattr(web, "require_auth", lambda request, session: (
        SimpleNamespace(id=1, tech_stack=None), SimpleNamespace(close=lambda: None)))
    r = TestClient(web.app).post("/hunt/technique", data={"technique_ids": "T10, T1003"})
    assert r.status_code == 400
