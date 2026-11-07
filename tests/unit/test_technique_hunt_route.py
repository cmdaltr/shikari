"""The Hunt page's technique field posts to /hunt/technique: the route takes the form and starts a run."""

from types import SimpleNamespace

from fastapi.testclient import TestClient

import shikari.app as web


def test_the_form_starts_a_technique_hunt(monkeypatch):
    started, progress = [], []
    monkeypatch.setattr(web, "require_auth", lambda request, session: (
        SimpleNamespace(id=1, tech_stack=None), SimpleNamespace(close=lambda: None)))
    monkeypatch.setattr(web, "start_progress", lambda name, data: progress.append((name, data)))
    monkeypatch.setattr(web, "threading", SimpleNamespace(Thread=lambda target, daemon=None, **kw: SimpleNamespace(
        start=lambda: started.append(target))))  # shikari.app's only: nothing runs, nothing lands in data/
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


def test_technique_hunt_indicators_split_by_platform():
    # Every group's examples mix platforms, and a source judges all of a detection's commands at
    # once, so each command goes with the platform whose source accepts it; a shell's bare name is no
    # indicator. A built-in tool also gets its usual bare name.
    guidance = {"cmd": ["systeminfo.exe", "cat /proc/cpuinfo", "cmd.exe"], "api": ["GetSystemInfo"]}
    split = dict((tuple(p), g) for p, g in web._by_platform(guidance, ["Linux", "macOS", "Windows"], {}))
    windows, unix = split[("Windows",)], split[("Linux", "macOS")]
    assert windows["cmd"] == ["systeminfo.exe", "systeminfo"] and windows["api"] == ["GetSystemInfo"]
    assert list(windows)[0] == "cmd"  # the first kind decides each source's query
    assert unix == {"cmd": ["cat /proc/cpuinfo"]}
    # a Windows-only technique gets no Linux entry, and guidance without commands is left as it was
    assert [p for p, _ in web._by_platform(guidance, ["Windows"], {})] == [["Windows"]]
    assert web._by_platform({"api": ["X"]}, ["Windows"], {}) == [(["Windows"], {"api": ["X"]})]


def test_procedure_examples_are_current_uses_of_the_technique():
    rel = lambda **kw: {"type": "relationship", "relationship_type": "uses", "target_ref": "ap--1", **kw}
    bundle = {"objects": [rel(description="a"), rel(description="b", revoked=True),
                          rel(description="c", x_mitre_deprecated=True), rel(description="d", target_ref="ap--2"),
                          {"type": "attack-pattern", "id": "ap--1", "description": "e"}]}
    assert web._procedure_examples(bundle, "ap--1") == "a"
