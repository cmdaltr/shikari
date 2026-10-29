"""
Unit tests for archer.lab.caldera, the CALDERA operations client (#30).

The CALDERA REST API is mocked with httpx.MockTransport, so nothing here talks to a live server.
ARCHER_HOME is pointed at a tmp directory, so collect() and the manifest readers write and read
only under the test's own home.
"""

import base64
import json

import httpx
import pytest

from archer.lab import caldera
from archer.lab.runner import LabError


# --------------------------------------------------------------------------- fixtures

@pytest.fixture(autouse=True)
def tmp_home(tmp_path, monkeypatch):
    """Point every data path (manifests, correlations) at a throwaway home."""
    home = tmp_path / "home"
    (home / "data").mkdir(parents=True)
    monkeypatch.setenv("ARCHER_HOME", str(home))
    monkeypatch.setattr(caldera.paths, "DATA", home / "data")
    monkeypatch.setattr(caldera.paths, "HOME", home)
    # The detection index is cached per directory; start each test with an empty cache.
    caldera._detection_index._cache = {}
    return home


def make_client(handler, api_key="SECRET-KEY-123"):
    """A Client whose transport is the given mock handler, keeping the real KEY header."""
    return caldera.Client("https://caldera.test", api_key, transport=httpx.MockTransport(handler))


def _json(obj, status=200):
    return httpx.Response(status, json=obj)


# --------------------------------------------------------------------------- settings

def test_settings_reads_file_block(monkeypatch):
    monkeypatch.delenv("CALDERA_URL", raising=False)
    monkeypatch.delenv("CALDERA_API_KEY", raising=False)
    monkeypatch.setattr("archer.build.bespoke.get_config",
                        lambda: {"caldera": {"url": "https://lab:8888/", "api_key": "filekey", "verify_tls": False}})
    s = caldera.settings()
    assert s == {"url": "https://lab:8888", "api_key": "filekey", "verify_tls": False}
    assert caldera.configured() is True


def test_settings_env_overrides_file(monkeypatch):
    monkeypatch.setattr("archer.build.bespoke.get_config",
                        lambda: {"caldera": {"url": "https://file:8888", "api_key": "filekey"}})
    monkeypatch.setenv("CALDERA_URL", "https://env:9999")
    monkeypatch.setenv("CALDERA_API_KEY", "envkey")
    s = caldera.settings()
    assert s["url"] == "https://env:9999"
    assert s["api_key"] == "envkey"
    assert s["verify_tls"] is True  # defaults on when unset


def test_not_configured_without_key(monkeypatch):
    monkeypatch.delenv("CALDERA_URL", raising=False)
    monkeypatch.delenv("CALDERA_API_KEY", raising=False)
    monkeypatch.setattr("archer.build.bespoke.get_config", lambda: {"caldera": {"url": "https://lab:8888"}})
    assert caldera.configured() is False


# --------------------------------------------------------------------------- client

def test_client_sends_key_header():
    seen = {}

    def handler(request):
        seen["key"] = request.headers.get("KEY")
        return _json([{"paw": "p1", "group": "g", "platform": "windows"}])

    client = make_client(handler, api_key="s3cr3t")
    assert client.agents() == [{"paw": "p1", "group": "g", "platform": "windows"}]
    assert seen["key"] == "s3cr3t"


def test_client_never_leaks_key_in_errors():
    key = "TOP-SECRET-KEY"

    def boom(request):
        raise httpx.ConnectError("connection refused")

    client = make_client(boom, api_key=key)
    with pytest.raises(LabError) as e:
        client.agents()
    assert key not in str(e.value)
    assert key not in (e.value.detail or "")
    assert key not in repr(client)


def test_client_survives_malformed_proxy_env(monkeypatch):
    # A sandbox/corporate NO_PROXY with an entry httpx can't parse ("[::1]") must not stop the
    # client from being built — it falls back to ignoring the environment's proxies.
    for var in ("NO_PROXY", "no_proxy"):
        monkeypatch.setenv(var, "localhost,127.0.0.1,::1,[::1],gateway.docker.internal")
    client = caldera.Client("https://caldera.test", "k")  # no transport: goes through trust_env
    assert client.url == "https://caldera.test"
    client._http.close()


def test_client_http_error_is_laberror():
    client = make_client(lambda r: _json({"error": "nope"}, status=500))
    with pytest.raises(LabError) as e:
        client.abilities()
    assert "500" in (e.value.detail or "")


# --------------------------------------------------------------------------- _decode

def test_decode_plain_base64_and_stdout_stderr():
    assert caldera._decode("just text with spaces") == "just text with spaces"
    assert caldera._decode(base64.b64encode(b"whoami /all").decode()) == "whoami /all"
    payload = base64.b64encode(json.dumps({"stdout": "out-here", "stderr": "err-here"}).encode()).decode()
    assert caldera._decode(payload) == "out-here\nerr-here"
    assert caldera._decode({"stdout": "a", "stderr": "b"}) == "a\nb"
    assert caldera._decode(None) == ""


# --------------------------------------------------------------------------- plan

def _ability(ability_id, tid, plugin, platform="windows", executor="psh", command="run"):
    return {"ability_id": ability_id, "technique_id": tid, "name": f"ab-{ability_id}", "plugin": plugin,
            "executors": [{"platform": platform, "name": executor, "command": command}]}


def _agents():
    return [{"paw": "paw1", "group": "red", "platform": "windows", "executors": ["psh", "cmd"]},
            {"paw": "paw2", "group": "blue", "platform": "linux", "executors": ["sh"]}]


def test_plan_prefers_exact_then_non_atomic():
    abilities = [
        _ability("exact-atomic", "T1057", "atomic"),
        _ability("exact-stock", "T1057", "stockpile"),       # non-atomic exact: should win for T1057
        _ability("sub-stock", "T1059.001", "stockpile"),     # only a sub of T1059
        _ability("exact-t1059-atomic", "T1059", "atomic"),   # exact for T1059 beats the sub even if atomic
    ]
    p = caldera.plan(abilities, _agents(), ["T1057", "T1059"], "red")
    chosen = {s["technique_id"]: s["ability_id"] for s in p["steps"]}
    assert chosen["T1057"] == "exact-stock"
    assert chosen["T1059"] == "exact-t1059-atomic"
    assert p["gaps"] == []
    assert p["agents"] == ["paw1"]


def test_plan_reports_gaps_for_unrunnable():
    # Only a macOS executor, but the red group is Windows -> no runnable ability -> a gap.
    abilities = [_ability("mac-only", "T1555", "stockpile", platform="darwin", executor="sh")]
    p = caldera.plan(abilities, _agents(), ["T1555"], "red")
    assert p["steps"] == []
    assert p["gaps"] == ["T1555"]


def test_plan_lines_shape():
    abilities = [_ability("a1", "T1057", "stockpile", command="Get-Process")]
    p = caldera.plan(abilities, _agents(), ["T1057", "T9999"], "red")
    lines = caldera.plan_lines(p, "op-label")
    assert lines[0].startswith("Create adversary 'op-label'")
    assert any("Start operation" in l for l in lines)
    assert any("T1057 ab-a1 on windows/psh: Get-Process" in l for l in lines)
    assert any("No runnable ability for T9999" in l for l in lines)


# --------------------------------------------------------------------------- operate

def test_operate_execute_false_posts_nothing():
    calls = []

    def handler(request):
        calls.append(request.method)
        if request.url.path.endswith("/abilities"):
            return _json([_ability("a1", "T1057", "stockpile")])
        if request.url.path.endswith("/agents"):
            return _json(_agents())
        return _json({}, status=404)

    client = make_client(handler)
    out = caldera.operate(client, ["T1057"], "red", execute=False, say=lambda *_: None)
    assert out["executed"] is False
    assert "POST" not in calls  # the dry run reads abilities/agents only


def test_operate_execute_creates_adversary_and_operation():
    posts = []

    def handler(request):
        if request.method == "GET" and request.url.path.endswith("/abilities"):
            return _json([_ability("a1", "T1057", "stockpile")])
        if request.method == "GET" and request.url.path.endswith("/agents"):
            return _json(_agents())
        if request.method == "POST" and request.url.path.endswith("/adversaries"):
            posts.append(("adversary", json.loads(request.content)))
            return _json({"adversary_id": "adv-1"})
        if request.method == "POST" and request.url.path.endswith("/operations"):
            posts.append(("operation", json.loads(request.content)))
            return _json({"id": "op-1", "name": "archer-operation"})
        return _json({}, status=404)

    client = make_client(handler)
    out = caldera.operate(client, ["T1057"], "red", execute=True, say=lambda *_: None)
    assert out["operation_id"] == "op-1"
    kinds = [k for k, _ in posts]
    assert kinds == ["adversary", "operation"]
    adv_body = dict(posts)["adversary"]
    assert adv_body["atomic_ordering"] == ["a1"]
    op_body = dict(posts)["operation"]
    assert op_body["group"] == "red"
    assert op_body["planner"] == {"id": caldera.PLANNER}


# --------------------------------------------------------------------------- collect

def test_collect_writes_manifest(tmp_home):
    result = base64.b64encode(json.dumps({"stdout": "PID 1234", "stderr": ""}).encode()).decode()

    def handler(request):
        p = request.url.path
        if p.endswith("/operations/op-1"):
            return _json({"id": "op-1", "name": "my-op", "state": "finished", "group": "red",
                          "start": "2026-10-28T10:00:00Z"})
        if p.endswith("/operations/op-1/links"):
            return _json([{"id": "lnk1", "paw": "paw1", "host": "WS01", "status": 0,
                           "command": base64.b64encode(b"Get-Process").decode(),
                           "ability": {"technique_id": "T1057", "name": "Process Discovery"},
                           "executor": {"platform": "windows", "name": "psh"},
                           "decide": "2026-10-28T10:00:05Z", "finish": "2026-10-28T10:00:09Z"}])
        if p.endswith("/links/lnk1/result"):
            # CALDERA 5.2 shape: {"link": {...}, "result": "<base64 of {stdout,stderr}>"}
            return _json({"link": {"id": "lnk1"}, "result": result})
        return _json({}, status=404)

    client = make_client(handler)
    manifest = caldera.collect(client, "op-1", say=lambda *_: None)
    assert manifest["name"] == "my-op"
    assert manifest["state"] == "finished"
    assert manifest["captured"] is False
    step = manifest["steps"][0]
    assert step["technique_id"] == "T1057"
    assert step["command"] == "Get-Process"
    assert step["host"] == "WS01"
    assert "PID 1234" in step["output"]
    # And it is on disk under the tmp home.
    written = tmp_home / "data" / "telemetry" / "caldera" / "my-op" / "manifest.json"
    assert written.is_file()
    assert caldera.load("my-op")["operation_id"] == "op-1"


# --------------------------------------------------------------------------- check_operation

def _write_detection(generate_dir, filename, name, tid, indicators):
    import yaml

    generate_dir.mkdir(parents=True, exist_ok=True)
    doc = {"name": name, "technique_id": tid, "indicators": indicators}
    (generate_dir / filename).write_text(yaml.safe_dump(doc), encoding="utf-8")


def _manifest(steps, **extra):
    return {"name": "op", "operation_id": "op-1", "state": "finished", "group": "red",
            "captured": False, "steps": steps, **extra}


def test_check_operation_matched_missed_no_detections(tmp_path):
    gd = tmp_path / "groups"
    _write_detection(gd, "proc.yaml", "Process Discovery", "T1057", {"cmd": ["Get-Process"]})
    _write_detection(gd, "shell.yaml", "PowerShell", "T1059", {"cmd": ["this-will-not-appear"]})
    manifest = _manifest([
        {"technique_id": "T1057", "host": "WS01", "command": "Get-Process -Name lsass"},
        {"technique_id": "T1059", "host": "WS01", "command": "whoami"},
        {"technique_id": "T1555", "host": "WS01", "command": "vaultcmd /list"},  # no saved detection
    ])
    out = caldera.check_operation(manifest, str(gd))
    status = {t["technique_id"]: t["status"] for t in out["techniques"]}
    assert status == {"T1057": "matched", "T1059": "missed", "T1555": "no_detections"}
    assert out["summary"] == {"techniques": 3, "matched": 1, "missed": 1, "no_detections": 1}
    assert out["evidence"] == "commands"
    t1057 = next(t for t in out["techniques"] if t["technique_id"] == "T1057")
    assert t1057["detections"][0]["matched"] is True
    assert t1057["detections"][0]["hits"] == [{"value": "Get-Process"}]
    assert t1057["unmatched_commands"] == []
    t1059 = next(t for t in out["techniques"] if t["technique_id"] == "T1059")
    assert t1059["unmatched_commands"][0]["command"] == "whoami"


def test_check_operation_matches_parent_technique(tmp_path):
    # A detection saved for the parent T1059 should match a step that ran a sub, T1059.001.
    gd = tmp_path / "groups"
    _write_detection(gd, "shell.yaml", "Command Shell", "T1059", {"cmd": ["Invoke-Expression"]})
    manifest = _manifest([{"technique_id": "T1059.001", "host": "WS01", "command": "Invoke-Expression $x"}])
    out = caldera.check_operation(manifest, str(gd))
    assert out["techniques"][0]["status"] == "matched"


# --------------------------------------------------------------------------- check_correlations

def _correlate_file(home, group, entries):
    base = home / "data" / "correlate"
    base.mkdir(parents=True, exist_ok=True)
    (base / f"{group}.json").write_text(json.dumps({"vendor_correlations": entries,
                                                     "cross_vendor_correlations": []}), encoding="utf-8")


def test_check_correlations_fired_half_missed(tmp_home, tmp_path):
    gd = tmp_path / "groups"
    _write_detection(gd, "a.yaml", "Det A", "T1057", {"cmd": ["Get-Process"]})
    _write_detection(gd, "b.yaml", "Det B", "T1059", {"cmd": ["Invoke-Expression"]})
    _correlate_file(tmp_home, "red", [{
        "a": "a.yaml", "b": ["b.yaml"], "vendor": "mde", "group": "red",
        "combined_query": "A join B within 1h"}])

    # Fired: both parts match, same host, 4 minutes apart (inside the 1h window).
    fired = _manifest([
        {"technique_id": "T1057", "host": "WS01", "command": "Get-Process",
         "decide": "2026-10-28T10:00:00Z", "finish": "2026-10-28T10:00:02Z"},
        {"technique_id": "T1059", "host": "WS01", "command": "Invoke-Expression $p",
         "decide": "2026-10-28T10:04:00Z", "finish": "2026-10-28T10:04:02Z"}])
    out = caldera.check_correlations(fired, str(gd))
    assert out["summary"]["testable"] == 1
    row = out["correlations"][0]
    assert row["status"] == "fired"
    assert row["host"] == "WS01"
    assert row["missing"] == []
    assert row["span_seconds"] <= row["window_seconds"]

    # Half-fired: part B's indicator never appears, so only A matched.
    half = _manifest([
        {"technique_id": "T1057", "host": "WS01", "command": "Get-Process",
         "decide": "2026-10-28T10:00:00Z", "finish": "2026-10-28T10:00:02Z"},
        {"technique_id": "T1059", "host": "WS01", "command": "some-other-shell",
         "decide": "2026-10-28T10:04:00Z", "finish": "2026-10-28T10:04:02Z"}])
    out = caldera.check_correlations(half, str(gd))
    assert out["correlations"][0]["status"] == "half_fired"
    assert out["correlations"][0]["missing"] == ["T1059"]

    # Different hosts: both matched, but never together on one host -> half-fired.
    split = _manifest([
        {"technique_id": "T1057", "host": "WS01", "command": "Get-Process",
         "decide": "2026-10-28T10:00:00Z", "finish": "2026-10-28T10:00:02Z"},
        {"technique_id": "T1059", "host": "WS02", "command": "Invoke-Expression $p",
         "decide": "2026-10-28T10:04:00Z", "finish": "2026-10-28T10:04:02Z"}])
    out = caldera.check_correlations(split, str(gd))
    assert out["correlations"][0]["status"] == "half_fired"

    # Outside the window: both matched on one host but 2 hours apart -> not fired.
    stale = _manifest([
        {"technique_id": "T1057", "host": "WS01", "command": "Get-Process",
         "decide": "2026-10-28T10:00:00Z", "finish": "2026-10-28T10:00:02Z"},
        {"technique_id": "T1059", "host": "WS01", "command": "Invoke-Expression $p",
         "decide": "2026-10-28T12:30:00Z", "finish": "2026-10-28T12:30:02Z"}])
    out = caldera.check_correlations(stale, str(gd))
    assert out["correlations"][0]["status"] != "fired"


def test_check_correlations_untestable_when_a_technique_did_not_run(tmp_home, tmp_path):
    gd = tmp_path / "groups"
    _write_detection(gd, "a.yaml", "Det A", "T1057", {"cmd": ["Get-Process"]})
    _write_detection(gd, "b.yaml", "Det B", "T1059", {"cmd": ["Invoke-Expression"]})
    _correlate_file(tmp_home, "red", [{
        "a": "a.yaml", "b": ["b.yaml"], "vendor": "mde", "group": "red",
        "combined_query": "A join B within 1h"}])
    # Only T1057 ran, so the correlation joining T1057+T1059 isn't testable at all.
    manifest = _manifest([{"technique_id": "T1057", "host": "WS01", "command": "Get-Process",
                           "decide": "2026-10-28T10:00:00Z", "finish": "2026-10-28T10:00:02Z"}])
    out = caldera.check_correlations(manifest, str(gd))
    assert out["summary"]["testable"] == 0
    assert out["correlations"] == []


# --------------------------------------------------------------------------- windows

def test_windows_widen_each_step():
    manifest = _manifest([
        {"technique_id": "T1057", "ability": "Process Discovery",
         "decide": "2026-10-28T10:00:00Z", "finish": "2026-10-28T10:00:30Z"},
        {"technique_id": "T1059", "ability": "no-times"}])  # dropped: no decide/finish
    wins = caldera.windows(manifest)
    assert len(wins) == 1
    w = wins[0]
    assert w["technique"] == "T1057"
    assert w["folder"] == "T1057-1"
    assert w["start"] == "2026-10-28T09:59:55Z"   # decide - 5s
    assert w["end"] == "2026-10-28T10:00:50Z"     # finish + 20s
