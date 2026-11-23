"""Hunt runs (shikari/hunt_runs.py, docs/suite/INTEGRATION.md): a stable id per POST /api/runs, the run's
detections kept past the group's next hunt, its queries counted against the SIEMs and never their results,
and its webhooks."""
import json
import logging
from datetime import datetime, timedelta

import pytest
from fastapi.testclient import TestClient
from samarkand import siem
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

import shikari.app as app_module
from shikari import hunt_runs, webhooks
from shikari.auth.session import create_session
from shikari.database.audit import Base as AuditBase
from shikari.database.models import Base, HuntRun, User, UserRole
from shikari.query import counts

# What a SIEM's rows hold here: none of it may be kept anywhere
ROW_MARKER = "row-secret-4c1d-victim-laptop-07"


@pytest.fixture
def db_factory(tmp_path, monkeypatch):
    engine = create_engine(f"sqlite:///{tmp_path / 'runs.db'}", connect_args={"check_same_thread": False})
    Base.metadata.create_all(engine)
    AuditBase.metadata.create_all(engine)
    factory = sessionmaker(bind=engine)
    monkeypatch.setattr("shikari.database.db.SessionLocal", factory)
    monkeypatch.setattr(webhooks.paths, "DATA", tmp_path)

    def _get_db():
        db = factory()
        try:
            yield db
        finally:
            db.close()
    monkeypatch.setattr(app_module, "get_db", _get_db)
    factory.path = tmp_path / "runs.db"
    return factory


def _user(factory, email, role=UserRole.STANDARD):
    db = factory()
    u = User(email=email, full_name=email.split("@")[0], password_hash="x", role=role, is_active=True)
    db.add(u)
    db.commit()
    db.refresh(u)
    db.expunge(u)
    db.close()
    return u


@pytest.fixture
def analyst(db_factory):
    return _user(db_factory, "analyst@example.org")


@pytest.fixture
def spawned(monkeypatch):
    """Runs the POST made, instead of starting their threads."""
    started = []
    monkeypatch.setattr(hunt_runs, "_spawn", lambda run_id, client: started.append(run_id))
    return started


@pytest.fixture
def sent(monkeypatch):
    """Every webhook event emitted, in order."""
    out = []
    monkeypatch.setattr(webhooks, "emit", lambda event, data: out.append((event, data)) or 1)
    return out


def _http(factory, user):
    http = TestClient(app_module.app, follow_redirects=False)
    db = factory()
    http.cookies.set("shikari_session", create_session(user.id, db=db))
    db.close()
    return http


def _detection(file, technique, *queries):
    return {"file": file, "name": f"{technique} detection", "techniques": [technique], "tactics": ["Execution"],
            "severity": "high", "platforms": [p for p, _ in queries],
            "queries": [{"platform": p, "data_source": "x", "query": q} for p, q in queries]}


class FakeClient:
    """shikari.client.ShikariClient as a hunt run uses it."""

    def __init__(self, detections=None, final=None, fail_start=None, during_wait=None):
        self.detections = detections if detections is not None else [
            _detection("APT29_T1059.001_Splunk.yaml", "T1059.001", ("Splunk", "index=win earliest=-1d powershell")),
            _detection("APT29_T1059.001_MDE.yaml", "T1059.001",
                       ("MicrosoftThreatProtection", "DeviceProcessEvents | where Timestamp > ago(1d)")),
            _detection("APT29_T1003.001_SecOps.yaml", "T1003.001", ("GoogleSecOps", "metadata.event_type = ...")),
        ]
        self.final = final or {"status": "complete", "phase": "complete", "created_yaml": 3}
        self.fail_start, self.during_wait, self.calls = fail_start, during_wait, []

    def hunt_group(self, group, correlate, osint):
        self.calls.append(("group", group))
        if self.fail_start:
            raise RuntimeError(self.fail_start)
        return group

    def hunt_cve(self, cves, correlate):
        self.calls.append(("cve", cves))
        ids = cves.split(",")
        return ids[0] if len(ids) == 1 else f"{ids[0]}_plus_{len(ids) - 1}"

    def hunt_techniques(self, ids):
        self.calls.append(("techniques", ids))
        return f"Hunt_{ids[0]}" if len(ids) == 1 else f"Hunt_{ids[0]}_plus_{len(ids) - 1}"

    def wait(self, run, timeout):
        if self.during_wait:
            self.during_wait(run)
        return self.final

    def results(self, run, latest=True):
        assert latest
        return {"ok": True, "group_name": run, "detections": self.detections, "correlations": []}


def _start(http, **body):
    return http.post("/api/runs", json={"kind": "group", "target": "APT29", **body})


@pytest.mark.unit
class TestStarting:
    @pytest.mark.parametrize("kind,target,group_name,call", [
        ("group", "APT29", "APT29", ("group", "APT29")),
        ("cve", "cve-2024-3400", "CVE-2024-3400", ("cve", "CVE-2024-3400")),
        ("cve", "CVE-2024-3400, CVE-2021-44228", "CVE-2024-3400_plus_1", ("cve", "CVE-2024-3400,CVE-2021-44228")),
        ("techniques", "T1059.001,t1003.001", "Hunt_T1059.001_plus_1", ("techniques", ["T1059.001", "T1003.001"])),
    ])
    def test_each_kind_starts_its_generation(self, db_factory, analyst, spawned, sent, kind, target, group_name, call):
        http = _http(db_factory, analyst)
        r = http.post("/api/runs", json={"kind": kind, "target": target, "external_ref": "HNT-26-003"})
        assert r.status_code == 202, r.text
        body = r.json()
        assert body == {"id": body["id"], "status": "queued", "group_name": group_name,
                        "status_url": f"/api/runs/{body['id']}"}
        assert spawned == [body["id"]]

        client = FakeClient()
        hunt_runs.work(body["id"], client)
        assert client.calls == [call]
        run = http.get(f"/api/runs/{body['id']}").json()
        assert run["status"] == "generated" and run["group_name"] == group_name and run["kind"] == kind
        assert run["external_ref"] == "HNT-26-003" and run["execute"] is False and run["window_days"] == 7
        assert run["completed_at"] and run["executed_at"] is None and run["error"] is None
        assert [d["file"] for d in run["detections"]] == [d["file"] for d in client.detections]
        assert set(run["detections"][0]) == {"file", "name", "techniques", "platforms", "queries"}
        assert run["detections"][0]["queries"] == [{"platform": "Splunk", "query": "index=win earliest=-1d powershell"}]
        assert run["counts"] == [] and run["totals"] == {"queries": 3, "run": 0, "hits": 0, "errors": 0, "skipped": 0}

    @pytest.mark.parametrize("body,problem", [
        ({"kind": "actor"}, "kind"),
        ({"target": ""}, "target"),
        ({"kind": "cve", "target": "CVE-1999-0001"}, "CVE"),
        ({"kind": "techniques", "target": "T1059.1"}, "technique"),
        ({"kind": "techniques", "target": "T1059,"}, None),
        ({"external_ref": "OST-26-14"}, "external_ref"),
        ({"external_ref": "ost-26-014"}, "external_ref"),
        ({"external_ref": "OST-26-014x"}, "external_ref"),
        ({"external_ref": "HNT-26-003\n"}, "external_ref"),
        ({"external_ref": "INC-26-003"}, "external_ref"),
        ({"external_ref": "OST-206-014"}, "external_ref"),
        ({"external_ref": 26}, "external_ref"),
        ({"execute": "yes"}, "execute"),
        ({"window_days": 0}, "window_days"),
        ({"window_days": 91}, "window_days"),
        ({"window_days": 7.5}, "window_days"),
        ({"window_days": True}, "window_days"),
    ])
    def test_a_bad_request_is_422(self, db_factory, analyst, spawned, body, problem):
        r = _start(_http(db_factory, analyst), **body)
        if problem is None:
            assert r.status_code == 202
            return
        assert r.status_code == 422 and problem.lower() in r.json()["error"].lower()

    @pytest.mark.parametrize("ref", ["OST-26-014", "HNT-26-003", "OST-2026-014", "HNT-26-12345", None, ""])
    def test_references_ostraka_gives(self, db_factory, analyst, spawned, ref):
        r = _start(_http(db_factory, analyst), external_ref=ref, execute=True, window_days=90)
        assert r.status_code == 202
        run = _http(db_factory, analyst).get(f"/api/runs/{r.json()['id']}").json()
        assert run["external_ref"] == (ref or None) and run["execute"] and run["window_days"] == 90

    def test_signed_in_only(self, db_factory):
        http = TestClient(app_module.app)
        assert http.post("/api/runs", json={"kind": "group", "target": "APT29"}).status_code == 401
        assert http.get("/api/runs").status_code == 401

    def test_an_unknown_group_fails_the_run_and_says_why(self, db_factory, analyst, spawned, sent):
        http = _http(db_factory, analyst)
        run_id = _start(http, external_ref="OST-26-014").json()["id"]
        hunt_runs.work(run_id, FakeClient(fail_start="Not a known ATT&CK group"))
        run = http.get(f"/api/runs/{run_id}").json()
        assert run["status"] == "failed" and "Not a known ATT&CK group" in run["error"]
        assert sent == [("run.failed", {"run": "APT29", "status": "failed", "error": run["error"],
                                        "run_id": run_id, "external_ref": "OST-26-014"})]

    def test_a_generation_that_errors_fails_the_run(self, db_factory, analyst, spawned, sent):
        http = _http(db_factory, analyst)
        run_id = _start(http).json()["id"]
        hunt_runs.work(run_id, FakeClient(final={"status": "error", "error": "ATT&CK bundle missing"}))
        run = http.get(f"/api/runs/{run_id}").json()
        assert run["status"] == "failed" and run["error"] == "ATT&CK bundle missing"
        assert [e for e, _ in sent] == ["run.failed"] and sent[0][1]["run_id"] == run_id

    def test_a_restart_fails_the_runs_it_cut_short(self, db_factory, analyst, spawned):
        http = _http(db_factory, analyst)
        ids = [_start(http).json()["id"] for _ in range(2)]
        hunt_runs.work(ids[1], FakeClient())
        assert hunt_runs.interrupted() == 1
        assert http.get(f"/api/runs/{ids[0]}").json()["status"] == "failed"
        assert http.get(f"/api/runs/{ids[1]}").json()["status"] == "generated"


@pytest.mark.unit
class TestKeeping:
    def test_a_later_hunt_of_the_same_group_doesnt_touch_a_runs_record(self, db_factory, analyst, spawned):
        http = _http(db_factory, analyst)
        first = _start(http, external_ref="HNT-26-003").json()["id"]
        hunt_runs.work(first, FakeClient())
        second = _start(http).json()["id"]
        hunt_runs.work(second, FakeClient(detections=[
            _detection("APT29_T1566.001_Splunk.yaml", "T1566.001", ("Splunk", "index=mail attachment"))]))
        assert first != second
        a, b = http.get(f"/api/runs/{first}").json(), http.get(f"/api/runs/{second}").json()
        assert len(a["detections"]) == 3 and a["detections"][0]["file"] == "APT29_T1059.001_Splunk.yaml"
        assert [d["file"] for d in b["detections"]] == ["APT29_T1566.001_Splunk.yaml"]
        assert a["group_name"] == b["group_name"] == "APT29"

    def test_listing_by_reference_and_by_owner(self, db_factory, analyst, spawned):
        other = _user(db_factory, "other@example.org")
        admin = _user(db_factory, "boss@example.org", role=UserRole.ADMIN)
        mine = _http(db_factory, analyst)
        theirs = _http(db_factory, other)
        a = _start(mine, external_ref="HNT-26-003").json()["id"]
        b = _start(mine, external_ref="OST-26-014").json()["id"]
        c = _start(theirs, external_ref="HNT-26-003").json()["id"]

        assert {r["id"] for r in mine.get("/api/runs").json()["runs"]} == {a, b}
        assert [r["id"] for r in mine.get("/api/runs", params={"external_ref": "HNT-26-003"}).json()["runs"]] == [a]
        listed = _http(db_factory, admin).get("/api/runs", params={"external_ref": "HNT-26-003"}).json()["runs"]
        assert {r["id"] for r in listed} == {a, c}
        assert "detections" not in listed[0] and "counts" not in listed[0] and "totals" in listed[0]
        assert theirs.get(f"/api/runs/{a}").status_code == 404  # not theirs
        assert _http(db_factory, admin).get(f"/api/runs/{a}").status_code == 200
        assert mine.get("/api/runs/not-an-id").status_code == 404

    def test_an_ostraka_token_starts_and_reads_runs_as_its_admin(self, db_factory, spawned):
        from shikari.auth import tokens

        admin = _user(db_factory, "boss@example.org", role=UserRole.ADMIN)
        db = db_factory()
        token, _ = tokens.create_token(db, admin.id, "Ostraka (paired)", scope=tokens.OSTRAKA)
        db.close()
        http = TestClient(app_module.app)
        auth = {"Authorization": f"Bearer {token}"}
        r = http.post("/api/runs", json={"kind": "techniques", "target": "T1059.001", "external_ref": "HNT-26-003",
                                         "execute": True}, headers=auth)
        assert r.status_code == 202
        db = db_factory()
        assert db.get(HuntRun, r.json()["id"]).user_id == admin.id
        db.close()
        assert http.get(r.json()["status_url"], headers=auth).json()["external_ref"] == "HNT-26-003"
        assert http.get("/api/runs?external_ref=HNT-26-003", headers=auth).json()["runs"][0]["id"] == r.json()["id"]


@pytest.mark.unit
class TestExecuting:
    def _counters(self, calls):
        def splunk(query, days, timeout):
            calls.append(("splunk", query, days, timeout))
            return 12

        def mde(query, days, timeout):
            calls.append(("mde", query, days, timeout))
            raise siem.SiemProblem("Advanced Hunting answered HTTP 400.")

        return {"splunk": splunk, "mde": mde}

    def test_counts_errors_and_skipped_platforms(self, db_factory, analyst, spawned, sent):
        http = _http(db_factory, analyst)
        run_id = _start(http, external_ref="HNT-26-003", execute=True, window_days=14).json()["id"]
        calls = []
        hunt_runs.work(run_id, FakeClient(), counters=lambda: self._counters(calls))
        run = http.get(f"/api/runs/{run_id}").json()
        assert run["status"] == "executed" and run["executed_at"]
        assert sorted(c[0] for c in calls) == ["mde", "splunk"] and all(c[2] == 14 for c in calls)
        assert run["counts"] == [
            {"file": "APT29_T1059.001_Splunk.yaml", "technique": "T1059.001", "platform": "Splunk",
             "query_index": 0, "hits": 12, "error": "", "skipped": False},
            {"file": "APT29_T1059.001_MDE.yaml", "technique": "T1059.001", "platform": "MicrosoftThreatProtection",
             "query_index": 0, "hits": None, "error": "Advanced Hunting answered HTTP 400.", "skipped": False},
            {"file": "APT29_T1003.001_SecOps.yaml", "technique": "T1003.001", "platform": "GoogleSecOps",
             "query_index": 0, "hits": None, "error": "No GoogleSecOps connection here", "skipped": True},
        ]
        assert run["totals"] == {"queries": 3, "run": 1, "hits": 12, "errors": 1, "skipped": 1}
        assert [e for e, _ in sent] == ["run.completed", "run.executed"]
        assert sent[1][1] == {"run_id": run_id, "external_ref": "HNT-26-003", "group_name": "APT29",
                              "totals": run["totals"]}

    def test_without_any_connection_every_query_is_skipped(self, db_factory, analyst, spawned, sent):
        http = _http(db_factory, analyst)
        run_id = _start(http, execute=True).json()["id"]
        hunt_runs.work(run_id, FakeClient(), counters=lambda: {})
        run = http.get(f"/api/runs/{run_id}").json()
        assert run["status"] == "executed" and all(c["skipped"] for c in run["counts"])
        assert run["totals"] == {"queries": 3, "run": 0, "hits": 0, "errors": 0, "skipped": 3}

    def test_a_slow_query_times_out_without_holding_the_run(self):
        import threading

        release = threading.Event()

        def stuck(query, days, timeout):
            release.wait(5)
            return 1

        detections = [_detection("a.yaml", "T1059", ("Splunk", "index=x"))]
        started = datetime.utcnow()
        out = hunt_runs.execute(detections, 7, {"splunk": stuck}, timeout=0.05, workers=1)
        release.set()
        assert out[0]["hits"] is None and "No answer" in out[0]["error"]
        assert datetime.utcnow() - started < timedelta(seconds=2)

    def test_at_most_the_bound_runs_at_once(self):
        import threading
        import time

        live, peak, lock = [0], [0], threading.Lock()

        def counter(query, days, timeout):
            with lock:
                live[0] += 1
                peak[0] = max(peak[0], live[0])
            time.sleep(0.02)
            with lock:
                live[0] -= 1
            return 0

        detections = [_detection(f"{i}.yaml", "T1059", ("Splunk", f"index={i}")) for i in range(12)]
        hunt_runs.execute(detections, 7, {"splunk": counter}, workers=3)
        assert 1 <= peak[0] <= 3

    def test_result_rows_are_never_stored_logged_or_returned(self, db_factory, analyst, spawned, sent, caplog,
                                                             capsys, monkeypatch):
        """The SIEM clients answer with rows that carry a marker. Only counts come out: the marker is in
        no table, no file Shikari wrote, no log line, no response and no webhook."""
        caplog.set_level(logging.DEBUG)
        asked = []

        class FakeSiem:
            base = "https://siem.example:8089/services"

            def __init__(self, platform):
                self.platform = platform

            def query(self, text, *, start=None, end=None, max_rows=1000, timeout=300.0):
                asked.append((self.platform, text, start, max_rows))
                if "boom" in text:
                    raise siem.SiemProblem("The search failed.")
                column = "Count" if self.platform == "mde" else counts.COUNT_COLUMN
                # A real SIEM answering a counted query sends one count row; this one also leaks a row
                return siem.Result([{column: 7, "DeviceName": ROW_MARKER},
                                    {"DeviceName": ROW_MARKER, "CommandLine": ROW_MARKER}], True,
                                   {"sid": ROW_MARKER})

        monkeypatch.setenv("SPLUNK_HOST", "splunk.example")
        monkeypatch.setenv("SPLUNK_TOKEN", "t")
        monkeypatch.setenv("SHIKARI_MDE_TENANT_ID", "a")
        monkeypatch.setenv("SHIKARI_MDE_CLIENT_ID", "b")
        monkeypatch.setenv("SHIKARI_MDE_CLIENT_SECRET", "c")
        monkeypatch.delenv("ELASTIC_URL", raising=False)
        monkeypatch.delenv("ELASTIC_HOST", raising=False)
        import shikari.query.mde as mde_module
        import shikari.query.splunk as splunk_module

        monkeypatch.setattr(splunk_module.siem, "Splunk", lambda *a, **k: FakeSiem("splunk"))
        monkeypatch.setattr(mde_module, "defender", lambda: FakeSiem("mde"))

        detections = FakeClient().detections + [_detection("x.yaml", "T1105", ("Splunk", "index=boom"))]
        http = _http(db_factory, analyst)
        run_id = _start(http, external_ref="OST-26-014", execute=True, window_days=3).json()["id"]
        hunt_runs.work(run_id, FakeClient(detections=detections))  # the real counters, over the fakes
        response = http.get(f"/api/runs/{run_id}")
        listing = http.get("/api/runs")
        run = response.json()

        assert run["status"] == "executed"
        assert [c["hits"] for c in run["counts"]] == [7, 7, None, None]
        assert run["counts"][3]["error"] == "The search failed." and run["counts"][2]["skipped"]
        # Each query was asked for its count over the run's window, not for its rows
        splunk_q = next(a for a in asked if a[0] == "splunk")
        assert splunk_q[1].endswith(f"| stats count AS {counts.COUNT_COLUMN}") and "earliest=-3d" in splunk_q[1]
        assert splunk_q[2] == "-3d" and splunk_q[3] == 1
        mde_q = next(a for a in asked if a[0] == "mde")
        assert mde_q[1].endswith("| count") and "ago(3d)" in mde_q[1] and "ago(1d)" not in mde_q[1]

        assert ROW_MARKER not in response.text and ROW_MARKER not in listing.text
        assert ROW_MARKER not in json.dumps(sent)
        assert ROW_MARKER not in caplog.text
        out = capsys.readouterr()
        assert ROW_MARKER not in out.out and ROW_MARKER not in out.err
        db = db_factory()
        stored = db.get(HuntRun, run_id)
        assert all(ROW_MARKER not in (getattr(stored, c.name) or "") for c in HuntRun.__table__.columns
                   if isinstance(getattr(stored, c.name), str))
        db.close()
        for path in db_factory.path.parent.rglob("*"):
            if path.is_file():
                assert ROW_MARKER.encode() not in path.read_bytes(), path


@pytest.mark.unit
class TestWebhooks:
    def test_a_runs_webhooks_carry_its_id_and_reference(self, db_factory, analyst, spawned, sent):
        http = _http(db_factory, analyst)
        run_id = _start(http, external_ref="HNT-26-003").json()["id"]
        # The progress record finishing while the run generates: the run sends its own, after its snapshot
        client = FakeClient(during_wait=lambda name: webhooks.emit_run(name, {"phase": "complete",
                                                                              "created_yaml": 3}))
        hunt_runs.work(run_id, client)
        assert [e for e, _ in sent] == ["run.completed"]
        event, data = sent[0]
        assert data["run_id"] == run_id and data["external_ref"] == "HNT-26-003" and data["run"] == "APT29"
        assert data["created_yaml"] == 3 and data["results_url"].endswith("/results/APT29")
        assert not hunt_runs.generating("APT29")

    def test_other_hunts_say_null(self, sent):
        webhooks.emit_run("FIN7", {"phase": "complete", "created_yaml": 2})
        webhooks.emit_run("FIN7", {"status": "error", "error": "boom"})
        assert [(e, d["run_id"], d["external_ref"]) for e, d in sent] == [
            ("run.completed", None, None), ("run.failed", None, None)]

    def test_run_executed_is_an_event_admins_can_subscribe_to(self):
        assert "run.executed" in webhooks.EVENTS
        assert webhooks.validate("https://ostraka.example.org/hook", ["run.executed"]) is None


@pytest.mark.unit
class TestWindowAndCount:
    def test_platform_labels(self):
        assert counts.platform_key("Splunk") == "splunk"
        assert counts.platform_key("MicrosoftThreatProtection") == "mde"
        assert counts.platform_key("Defender XDR") == "mde"
        assert counts.platform_key("Elastic") == "elastic"
        assert counts.platform_key("GoogleSecOps") is None and counts.platform_key("") is None

    def test_each_querys_own_window_becomes_the_runs(self):
        assert counts.windowed("splunk", "index=x earliest=-1d | stats count by host", 7) == \
            "index=x earliest=-7d | stats count by host"
        assert counts.windowed("elastic", "FROM logs-*\n| WHERE @timestamp >= NOW() - 1 day", 30) == \
            "FROM logs-*\n| WHERE @timestamp >= NOW() - 30 days"
        assert counts.windowed("mde", "DeviceEvents | where Timestamp > ago(1d)", 2) == \
            "DeviceEvents | where Timestamp > ago(2d)"
        assert counts.windowed("mde", "DeviceEvents | where X == 1", 2) == \
            "DeviceEvents\n| where Timestamp > ago(2d)\n| where X == 1"
        with pytest.raises(counts.WindowProblem):
            counts.windowed("mde", "let x = 1; DeviceEvents | where X == x", 2)

    def test_a_counted_query_asks_for_a_count(self):
        assert counts.counted("splunk", "index=x") == f"index=x\n| stats count AS {counts.COUNT_COLUMN}"
        assert counts.counted("elastic", "FROM x") == f"FROM x\n| STATS {counts.COUNT_COLUMN} = COUNT(*)"
        assert counts.counted("mde", "DeviceEvents") == "DeviceEvents\n| count"
        assert counts.read_count("mde", [{"Count": 4}]) == 4 and counts.read_count("splunk", []) == 0
        assert counts.read_count("splunk", [{counts.COUNT_COLUMN: "12"}]) == 12
        with pytest.raises(ValueError):
            counts.read_count("elastic", [{"other": 1}])
