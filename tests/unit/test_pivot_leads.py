"""X-SIEM pivot leads (#46): each stage's results joined on the playbook's keys into ranked entities,
and what didn't join said with the reason (shikari/correlation/leads.py, POST /api/pivots/leads)."""
import json

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import shikari.app as app_module
from shikari.auth.password import hash_password
from shikari.auth.session import create_session
from shikari.correlation.leads import consolidate, normalise, parse_time, read_export
from shikari.database.audit import Base as AuditBase
from shikari.database.models import Base, User, UserRole

PLAYBOOK = {
    "correlation_id": "xv_test", "time_window": "1h",
    "join_keys": [{"entity": "host"}, {"entity": "user"}],
    "stages": [
        {"technique_id": "T1566.001", "technique_name": "Spearphishing Attachment",
         "vendors": {"googlesecops": {"label": "Google SecOps", "query": "q1"}}},
        {"technique_id": "T1059.001", "technique_name": "PowerShell",
         "vendors": {"mde": {"label": "Defender XDR", "query": "q2"}}},
        {"technique_id": "T1003.001", "technique_name": "LSASS Memory",
         "vendors": {"splunk": {"label": "Splunk", "query": "q3"}, "elastic": {"label": "Elastic", "query": "q4"}}},
    ],
}


def _results():
    """WS01 completes the chain in order across three SIEMs, under each one's own names; WS02 only
    the first stage; WS03's last stage is three hours late."""
    return {
        0: {"googlesecops": [
            {"metadata": {"event_timestamp": "2026-11-09T10:00:00Z"}, "principal": {"hostname": "WS01.corp.local"}},
            {"metadata": {"event_timestamp": "2026-11-09T10:05:00Z"}, "principal": {"hostname": "ws02"}},
            {"metadata": {"event_timestamp": "2026-11-09T10:00:00Z"}, "principal": {"hostname": "ws03"}},
        ]},
        1: {"mde": [
            {"Timestamp": "2026-11-09T10:10:00.1234567Z", "DeviceName": "ws01.corp.local", "AccountName": "jdoe"},
            {"Timestamp": "2026-11-09T10:20:00Z", "DeviceName": "WS03", "AccountName": "asmith"},
        ]},
        2: {"splunk": [{"_time": "2026-11-09 10:30:00.000 GMT", "host": "ws01", "user": "CORP\\jdoe"}],
            "elastic": [{"@timestamp": "2026-11-09T13:30:00Z", "host.name": "ws03"},
                        {"@timestamp": "2026-11-09T10:40:00Z", "process": {"name": "x"}}]},
    }


def _lead(out, value):
    return next(l for l in out["leads"] if l["value"] == value)


@pytest.mark.unit
class TestJoining:
    def test_the_entity_that_completes_the_chain_ranks_first(self):
        out = consolidate(PLAYBOOK, _results())
        top = out["leads"][0]
        assert (top["entity"], top["value"], top["stages_hit"], top["in_order"]) == ("host", "ws01", 3, True)
        assert [h["vendor"] for h in top["hits"]] == ["googlesecops", "mde", "splunk"]
        assert top["span_seconds"] == 1800 and out["summary"]["complete"] == 1

    def test_a_first_stage_only_entity_stays_a_low_lead(self):
        out = consolidate(PLAYBOOK, _results())
        ws02 = _lead(out, "ws02")
        assert ws02["stages_hit"] == 1 and ws02["missing"] == [1, 2] and ws02["rank"] > 1

    def test_a_stage_beyond_the_window_is_reported_not_joined(self):
        out = consolidate(PLAYBOOK, _results())
        assert _lead(out, "ws03")["stages_hit"] == 2
        late = [u for u in out["unjoined"] if u["reason"] == "outside_window"]
        assert late and late[0]["stage"] == 2 and late[0]["vendor"] == "elastic"
        # With enough skew allowed it joins
        assert _lead(consolidate(PLAYBOOK, _results(), tolerance=4 * 3600), "ws03")["stages_hit"] == 3

    def test_events_without_a_key_are_reported(self):
        out = consolidate(PLAYBOOK, _results())
        no_keys = [u for u in out["unjoined"] if u["reason"] == "no_keys"]
        assert no_keys[0]["vendor"] == "elastic" and "host.name" in no_keys[0]["detail"]

    def test_a_stage_with_no_results_is_reported(self):
        results = _results()
        del results[1]
        out = consolidate(PLAYBOOK, results)
        assert any(u["reason"] == "no_results" and u["stage"] == 1 for u in out["unjoined"])
        assert out["summary"]["complete"] == 0

    def test_a_user_lead_that_repeats_the_host_lead_is_dropped(self):
        playbook = {**PLAYBOOK, "stages": PLAYBOOK["stages"][1:]}
        results = {0: {"mde": [{"Timestamp": "2026-11-09T10:10:00Z", "DeviceName": "ws09", "AccountName": "bob"}]},
                   1: {"splunk": [{"_time": "1794219000", "host": "ws09", "user": "bob"}]}}
        values = [(l["entity"], l["value"]) for l in consolidate(playbook, results)["leads"]]
        assert ("host", "ws09") in values and ("user", "bob") not in values

    def test_out_of_order_stages_rank_below_in_order_ones(self):
        playbook = {**PLAYBOOK, "stages": PLAYBOOK["stages"][1:]}
        results = {0: {"mde": [{"Timestamp": "2026-11-09T10:00:00Z", "DeviceName": "a"},
                               {"Timestamp": "2026-11-09T10:20:00Z", "DeviceName": "b"}]},
                   1: {"splunk": [{"_time": "2026-11-09T10:10:00Z", "host": "a"},
                                  {"_time": "2026-11-09T10:10:00Z", "host": "b"}]}}
        leads = consolidate(playbook, results)["leads"]
        assert [l["value"] for l in leads] == ["a", "b"] and not leads[1]["in_order"]

    def test_thousands_of_events_join_quickly(self):
        import time

        rows = [{"Timestamp": 1794218400 + i, "DeviceName": "busy"} for i in range(20000)]
        started = time.time()
        out = consolidate({**PLAYBOOK, "stages": PLAYBOOK["stages"][1:]},
                          {0: {"mde": rows}, 1: {"splunk": [{"_time": 1794218400 + 600, "host": "busy"}]}})
        assert out["leads"][0]["stages_hit"] == 2 and time.time() - started < 5


@pytest.mark.unit
class TestReading:
    @pytest.mark.parametrize("entity,raw,want", [
        ("host", "WS01.corp.local", "ws01"), ("host", "10.1.2.3", "10.1.2.3"), ("host", "-", None),
        ("user", "CORP\\JDoe", "jdoe"), ("user", "jdoe@corp.com", "jdoe"), ("user", "NT AUTHORITY\\SYSTEM", None),
        ("ip", ["10.0.0.5", "10.0.0.6"], "10.0.0.5"), ("process_hash", "ABCDEF", "abcdef"),
    ])
    def test_aliases_normalise(self, entity, raw, want):
        assert normalise(entity, raw) == want

    @pytest.mark.parametrize("raw", ["2026-11-09T10:00:00Z", "2026-11-09T10:00:00.0000000Z", "2026-11-09 10:00:00.000 GMT",
                                     1794218400, "1794218400", 1794218400000, "2026-11-09T11:00:00+01:00"])
    def test_times_in_every_siems_form(self, raw):
        assert parse_time(raw) == 1794218400

    def test_exports(self):
        assert read_export("a.csv", b"\xef\xbb\xbfDeviceName,Timestamp\nws01,2026-11-09T10:00:00Z\n") == [
            {"DeviceName": "ws01", "Timestamp": "2026-11-09T10:00:00Z"}]
        assert read_export("a.json", json.dumps({"results": [{"host": "a"}]}).encode()) == [{"host": "a"}]
        assert read_export("a.jsonl", b'{"host": "a"}\n{"host": "b"}\n') == [{"host": "a"}, {"host": "b"}]
        es = {"hits": {"hits": [{"_source": {"host": {"name": "a"}}}]}}
        assert read_export("es.json", json.dumps(es).encode()) == [{"host": {"name": "a"}}]


@pytest.fixture
def client(monkeypatch, tmp_path):
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    AuditBase.metadata.create_all(engine)
    factory = sessionmaker(bind=engine)

    def _get_db():
        db = factory()
        try:
            yield db
        finally:
            db.close()
    monkeypatch.setattr(app_module, "get_db", _get_db)
    monkeypatch.setattr(app_module, "CORRELATE_DIR", str(tmp_path))
    (tmp_path / "APT_Test.json").write_text(json.dumps({"cross_vendor_correlations": [PLAYBOOK]}))
    db = factory()
    user = User(email="analyst@example.org", full_name="Analyst", password_hash=hash_password("Old-passw0rd-1234567!"),
                role=UserRole.STANDARD, is_active=True)
    db.add(user)
    db.commit()
    c = TestClient(app_module.app, follow_redirects=False)
    c.cookies.set("shikari_session", create_session(user.id, remember_me=False, db=db))
    db.close()
    return c


def _files(results):
    return [(f"s{i}_{v}", (f"s{i}_{v}.json", json.dumps(rows).encode(), "application/json"))
            for i, by_vendor in results.items() for v, rows in by_vendor.items()]


@pytest.mark.unit
class TestEndpoint:
    def test_uploaded_exports_become_leads(self, client):
        r = client.post("/api/pivots/leads", data={"group_name": "APT Test", "correlation_id": "xv_test"},
                        files=_files(_results()))
        assert r.status_code == 200 and r.json()["leads"][0]["value"] == "ws01"

    def test_a_stage_runs_through_a_configured_client(self, client, monkeypatch):
        ran = []
        monkeypatch.setattr(app_module, "_pivot_clients", lambda: {"mde": lambda q: (ran.append(q), {
            "status": "success", "results": _results()[1]["mde"], "stats": {}})[1]})
        results = _results()
        del results[1]
        r = client.post("/api/pivots/leads", data={"group_name": "APT Test", "correlation_id": "xv_test",
                                                   "run": "1:mde,2:splunk"}, files=_files(results))
        body = r.json()
        assert ran == ["q2"] and body["ran"] == [{"stage": 1, "vendor": "mde", "rows": 2, "truncated": False}]
        assert body["leads"][0]["stages_hit"] == 3

    def test_a_failed_run_is_reported(self, client, monkeypatch):
        monkeypatch.setattr(app_module, "_pivot_clients",
                            lambda: {"mde": lambda q: {"status": "error", "error": "Semantic error"}})
        r = client.post("/api/pivots/leads", data={"group_name": "APT Test", "correlation_id": "xv_test", "run": "1:mde"})
        assert r.json()["problems"] == ["Stage 2, Defender XDR: Semantic error"]

    @pytest.mark.parametrize("form,status", [
        ({"group_name": "APT Test", "correlation_id": "nope"}, 404),
        ({"group_name": "../../etc/passwd", "correlation_id": "xv_test"}, 404),
        ({"group_name": "APT Test", "correlation_id": "xv_test", "tolerance": "soon"}, 400),
    ])
    def test_refusals(self, client, form, status):
        assert client.post("/api/pivots/leads", data=form).status_code == status

    def test_a_file_that_isnt_an_export(self, client):
        r = client.post("/api/pivots/leads", data={"group_name": "APT Test", "correlation_id": "xv_test"},
                        files=[("s0_googlesecops", ("x.json", b"{not json", "application/json"))])
        assert r.status_code == 400

    def test_signed_out_is_refused(self, client):
        client.cookies.clear()
        assert client.post("/api/pivots/leads", data={"group_name": "APT Test"}).status_code == 401


@pytest.mark.unit
def test_a_late_event_naming_two_entities_is_counted_once():
    playbook = {**PLAYBOOK, "stages": PLAYBOOK["stages"][1:]}
    results = {0: {"mde": [{"Timestamp": "2026-11-09T10:00:00Z", "DeviceName": "ws5", "AccountName": "svc"}]},
               1: {"splunk": [{"_time": "2026-11-09T16:00:00Z", "host": "ws5", "user": "svc"}]}}
    late = [u for u in consolidate(playbook, results)["unjoined"] if u["reason"] == "outside_window"]
    assert [u["events"] for u in late] == [1]
