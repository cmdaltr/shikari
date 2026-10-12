"""
ATT&CK Flow edits persist per user and group once the group's results are in
that user's library, and not before.
"""
import json
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from archer.database.models import Base, LibraryDetection, User, DetectionType
from archer.visualization import flow_layouts as fl


@pytest.fixture
def db():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    s = sessionmaker(bind=engine)()
    s.add(User(id=1, email="a@b.c", full_name="A", password_hash="x"))
    s.commit()
    yield s
    s.close()


def _save_to_library(db, tags):
    db.add(LibraryDetection(user_id=1, title="T1078.004 - x", detection_type=DetectionType.DETECTION,
                            content="{}", tags=json.dumps(tags)))
    db.commit()


def test_clean_state_keeps_only_well_formed_fields():
    out = fl.clean_state({
        "vertical": True, "gaps": "yes", "vendors": ["mde", "qradar"],
        "removed": ["T1078.004", "<script>", "T1"],
        "unlinked": ["T1078.004>T1543.003", "T1078>x>y", "T1078.004>bad"],
        "offsets": {"T1078.004": [10, -5.55], "T1059": [float("inf"), 0], "T1105": [True, 1], "x": [1, 2],
                    "T1190": [1e9, 3]},
        "extra": "dropped",
    })
    assert out == {"vertical": True, "vendors": ["mde"], "removed": ["T1078.004"],
                   "unlinked": ["T1078.004>T1543.003"],
                   "offsets": {"T1078.004": [10.0, -5.5], "T1190": [fl.MAX_OFFSET, 3.0]}}


def test_library_tag_matches_save_to_library():
    assert fl.library_tag("Scattered_Spider") == "Group:Scattered Spider"
    assert fl.library_tag("CVE-2024-3400") == "CVE:CVE-2024-3400"


def test_results_in_library_matches_exact_tag(db):
    assert not fl.results_in_library(db, 1, "Scattered_Spider")
    _save_to_library(db, ["Group:Scattered Spider Extra", "Hunt-1"])
    assert not fl.results_in_library(db, 1, "Scattered_Spider")  # not a prefix match
    _save_to_library(db, ["Group:Scattered Spider"])
    assert fl.results_in_library(db, 1, "Scattered_Spider")
    assert not fl.results_in_library(db, 2, "Scattered_Spider")  # another user's library


def _client(db):
    app = FastAPI()
    app.include_router(fl.router)
    client = TestClient(app)
    client.cookies.set("archer_session", "s")
    return client


def test_put_requires_results_in_library_then_round_trips(db):
    state = {"vertical": True, "removed": ["T1105"], "offsets": {"T1105": [4, 5]}}
    with patch.object(fl, "get_db", lambda: iter([db])), \
         patch("archer.auth.get_user_from_session_id", return_value=SimpleNamespace(id=1)), \
         patch.object(db, "close"):
        client = _client(db)
        r = client.put("/api/flow-layout", json={"group_name": "Scattered Spider", "state": state})
        assert r.status_code == 409
        _save_to_library(db, ["Group:Scattered Spider"])
        r = client.put("/api/flow-layout", json={"group_name": "Scattered Spider", "state": state})
        assert r.status_code == 200
        r = client.put("/api/flow-layout", json={"group_name": "Scattered Spider", "state": {**state, "vertical": False}})
        assert r.status_code == 200
    assert fl.load_layout(db, 1, "Scattered_Spider") == {
        "vertical": False, "removed": ["T1105"], "offsets": {"T1105": [4.0, 5.0]}}


def test_put_rejects_anonymous_and_oversized(db):
    app = FastAPI()
    app.include_router(fl.router)
    client = TestClient(app)
    assert client.put("/api/flow-layout", json={"group_name": "x", "state": {}}).status_code == 401
    client.cookies.set("archer_session", "s")
    big = {"group_name": "x", "state": {"removed": ["T1105"] * 60000}}
    assert client.put("/api/flow-layout", json=big).status_code == 413


def test_group_from_tag_reverses_library_tag():
    assert fl.group_from_tag("Group:Scattered Spider") == "Scattered_Spider"
    assert fl.group_from_tag("CVE:CVE-2024-3400") == "CVE-2024-3400"
    assert fl.group_from_tag("Hunt-1") is None
    for g in ("Scattered_Spider", "CVE-2024-3400", "APT29"):
        assert fl.group_from_tag(fl.library_tag(g)) == g


def test_layout_goes_when_the_groups_last_library_item_does(db):
    from archer.database.models import FlowLayout
    db.add(User(id=2, email="b@b.c", full_name="B", password_hash="x"))
    _save_to_library(db, ["Group:Scattered Spider"])
    _save_to_library(db, ["Group:Scattered Spider", "Hunt-1"])
    fl.save_layout(db, 1, "Scattered_Spider", {"vertical": True})
    fl.save_layout(db, 2, "Scattered_Spider", {"vertical": True})  # another user's layout stays
    first, second = db.query(LibraryDetection).order_by(LibraryDetection.id).all()

    tags = [first.tags]
    db.delete(first); db.flush()
    assert fl.prune_layouts(db, 1, tags) == 0  # one item still in the library
    assert fl.load_layout(db, 1, "Scattered_Spider") == {"vertical": True}

    tags = [second.tags]
    db.delete(second); db.flush()
    assert fl.prune_layouts(db, 1, tags) == 1
    assert fl.load_layout(db, 1, "Scattered_Spider") is None
    assert db.query(FlowLayout).filter(FlowLayout.user_id == 2).count() == 1


def test_layout_goes_when_the_group_tag_is_removed(db):
    _save_to_library(db, ["CVE:CVE-2024-3400"])
    fl.save_layout(db, 1, "CVE-2024-3400", {"reversed": True})
    item = db.query(LibraryDetection).one()
    old = [item.tags]
    item.tags = json.dumps(["Hunt-1"]); db.flush()
    assert fl.prune_layouts(db, 1, old) == 1
    assert fl.load_layout(db, 1, "CVE-2024-3400") is None


def test_export_applies_edits_to_the_saved_view(tmp_path):
    view = {"lanes": [{"tactic": "Execution", "nodes": [
                {"id": "T1059", "name": "Cmd", "tactics": ["Execution"], "vendors": {"mde": 1}, "detected": True, "degree": 1},
                {"id": "T1105", "name": "Tool", "tactics": ["Execution"], "vendors": {"mde": 1}, "detected": True, "degree": 1}]}],
            "edges": [{"from": "T1059", "to": "T1105", "vendors": ["mde"], "relevance": 0.8}],
            "vendors": [{"key": "mde", "name": "MDE"}], "stats": {}}
    (tmp_path / "Scattered_Spider_flow_view.json").write_text(json.dumps({"group_name": "Scattered Spider", "view": view}))
    app = FastAPI()
    app.include_router(fl.router)
    client = TestClient(app)
    with patch("archer.config.ATTACK_FLOWS_DIR", str(tmp_path)):
        r = client.post("/api/attack-flow/export", json={"group_name": "Scattered Spider", "state": {}})
        assert r.status_code == 200
        assert "Scattered_Spider_edited_flow.json" in r.headers["content-disposition"]
        assert {o.get("technique_id") for o in r.json()["objects"]} >= {"T1059", "T1105"}
        r = client.post("/api/attack-flow/export",
                        json={"group_name": "Scattered Spider", "state": {"unlinked": ["T1059>T1105"]}})
        assert not [o for o in r.json()["objects"] if o["type"] == "attack-action"]
        assert client.post("/api/attack-flow/export", json={"group_name": "APT1", "state": {}}).status_code == 404
        assert client.post("/api/attack-flow/export", json={"group_name": "../etc", "state": {}}).status_code in (400, 404)


def test_library_flows_lists_each_saved_group_with_its_flow(db, tmp_path, monkeypatch):
    monkeypatch.setattr("archer.config.ATTACK_FLOWS_DIR", str(tmp_path))
    monkeypatch.setattr("archer.build.progress.read_progress", lambda g: {})
    (tmp_path / "APT29_flow_view.json").write_text(json.dumps(
        {"group_name": "APT29", "view": {"lanes": [], "stats": {"techniques": 3}}}))
    _save_to_library(db, ["Group:APT29", "Incident-1"])
    _save_to_library(db, ["CVE:CVE-2024-3400"])
    _save_to_library(db, ["Group:Some Blog Post"])
    bundle = SimpleNamespace(objects=[{"type": "intrusion-set", "name": "APT29", "aliases": ["Cozy Bear"]}])

    flows = fl.library_flows(db, 1, bundle)
    assert [(f["group"], f["kind"]) for f in flows] == [
        ("APT29", "Threat group"), ("Some_Blog_Post", "Report"), ("CVE-2024-3400", "CVE")]
    assert flows[0]["stats"] == {"techniques": 3} and flows[0]["saved"]
    assert flows[1]["view"] is None
    assert fl.library_flows(db, 2, bundle) == []
