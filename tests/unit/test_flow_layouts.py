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
