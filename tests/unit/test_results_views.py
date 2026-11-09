"""Results (a group's page) and Interim results (one run's): Library status and the group check."""

import json

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

import shikari.app as app_module
from shikari.database.models import Base, DetectionType, LibraryDetection, User


@pytest.fixture
def db(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 't.db'}")
    Base.metadata.create_all(engine)
    s = sessionmaker(bind=engine)()
    s.add(User(id=1, email="u@x", full_name="u", password_hash="x"))
    for uid, tag, platform, technique, title in [
        (1, "Group:Scattered Spider", "mde", "T1057", "Process discovery"),
        (1, "Group:APT29", "mde", "T1003", "Credential dumping"),         # another group's
        (2, "Group:Scattered Spider", "mde", "T1003", "Credential dumping"),  # another user's
    ]:
        s.add(LibraryDetection(user_id=uid, title=title, detection_type=DetectionType.DETECTION, platform=platform,
                               content=json.dumps({"technique": technique, "title": title}), tags=json.dumps([tag])))
    s.commit()
    yield s
    s.close()


@pytest.mark.unit
def test_saved_files_are_the_users_own_for_this_group(db):
    detections = [{"name": "mde", "all_files": [
        {"file": "a.yaml", "technique": "t1057", "title": "Process discovery"},
        {"file": "b.yaml", "technique": "T1003", "title": "Credential dumping"},
    ]}, {"name": "splunk", "all_files": [{"file": "c.yaml", "technique": "T1057", "title": "Process discovery"}]}]
    assert app_module._saved_detection_files(db, 1, "Scattered_Spider", detections) == {"mde": ["a.yaml"]}


@pytest.mark.unit
def test_library_group_name():
    assert app_module.library_group_name("Scattered_Spider") == "Scattered Spider"
    assert app_module.library_group_name("CVE-2024-3400") == "CVE-2024-3400"


@pytest.mark.unit
def test_a_group_with_a_space_is_an_attack_group(monkeypatch):
    monkeypatch.setattr(app_module.app.state, "bundle", object(), raising=False)
    monkeypatch.setattr(app_module, "check_group_in_mitre", lambda b, g: "Y" if g == "Scattered Spider" else "N")
    assert app_module._is_attack_group("Scattered_Spider")
    assert not app_module._is_attack_group("Report_Something")
