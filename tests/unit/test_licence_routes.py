"""Installing a licence from the admin page (Assessments -> Report branding -> Licence): check, read
the terms, accept, install. The API refuses an install without acceptance (422) or for terms that
are no longer current (409), and records who accepted which version, in the licence and the audit log.

Signs with a throwaway key patched into PUBLIC_KEYS, as tests/test_licensing.py does.
"""

import json
from datetime import date, timedelta

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import shikari.app as app_module
from shikari import licensing as L
from shikari.database.audit import AuditLog
from shikari.database.models import Base, User, UserRole


class _Session:
    """The real session, but routes' db.close() leaves it open for the test to read back."""

    def __init__(self, db):
        self._db = db

    def close(self):
        pass

    def __getattr__(self, name):
        return getattr(self._db, name)


@pytest.fixture
def signing_key(monkeypatch):
    key = Ed25519PrivateKey.generate()
    monkeypatch.setattr(L, "PUBLIC_KEYS", (key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex(),))
    return key


@pytest.fixture
def db():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    AuditLog.metadata.create_all(engine)  # the audit log has a declarative base of its own
    s = sessionmaker(bind=engine)()
    s.add(User(id=1, email="ada@example.org", full_name="Ada Admin", password_hash="x", role=UserRole.ADMIN))
    s.commit()
    yield s
    s.close()


@pytest.fixture
def client(db, tmp_path, monkeypatch):
    monkeypatch.setattr(L, "INSTALL_PATH", tmp_path / "licence.json")
    monkeypatch.setattr(L, "_cache", {"path": None, "mtime": None, "licence": None, "error": None, "accepted": None})
    monkeypatch.delenv("SHIKARI_LICENCE", raising=False)
    monkeypatch.setattr(L.paths, "HOME", tmp_path)
    admin = db.get(User, 1)
    monkeypatch.setattr(app_module, "_require_admin", lambda request, session, json=True: (admin, _Session(db)))
    return TestClient(app_module.app)


def _line(key, expires=date(2027, 11, 30)):
    return L.sign(key, L.Licence("lic_route", "Northwind Ltd", L.Edition.PRO, 5, date(2026, 11, 11), expires))


def test_check_says_what_the_licence_is_and_installs_nothing(client, signing_key, tmp_path):
    r = client.post("/api/report-branding/licence/check", data={"licence": _line(signing_key)})
    assert r.status_code == 200
    j = r.json()
    assert (j["licensee"], j["edition"], j["seats"], j["expires"]) == ("Northwind Ltd", "pro", 5, "2027-11-30")
    assert j["terms_version"] == "1.0" and not (tmp_path / "licence.json").exists()


def test_check_refuses_a_damaged_licence(client, signing_key):
    r = client.post("/api/report-branding/licence/check", data={"licence": _line(signing_key)[:-6] + "AAAAAA"})
    assert r.status_code == 422 and "altered" in r.json()["error"]


def test_the_terms_are_the_shipped_copy(client):
    r = client.get("/api/report-branding/licence/terms")
    assert r.status_code == 200 and r.json()["version"] == "1.0"
    assert r.json()["text"] == L.TERMS.read_text("utf-8")


def test_install_without_accepting_the_terms_is_refused(client, signing_key, tmp_path):
    r = client.post("/api/report-branding/licence", data={"licence": _line(signing_key), "terms_version": "1.0"})
    assert r.status_code == 422 and "Accept the commercial licence terms for Northwind Ltd" in r.json()["error"]
    assert not (tmp_path / "licence.json").exists()


def test_install_accepting_old_terms_is_refused(client, signing_key, tmp_path):
    r = client.post("/api/report-branding/licence",
                    data={"licence": _line(signing_key), "accept_terms": "1", "terms_version": "0.9"})
    assert r.status_code == 409 and "now version 1.0" in r.json()["error"]
    assert not (tmp_path / "licence.json").exists()


def test_install_records_the_acceptance_and_audits_the_version(client, signing_key, db):
    r = client.post("/api/report-branding/licence",
                    data={"licence": _line(signing_key), "accept_terms": "1", "terms_version": "1.0"})
    assert r.status_code == 200, r.text
    accepted = r.json()["status"]["accepted"]
    assert (accepted["terms_version"], accepted["accepted_by"], accepted["accepted_by_name"]) == \
        ("1.0", 1, "Ada Admin <ada@example.org>")
    entry = db.query(AuditLog).filter(AuditLog.event_type == "licence_installed").one()
    details = json.loads(entry.details)
    assert details["terms_version"] == "1.0" and details["licence_id"] == "lic_route" and entry.user_id == 1


def test_the_page_walks_check_terms_tick_install_and_shows_who_accepted(client, signing_key):
    page = client.get("/settings/report-branding").text
    for step in ('id="rb-lic-check"', 'id="rb-lic-terms"', 'id="rb-lic-tick"', 'id="rb-lic-install" disabled',
                 "/api/report-branding/licence/check", "/api/report-branding/licence/terms",
                 "I accept the Shikari Commercial Licence, version ${terms.version}, on behalf of ${lic.licensee}, "
                 "and I have authority to do so"):
        assert step in page
    assert "accepted by" not in page
    client.post("/api/report-branding/licence",
                data={"licence": _line(signing_key), "accept_terms": "1", "terms_version": "1.0"})
    page = client.get("/settings/report-branding").text
    assert "Commercial licence v1.0 accepted by" in page and "Ada Admin &lt;ada@example.org&gt;" in page


def test_admins_see_the_grace_warning_on_every_page(signing_key, client, db):
    L.install(_line(signing_key, expires=date.today() - timedelta(days=5)),  # five days into grace
              accepted_by_name="Ada Admin <ada@example.org>")
    admin = db.get(User, 1)
    assert "grace period" in app_module._licence_notice(admin)
    analyst = User(id=2, email="bo@example.org", full_name="Bo", password_hash="x", role=UserRole.STANDARD)
    assert app_module._licence_notice(analyst) == "" and app_module._licence_notice(None) == ""
    base = open(app_module.paths.TEMPLATES / "base.html", encoding="utf-8").read()
    assert "licence_notice(user)" in base
