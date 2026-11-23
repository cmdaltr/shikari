"""Pairing with Ostraka (shikari/pairing.py, docs/suite/INTEGRATION.md): codes made, listed and withdrawn by
an admin; claimed once, with no sign-in, for an `ostraka` token and a webhook made together."""
import json
import threading
from datetime import datetime, timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

import shikari.app as app_module
from shikari import pairing, webhooks
from shikari.auth import tokens
from shikari.auth.session import create_session
from shikari.database.audit import AuditLog, Base as AuditBase
from shikari.database.models import ApiToken, Base, PairingCode, User, UserRole

HOOK_URL = "https://ostraka.example.org/api/integrations/shikari/webhook"


@pytest.fixture
def db_factory(tmp_path, monkeypatch):
    # A file, not :memory:, so claims on two threads each have their own connection
    engine = create_engine(f"sqlite:///{tmp_path / 'pair.db'}", connect_args={"check_same_thread": False})
    Base.metadata.create_all(engine)
    AuditBase.metadata.create_all(engine)
    factory = sessionmaker(bind=engine)
    monkeypatch.setattr("shikari.database.db.SessionLocal", factory)
    monkeypatch.setattr(webhooks.paths, "DATA", tmp_path)
    monkeypatch.setattr(tokens, "_sessions", {})

    def _get_db():
        db = factory()
        try:
            yield db
        finally:
            db.close()
    monkeypatch.setattr(app_module, "get_db", _get_db)
    return factory


def _user(factory, email, role=UserRole.ADMIN, **extra):
    db = factory()
    u = User(email=email, full_name=email.split("@")[0], password_hash="x", role=role, is_active=True, **extra)
    db.add(u)
    db.commit()
    db.refresh(u)
    db.expunge(u)
    db.close()
    return u


@pytest.fixture
def admin(db_factory):
    return _user(db_factory, "boss@example.org")


@pytest.fixture
def http(db_factory):
    return TestClient(app_module.app, follow_redirects=False)


def _signed_in(http, factory, user):
    db = factory()
    http.cookies.set("shikari_session", create_session(user.id, db=db))
    db.close()
    return http


def _make(http, factory, admin, note="Ostraka on the homelab"):
    _signed_in(http, factory, admin)
    r = http.post("/api/pairing", json={"note": note})
    assert r.status_code == 201, r.text
    http.cookies.clear()
    return r.json()


def _code(link):
    return link.split("/pair#", 1)[1]


def _claim(http, code, url=HOOK_URL):
    return http.post("/api/pairing/claim", json={"code": code, "product": "ostraka", "name": "Ostraka",
                                                 "version": "0.3.0", "webhook_url": url})


def _audits(factory, event):
    db = factory()
    try:
        return [json.loads(a.details) | {"_success": a.success, "_user": a.user_id, "_ip": a.ip_address}
                for a in db.query(AuditLog).filter(AuditLog.event_type == event).all()]
    finally:
        db.close()


@pytest.mark.unit
class TestMaking:
    def test_the_link_its_lifetime_and_only_its_hash_kept(self, http, db_factory, admin, monkeypatch):
        monkeypatch.setenv("SHIKARI_PUBLIC_URL", "https://shikari.example.org/")
        made = _make(http, db_factory, admin)
        assert made["link"].startswith("https://shikari.example.org/pair#pair_")
        code = _code(made["link"])
        assert len(code) > 40
        db = db_factory()
        row = db.get(PairingCode, made["id"])
        assert row.code_hash == pairing.code_hash(code) != code and row.note == "Ostraka on the homelab"
        assert timedelta(minutes=9) < row.expires_at - datetime.utcnow() <= timedelta(minutes=10)
        db.close()
        [audit] = _audits(db_factory, pairing.EVENT_PAIRING_CREATED)
        assert audit["pairing_id"] == made["id"] and audit["_user"] == admin.id

    def test_without_a_public_url_the_link_names_the_admins_address(self, http, db_factory, admin, monkeypatch):
        monkeypatch.delenv("SHIKARI_PUBLIC_URL", raising=False)
        _signed_in(http, db_factory, admin)
        r = http.post("/api/pairing", json={}, headers={"X-Forwarded-Host": "homelab.example.ts.net:32453"})
        assert r.json()["link"].startswith("http://homelab.example.ts.net:32453/pair#pair_")

    def test_listed_and_withdrawn_by_an_admin_and_audited(self, http, db_factory, admin):
        first = _make(http, db_factory, admin, "first")
        second = _make(http, db_factory, admin, "second")
        _signed_in(http, db_factory, admin)
        listed = http.get("/api/pairing").json()
        assert [c["note"] for c in listed] == ["second", "first"]
        assert set(listed[0]) == {"id", "note", "created_by", "created_at", "expires_at", "claimed_at",
                                  "claimed_by_name"}
        assert listed[0]["created_by"] == admin.email and listed[0]["claimed_at"] is None
        assert "link" not in listed[0] and not any("pair_" in json.dumps(c) for c in listed)

        assert http.delete(f"/api/pairing/{first['id']}").status_code == 204
        assert http.delete(f"/api/pairing/{first['id']}").status_code == 404
        assert [c["note"] for c in http.get("/api/pairing").json()] == ["second"]
        assert _audits(db_factory, pairing.EVENT_PAIRING_WITHDRAWN)[0]["pairing_id"] == first["id"]
        assert second

    def test_only_an_admin(self, http, db_factory):
        analyst = _user(db_factory, "analyst@example.org", role=UserRole.OPERATOR)
        assert http.post("/api/pairing", json={}).status_code == 401
        _signed_in(http, db_factory, analyst)
        assert http.post("/api/pairing", json={}).status_code == 403
        assert http.get("/api/pairing").status_code == 403
        assert http.delete("/api/pairing/1").status_code == 403


@pytest.mark.unit
class TestClaiming:
    def test_the_claim_makes_the_token_and_the_webhook(self, http, db_factory, admin):
        made = _make(http, db_factory, admin)
        r = _claim(http, _code(made["link"]))
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["product"] == "shikari" and body["version"]
        assert body["events"] == ["run.completed", "run.failed", "run.executed"]
        assert body["token"].startswith("shik_") and body["webhook_secret"]

        db = db_factory()
        [token] = db.query(ApiToken).all()
        assert token.user_id == admin.id and token.name == "Ostraka (paired)" and token.scope == tokens.OSTRAKA
        assert body["token"] not in (token.token_hash, token.prefix)
        assert timedelta(days=364) < token.expires_at - datetime.utcnow() <= timedelta(days=365)
        assert body["token_expires_at"].startswith(token.expires_at.isoformat()[:16])
        row = db.get(PairingCode, made["id"])
        assert row.claimed_at and row.claimed_by_name == "Ostraka" and row.token_id == token.id
        db.close()

        [hook] = webhooks._load()
        assert hook["id"] == body["webhook_id"] == row.webhook_id and hook["url"] == HOOK_URL
        assert hook["secret"] == body["webhook_secret"] and hook["description"] == "Ostraka (paired)"
        assert sorted(hook["events"]) == sorted(pairing.EVENTS) and hook["enabled"]

        [audit] = _audits(db_factory, pairing.EVENT_PAIRING_CLAIMED)
        assert audit["made_by"] == admin.email and audit["token_prefix"] == token.prefix
        assert audit["webhook_id"] == hook["id"] and audit["_ip"]
        assert body["token"] not in json.dumps(audit) and body["webhook_secret"] not in json.dumps(audit)

        # The admin sees it claimed, and its token in their list with its scope
        _signed_in(http, db_factory, admin)
        assert http.get("/api/pairing").json()[0]["claimed_by_name"] == "Ostraka"
        [listed] = http.get("/api/profile/tokens").json()["tokens"]
        assert listed["scope"] == "ostraka" and listed["expires"]

    def test_made_even_on_a_free_install(self, http, db_factory, admin, monkeypatch):
        monkeypatch.setattr(webhooks, "_automation_on", lambda: False)
        assert _claim(http, _code(_make(http, db_factory, admin)["link"])).status_code == 200
        assert len(webhooks._load()) == 1

    def test_a_code_works_once(self, http, db_factory, admin):
        code = _code(_make(http, db_factory, admin)["link"])
        assert _claim(http, code).status_code == 200
        again = _claim(http, code)
        assert again.status_code == 404 and again.json() == {"detail": pairing.NOT_VALID}
        db = db_factory()
        assert db.query(ApiToken).count() == 1
        db.close()
        assert len(webhooks._load()) == 1
        refused = _audits(db_factory, pairing.EVENT_PAIRING_CLAIM_REFUSED)
        assert [(a["reason"], a["_success"]) for a in refused] == [("claimed", False)]

    def test_of_two_claims_at_once_only_one_succeeds(self, db_factory, admin):
        db = db_factory()
        _, link = pairing.create_code(db, db.get(User, admin.id), base="https://s.example")
        db.close()
        code = _code(link)
        results, start = [], threading.Barrier(4)

        def go():
            session = db_factory()
            start.wait()
            try:
                results.append(pairing.claim(session, {"code": code, "webhook_url": HOOK_URL})["token"])
            except pairing.ClaimRefused as e:
                results.append(e.status)
            finally:
                session.close()

        threads = [threading.Thread(target=go) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert sorted(map(str, results))[:3] == ["404", "404", "404"]
        assert sum(1 for r in results if isinstance(r, str)) == 1
        db = db_factory()
        assert db.query(ApiToken).count() == 1
        db.close()
        assert len(webhooks._load()) == 1

    def test_the_conditional_update_lets_one_of_two_checked_claims_through(self, db_factory, admin):
        """Both claims passed the checks before either took the row: the update lets only one through."""
        db = db_factory()
        row, _ = pairing.create_code(db, db.get(User, admin.id), base="https://s.example")
        now = datetime.utcnow()
        assert pairing.take(db, row.id, now, "Ostraka", "10.0.0.5")
        assert not pairing.take(db, row.id, now, "Ostraka", "10.0.0.6")
        db.refresh(row)
        assert row.claim_ip == "10.0.0.5"
        db.close()

    def test_an_expired_code(self, http, db_factory, admin):
        made = _make(http, db_factory, admin)
        db = db_factory()
        db.get(PairingCode, made["id"]).expires_at = datetime.utcnow() - timedelta(seconds=1)
        db.commit()
        db.close()
        r = _claim(http, _code(made["link"]))
        assert r.status_code == 410 and r.json() == {"detail": pairing.EXPIRED}
        assert _audits(db_factory, pairing.EVENT_PAIRING_CLAIM_REFUSED)[0]["reason"] == "expired"

    def test_a_withdrawn_code(self, http, db_factory, admin):
        made = _make(http, db_factory, admin)
        _signed_in(http, db_factory, admin)
        http.delete(f"/api/pairing/{made['id']}")
        http.cookies.clear()
        r = _claim(http, _code(made["link"]))
        assert r.status_code == 404 and r.json() == {"detail": pairing.NOT_VALID}

    def test_an_unknown_or_malformed_code(self, http, db_factory):
        for code in ("pair_" + "x" * 43, "not-a-code", None, 42):
            r = _claim(http, code)
            assert r.status_code == 404 and r.json() == {"detail": pairing.NOT_VALID}
        assert http.post("/api/pairing/claim", json=[]).status_code == 404

    @pytest.mark.parametrize("change", [{"role": UserRole.OPERATOR}, {"is_active": False}])
    def test_refused_once_its_admin_is_demoted_or_deactivated(self, http, db_factory, admin, change):
        made = _make(http, db_factory, admin)
        db = db_factory()
        user = db.get(User, admin.id)
        for k, v in change.items():
            setattr(user, k, v)
        db.commit()
        db.close()
        r = _claim(http, _code(made["link"]))
        assert r.status_code == 404 and r.json() == {"detail": pairing.NOT_VALID}
        db = db_factory()
        assert db.query(ApiToken).count() == 0 and db.get(PairingCode, made["id"]).claimed_at is None
        db.close()
        assert _audits(db_factory, pairing.EVENT_PAIRING_CLAIM_REFUSED)[0]["reason"] == "not an admin"

    @pytest.mark.parametrize("url", ["http://ostraka.example.org/hook", "https://169.254.169.254/latest",
                                     "https://user:pw@ostraka.example.org/", "ftp://x", "", None])
    def test_a_bad_webhook_url_is_refused_and_the_code_kept(self, http, db_factory, admin, url):
        made = _make(http, db_factory, admin)
        r = _claim(http, _code(made["link"]), url=url)
        assert r.status_code == 422 and r.json()["detail"]
        db = db_factory()
        assert db.query(ApiToken).count() == 0 and db.get(PairingCode, made["id"]).claimed_at is None
        db.close()
        assert webhooks._load() == []
        assert _claim(http, _code(made["link"])).status_code == 200  # still works with a good one

    def test_the_claim_needs_no_sign_in_and_another_site_cant_post_it(self, http, db_factory, admin):
        code = _code(_make(http, db_factory, admin)["link"])
        r = http.post("/api/pairing/claim", json={"code": code, "webhook_url": HOOK_URL},
                      headers={"Sec-Fetch-Site": "cross-site"})
        assert r.status_code == 403
        assert _claim(http, code).status_code == 200

    def test_the_pair_page_says_what_the_link_is(self, http):
        r = http.get("/pair")
        assert r.status_code == 200 and "pairing link" in r.text and "Ostraka" in r.text
