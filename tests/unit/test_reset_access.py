"""Reset access (shikari/auth/reset_access.py): issuing the link from the admin API and the command line,
and the page that sets a new password and a new authenticator."""
import json
import re
from datetime import datetime, timedelta

import pyotp
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import shikari.app as app_module
from shikari.auth import lockout, reset_access as ra
from shikari.auth import tokens as api_tokens
from shikari.auth.mfa import generate_backup_codes, verify_backup_code
from shikari.auth.password import hash_password, verify_password
from shikari.auth.password_reset import create_password_reset_request, validate_reset_token
from shikari.auth.session import create_session, get_user_from_session_id
from shikari.database.audit import AuditLog, Base as AuditBase
from shikari.database.models import ApiToken, Base, PasswordReset, Session, User, UserRole

NEW_PASSWORD = "Brand-new-passw0rd!"
OLD_SECRET = pyotp.random_base32()


@pytest.fixture
def engine():
    eng = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(eng)
    AuditBase.metadata.create_all(eng)
    return eng


@pytest.fixture
def db_factory(engine):
    return sessionmaker(bind=engine)


def _add_user(db_factory, email, role=UserRole.STANDARD, **extra):
    db = db_factory()
    u = User(email=email, full_name=email.split("@")[0].title(), password_hash=hash_password("Old-passw0rd-1234567!"),
             role=role, **{"is_active": True, **extra})
    db.add(u)
    db.commit()
    db.refresh(u)
    db.close()
    return u


@pytest.fixture
def user(db_factory):
    _, old_codes = generate_backup_codes(2)
    return _add_user(db_factory, "lost@example.org", mfa_secret=OLD_SECRET, mfa_enabled=True,
                     backup_codes=old_codes, failed_login_attempts=7,
                     locked_until=datetime.utcnow() + timedelta(minutes=30))


@pytest.fixture
def admin(db_factory):
    return _add_user(db_factory, "boss@example.org", role=UserRole.ADMIN)


@pytest.fixture
def client(db_factory, monkeypatch):
    def _get_db():
        db = db_factory()
        try:
            yield db
        finally:
            db.close()
    monkeypatch.setattr(app_module, "get_db", _get_db)
    return TestClient(app_module.app, follow_redirects=False)


def _token(link):
    assert "?" not in link and "token=" not in link  # in the fragment, never the query string
    return link.split("/reset-access#", 1)[1]


def _issue(db_factory, email="lost@example.org", **kw):
    db = db_factory()
    try:
        return ra.issue_reset_access(db, email=email, **kw)[1]
    finally:
        db.close()


def _audits(db_factory, event):
    db = db_factory()
    try:
        return db.query(AuditLog).filter(AuditLog.event_type == event).all()
    finally:
        db.close()


@pytest.mark.unit
class TestIssue:
    def test_ends_sessions_clears_lockout_and_audits(self, db_factory, user, admin):
        db = db_factory()
        sid = create_session(user.id, remember_me=True, db=db)
        _, link = ra.issue_reset_access(db, user_id=user.id, actor=db.get(User, admin.id))
        assert get_user_from_session_id(sid, db) is None
        assert db.query(Session).filter(Session.user_id == user.id).count() == 0
        db.expire_all()
        u = db.get(User, user.id)
        assert u.failed_login_attempts == 0 and u.locked_until is None
        db.close()
        assert link.startswith(ra.reset_link("")) and link.endswith("/reset-access#" + _token(link))
        [row] = _audits(db_factory, ra.EVENT_ACCESS_RESET_ISSUED)
        assert row.user_id == user.id and row.email == user.email
        details = json.loads(row.details)
        assert details["actor_id"] == admin.id and details["via"] == "admin" and details["tokens_revoked"] == 0

    def test_revokes_api_tokens(self, db_factory, user, admin):
        db = db_factory()
        api_tokens.create_token(db, user.id, "laptop")
        api_tokens.create_token(db, user.id, "ci")
        kept, _ = api_tokens.create_token(db, admin.id, "someone else's")
        db.close()
        _issue(db_factory)
        db = db_factory()
        assert db.query(ApiToken).filter(ApiToken.user_id == user.id).count() == 0
        assert db.query(ApiToken).filter(ApiToken.user_id == admin.id).count() == 1
        db.close()
        [row] = _audits(db_factory, ra.EVENT_ACCESS_RESET_ISSUED)
        assert json.loads(row.details)["tokens_revoked"] == 2

    def test_token_is_stored_only_as_its_hash(self, db_factory, user):
        token = _token(_issue(db_factory))
        db = db_factory()
        [row] = db.query(PasswordReset).filter(PasswordReset.kind == ra.RESET_ACCESS_KIND).all()
        assert row.reset_token == ra.token_hash(token) and row.reset_token != token
        assert ra.RESET_ACCESS_EXPIRY_HOURS == 24
        assert timedelta(hours=23) < row.expires_at - datetime.utcnow() <= timedelta(hours=24)
        db.close()

    def test_a_new_link_kills_earlier_ones_of_either_kind(self, db_factory, user):
        db = db_factory()
        emailed = create_password_reset_request(user.email, db)
        db.close()
        first = _token(_issue(db_factory))
        second = _token(_issue(db_factory))
        db = db_factory()
        assert ra.open_reset(db, first) is None and ra.open_reset(db, second) is not None
        assert validate_reset_token(emailed, db) is None
        db.close()

    def test_an_emailed_reset_cannot_cancel_or_use_an_access_link(self, db_factory, user):
        token = _token(_issue(db_factory))
        db = db_factory()
        create_password_reset_request(user.email, db)  # anyone can ask for one
        assert ra.open_reset(db, token) is not None
        assert validate_reset_token(token, db) is None
        assert validate_reset_token(ra.token_hash(token), db) is None
        db.close()

    def test_unknown_and_deactivated_accounts_refused(self, db_factory, user):
        db = db_factory()
        with pytest.raises(ra.ResetAccessError, match="no account"):
            ra.issue_reset_access(db, email="nobody@example.org")
        db.get(User, user.id).is_active = False
        db.commit()
        with pytest.raises(ra.ResetAccessError, match="deactivated"):
            ra.issue_reset_access(db, email=user.email)
        assert db.query(PasswordReset).count() == 0
        db.close()


def _page(client, token=None):
    r = client.get("/reset-access")  # the token is the link's fragment: never sent
    m = re.search(r'let csrf = "([^"]+)"', r.text)
    return r, m.group(1) if m else None


def _start(client, token, csrf, password=NEW_PASSWORD):
    return client.post("/api/auth/reset-access/start",
                       json={"token": token, "csrf_token": csrf, "new_password": password})


def _complete(client, token, csrf, code):
    return client.post("/api/auth/reset-access/complete", json={"token": token, "csrf_token": csrf, "code": code})


@pytest.mark.unit
class TestPage:
    def test_the_whole_flow(self, client, db_factory, user):
        token = _token(_issue(db_factory))
        r, csrf = _page(client, token)
        assert r.status_code == 200 and csrf

        r = _start(client, token, csrf)
        assert r.status_code == 200 and r.json()["qr_code"].startswith("data:image/png;base64,")
        assert r.json()["email"] == user.email
        secret, csrf = r.json()["secret"], r.json()["csrf_token"]
        assert secret != OLD_SECRET

        db = db_factory()
        u = db.get(User, user.id)
        assert u.mfa_secret == OLD_SECRET and not verify_password(NEW_PASSWORD, u.password_hash), \
            "nothing changes before the code checks out"
        row = db.query(PasswordReset).filter(PasswordReset.kind == ra.RESET_ACCESS_KIND).one()
        assert row.pending_mfa_secret == secret  # held on the link, not trusted from the client
        old_codes = u.backup_codes
        db.close()

        r = _complete(client, token, csrf, "000000" if pyotp.TOTP(secret).now() != "000000" else "111111")
        assert r.status_code == 422 and "didn't match" in r.json()["error"]
        csrf = r.json()["csrf_token"]

        r = _complete(client, token, csrf, pyotp.TOTP(secret).now())
        assert r.status_code == 200 and r.json()["success"]
        codes = r.json()["backup_codes"]
        assert len(codes) == 10
        session_id = r.cookies.get("shikari_session")
        assert session_id

        db = db_factory()
        u = db.get(User, user.id)
        assert verify_password(NEW_PASSWORD, u.password_hash)
        assert u.mfa_enabled and u.mfa_secret == secret
        assert u.backup_codes != old_codes and verify_backup_code(u.backup_codes, codes[0])[0]
        assert u.failed_login_attempts == 0 and u.locked_until is None
        assert get_user_from_session_id(session_id, db).id == user.id
        row = db.query(PasswordReset).filter(PasswordReset.kind == ra.RESET_ACCESS_KIND).one()
        assert row.used and row.pending_password_hash is None and row.pending_mfa_secret is None
        db.close()
        assert len(_audits(db_factory, ra.EVENT_ACCESS_RESET_COMPLETED)) == 2  # the wrong code, then success

        # Single use: both steps
        assert _start(client, token, "x").status_code == 403  # no live page token
        assert _start(client, token, _page(client)[1]).status_code == 410
        assert _complete(client, token, _page(client)[1], pyotp.TOTP(secret).now()).status_code == 410

    def test_tokens_made_between_issue_and_use_are_revoked_on_completion(self, client, db_factory, user):
        token = _token(_issue(db_factory))
        db = db_factory()
        api_tokens.create_token(db, user.id, "made with the old password")
        db.close()
        _, csrf = _page(client)
        r = _start(client, token, csrf)
        r = _complete(client, token, r.json()["csrf_token"], pyotp.TOTP(r.json()["secret"]).now())
        assert r.status_code == 200
        db = db_factory()
        assert db.query(ApiToken).filter(ApiToken.user_id == user.id).count() == 0
        db.close()
        done = [a for a in _audits(db_factory, ra.EVENT_ACCESS_RESET_COMPLETED) if a.success]
        assert json.loads(done[0].details)["tokens_revoked"] == 1

    def test_wrong_codes_lock_the_account(self, client, db_factory, user):
        token = _token(_issue(db_factory))
        _, csrf = _page(client)
        r = _start(client, token, csrf)
        secret, csrf = r.json()["secret"], r.json()["csrf_token"]
        right = pyotp.TOTP(secret).now()
        wrong = next(c for c in ("000000", "111111", "222222") if not pyotp.TOTP(secret).verify(c, valid_window=1))
        for attempt in range(1, lockout.LOCK_AFTER_ATTEMPTS + 1):
            r = _complete(client, token, csrf, wrong)
            csrf = r.json()["csrf_token"]
            assert r.status_code == (429 if attempt == lockout.LOCK_AFTER_ATTEMPTS else 422)
        assert "locked" in r.json()["error"].lower()
        db = db_factory()
        u = db.get(User, user.id)
        assert lockout.is_locked(u) and u.failed_login_attempts == lockout.LOCK_AFTER_ATTEMPTS
        db.close()

        r = _complete(client, token, csrf, right)  # the right code, while locked
        assert r.status_code == 429 and "locked" in r.json()["error"].lower()
        db = db_factory()
        assert not verify_password(NEW_PASSWORD, db.get(User, user.id).password_hash)
        assert ra.open_reset(db, token) is not None, "the link survives the lock"
        db.close()

        db = db_factory()  # the lock expires
        db.get(User, user.id).locked_until = datetime.utcnow() - timedelta(seconds=1)
        db.commit()
        db.close()
        r = _complete(client, token, r.json()["csrf_token"], pyotp.TOTP(secret).now())
        assert r.status_code == 200
        db = db_factory()
        u = db.get(User, user.id)
        assert u.failed_login_attempts == 0 and u.locked_until is None
        db.close()

    def test_the_page_reads_the_token_from_the_fragment_only(self, client):
        r, csrf = _page(client)
        assert r.status_code == 200 and csrf
        assert "location.hash" in r.text and "URLSearchParams" not in r.text

    def test_a_query_string_token_is_not_accepted(self, client, db_factory, user):
        token = _token(_issue(db_factory))
        r = client.get(f"/reset-access?token={token}")
        csrf = re.search(r'let csrf = "([^"]+)"', r.text).group(1)
        r = client.post(f"/api/auth/reset-access/start?token={token}",
                        json={"csrf_token": csrf, "new_password": NEW_PASSWORD})
        assert r.status_code == 410

    def test_mfa_is_required_even_for_an_account_without_it(self, client, db_factory):
        plain = _add_user(db_factory, "nomfa@example.org")
        token = _token(_issue(db_factory, email=plain.email))
        _, csrf = _page(client, token)
        r = _start(client, token, csrf)
        r = _complete(client, token, r.json()["csrf_token"], pyotp.TOTP(r.json()["secret"]).now())
        assert r.status_code == 200
        db = db_factory()
        assert db.get(User, plain.id).mfa_enabled
        db.close()

    def test_the_code_step_needs_the_password_step_first(self, client, db_factory, user):
        token = _token(_issue(db_factory))
        _, csrf = _page(client, token)
        r = _complete(client, token, csrf, "123456")
        assert r.status_code == 422 and "password first" in r.json()["error"]

    def test_the_full_password_rule_applies(self, client, db_factory, user):
        token = _token(_issue(db_factory))
        _, csrf = _page(client, token)
        r = _start(client, token, csrf, password="short1!")
        assert r.status_code == 422 and "16 characters" in r.json()["error"]

    def test_an_expired_link_is_refused(self, client, db_factory, user):
        token = _token(_issue(db_factory))
        db = db_factory()
        db.query(PasswordReset).update({"expires_at": datetime.utcnow() - timedelta(seconds=1)})
        db.commit()
        db.close()
        r = _start(client, token, _page(client)[1])
        assert r.status_code == 410 and "expired" in r.json()["error"]

    def test_a_deactivated_account_cannot_finish(self, client, db_factory, user):
        token = _token(_issue(db_factory))
        _, csrf = _page(client, token)
        db = db_factory()
        db.get(User, user.id).is_active = False
        db.commit()
        db.close()
        assert _start(client, token, csrf).status_code == 410

    def test_csrf_token_required(self, client, db_factory, user):
        token = _token(_issue(db_factory))
        _page(client, token)
        assert _start(client, token, "forged").status_code == 403

    @pytest.mark.login_gate
    def test_reachable_without_signing_in(self, client, db_factory, user):
        token = _token(_issue(db_factory))
        r, csrf = _page(client, token)
        assert r.status_code == 200
        assert _start(client, token, csrf).status_code == 200


def _signed_in_as(client, db_factory, u):
    db = db_factory()
    client.cookies.set("shikari_session", create_session(u.id, remember_me=False, db=db))
    db.close()


@pytest.mark.unit
class TestAdminEndpoint:
    def test_admin_gets_a_link(self, client, db_factory, user, admin):
        _signed_in_as(client, db_factory, admin)
        r = client.post(f"/api/admin/users/{user.id}/reset-access")
        assert r.status_code == 200
        body = r.json()
        assert body["email"] == user.email and "/reset-access#" in body["link"]
        assert body["expires_in_hours"] == ra.RESET_ACCESS_EXPIRY_HOURS
        db = db_factory()
        assert ra.open_reset(db, _token(body["link"])) is not None
        db.close()

    def test_unknown_and_deactivated_users(self, client, db_factory, admin):
        _signed_in_as(client, db_factory, admin)
        assert client.post("/api/admin/users/999/reset-access").status_code == 404
        gone = _add_user(db_factory, "gone@example.org", is_active=False)
        r = client.post(f"/api/admin/users/{gone.id}/reset-access")
        assert r.status_code == 409 and "deactivated" in r.json()["error"]

    def test_a_temporary_admin_is_refused(self, client, db_factory, user):
        temp = _add_user(db_factory, "temp@example.org", temp_role=UserRole.ADMIN,
                         temp_role_expires=datetime.utcnow() + timedelta(hours=1))
        _signed_in_as(client, db_factory, temp)
        assert client.post(f"/api/admin/users/{user.id}/reset-access").status_code == 403
        db = db_factory()
        assert db.query(PasswordReset).count() == 0
        db.close()

    def test_standard_user_and_anonymous_refused(self, client, db_factory, user):
        assert client.post(f"/api/admin/users/{user.id}/reset-access").status_code == 401
        _signed_in_as(client, db_factory, _add_user(db_factory, "peer@example.org"))
        assert client.post(f"/api/admin/users/{user.id}/reset-access").status_code == 403

    def test_the_old_admin_password_route_is_gone(self, client, db_factory, user, admin):
        _signed_in_as(client, db_factory, admin)
        r = client.post("/api/admin/reset-password", json={"user_id": user.id, "new_password": NEW_PASSWORD})
        assert r.status_code in (404, 405)


@pytest.mark.unit
class TestCommandLine:
    @pytest.fixture(autouse=True)
    def _database(self, monkeypatch, engine, db_factory):
        from shikari.database import db as db_module

        monkeypatch.setattr(db_module, "engine", engine)
        monkeypatch.setattr(db_module, "SessionLocal", db_factory)

    def test_prints_the_link(self, db_factory, user, capsys):
        from shikari.cli.reset_access import main

        assert main([user.email.upper()]) == 0
        link = re.search(r"(\S+/reset-access#\S+)", capsys.readouterr().out).group(1)
        db = db_factory()
        assert ra.open_reset(db, _token(link)) is not None
        db.close()
        [row] = _audits(db_factory, ra.EVENT_ACCESS_RESET_ISSUED)
        assert json.loads(row.details)["via"] == "cli" and json.loads(row.details)["actor_id"] is None

    def test_refuses_an_unknown_account(self, user, capsys):
        from shikari.cli.reset_access import main

        assert main(["nobody@example.org"]) == 1
        assert "no account" in capsys.readouterr().err

    def test_on_the_host_command(self):
        from shikari import service

        assert service.HANDOVER["reset-access"] == ("shikari.cli.reset_access", False)


@pytest.mark.unit
def test_lockout_counts_to_the_threshold_then_clears():
    u = User(failed_login_attempts=0)
    for _ in range(lockout.LOCK_AFTER_ATTEMPTS - 1):
        assert not lockout.record_failure(u)
    assert not lockout.is_locked(u)
    assert lockout.record_failure(u) and lockout.is_locked(u)
    lockout.clear(u)
    assert u.failed_login_attempts == 0 and not lockout.is_locked(u)
