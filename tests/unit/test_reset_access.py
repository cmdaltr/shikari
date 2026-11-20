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

    def test_a_new_link_kills_earlier_ones(self, db_factory, user):
        first = _token(_issue(db_factory))
        second = _token(_issue(db_factory))
        db = db_factory()
        assert ra.open_reset(db, first) is None and ra.open_reset(db, second) is not None
        db.close()

    def test_a_row_of_the_old_emailed_reset_is_never_accepted(self, db_factory, user):
        """The 1-hour ?token= reset (kind NULL) is gone; a row it left behind opens nothing."""
        token = "legacy-emailed-token"
        db = db_factory()
        db.add(PasswordReset(user_id=user.id, reset_token=ra.token_hash(token),
                             expires_at=datetime.utcnow() + timedelta(hours=1)))
        db.add(PasswordReset(user_id=user.id, reset_token="plain-" + token,
                             expires_at=datetime.utcnow() + timedelta(hours=1)))
        db.commit()
        assert ra.find_reset(db, token) == (None, "invalid")
        assert ra.find_reset(db, "plain-" + token) == (None, "invalid")
        db.close()

    def test_the_old_emailed_reset_module_is_gone(self):
        import importlib.util

        assert importlib.util.find_spec("shikari.auth.password_reset") is None

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
        assert len(_audits(db_factory, ra.EVENT_ACCESS_RESET_FAILED)) == 1  # the wrong code
        [done] = _audits(db_factory, ra.EVENT_ACCESS_RESET_COMPLETED)
        assert json.loads(done.details)["via"] == "cli"  # issued without an admin, as the CLI does

        # Single use: both steps, with the generic "not valid"
        assert _start(client, token, "x").status_code == 403  # no live page token
        r = _start(client, token, _page(client)[1])
        assert r.status_code == 404 and r.json()["error"] == app_module.RESET_ACCESS_GONE
        assert _complete(client, token, _page(client)[1], pyotp.TOTP(secret).now()).status_code == 404

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
        [locked] = _audits(db_factory, "account_locked")
        assert locked.user_id == user.id and json.loads(locked.details)["via"] == "reset-access"

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
        assert r.status_code == 404

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

    def test_an_expired_link_mentions_forgot_password_only_where_it_works(self, client, db_factory, user, email_on):
        token = _token(_issue(db_factory))
        db = db_factory()
        db.query(PasswordReset).update({"expires_at": datetime.utcnow() - timedelta(hours=1)})
        db.commit()
        db.close()
        r = _start(client, token, _page(client)[1])
        assert r.status_code == 410 and r.json()["error"] == app_module.RESET_ACCESS_EXPIRED_SELF

    def test_an_expired_link_says_so_and_forgets_what_was_chosen(self, client, db_factory, user):
        token = _token(_issue(db_factory))
        _start(client, token, _page(client)[1])
        db = db_factory()
        # A day and a bit past its time: still "expired", not the generic "not valid"
        db.query(PasswordReset).update({"expires_at": datetime.utcnow() - timedelta(hours=25)})
        db.commit()
        db.close()
        r = _start(client, token, _page(client)[1])
        assert r.status_code == 410 and r.json()["error"] == app_module.RESET_ACCESS_EXPIRED
        assert "expired" in r.json()["error"]
        db = db_factory()
        row = db.query(PasswordReset).filter(PasswordReset.reset_token == ra.token_hash(token)).one()
        assert row.pending_password_hash is None and row.pending_mfa_secret is None
        db.close()
        r = _complete(client, token, _page(client)[1], "123456")
        assert r.status_code == 410

    def test_unknown_and_replaced_links_get_the_same_generic_answer(self, client, db_factory, user):
        replaced = _token(_issue(db_factory))
        _issue(db_factory)
        unknown = _start(client, "no-such-token", _page(client)[1])
        old = _start(client, replaced, _page(client)[1])
        assert unknown.status_code == old.status_code == 404
        assert unknown.json() == old.json() and "expired" not in old.json()["error"]

    def test_opening_the_link_again_shows_the_same_authenticator(self, client, db_factory, user):
        token = _token(_issue(db_factory))
        first = _start(client, token, _page(client)[1]).json()
        second = _start(client, token, _page(client)[1], password="Another-new-passw0rd!").json()
        assert first["secret"] == second["secret"] and first["qr_code"] == second["qr_code"]
        db = db_factory()
        row = db.query(PasswordReset).filter(PasswordReset.reset_token == ra.token_hash(token)).one()
        assert verify_password("Another-new-passw0rd!", row.pending_password_hash), "the later password wins"
        db.close()

    def test_a_deactivated_account_cannot_finish(self, client, db_factory, user):
        token = _token(_issue(db_factory))
        _, csrf = _page(client, token)
        db = db_factory()
        db.get(User, user.id).is_active = False
        db.commit()
        db.close()
        assert _start(client, token, csrf).status_code == 404

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


@pytest.mark.unit
class TestDeadLinksAndRaces:
    def test_the_old_password_still_signs_in_while_a_reset_is_open(self, client, db_factory, monkeypatch):
        """Ben's decision (20 November 2026): nothing refuses sign-in because a reset link is open; the
        old password and authenticator work until the reset is completed."""
        from shikari.security import csrf, rate_limit

        monkeypatch.setattr(csrf, "validate_csrf_token", lambda *a: True)
        monkeypatch.setattr(rate_limit, "check_rate_limit", lambda key, **kw: (True, 5))
        plain = _add_user(db_factory, "still@example.org")
        _issue(db_factory, email=plain.email)
        client.cookies.set("shikari_csrf_session", "x")
        r = client.post("/login", data={"email": plain.email, "password": "Old-passw0rd-1234567!", "csrf_token": "t"})
        assert r.status_code == 303 and r.cookies.get("shikari_session")

    def test_a_link_completes_once_when_two_try_at_the_same_time(self, db_factory, user):
        token = _token(_issue(db_factory))
        first, second = db_factory(), db_factory()
        ra.start_reset(first, ra.open_reset(first, token), NEW_PASSWORD)
        row_one, row_two = ra.open_reset(first, token), ra.open_reset(second, token)
        code = pyotp.TOTP(row_one.pending_mfa_secret).now()
        ra.complete_reset(first, row_one, code)
        with pytest.raises(ra.ResetAccessError, match="already been used"):
            ra.complete_reset(second, row_two, code)
        first.close(), second.close()

    def test_a_replaced_link_keeps_nothing_chosen(self, db_factory, user):
        token = _token(_issue(db_factory))
        db = db_factory()
        ra.start_reset(db, ra.open_reset(db, token), NEW_PASSWORD)
        db.close()
        _issue(db_factory)
        db = db_factory()
        old = db.query(PasswordReset).filter(PasswordReset.reset_token == ra.token_hash(token)).one()
        assert old.used and old.pending_password_hash is None and old.pending_mfa_secret is None
        db.close()

    def test_without_base_url_the_link_names_the_address_the_admin_used(self, db_factory, user, monkeypatch):
        monkeypatch.delenv("BASE_URL", raising=False)
        assert _issue(db_factory, base_url="https://shikari.example.net/").startswith(
            "https://shikari.example.net/reset-access#")


def _sign_in(client, email, password, monkeypatch):
    from shikari.security import csrf, rate_limit

    monkeypatch.setattr(csrf, "validate_csrf_token", lambda *a: True)
    monkeypatch.setattr(rate_limit, "check_rate_limit", lambda key, **kw: (True, 5))
    client.cookies.set("shikari_csrf_session", "x")
    return client.post("/login", data={"email": email, "password": password, "csrf_token": "t"})


@pytest.mark.unit
class TestSignInLock:
    def test_the_locking_attempt_and_a_locked_account_get_429_and_the_lock_is_audited(
            self, client, db_factory, monkeypatch):
        u = _add_user(db_factory, "guessed@example.org")
        for attempt in range(1, lockout.LOCK_AFTER_ATTEMPTS + 1):
            r = _sign_in(client, u.email, "wrong-password", monkeypatch)
            assert r.status_code == (429 if attempt == lockout.LOCK_AFTER_ATTEMPTS else 401)
        assert "locked" in r.text.lower()
        r = _sign_in(client, u.email, "Old-passw0rd-1234567!", monkeypatch)  # the right one, while locked
        assert r.status_code == 429 and "locked" in r.text.lower()
        [locked] = _audits(db_factory, "account_locked")
        assert locked.user_id == u.id and json.loads(locked.details)["via"] == "sign-in"


SENT = []


@pytest.fixture
def email_on(monkeypatch):
    from shikari.auth import email as email_module
    from shikari.security import rate_limit

    SENT.clear()
    monkeypatch.setattr(email_module, "EMAIL_ENABLED", True)
    monkeypatch.setenv("BASE_URL", "https://shikari.example.net")
    monkeypatch.setattr(email_module, "BASE_URL", "https://shikari.example.net")
    monkeypatch.setattr(email_module, "send_email",
                        lambda **kw: SENT.append(kw) or True)
    rate_limit._rate_limit_storage.clear()
    yield SENT
    rate_limit._rate_limit_storage.clear()


def _forgot(client, email):
    return client.post("/api/auth/reset-access/request", json={"email": email})


def _emailed_token():
    link = re.search(r"(https://shikari\.example\.net/reset-access#\S+)", SENT[-1]["text_body"]).group(1)
    return _token(link)


@pytest.mark.unit
class TestSelfService:
    def test_the_same_answer_whether_or_not_an_account_matched(self, client, db_factory, user, email_on):
        known, unknown = _forgot(client, user.email.upper()), _forgot(client, "nobody@example.org")
        assert known.status_code == unknown.status_code == 200
        assert known.json() == unknown.json() == {"success": True, "message": app_module.SELF_SERVICE_SENT}
        assert "If that address has an account, a link is on its way" in known.json()["message"]
        assert len(email_on) == 1 and email_on[0]["to_email"] == user.email
        assert "reset-access#" in email_on[0]["html_body"] and "?token=" not in email_on[0]["text_body"]

    def test_issuing_ends_nothing_and_completing_ends_everything(self, client, db_factory, user, email_on):
        db = db_factory()
        sid = create_session(user.id, remember_me=False, db=db)
        api_tokens.create_token(db, user.id, "laptop")
        db.close()
        _forgot(client, user.email)
        db = db_factory()
        assert get_user_from_session_id(sid, db) is not None, "anyone can ask: no session ends on issue"
        assert db.query(ApiToken).filter(ApiToken.user_id == user.id).count() == 1
        u = db.get(User, user.id)
        assert lockout.is_locked(u), "nor does asking clear a lockout"
        u.locked_until = None
        u.failed_login_attempts = 0
        db.commit()
        db.close()
        [issued] = _audits(db_factory, ra.EVENT_ACCESS_RESET_ISSUED)
        assert json.loads(issued.details)["via"] == "self-service"

        token = _emailed_token()
        r = _start(client, token, _page(client)[1])
        r = _complete(client, token, r.json()["csrf_token"], pyotp.TOTP(r.json()["secret"]).now())
        assert r.status_code == 200 and len(r.json()["backup_codes"]) == 10
        db = db_factory()
        assert get_user_from_session_id(sid, db) is None
        assert db.query(ApiToken).filter(ApiToken.user_id == user.id).count() == 0
        u = db.get(User, user.id)
        assert verify_password(NEW_PASSWORD, u.password_hash) and u.mfa_secret != OLD_SECRET
        db.close()
        done = [a for a in _audits(db_factory, ra.EVENT_ACCESS_RESET_COMPLETED) if a.success]
        assert json.loads(done[0].details) == {"via": "self-service", "tokens_revoked": 1}

    def test_replaces_an_earlier_self_service_link(self, client, db_factory, user, email_on):
        _forgot(client, user.email)
        first = _emailed_token()
        _forgot(client, user.email)
        second = _emailed_token()
        db = db_factory()
        assert ra.open_reset(db, first) is None and ra.open_reset(db, second) is not None
        db.close()

    def test_never_replaces_an_open_admin_issued_reset(self, client, db_factory, user, email_on):
        admin_link = _token(_issue(db_factory))
        r = _forgot(client, user.email)
        assert r.json()["message"] == app_module.SELF_SERVICE_SENT and not email_on
        db = db_factory()
        assert ra.open_reset(db, admin_link) is not None
        db.close()
        refused = [a for a in _audits(db_factory, ra.EVENT_ACCESS_RESET_ISSUED) if not a.success]
        assert json.loads(refused[0].details)["via"] == "self-service"

    def test_an_admin_reset_replaces_a_self_service_link(self, client, db_factory, user, email_on):
        _forgot(client, user.email)
        emailed = _emailed_token()
        _issue(db_factory)
        db = db_factory()
        assert ra.open_reset(db, emailed) is None
        db.close()

    def test_deactivated_and_address_less_accounts_get_nothing(self, client, db_factory, email_on):
        gone = _add_user(db_factory, "gone@example.org", is_active=False)
        _add_user(db_factory, "admin")  # the local default admin signs in as `admin`: nowhere to send
        assert _forgot(client, gone.email).status_code == 200
        assert _forgot(client, "admin").status_code == 200
        assert not email_on

    def test_rate_limited_per_address_and_per_ip(self, client, db_factory, user, email_on):
        for _ in range(app_module.SELF_SERVICE_PER_ADDRESS):
            assert _forgot(client, user.email).status_code == 200
        assert _forgot(client, user.email).status_code == 429
        sent = len(email_on)
        for n in range(app_module.SELF_SERVICE_PER_IP - app_module.SELF_SERVICE_PER_ADDRESS):
            assert _forgot(client, f"other{n}@example.org").status_code == 200
        assert _forgot(client, "one-more@example.org").status_code == 429
        assert len(email_on) == sent

    def test_without_email_the_page_says_ask_an_administrator(self, client, monkeypatch):
        from shikari.auth import email as email_module

        monkeypatch.setattr(email_module, "EMAIL_ENABLED", False)
        r = client.get("/forgot-password")
        assert r.status_code == 200 and "Ask an administrator" in r.text and 'id="forgot-form"' not in r.text
        r = _forgot(client, "lost@example.org")
        assert r.status_code == 503 and "administrator" in r.json()["error"]

    def test_without_base_url_it_stays_off(self, client, monkeypatch, user):
        """An emailed link built from the request's Host header would go wherever the asker pointed it."""
        from shikari.auth import email as email_module

        monkeypatch.setattr(email_module, "EMAIL_ENABLED", True)
        monkeypatch.delenv("BASE_URL", raising=False)
        assert _forgot(client, user.email).status_code == 503

    def test_with_email_the_page_has_the_form(self, client, email_on):
        r = client.get("/forgot-password")
        assert 'id="forgot-form"' in r.text and "/api/auth/reset-access/request" in r.text

    def test_wrong_codes_on_a_self_service_link_count_towards_the_lockout(self, client, db_factory, email_on):
        u = _add_user(db_factory, "selfie@example.org")
        _forgot(client, u.email)
        token = _emailed_token()
        r = _start(client, token, _page(client)[1])
        secret, csrf = r.json()["secret"], r.json()["csrf_token"]
        wrong = next(c for c in ("000000", "111111", "222222") if not pyotp.TOTP(secret).verify(c, valid_window=1))
        r = _complete(client, token, csrf, wrong)
        assert r.status_code == 422
        db = db_factory()
        assert db.get(User, u.id).failed_login_attempts == 1
        db.close()


@pytest.mark.unit
class TestDeactivation:
    @pytest.mark.parametrize("how", ["put", "delete"])
    def test_ends_sessions_and_revokes_api_tokens(self, client, db_factory, admin, how):
        victim = _add_user(db_factory, "leaver@example.org")
        db = db_factory()
        sid = create_session(victim.id, remember_me=True, db=db)
        api_tokens.create_token(db, victim.id, "laptop")
        db.close()
        _signed_in_as(client, db_factory, admin)
        if how == "put":
            r = client.put(f"/api/admin/users/{victim.id}", json={"is_active": False})
        else:
            r = client.delete(f"/api/admin/users/{victim.id}")
        assert r.status_code == 200 and r.json()["success"]
        db = db_factory()
        assert not db.get(User, victim.id).is_active
        assert get_user_from_session_id(sid, db) is None
        assert db.query(Session).filter(Session.user_id == victim.id).count() == 0
        assert db.query(ApiToken).filter(ApiToken.user_id == victim.id).count() == 0
        db.close()
        [row] = _audits(db_factory, "user_deactivated")
        assert row.user_id == victim.id and json.loads(row.details)["tokens_revoked"] == 1

    def test_other_edits_end_nothing(self, client, db_factory, admin):
        stays = _add_user(db_factory, "stays@example.org")
        db = db_factory()
        sid = create_session(stays.id, remember_me=True, db=db)
        db.close()
        _signed_in_as(client, db_factory, admin)
        assert client.put(f"/api/admin/users/{stays.id}", json={"full_name": "Still Here"}).json()["success"]
        db = db_factory()
        assert get_user_from_session_id(sid, db) is not None
        db.close()
        assert not _audits(db_factory, "user_deactivated")


@pytest.mark.unit
class TestEmailedLinksNeverFollowTheRequest:
    def test_a_forged_host_never_reaches_the_email(self, client, db_factory, user, email_on):
        """Host-header injection: the emailed link names BASE_URL, whatever Host or X-Forwarded-*
        the request carried."""
        r = client.post("/api/auth/reset-access/request", json={"email": user.email},
                        headers={"Host": "evil.example", "X-Forwarded-Host": "evil.example",
                                 "X-Forwarded-Proto": "http", "Forwarded": "host=evil.example"})
        assert r.status_code == 200 and len(email_on) == 1
        sent = email_on[0]
        assert "evil.example" not in sent["text_body"] and "evil.example" not in sent["html_body"]
        assert "https://shikari.example.net/reset-access#" in sent["text_body"]

    def test_without_base_url_the_endpoint_refuses_whatever_the_host(self, client, user, monkeypatch):
        from shikari.auth import email as email_module

        sent = []
        monkeypatch.setattr(email_module, "EMAIL_ENABLED", True)
        monkeypatch.setattr(email_module, "send_email", lambda **kw: sent.append(kw) or True)
        monkeypatch.delenv("BASE_URL", raising=False)
        r = client.post("/api/auth/reset-access/request", json={"email": user.email},
                        headers={"Host": "evil.example"})
        assert r.status_code == 503 and r.json()["error"] == app_module.SELF_SERVICE_OFF and not sent
        page = client.get("/forgot-password")
        assert "Ask an administrator" in page.text and 'id="forgot-form"' not in page.text
