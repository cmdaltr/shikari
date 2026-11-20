"""Invitations (shikari/auth/invitations.py): issuing from the admin API and the command line, accepting
on the page, and self-registration closed on a server."""
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
from shikari import licence
from shikari.auth import invitations as inv
from shikari.auth.mfa import verify_backup_code
from shikari.auth.password import hash_password, verify_password
from shikari.auth.session import create_session, get_user_from_session_id
from shikari.database.audit import AuditLog, Base as AuditBase
from shikari.database.models import Base, Invitation, User, UserRole

PASSWORD = "Brand-new-passw0rd!"


@pytest.fixture
def engine():
    eng = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(eng)
    AuditBase.metadata.create_all(eng)
    return eng


@pytest.fixture
def db_factory(engine):
    return sessionmaker(bind=engine)


@pytest.fixture(autouse=True)
def unlimited_seats(monkeypatch):
    monkeypatch.setattr(licence, "seats_allowed", lambda: None)


def _add_user(db_factory, email, role=UserRole.STANDARD, **extra):
    db = db_factory()
    u = User(email=email, full_name="Someone", password_hash=hash_password("Old-passw0rd-1234567!"), role=role,
             **{"is_active": True, **extra})
    db.add(u)
    db.commit()
    db.refresh(u)
    db.close()
    return u


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
    assert "?" not in link and "token=" not in link
    return link.split("/accept-invite#", 1)[1]


def _invite(db_factory, email="new.person@example.org", role="operator", **kw):
    db = db_factory()
    try:
        return inv.create_invitation(db, email=email, role=role, **kw)[1]
    finally:
        db.close()


def _audits(db_factory, event):
    db = db_factory()
    try:
        return db.query(AuditLog).filter(AuditLog.event_type == event).all()
    finally:
        db.close()


def _csrf(client):
    r = client.get("/accept-invite")
    return re.search(r'let csrf = "([^"]+)"', r.text).group(1)


def _start(client, token, csrf, name="New Person", password=PASSWORD):
    return client.post("/api/auth/invitation/start",
                       json={"token": token, "csrf_token": csrf, "full_name": name, "new_password": password})


def _complete(client, token, csrf, code):
    return client.post("/api/auth/invitation/complete", json={"token": token, "csrf_token": csrf, "code": code})


def _accept(client, token):
    r = _start(client, token, _csrf(client))
    return _complete(client, token, r.json()["csrf_token"], pyotp.TOTP(r.json()["secret"]).now())


@pytest.mark.unit
class TestIssue:
    def test_link_token_hashed_lifetime_and_audit(self, db_factory, admin):
        db = db_factory()
        invitation, link = inv.create_invitation(db, email="New.Person@Example.org", role="operator",
                                                 full_name="New Person", actor=db.get(User, admin.id))
        token = _token(link)
        assert link.startswith(inv.invitation_link(""))
        assert invitation.token_hash == inv.links.token_hash(token) != token
        assert invitation.email == "new.person@example.org" and invitation.role == UserRole.OPERATOR
        assert inv.INVITATION_EXPIRY_HOURS == 24
        assert timedelta(hours=23) < invitation.expires_at - datetime.utcnow() <= timedelta(hours=24)
        db.close()
        [row] = _audits(db_factory, inv.EVENT_INVITATION_CREATED)
        d = json.loads(row.details)
        assert row.user_id == admin.id and row.email == "new.person@example.org"
        assert d["role"] == "operator" and d["actor_email"] == admin.email and d["via"] == "admin"

    def test_a_new_invitation_replaces_the_earlier_one(self, db_factory):
        first, second = _token(_invite(db_factory)), _token(_invite(db_factory))
        db = db_factory()
        assert inv.open_invitation(db, first) is None and inv.open_invitation(db, second) is not None
        db.close()

    def test_an_existing_account_is_pointed_at_reset_access(self, db_factory, admin):
        db = db_factory()
        with pytest.raises(inv.AccountExists, match="Reset access"):
            inv.create_invitation(db, email=admin.email, role="standard")
        db.close()

    def test_bad_email_role_or_name_refused(self, db_factory):
        db = db_factory()
        for kw in ({"email": "nope", "role": "standard"}, {"email": "ok.person@example.org", "role": "god"},
                   {"email": "ok.person@example.org", "role": "standard", "full_name": "<script>"}):
            with pytest.raises(inv.InvitationError):
                inv.create_invitation(db, **kw)
        assert db.query(Invitation).count() == 0
        db.close()

    def test_seats_count_active_accounts_and_open_invitations(self, db_factory, admin, monkeypatch):
        monkeypatch.setattr(licence, "seats_allowed", lambda: 2)
        _invite(db_factory, email="first.one@example.org")  # admin + this = 2
        db = db_factory()
        with pytest.raises(inv.SeatsFull):
            inv.create_invitation(db, email="second.one@example.org", role="standard")
        # Re-inviting the same person replaces their invitation rather than taking another seat
        inv.create_invitation(db, email="first.one@example.org", role="standard")
        db.close()


@pytest.mark.unit
class TestAccept:
    def test_the_whole_flow(self, client, db_factory):
        token = _token(_invite(db_factory, full_name="Suggested Name"))
        csrf = _csrf(client)
        r = client.post("/api/auth/invitation/preview", json={"token": token})
        assert r.json()["email"] == "new.person@example.org" and r.json()["full_name"] == "Suggested Name"

        r = _start(client, token, csrf, name="Chosen Name")
        assert r.status_code == 200 and r.json()["qr_code"].startswith("data:image/png;base64,")
        secret, csrf = r.json()["secret"], r.json()["csrf_token"]
        db = db_factory()
        assert db.query(User).filter(User.email == "new.person@example.org").count() == 0, \
            "no account before the code checks out"
        assert db.query(Invitation).one().pending_mfa_secret == secret
        db.close()

        wrong = next(c for c in ("000000", "111111", "222222") if not pyotp.TOTP(secret).verify(c, valid_window=1))
        for _ in range(7):  # no lockout: there's no account yet (as in Ostraka)
            r = _complete(client, token, csrf, wrong)
            assert r.status_code == 422 and "didn't match" in r.json()["error"]
            csrf = r.json()["csrf_token"]

        r = _complete(client, token, csrf, pyotp.TOTP(secret).now())
        assert r.status_code == 200
        codes = r.json()["backup_codes"]
        session_id = r.cookies.get("shikari_session")
        db = db_factory()
        u = db.query(User).filter(User.email == "new.person@example.org").one()
        assert u.role == UserRole.OPERATOR and u.full_name == "Chosen Name" and u.is_active
        assert verify_password(PASSWORD, u.password_hash)
        assert u.mfa_enabled and u.mfa_secret == secret and verify_backup_code(u.backup_codes, codes[0])[0]
        assert get_user_from_session_id(session_id, db).id == u.id
        row = db.query(Invitation).one()
        assert row.accepted_at and row.user_id == u.id and row.pending_password_hash is None
        db.close()
        [created] = _audits(db_factory, inv.EVENT_ACCOUNT_CREATED)
        assert created.user_id == u.id and json.loads(created.details)["role"] == "operator"

        # Single use
        assert _start(client, token, _csrf(client)).status_code == 410
        assert _complete(client, token, _csrf(client), pyotp.TOTP(secret).now()).status_code == 410
        assert client.post("/api/auth/invitation/preview", json={"token": token}).status_code == 410

    def test_name_and_password_rules(self, client, db_factory):
        token = _token(_invite(db_factory))
        r = _start(client, token, _csrf(client), password="short1!")
        assert r.status_code == 422 and "16 characters" in r.json()["error"]
        r = _start(client, token, r.json()["csrf_token"], name="")
        assert r.status_code == 422

    def test_expired_and_revoked_links_refused(self, client, db_factory, admin):
        token = _token(_invite(db_factory))
        db = db_factory()
        db.query(Invitation).update({"expires_at": datetime.utcnow() - timedelta(seconds=1)})
        db.commit()
        db.close()
        assert _start(client, token, _csrf(client)).status_code == 410
        token = _token(_invite(db_factory, email="other.one@example.org"))
        db = db_factory()
        assert inv.revoke(db, db.query(Invitation).filter_by(email="other.one@example.org").one().id,
                          db.get(User, admin.id))
        db.close()
        assert _start(client, token, _csrf(client)).status_code == 410

    def test_seats_checked_again_at_completion(self, client, db_factory, admin, monkeypatch):
        token = _token(_invite(db_factory))
        monkeypatch.setattr(licence, "seats_allowed", lambda: 1)  # taken since by the admin alone
        r = _accept(client, token)
        assert r.status_code == 402
        db = db_factory()
        assert db.query(User).count() == 1
        db.close()

    def test_an_account_made_meanwhile_is_refused(self, client, db_factory):
        token = _token(_invite(db_factory))
        _add_user(db_factory, "new.person@example.org")
        assert _accept(client, token).status_code == 409

    def test_needs_a_csrf_token_and_no_query_token(self, client, db_factory):
        token = _token(_invite(db_factory))
        assert _start(client, token, "forged").status_code == 403
        r = client.get(f"/accept-invite?token={token}")
        assert "location.hash" in r.text and "URLSearchParams" not in r.text
        csrf = re.search(r'let csrf = "([^"]+)"', r.text).group(1)
        r = client.post(f"/api/auth/invitation/start?token={token}",
                        json={"csrf_token": csrf, "full_name": "A B", "new_password": PASSWORD})
        assert r.status_code == 410

    @pytest.mark.login_gate
    def test_reachable_without_signing_in(self, client, db_factory):
        token = _token(_invite(db_factory))
        assert client.get("/accept-invite").status_code == 200
        assert client.post("/api/auth/invitation/preview", json={"token": token}).status_code == 200
        assert _accept(client, token).status_code == 200


def _signed_in_as(client, db_factory, u):
    db = db_factory()
    client.cookies.set("shikari_session", create_session(u.id, remember_me=False, db=db))
    db.close()


@pytest.mark.unit
class TestAdminEndpoints:
    def test_invite_list_revoke(self, client, db_factory, admin):
        _signed_in_as(client, db_factory, admin)
        r = client.post("/api/admin/invitations", json={"email": "new.person@example.org", "role": "admin"})
        assert r.status_code == 200 and "/accept-invite#" in r.json()["link"] and r.json()["expires_in_hours"] == 24
        listed = client.get("/api/admin/invitations").json()["invitations"]
        assert [i["email"] for i in listed] == ["new.person@example.org"] and listed[0]["role"] == "admin"
        assert client.delete(f"/api/admin/invitations/{listed[0]['id']}").json()["success"]
        assert client.get("/api/admin/invitations").json()["invitations"] == []
        assert client.delete(f"/api/admin/invitations/{listed[0]['id']}").status_code == 404
        [revoked] = _audits(db_factory, inv.EVENT_INVITATION_REVOKED)
        assert revoked.user_id == admin.id and revoked.email == "new.person@example.org"

    def test_refusals(self, client, db_factory, admin, monkeypatch):
        _signed_in_as(client, db_factory, admin)
        r = client.post("/api/admin/invitations", json={"email": admin.email, "role": "standard"})
        assert r.status_code == 409 and "Reset access" in r.json()["error"]
        monkeypatch.setattr(licence, "seats_allowed", lambda: 1)
        assert client.post("/api/admin/invitations",
                           json={"email": "new.person@example.org", "role": "standard"}).status_code == 402

    def test_permanent_admins_only(self, client, db_factory):
        assert client.post("/api/admin/invitations", json={}).status_code == 401
        temp = _add_user(db_factory, "temp.admin@example.org", temp_role=UserRole.ADMIN,
                         temp_role_expires=datetime.utcnow() + timedelta(hours=1))
        _signed_in_as(client, db_factory, temp)
        for method, path in (("POST", "/api/admin/invitations"), ("GET", "/api/admin/invitations"),
                             ("DELETE", "/api/admin/invitations/1")):
            assert client.request(method, path, json={"email": "x.person@example.org"}).status_code == 403
        db = db_factory()
        assert db.query(Invitation).count() == 0
        db.close()

    def test_creating_a_user_with_a_typed_password_is_gone(self, client, db_factory, admin):
        _signed_in_as(client, db_factory, admin)
        r = client.post("/api/admin/users", json={"email": "typed.pass@example.org", "full_name": "Typed",
                                                  "password": PASSWORD, "role": "standard"})
        assert r.status_code == 405
        db = db_factory()
        assert db.query(User).filter(User.email == "typed.pass@example.org").count() == 0
        db.close()


@pytest.fixture
def desktop():
    """Set app.state.desktop for a test (starlette's State doesn't undo cleanly under monkeypatch)."""
    was = app_module.app.state.desktop

    def set_(value):
        app_module.app.state.desktop = value
    yield set_
    app_module.app.state.desktop = was


@pytest.mark.unit
class TestRegistration:
    def test_closed_on_a_server(self, client, desktop):
        desktop(False)
        r = client.get("/register")
        assert r.status_code == 303 and r.headers["location"] == "/login?invite_only=1"
        r = client.post("/register", data={"email": "self.made@example.org", "full_name": "Self Made",
                                           "password": PASSWORD, "password_confirm": PASSWORD, "csrf_token": "t"})
        assert r.status_code == 303 and r.headers["location"] == "/login?invite_only=1"
        page = client.get("/login?invite_only=1").text
        assert "Ask an admin for an invitation" in page and 'href="/register"' not in page

    def test_open_in_the_desktop_app(self, client, desktop):
        desktop(True)
        assert client.get("/register").status_code == 200
        assert 'href="/register"' in client.get("/login").text


@pytest.mark.unit
class TestCommandLine:
    @pytest.fixture(autouse=True)
    def _database(self, monkeypatch, engine, db_factory):
        from shikari.database import db as db_module

        monkeypatch.setattr(db_module, "engine", engine)
        monkeypatch.setattr(db_module, "SessionLocal", db_factory)

    def test_invite_prints_the_link(self, db_factory, capsys):
        from shikari.cli.invite import main

        assert main(["new.person@example.org", "--role", "operator", "--name", "New Person"]) == 0
        link = re.search(r"(\S+/accept-invite#\S+)", capsys.readouterr().out).group(1)
        db = db_factory()
        row = inv.open_invitation(db, _token(link))
        assert row.role == UserRole.OPERATOR and row.full_name == "New Person" and row.invited_by is None
        db.close()
        [a] = _audits(db_factory, inv.EVENT_INVITATION_CREATED)
        assert json.loads(a.details)["via"] == "cli"

    def test_invite_refuses_an_existing_account(self, db_factory, admin, capsys):
        from shikari.cli.invite import main

        assert main([admin.email]) == 1 and "Reset access" in capsys.readouterr().err

    def test_bootstrap_refused_while_an_admin_exists_unless_forced(self, db_factory, admin, capsys):
        from shikari.cli.invite import ADMIN_EXISTS, main

        assert main(["new.admin@example.org", "--bootstrap"]) == ADMIN_EXISTS
        assert main(["new.admin@example.org", "--bootstrap", "--force"]) == 0
        db = db_factory()
        assert db.query(Invitation).one().role == UserRole.ADMIN
        db.close()

    def test_bootstrap_with_no_admin_and_only_the_newest_link_works(self, db_factory, capsys, monkeypatch):
        from shikari.cli.invite import main

        monkeypatch.setattr(licence, "seats_allowed", lambda: 0)  # getting back in always works
        assert main(["first.admin@example.org", "--bootstrap"]) == 0
        assert main(["second.admin@example.org", "--bootstrap"]) == 0
        db = db_factory()
        assert [i.email for i in inv.pending(db)] == ["second.admin@example.org"]
        db.close()

    def test_create_admin_script_is_the_bootstrap(self, monkeypatch):
        import importlib.util
        from pathlib import Path

        calls = []
        monkeypatch.setattr("shikari.cli.invite.invite", lambda *a, **k: calls.append((a, k)) or 0)
        path = Path(__file__).parents[2] / "scripts" / "admin" / "create_admin.py"
        cwd = Path.cwd()
        try:
            spec = importlib.util.spec_from_file_location("create_admin", path)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            assert module.main(["boss.two@example.org", "--force"]) == 0
        finally:
            import os
            os.chdir(cwd)
        assert calls == [(("boss.two@example.org", "admin"), {"bootstrap": True, "force": True})]

    def test_on_the_host_command(self):
        from shikari import service

        assert service.HANDOVER["invite"] == ("shikari.cli.invite", False)


def _held(db_factory, link):
    """Name and password chosen on the invitation; returns a current code from its new authenticator."""
    db = db_factory()
    invitation = inv.open_invitation(db, _token(link))
    secret = inv.start_invitation(db, invitation, "New Person", PASSWORD)
    db.close()
    return pyotp.TOTP(secret).now()


@pytest.mark.unit
class TestDeadLinksAndRaces:
    def test_the_bootstrap_completes_when_seats_are_full(self, db_factory, monkeypatch):
        monkeypatch.setattr(licence, "seats_allowed", lambda: 1)
        _add_user(db_factory, "only.user@example.org")
        db = db_factory()
        link = inv.bootstrap_admin(db, "first.admin@example.org")[1]
        db.close()
        code = _held(db_factory, link)
        db = db_factory()
        user, _ = inv.complete_invitation(db, inv.open_invitation(db, _token(link)), code)
        assert user.role == UserRole.ADMIN
        db.close()

    def test_an_invitation_dies_with_its_admins_role(self, db_factory, admin):
        link = _invite(db_factory, role="admin", actor=admin)
        code = _held(db_factory, link)
        db = db_factory()
        db.query(User).filter(User.id == admin.id).update({"role": UserRole.STANDARD})
        db.commit()
        with pytest.raises(inv.InvitationError, match="no longer can"):
            inv.complete_invitation(db, inv.open_invitation(db, _token(link)), code)
        db.close()

    def test_an_invitation_is_accepted_once_when_two_try_at_the_same_time(self, db_factory, admin):
        link = _invite(db_factory, actor=admin)
        code = _held(db_factory, link)
        first, second = db_factory(), db_factory()
        one, two = inv.open_invitation(first, _token(link)), inv.open_invitation(second, _token(link))
        inv.complete_invitation(first, one, code)
        with pytest.raises(inv.InvitationError):
            inv.complete_invitation(second, two, code)
        first.close(), second.close()

    def test_a_revoked_invitation_keeps_nothing_chosen(self, db_factory, admin):
        link = _invite(db_factory, actor=admin)
        _held(db_factory, link)
        db = db_factory()
        invitation = db.query(Invitation).one()
        assert inv.revoke(db, invitation.id, admin)
        db.refresh(invitation)
        assert not (invitation.pending_password_hash or invitation.pending_mfa_secret or invitation.pending_full_name)
        db.close()
