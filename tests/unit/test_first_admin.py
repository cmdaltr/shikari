"""First admins (shikari/deployment.py): a local Shikari's default `admin`, only on loopback; a team server's
first-admin invitation, and `shikari first-admin` / scripts/admin/create_admin.py."""
import json
import re

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import shikari.app as app_module
from shikari import deployment, licence
from shikari.auth import invitations as inv
from shikari.auth.password import hash_password, verify_password
from shikari.database.audit import AuditLog, Base as AuditBase
from shikari.database.models import Base, Invitation, User, UserRole


@pytest.fixture
def engine():
    eng = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(eng)
    AuditBase.metadata.create_all(eng)
    return eng


@pytest.fixture
def db_factory(engine):
    return sessionmaker(bind=engine)


@pytest.fixture
def db(db_factory):
    session = db_factory()
    yield session
    session.close()


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    for name in ("SHIKARI_MODE", "SHIKARI_ADMIN_EMAIL", "SHIKARI_HOST", "UVICORN_HOST"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(licence, "seats_allowed", lambda: None)


def _admin(db, email, password="Some-passw0rd-1234567!"):
    u = User(email=email, full_name="Admin", password_hash=hash_password(password), role=UserRole.ADMIN,
             is_active=True)
    db.add(u)
    db.commit()
    return u


LOOPBACK = ["uvicorn", "shikari.app:app", "--host", "127.0.0.1"]


@pytest.mark.unit
class TestTheSignal:
    def test_server_only_when_it_says_so(self, monkeypatch):
        assert not deployment.is_server()
        for value in ("local", "", "1", "true"):
            monkeypatch.setenv("SHIKARI_MODE", value)
            assert not deployment.is_server()
        monkeypatch.setenv("SHIKARI_MODE", "Server")
        assert deployment.is_server()

    @pytest.mark.parametrize("argv,host", [(["x", "--host", "0.0.0.0"], "0.0.0.0"), (["x", "--host=::"], "::"),
                                           (["x"], None)])
    def test_bind_host_from_the_command_line(self, argv, host):
        assert deployment.bind_host(argv) == host

    def test_bind_host_falls_back_to_shikari_host(self, monkeypatch):
        monkeypatch.setenv("SHIKARI_HOST", "10.0.0.5")
        assert deployment.bind_host(["x"]) == "10.0.0.5"

    def test_bind_host_reads_uvicorns_own_setting(self, monkeypatch):
        """`UVICORN_HOST=0.0.0.0 uvicorn shikari.app:app` binds every address with no --host given."""
        monkeypatch.setenv("UVICORN_HOST", "0.0.0.0")
        monkeypatch.setenv("SHIKARI_HOST", "127.0.0.1")
        assert deployment.bind_host(["uvicorn", "shikari.app:app"]) == "0.0.0.0"
        assert deployment.bind_host(["uvicorn", "--host", "127.0.0.1"]) == "127.0.0.1", "--host wins, as in uvicorn"

    def test_registration_open_only_locally_on_loopback(self, monkeypatch):
        assert deployment.registration_open(LOOPBACK)
        assert not deployment.registration_open(["uvicorn", "--host", "0.0.0.0"])
        monkeypatch.setenv("UVICORN_HOST", "192.168.1.4")
        assert not deployment.registration_open(["uvicorn"])
        monkeypatch.delenv("UVICORN_HOST")
        monkeypatch.setenv("SHIKARI_MODE", "server")
        assert not deployment.registration_open(LOOPBACK)

    @pytest.mark.parametrize("host,ok", [(None, True), ("127.0.0.1", True), ("::1", True), ("[::1]", True),
                                         ("localhost", True), ("127.0.0.2", True), ("0.0.0.0", False),
                                         ("::", False), ("192.168.1.10", False), ("100.64.1.2", False),
                                         ("shikari.example.org", False)])
    def test_loopback_only(self, host, ok):
        assert deployment.loopback_only(host) is ok


@pytest.mark.unit
class TestLocal:
    def test_seeds_admin_with_the_default_password(self, db):
        assert deployment.ensure_first_admin(db, LOOPBACK) == "seeded"
        [u] = db.query(User).all()
        assert u.email == "admin" and u.role == UserRole.ADMIN and verify_password("BigGameHunter", u.password_hash)
        assert deployment.ensure_first_admin(db, LOOPBACK) == "nothing"  # idempotent
        assert db.query(User).count() == 1
        [row] = db.query(AuditLog).filter(AuditLog.event_type == deployment.EVENT_DEFAULT_ADMIN_SEEDED).all()
        assert row.user_id == u.id and row.email == "admin" and row.success

    def test_not_seeded_when_uvicorn_host_is_a_network_address(self, db, monkeypatch):
        monkeypatch.setenv("UVICORN_HOST", "0.0.0.0")
        assert deployment.ensure_first_admin(db, ["uvicorn", "shikari.app:app"]) == "refused-network"
        assert db.query(User).count() == 0
        assert not db.query(AuditLog).filter(AuditLog.event_type == deployment.EVENT_DEFAULT_ADMIN_SEEDED).count()

    def test_desktop_app_counts_as_loopback(self, db):
        assert deployment.ensure_first_admin(db, ["python", "-m", "shikari"]) == "seeded"

    @pytest.mark.parametrize("argv", [["uvicorn", "--host", "0.0.0.0"], ["serve", "--host=192.168.1.4"]])
    def test_not_seeded_on_a_network_address(self, db, argv, capsys):
        assert deployment.ensure_first_admin(db, argv) == "refused-network"
        assert db.query(User).count() == 0
        out = capsys.readouterr().out
        assert "No default admin" in out and "shikari first-admin" in out

    def test_renames_the_old_default_admin(self, db_factory, db):
        old = _admin(db, "admin@shikari.app", "BigGameHunter")
        assert deployment.ensure_first_admin(db, LOOPBACK) == "renamed"
        db.expire_all()
        assert db.get(User, old.id).email == "admin"
        assert deployment.ensure_first_admin(db, LOOPBACK) == "nothing"
        [row] = db.query(AuditLog).filter(AuditLog.event_type == deployment.EVENT_DEFAULT_ADMIN_RENAMED).all()
        assert row.user_id == old.id

    def test_no_rename_when_admin_is_taken(self, db):
        _admin(db, "admin")
        old = _admin(db, "admin@shikari.app")
        assert deployment.ensure_first_admin(db, LOOPBACK) == "nothing"
        db.expire_all()
        assert db.get(User, old.id).email == "admin@shikari.app"

    def test_signs_in_as_admin(self, db_factory, monkeypatch):
        from shikari.security import csrf, rate_limit

        db = db_factory()
        deployment.ensure_first_admin(db, LOOPBACK)
        db.close()

        def _get_db():
            s = db_factory()
            try:
                yield s
            finally:
                s.close()
        monkeypatch.setattr(app_module, "get_db", _get_db)
        monkeypatch.setattr(csrf, "validate_csrf_token", lambda *a: True)
        monkeypatch.setattr(rate_limit, "check_rate_limit", lambda key, **kw: (True, 5))
        client = TestClient(app_module.app, follow_redirects=False)
        page = client.get("/login").text
        assert 'type="text"' in page and "or admin" in page  # the field takes a plain username here
        client.cookies.set("shikari_csrf_session", "x")
        r = client.post("/login", data={"email": "admin", "password": "BigGameHunter", "csrf_token": "t"})
        assert r.status_code == 303 and r.cookies.get("shikari_session")


@pytest.mark.unit
class TestServer:
    @pytest.fixture(autouse=True)
    def server(self, monkeypatch):
        monkeypatch.setenv("SHIKARI_MODE", "server")

    def test_seeds_nothing_and_says_how(self, db, capsys):
        assert deployment.ensure_first_admin(db, LOOPBACK) == "waiting"
        assert db.query(User).count() == 0 and db.query(Invitation).count() == 0
        assert "shikari first-admin" in capsys.readouterr().out

    def test_issues_and_prints_the_first_admin_invitation(self, db, monkeypatch, capsys):
        monkeypatch.setenv("SHIKARI_ADMIN_EMAIL", "first.admin@example.org")
        monkeypatch.delenv("BASE_URL", raising=False)
        assert deployment.ensure_first_admin(db, LOOPBACK) == "invited"
        assert db.query(User).count() == 0
        printed = capsys.readouterr()
        out = printed.out
        assert "BASE_URL isn't set" in printed.err, "a localhost link is warned about on stderr"
        link = re.search(r"(\S+/accept-invite#\S+)", out).group(1)
        row = inv.open_invitation(db, link.split("#", 1)[1])
        assert row.email == "first.admin@example.org" and row.role == UserRole.ADMIN and row.invited_by is None
        # A restart while it's open doesn't issue another
        assert deployment.ensure_first_admin(db, LOOPBACK) == "pending"
        assert db.query(Invitation).count() == 1

    def test_nothing_once_there_is_an_admin(self, db, monkeypatch):
        monkeypatch.setenv("SHIKARI_ADMIN_EMAIL", "first.admin@example.org")
        _admin(db, "boss@example.org")
        assert deployment.ensure_first_admin(db, LOOPBACK) == "nothing"
        assert db.query(Invitation).count() == 0

    def test_no_rename_and_a_warning_for_a_leftover_default_password(self, db, capsys):
        old = _admin(db, "admin@shikari.app", "BigGameHunter")
        assert deployment.ensure_first_admin(db, LOOPBACK) == "nothing"
        db.expire_all()
        assert db.get(User, old.id).email == "admin@shikari.app"
        assert "public default password" in capsys.readouterr().out


@pytest.mark.unit
class TestFirstAdminCommand:
    @pytest.fixture(autouse=True)
    def _database(self, monkeypatch, engine, db_factory):
        from shikari.database import db as db_module

        monkeypatch.setattr(db_module, "engine", engine)
        monkeypatch.setattr(db_module, "SessionLocal", db_factory)

    def test_refused_while_an_admin_exists_unless_forced(self, db, capsys):
        from shikari.cli.first_admin import ADMIN_EXISTS, main

        _admin(db, "boss@example.org")
        assert main(["new.admin@example.org"]) == ADMIN_EXISTS == 5  # the same in Ostraka and Rowanholt
        assert "already has an active admin" in capsys.readouterr().err
        assert main(["new.admin@example.org", "--force"]) == 0
        assert db.query(Invitation).one().role == UserRole.ADMIN

    def test_link_only_and_only_the_newest_works(self, db, capsys, monkeypatch):
        from shikari.cli.first_admin import main

        monkeypatch.setattr(licence, "seats_allowed", lambda: 0)  # getting a first admin always works
        assert main(["first.admin@example.org", "--link-only"]) == 0
        out = capsys.readouterr().out.strip()
        assert re.fullmatch(r"\S+/accept-invite#\S+", out)
        assert main(["second.admin@example.org"]) == 0
        assert [i.email for i in inv.pending(db)] == ["second.admin@example.org"]
        [revoked] = db.query(AuditLog).filter(AuditLog.event_type == inv.EVENT_INVITATION_REVOKED).all()
        assert revoked.email == "first.admin@example.org" and json.loads(revoked.details)["reason"] == "replaced"

    def test_every_printed_link_warns_without_base_url(self, db, capsys, monkeypatch):
        from shikari.cli.first_admin import main
        from shikari.cli.invite import main as invite_main
        from shikari.cli.reset_access import main as reset_main

        monkeypatch.delenv("BASE_URL", raising=False)
        assert main(["first.admin@example.org", "--link-only"]) == 0
        assert "BASE_URL isn't set" in capsys.readouterr().err
        assert invite_main(["someone@example.org"]) == 0
        assert "BASE_URL isn't set" in capsys.readouterr().err
        _admin(db, "boss@example.org")
        assert reset_main(["boss@example.org"]) == 0
        assert "BASE_URL isn't set" in capsys.readouterr().err
        monkeypatch.setenv("BASE_URL", "https://shikari.example.net")
        assert invite_main(["another@example.org"]) == 0
        assert "BASE_URL" not in capsys.readouterr().err

    def test_create_admin_script_runs_it(self, monkeypatch):
        import importlib.util
        import os
        from pathlib import Path

        calls = []
        monkeypatch.setattr("shikari.cli.first_admin.main", lambda *a, **k: calls.append(k) or 0)
        path = Path(__file__).parents[2] / "scripts" / "admin" / "create_admin.py"
        cwd = Path.cwd()
        try:
            spec = importlib.util.spec_from_file_location("create_admin", path)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            assert module.main(prog="create_admin.py") == 0
        finally:
            os.chdir(cwd)
        assert calls == [{"prog": "create_admin.py"}]

    def test_on_the_host_command(self):
        from shikari import service

        assert service.HANDOVER["first-admin"] == ("shikari.cli.first_admin", False)
