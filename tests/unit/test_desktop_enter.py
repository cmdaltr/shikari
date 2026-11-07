"""The desktop app's window signs itself in with a one-time token; nothing else can use the route."""
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import shikari.app as app_module
from shikari.auth.password import hash_password
from shikari.database.models import Base, User, UserRole

TOKEN = "t" * 43


@pytest.fixture
def db_factory():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine)
    db = factory()
    db.add(User(email="admin@shikari.app", full_name="Admin", password_hash=hash_password("Original-passw0rd-123"),
                role=UserRole.ADMIN, is_active=True))
    db.commit()
    db.close()
    return factory


def _client(db_factory, monkeypatch, host="127.0.0.1"):
    def _get_db():
        db = db_factory()
        try:
            yield db
        finally:
            db.close()
    monkeypatch.setattr(app_module, "get_db", _get_db)
    return TestClient(app_module.app, client=(host, 50000), follow_redirects=False)


def test_window_signs_in_once(db_factory, monkeypatch):
    monkeypatch.setenv("SHIKARI_DESKTOP_TOKEN", TOKEN)
    client = _client(db_factory, monkeypatch)
    first = client.get(f"/desktop/enter?token={TOKEN}")
    assert first.status_code == 303 and first.headers["location"] == "/"
    assert "shikari_session=" in first.headers["set-cookie"]
    # Spent: a second use (a browser replaying the URL) goes to the login page
    again = _client(db_factory, monkeypatch).get(f"/desktop/enter?token={TOKEN}")
    assert again.headers["location"] == "/login" and "set-cookie" not in again.headers


@pytest.mark.parametrize("token, host, env", [
    ("wrong", "127.0.0.1", TOKEN),        # a guess
    (TOKEN, "192.0.2.10", TOKEN),         # not this computer
    (TOKEN, "127.0.0.1", None),           # a server the desktop app didn't start
])
def test_everything_else_goes_to_login(db_factory, monkeypatch, token, host, env):
    if env:
        monkeypatch.setenv("SHIKARI_DESKTOP_TOKEN", env)
    else:
        monkeypatch.delenv("SHIKARI_DESKTOP_TOKEN", raising=False)
    r = _client(db_factory, monkeypatch, host).get(f"/desktop/enter?token={token}")
    assert r.status_code == 303 and r.headers["location"] == "/login"
    assert "set-cookie" not in r.headers
