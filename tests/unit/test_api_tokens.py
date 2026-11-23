"""Personal API tokens (shikari/auth/tokens.py): hashed, map to a session, revocable."""

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from shikari.auth import tokens
from shikari.auth.session import get_user_from_session_id
from shikari.database.models import ApiToken, Base, User


@pytest.fixture
def db(tmp_path, monkeypatch):
    engine = create_engine(f"sqlite:///{tmp_path / 't.db'}")
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine)
    session = factory()
    session.add(User(id=1, email="u@x", full_name="u", password_hash="x"))
    session.commit()
    monkeypatch.setattr("shikari.database.db.SessionLocal", factory)
    monkeypatch.setattr(tokens, "_sessions", {})
    yield session
    session.close()


@pytest.mark.unit
def test_a_token_signs_in_as_its_owner_until_revoked(db):
    token, info = tokens.create_token(db, 1, "MCP")
    assert token.startswith("shik_") and info["prefix"] == token[:11]
    stored = db.query(ApiToken).one()
    assert token not in (stored.token_hash, stored.prefix)  # only the hash is kept

    session_id = tokens.session_for(token)
    assert get_user_from_session_id(session_id, db).id == 1
    assert tokens.session_for(token) == session_id  # reused, not a session per request

    assert tokens.session_for("shik_wrong") is None and tokens.session_for("not-a-token") is None
    assert tokens.revoke_token(db, 1, info["id"])
    assert tokens.session_for(token) is None
    assert get_user_from_session_id(session_id, db) is None  # its session is gone too
    assert not tokens.revoke_token(db, 1, info["id"])


@pytest.mark.unit
def test_tokens_are_per_user(db):
    db.add(User(id=2, email="v@x", full_name="v", password_hash="x"))
    db.commit()
    _, info = tokens.create_token(db, 1, "a")
    assert tokens.list_tokens(db, 2) == []
    assert not tokens.revoke_token(db, 2, info["id"])
    assert [t["name"] for t in tokens.list_tokens(db, 1)] == ["a"]


@pytest.mark.unit
def test_tokens_from_before_the_rename_still_sign_in(db):
    legacy = "arch_" + "x" * 43
    db.add(ApiToken(user_id=1, name="old", token_hash=tokens._hash(legacy), prefix=legacy[:11]))
    db.commit()
    assert get_user_from_session_id(tokens.session_for(legacy), db).id == 1


@pytest.mark.unit
def test_existing_tokens_are_full_and_new_ones_say_their_scope(db):
    legacy = "shik_" + "y" * 43
    db.add(ApiToken(user_id=1, name="old", token_hash=tokens._hash(legacy), prefix=legacy[:11]))
    db.commit()
    assert tokens.resolve(legacy)[1] == tokens.FULL  # NULL scope: made before scopes
    token, info = tokens.create_token(db, 1, "Ostraka (paired)", scope=tokens.OSTRAKA)
    assert info["scope"] == "ostraka" and tokens.resolve(token)[1] == tokens.OSTRAKA
    assert {t["name"]: t["scope"] for t in tokens.list_tokens(db, 1)} == {"old": "full", "Ostraka (paired)": "ostraka"}
    with pytest.raises(ValueError):
        tokens.create_token(db, 1, "x", scope="admin")


@pytest.mark.unit
def test_an_expired_token_no_longer_signs_in(db):
    from datetime import datetime, timedelta

    token, _ = tokens.create_token(db, 1, "soon", expires_at=datetime.utcnow() + timedelta(minutes=1))
    assert tokens.session_for(token)
    db.query(ApiToken).update({"expires_at": datetime.utcnow() - timedelta(seconds=1)})
    db.commit()
    assert tokens.session_for(token) is None and tokens.resolve(token) is None


# docs/suite/INTEGRATION.md, "The ostraka token scope": these and nothing else
OSTRAKA_ALLOWED = [("GET", "/health"), ("GET", "/api/coverage"), ("GET", "/api/runs"),
                   ("GET", "/api/runs/3f2a9c01d4e5b6a7"), ("GET", "/api/results/APT29"),
                   ("GET", "/api/results/CVE-2024-3400"), ("GET", "/progress_status"), ("POST", "/api/runs")]
OSTRAKA_REFUSED = [("HEAD", "/health"), ("POST", "/health"), ("POST", "/api/coverage"), ("DELETE", "/api/runs/x"),
                   ("PATCH", "/api/runs/x"), ("POST", "/api/runs/x"), ("GET", "/api/runs/x/detections"),
                   ("GET", "/api/results/APT29/extra"), ("GET", "/api/results"), ("GET", "/api/runs/"),
                   ("GET", "/api/webhooks"), ("POST", "/api/webhooks"), ("GET", "/api/pairing"),
                   ("POST", "/api/pairing"), ("POST", "/api/pairing/claim"), ("DELETE", "/api/pairing/1"),
                   ("GET", "/api/profile/tokens"), ("POST", "/api/profile/tokens"), ("POST", "/generate"),
                   ("POST", "/generate/cve"), ("POST", "/hunt/technique"), ("POST", "/api/batch"),
                   ("GET", "/api/batch"), ("POST", "/api/pivots/leads"), ("GET", "/api/admin/users"),
                   ("POST", "/mcp"), ("GET", "/results"), ("GET", "/profile"), ("GET", "/api/library"),
                   ("GET", "/api/download/all/APT29"), ("GET", "/progress_status/x"), ("GET", "/healthz")]


@pytest.mark.unit
@pytest.mark.parametrize("method,path", OSTRAKA_ALLOWED)
def test_the_ostraka_scope_allows_its_routes(method, path):
    assert tokens.allows(tokens.OSTRAKA, method, path)
    assert tokens.allows(tokens.FULL, method, path) and tokens.allows(None, method, path)


@pytest.mark.unit
@pytest.mark.parametrize("method,path", OSTRAKA_REFUSED)
def test_the_ostraka_scope_refuses_everything_else(method, path):
    assert not tokens.allows(tokens.OSTRAKA, method, path)
    assert tokens.allows(tokens.FULL, method, path)


@pytest.mark.unit
def test_an_unknown_scope_allows_nothing():
    assert not tokens.allows("readonly", "GET", "/health")


@pytest.mark.unit
def test_the_middleware_holds_an_ostraka_token_to_its_scope(db, monkeypatch):
    from fastapi.testclient import TestClient

    import shikari.app as app_module
    from shikari.database.models import UserRole

    db.query(User).filter(User.id == 1).update({"role": UserRole.ADMIN, "is_active": True})
    db.commit()

    def _get_db():
        yield db
    monkeypatch.setattr(app_module, "get_db", _get_db)
    http = TestClient(app_module.app)
    scoped, _ = tokens.create_token(db, 1, "Ostraka (paired)", scope=tokens.OSTRAKA)
    full, _ = tokens.create_token(db, 1, "laptop")

    def call(token, method, path, **kw):
        return http.request(method, path, headers={"Authorization": f"Bearer {token}"}, **kw)

    assert call(scoped, "GET", "/health").status_code == 200
    assert call(scoped, "GET", "/api/runs").status_code == 200
    for method, path in (("GET", "/api/webhooks"), ("POST", "/api/pairing"), ("GET", "/api/profile/tokens"),
                         ("POST", "/api/runs/x"), ("GET", "/login")):
        r = call(scoped, method, path, json={})
        assert r.status_code == 403 and "scope (ostraka)" in r.json()["error"], (method, path)
    # A full token reaches the same routes (an admin's webhooks), refused only by what its owner may do
    assert call(full, "GET", "/api/webhooks").status_code == 200
    assert call(full, "GET", "/api/pairing").status_code == 200
