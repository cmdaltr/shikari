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
