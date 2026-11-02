"""Regression tests for the October 2026 review fixes (drafts, XSS, SSRF, password reset, query quoting)."""
import socket

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import shikari.app as app_module
from shikari.auth.password import hash_password, validate_password, verify_password
from shikari.auth.password_reset import create_password_reset_request, reset_password_with_token
from shikari.build.queries import _q
from shikari.database.models import Base, PasswordReset, User, UserRole
from shikari.parsers import blog_analyzer


@pytest.fixture
def db_factory():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine)


@pytest.fixture
def user(db_factory):
    db = db_factory()
    u = User(email="victim@example.org", full_name="Victim", password_hash=hash_password("Original-passw0rd-123"),
             role=UserRole.ADMIN, is_active=True)
    db.add(u)
    db.commit()
    db.refresh(u)
    db.close()
    return u


@pytest.fixture
def client(db_factory, monkeypatch):
    def _get_db():
        db = db_factory()
        try:
            yield db
        finally:
            db.close()
    monkeypatch.setattr(app_module, "get_db", _get_db)
    return TestClient(app_module.app)  # no context manager: startup hooks (ATT&CK load) are not run


@pytest.mark.unit
class TestDescriptionEscaping:
    def test_markup_is_escaped(self):
        out = app_module.markdown_links_to_html('<img src=x onerror=alert(1)> [C0027](https://attack.mitre.org/campaigns/C0027)')
        assert "<img" not in out
        assert '<a href="https://attack.mitre.org/campaigns/C0027" target="_blank" rel="noopener noreferrer">C0027</a>' in out

    def test_javascript_links_are_not_linked(self):
        assert "<a " not in app_module.markdown_links_to_html("[x](javascript:alert(1))")

    def test_library_rebuilds_legacy_html_safely(self):
        legacy = {"description_html": 'See <a href="https://x.test/a" target="_blank">ref</a><script>alert(1)</script>'}
        out = app_module.library_description_html(legacy)
        assert "<script>" not in out and '<a href="https://x.test/a"' in out


@pytest.mark.unit
class TestDrafts:
    def test_requires_login(self, client):
        assert client.post("/save_draft", json={"draft_id": "a"}).status_code == 401

    @pytest.mark.parametrize("draft_id", ["../../etc/x", "a/b", "..", ""])
    def test_traversal_ids_rejected(self, client, draft_id):
        assert client.get("/load_draft", params={"draft_id": draft_id}).status_code == 400


@pytest.mark.unit
class TestPasswordReset:
    def test_reset_flow_round_trip(self, db_factory, user):
        db = db_factory()
        token = create_password_reset_request(user.email, db)
        assert token and db.query(PasswordReset).filter_by(reset_token=token, used=False).count() == 1
        assert reset_password_with_token(token, "New-passw0rd-1234567", db)
        refreshed = db.query(User).get(user.id)
        assert verify_password("New-passw0rd-1234567", refreshed.password_hash)
        assert not reset_password_with_token(token, "Another-passw0rd-123", db), "token must be single use"
        db.close()

    def test_request_reset_never_returns_token(self, client, user, monkeypatch):
        monkeypatch.setattr("shikari.auth.email.EMAIL_ENABLED", False)
        known = client.post("/api/auth/request-reset", json={"email": user.email}).json()
        unknown = client.post("/api/auth/request-reset", json={"email": "nobody@example.org"}).json()
        assert "token" not in known and "reset_url" not in known
        assert known == unknown, "response must not reveal whether the account exists"

    def test_multibyte_password_over_72_bytes_rejected(self):
        pw = "a1!" + "密" * 30  # 33 characters, 93 bytes
        ok, _ = validate_password(pw)
        assert not ok


@pytest.mark.unit
class TestSsrfGuard:
    @staticmethod
    def _resolve_to(monkeypatch, mapping):
        def fake(host, *a, **k):
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (mapping[host], 0))]
        monkeypatch.setattr(socket, "getaddrinfo", fake)

    @pytest.mark.parametrize("ip", ["127.0.0.1", "10.1.2.3", "169.254.169.254", "100.100.1.1", "0.0.0.0"])
    def test_internal_addresses_blocked(self, monkeypatch, ip):
        self._resolve_to(monkeypatch, {"h.test": ip})
        with pytest.raises(ValueError):
            blog_analyzer._check_public_url("http://h.test/")

    def test_redirect_to_internal_blocked(self, monkeypatch):
        self._resolve_to(monkeypatch, {"public.test": "93.184.216.34", "meta.test": "169.254.169.254"})

        class Redirect:
            is_redirect = True
            headers = {"Location": "http://meta.test/latest/meta-data/"}

        calls = []
        monkeypatch.setattr(blog_analyzer.requests, "get", lambda url, **k: calls.append(url) or Redirect())
        with pytest.raises(ValueError):
            blog_analyzer._fetch_public_url("http://public.test/post")
        assert calls == ["http://public.test/post"], "internal hop must not be requested"


@pytest.mark.unit
def test_query_literal_escaping():
    assert _q('C:\\Users\\"x"') == 'C:\\\\Users\\\\\\"x\\"'
