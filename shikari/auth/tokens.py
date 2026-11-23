"""
Personal API tokens: `Authorization: Bearer shik_...` signs a request in as the token's
owner. The app's middleware turns a valid token into an ordinary session cookie for the
request, so every route accepts tokens without changes.

Tokens are random, shown once, and stored as SHA-256 hashes. A request signed in with a
token can't create more tokens: revoking a leaked token is then enough.

A token has a scope. `full` (every token made on the profile page, and every token from before scopes)
may do anything its owner may. `ostraka` is the token a pairing makes (shikari/pairing.py): it may only
read coverage, hunt runs, results and progress and start hunt runs, as docs/suite/INTEGRATION.md lists,
and the app's middleware refuses anything else with 403 (allows()). A token may also expire.
"""

import hashlib
import re
import secrets
import threading
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple

PREFIX = "shik_"
_LEGACY_PREFIXES = ("arch_",)   # tokens issued before the rename still sign in
_TOUCH_EVERY = timedelta(minutes=5)

_sessions: Dict[str, str] = {}   # token hash -> session id it maps to
_lock = threading.Lock()

FULL, OSTRAKA = "full", "ostraka"
SCOPES = (FULL, OSTRAKA)

# What an `ostraka` token may ask for (docs/suite/INTEGRATION.md, "The ostraka token scope"): the method
# and the whole path, matched exactly. One path segment where an id or a group goes.
_SEGMENT = r"[^/]+"
OSTRAKA_ROUTES = tuple((method, re.compile(f"^{pattern}$")) for method, pattern in (
    ("GET", "/health"),
    ("GET", "/api/coverage"),
    ("GET", "/api/runs"),
    ("GET", f"/api/runs/{_SEGMENT}"),
    ("GET", f"/api/results/{_SEGMENT}"),
    ("GET", "/progress_status"),
    ("POST", "/api/runs"),
))


def allows(scope: Optional[str], method: str, path: str) -> bool:
    """Whether a token of this scope may make this request. A full token (or one from before scopes,
    NULL) may make any; an `ostraka` one only OSTRAKA_ROUTES; an unknown scope none."""
    if scope in (None, "", FULL):
        return True
    if scope == OSTRAKA:
        return any(method.upper() == m and pattern.match(path) for m, pattern in OSTRAKA_ROUTES)
    return False


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def create_token(db, user_id: int, name: str, *, scope: str = FULL,
                 expires_at: Optional[datetime] = None) -> Tuple[str, Dict]:
    """A new token for the user, and how the API describes it; the token itself is only returned here."""
    from shikari.database.models import ApiToken

    if scope not in SCOPES:
        raise ValueError(f"A token's scope is one of: {', '.join(SCOPES)}")
    token = PREFIX + secrets.token_urlsafe(32)
    row = ApiToken(user_id=user_id, name=(name or "API token").strip()[:100], token_hash=_hash(token),
                   prefix=token[:len(PREFIX) + 6], scope=scope, expires_at=expires_at)
    db.add(row)
    db.commit()
    return token, _describe(row)


def list_tokens(db, user_id: int) -> List[Dict]:
    from shikari.database.models import ApiToken

    rows = db.query(ApiToken).filter(ApiToken.user_id == user_id).order_by(ApiToken.created_at.desc()).all()
    return [_describe(r) for r in rows]


def revoke_token(db, user_id: int, token_id: int) -> bool:
    from shikari.auth.session import delete_session
    from shikari.database.models import ApiToken

    row = db.query(ApiToken).filter(ApiToken.id == token_id, ApiToken.user_id == user_id).first()
    if not row:
        return False
    with _lock:
        session_id = _sessions.pop(row.token_hash, None)
    db.delete(row)
    db.commit()
    if session_id:
        delete_session(session_id, db)
    return True


def revoke_all(db, user_id: int) -> int:
    """Revoke every token the user has (the caller commits); how many there were."""
    from shikari.database.models import ApiToken

    rows = db.query(ApiToken).filter(ApiToken.user_id == user_id).all()
    with _lock:
        for row in rows:
            _sessions.pop(row.token_hash, None)
    for row in rows:
        db.delete(row)
    return len(rows)


def session_for(token: str) -> Optional[str]:
    """The session id a valid token signs in as (created on first use), else None."""
    found = resolve(token)
    return found[0] if found else None


def resolve(token: str) -> Optional[Tuple[str, str]]:
    """(session id, scope) for a valid, unexpired token (the session created on first use), else None."""
    from shikari.auth.session import create_session, get_user_from_session_id
    from shikari.database import db as database
    from shikari.database.models import ApiToken

    if not token.startswith((PREFIX,) + _LEGACY_PREFIXES):
        return None
    digest = _hash(token)
    from sqlalchemy.exc import SQLAlchemyError

    db = database.SessionLocal()
    try:
        try:
            row = db.query(ApiToken).filter(ApiToken.token_hash == digest).first()
        except SQLAlchemyError:
            # A database start-up hasn't brought up to date (init_db adds scope): refuse, don't fail
            return None
        if row is None or (row.expires_at is not None and row.expires_at <= datetime.utcnow()):
            return None
        with _lock:
            session_id = _sessions.get(digest)
        user = get_user_from_session_id(session_id, db) if session_id else None
        if user is None or user.id != row.user_id:
            session_id = create_session(row.user_id, remember_me=True, db=db)
            with _lock:
                _sessions[digest] = session_id
        now = datetime.utcnow()
        if row.last_used_at is None or now - row.last_used_at > _TOUCH_EVERY:
            row.last_used_at = now
            db.commit()
        return session_id, row.scope or FULL
    finally:
        db.close()


def _iso(when: Optional[datetime]) -> Optional[str]:
    return when.isoformat() + "Z" if when else None


def _describe(row) -> Dict:
    return {"id": row.id, "name": row.name, "prefix": row.prefix, "scope": row.scope or FULL,
            "created": _iso(row.created_at), "last_used": _iso(row.last_used_at),
            "expires": _iso(row.expires_at)}
