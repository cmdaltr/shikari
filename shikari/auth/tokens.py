"""
Personal API tokens: `Authorization: Bearer arch_...` signs a request in as the token's
owner. The app's middleware turns a valid token into an ordinary session cookie for the
request, so every route accepts tokens without changes.

Tokens are random, shown once, and stored as SHA-256 hashes. A request signed in with a
token can't create more tokens: revoking a leaked token is then enough.
"""

import hashlib
import secrets
import threading
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple

PREFIX = "arch_"
_TOUCH_EVERY = timedelta(minutes=5)

_sessions: Dict[str, str] = {}   # token hash -> session id it maps to
_lock = threading.Lock()


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def create_token(db, user_id: int, name: str) -> Tuple[str, Dict]:
    from shikari.database.models import ApiToken

    token = PREFIX + secrets.token_urlsafe(32)
    row = ApiToken(user_id=user_id, name=(name or "API token").strip()[:100], token_hash=_hash(token),
                   prefix=token[:len(PREFIX) + 6])
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


def session_for(token: str) -> Optional[str]:
    """The session id a valid token signs in as (created on first use), else None."""
    from shikari.auth.session import create_session, get_user_from_session_id
    from shikari.database.db import SessionLocal
    from shikari.database.models import ApiToken

    if not token.startswith(PREFIX):
        return None
    digest = _hash(token)
    db = SessionLocal()
    try:
        row = db.query(ApiToken).filter(ApiToken.token_hash == digest).first()
        if row is None:
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
        return session_id
    finally:
        db.close()


def _describe(row) -> Dict:
    return {"id": row.id, "name": row.name, "prefix": row.prefix,
            "created": row.created_at.isoformat() + "Z" if row.created_at else None,
            "last_used": row.last_used_at.isoformat() + "Z" if row.last_used_at else None}
