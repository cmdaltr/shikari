"""
Pairing with Ostraka (docs/suite/INTEGRATION.md, "Pairing"): an admin makes a one-use link here
(Settings → Config → Pair with Ostraka, or POST /api/pairing), an Ostraka admin pastes it into Ostraka,
and Ostraka claims it. The claim makes an API token in the `ostraka` scope (shikari/auth/tokens.py) and
a webhook to Ostraka for the hunt-run events (shikari/webhooks.py) together, and answers with both
secrets, which aren't shown anywhere else.

    POST   /api/pairing           {"note"} -> 201 {"id", "link", "expires_at"}           admin
    GET    /api/pairing           every code not withdrawn, newest first                  admin
    DELETE /api/pairing/{id}      withdraws an unclaimed code -> 204                      admin
    POST   /api/pairing/claim     {"code", "product", "name", "version", "webhook_url"}   no sign-in

The link is <public origin>/pair#pair_<token>: SHIKARI_PUBLIC_URL when it's set (as webhooks name the
server), else the address the admin asked from. A code works once, within 10 minutes; only its SHA-256
is stored, and it's claimed with one conditional UPDATE, so of two claims at once only one succeeds.
The code is the credential, so the claim needs no sign-in; a claim is refused (and audited) when the
code is unknown, spent or withdrawn, has expired, or its admin is deactivated or no longer an admin.
Removing the token (Profile → Security → API tokens) or the webhook undoes a pairing.
"""

import hashlib
import json
import os
import secrets
from datetime import datetime, timedelta
from typing import Dict, List, Optional

from fastapi import APIRouter, Cookie, Request
from fastapi.responses import JSONResponse, Response

CODE_PREFIX = "pair_"
CODE_MINUTES = 10
TOKEN_DAYS = 365
PAIRED_NAME = "Ostraka (paired)"
EVENTS = ("run.completed", "run.failed", "run.executed")

EVENT_PAIRING_CREATED = "pairing_created"
EVENT_PAIRING_WITHDRAWN = "pairing_withdrawn"
EVENT_PAIRING_CLAIMED = "pairing_claimed"
EVENT_PAIRING_CLAIM_REFUSED = "pairing_claim_refused"

NOT_VALID = "This pairing link isn't valid. Ask for a new one."
EXPIRED = "This pairing link has expired. Ask for a new one."

router = APIRouter()


class ClaimRefused(Exception):
    """A claim that can't succeed: the HTTP status and the words the contract gives it."""

    def __init__(self, status: int, detail: str, reason: str):
        super().__init__(detail)
        self.status, self.detail, self.reason = status, detail, reason


def new_code() -> str:
    return CODE_PREFIX + secrets.token_urlsafe(32)


def code_hash(code: str) -> str:
    return hashlib.sha256(code.encode()).hexdigest()


def origin(request: Request) -> str:
    """The server's public origin for a link: SHIKARI_PUBLIC_URL, else the admin's own address."""
    from shikari.auth.links import request_origin

    return (os.getenv("SHIKARI_PUBLIC_URL") or "").strip().rstrip("/") or request_origin(request)


def _iso(when: Optional[datetime]) -> Optional[str]:
    return when.isoformat() + "Z" if when else None


def _audit(db, event: str, *, user_id: Optional[int], email: Optional[str] = None, success: bool = True,
           ip_address: Optional[str] = None, user_agent: Optional[str] = None, **details) -> None:
    from shikari.database.audit import log_audit_event

    log_audit_event(db, event, user_id=user_id, email=email, ip_address=ip_address, user_agent=user_agent,
                    success=success, details=json.dumps(details))


def create_code(db, admin, note: str = "", *, base: str, ip_address: Optional[str] = None,
                user_agent: Optional[str] = None):
    """A new pairing code by this admin: (row, link). The link is only ever returned here."""
    from shikari.database.models import PairingCode

    code = new_code()
    now = datetime.utcnow()
    row = PairingCode(code_hash=code_hash(code), note=(note or "").strip()[:200], created_by=admin.id,
                      created_at=now, expires_at=now + timedelta(minutes=CODE_MINUTES))
    db.add(row)
    db.commit()
    db.refresh(row)
    _audit(db, EVENT_PAIRING_CREATED, user_id=admin.id, email=admin.email, ip_address=ip_address,
           user_agent=user_agent, pairing_id=row.id, note=row.note, expires_in_minutes=CODE_MINUTES)
    return row, f"{base.rstrip('/')}/pair#{code}"


def list_codes(db) -> List[Dict]:
    from shikari.database.models import PairingCode, User

    rows = (db.query(PairingCode, User.email).outerjoin(User, User.id == PairingCode.created_by)
            .filter(PairingCode.withdrawn_at.is_(None)).order_by(PairingCode.created_at.desc()).limit(100).all())
    return [{"id": r.id, "note": r.note, "created_by": email, "created_at": _iso(r.created_at),
             "expires_at": _iso(r.expires_at), "claimed_at": _iso(r.claimed_at),
             "claimed_by_name": r.claimed_by_name} for r, email in rows]


def withdraw_code(db, admin, code_id: int, *, ip_address: Optional[str] = None,
                  user_agent: Optional[str] = None) -> bool:
    """Withdraw an unclaimed code; False when there's no such code or it's been claimed or withdrawn."""
    from shikari.database.models import PairingCode

    done = db.query(PairingCode).filter(PairingCode.id == code_id, PairingCode.claimed_at.is_(None),
                                        PairingCode.withdrawn_at.is_(None)
                                        ).update({"withdrawn_at": datetime.utcnow()}, synchronize_session=False)
    db.commit()
    if done:
        _audit(db, EVENT_PAIRING_WITHDRAWN, user_id=admin.id, email=admin.email, ip_address=ip_address,
               user_agent=user_agent, pairing_id=code_id)
    return bool(done)


def _version() -> str:
    try:
        from importlib.metadata import version

        return version("shikari")
    except Exception:
        return "unknown"


def take(db, code_id: int, now: datetime, name: str, ip_address: Optional[str]) -> bool:
    """Claim the row with one conditional UPDATE, only while it's still open: of two claims that both
    passed the checks, only one changes it."""
    from shikari.database.models import PairingCode

    taken = db.query(PairingCode).filter(PairingCode.id == code_id, PairingCode.claimed_at.is_(None),
                                         PairingCode.withdrawn_at.is_(None), PairingCode.expires_at > now
                                         ).update({"claimed_at": now, "claimed_by_name": name,
                                                   "claim_ip": (ip_address or "")[:45] or None},
                                                  synchronize_session=False)
    db.commit()
    return bool(taken)


def claim(db, body: Dict, *, ip_address: Optional[str] = None, user_agent: Optional[str] = None) -> Dict:
    """Claim a code: the `ostraka` token and the webhook, made together. Raises ClaimRefused (audited)."""
    from samarkand import webhooks as shared

    from shikari import webhooks
    from shikari.auth import tokens
    from shikari.database.models import PairingCode, User, UserRole, at_least

    body = body if isinstance(body, dict) else {}
    code = body.get("code")
    row = None
    if isinstance(code, str) and code.startswith(CODE_PREFIX):
        row = db.query(PairingCode).filter(PairingCode.code_hash == code_hash(code)).first()

    def refuse(status: int, detail: str, reason: str):
        _audit(db, EVENT_PAIRING_CLAIM_REFUSED, user_id=row.created_by if row else None, success=False,
               ip_address=ip_address, user_agent=user_agent, pairing_id=row.id if row else None, reason=reason)
        return ClaimRefused(status, detail, reason)

    now = datetime.utcnow()
    if row is None:
        raise refuse(404, NOT_VALID, "unknown")
    if row.claimed_at is not None:
        raise refuse(404, NOT_VALID, "claimed")
    if row.withdrawn_at is not None:
        raise refuse(404, NOT_VALID, "withdrawn")
    if row.expires_at <= now:
        raise refuse(410, EXPIRED, "expired")
    admin = db.get(User, row.created_by)
    if admin is None or not admin.is_active or not at_least(admin, UserRole.ADMIN):
        raise refuse(404, NOT_VALID, "not an admin")
    url = body.get("webhook_url")
    problem = shared.url_problem(url) if isinstance(url, str) and url.strip() else "Give the webhook's URL."
    if problem:
        raise refuse(422, problem, "webhook_url")

    name = str(body.get("name") or "Ostraka").strip()[:100] or "Ostraka"
    if not take(db, row.id, now, name, ip_address):
        raise refuse(404, NOT_VALID, "claimed")

    expires = now + timedelta(days=TOKEN_DAYS)
    token, info = tokens.create_token(db, admin.id, PAIRED_NAME, scope=tokens.OSTRAKA, expires_at=expires)
    # Made even on a Free install: it doesn't fire until a licence with `automation` is in
    hook = webhooks.add(url.strip(), list(EVENTS), None, PAIRED_NAME)
    db.query(PairingCode).filter(PairingCode.id == row.id).update(
        {"token_id": info["id"], "webhook_id": hook["id"]}, synchronize_session=False)
    db.commit()
    _audit(db, EVENT_PAIRING_CLAIMED, user_id=admin.id, email=admin.email, ip_address=ip_address,
           user_agent=user_agent, pairing_id=row.id, made_by=admin.email, token_prefix=info["prefix"],
           webhook_id=hook["id"], product=str(body.get("product") or "")[:32], name=name,
           version=str(body.get("version") or "")[:32])
    return {"product": "shikari", "version": _version(), "token": token, "token_expires_at": _iso(expires),
            "webhook_id": hook["id"], "webhook_secret": hook["secret"], "events": list(EVENTS)}


# ---------------------------------------------------------------------------------------------------
# Routes


def _db():
    from shikari.database import db as database

    return database.SessionLocal()


def _admin(db, shikari_session: Optional[str]):
    """(admin, None), or (None, the refusal)."""
    from shikari.auth import get_user_from_session_id
    from shikari.database.models import UserRole, at_least

    user = get_user_from_session_id(shikari_session, db) if shikari_session else None
    if not user:
        return None, JSONResponse({"error": "Please log in"}, status_code=401)
    if not at_least(user, UserRole.ADMIN):
        return None, JSONResponse({"error": "Pairing is an admin setting"}, status_code=403)
    return user, None


def _client_ip(request: Request) -> Optional[str]:
    return request.client.host if request.client else None


@router.post("/api/pairing")
async def make_code(request: Request, shikari_session: Optional[str] = Cookie(None)):
    db = _db()
    try:
        admin, denied = _admin(db, shikari_session)
        if denied:
            return denied
        try:
            body = await request.json()
        except ValueError:
            body = {}
        note = body.get("note") if isinstance(body, dict) else ""
        row, link = create_code(db, admin, str(note or ""), base=origin(request), ip_address=_client_ip(request),
                                user_agent=request.headers.get("user-agent"))
        return JSONResponse({"id": row.id, "link": link, "expires_at": _iso(row.expires_at)}, status_code=201)
    finally:
        db.close()


@router.get("/api/pairing")
def open_codes(shikari_session: Optional[str] = Cookie(None)):
    db = _db()
    try:
        _, denied = _admin(db, shikari_session)
        if denied:
            return denied
        return list_codes(db)
    finally:
        db.close()


@router.delete("/api/pairing/{code_id}")
def withdraw(code_id: int, request: Request, shikari_session: Optional[str] = Cookie(None)):
    db = _db()
    try:
        admin, denied = _admin(db, shikari_session)
        if denied:
            return denied
        if not withdraw_code(db, admin, code_id, ip_address=_client_ip(request),
                             user_agent=request.headers.get("user-agent")):
            return JSONResponse({"error": "No open pairing code with that id"}, status_code=404)
        return Response(status_code=204)
    finally:
        db.close()


@router.post("/api/pairing/claim")
async def claim_code(request: Request):
    try:
        body = await request.json()
    except ValueError:
        body = {}
    db = _db()
    try:
        return claim(db, body, ip_address=_client_ip(request), user_agent=request.headers.get("user-agent"))
    except ClaimRefused as e:
        return JSONResponse({"detail": e.detail}, status_code=e.status)
    finally:
        db.close()


PAIR_PAGE = """<!doctype html>
<html lang="en-GB"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Pairing link · Shikari</title></head>
<body style="font-family:system-ui,sans-serif;max-width:40rem;margin:4rem auto;padding:0 16px;line-height:1.6;">
<h1>This is a pairing link</h1>
<p>It pairs Ostraka with this Shikari. Don't open it here: copy the whole link, and paste it into Ostraka
(Settings &rarr; Integrations) as an Ostraka admin. It works once, within 10 minutes of being made.</p>
<p>Lost it, or it's expired? A Shikari admin can make a new one under Settings &rarr; Config &rarr; Pair with
Ostraka.</p>
</body></html>"""


@router.get("/pair", include_in_schema=False)
def pair_page():
    """Where a pairing link lands in a browser: the code stays after #, so it never reaches the server."""
    from fastapi.responses import HTMLResponse

    return HTMLResponse(PAIR_PAGE, headers={"Cache-Control": "no-store"})
