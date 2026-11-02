"""
Just-in-time privilege elevation: a request → peer-approval → auto-expiring grant workflow.

A user asks for a higher role (Operational analyst or Admin) for a set time. A *different* user
whose own effective role is at least the requested one approves it. The grant then activates after
a short delay and expires on its own; anyone involved (requester, approver or an admin) can revoke
it early. The in-force grant is materialised onto User.temp_role/_starts/_expires, so the hot path
(models.at_least) stays a field read — this module is only touched when a request changes.
"""

from datetime import datetime, timedelta
from typing import List, Optional

from fastapi import APIRouter, Cookie, Request
from fastapi.responses import JSONResponse

from shikari.auth import get_user_from_session_id
from shikari.database.db import get_db
from shikari.database.models import RoleRequest, User, UserRole, at_least, effective_role, role_rank

router = APIRouter(prefix="/api/access", tags=["access"])

ACTIVATION_DELAY = timedelta(minutes=1)  # grant starts this long after approval
ALLOWED_DURATIONS = (1, 4, 8, 24)        # hours
REQUESTABLE = (UserRole.OPERATOR, UserRole.ADMIN)
_LABEL = {UserRole.STANDARD: "Analyst", UserRole.OPERATOR: "Operational analyst", UserRole.ADMIN: "Admin"}


class ElevationError(Exception):
    def __init__(self, message: str, status: int = 400):
        self.message, self.status = message, status


def role_label(role) -> str:
    try:
        return _LABEL.get(role if isinstance(role, UserRole) else UserRole(role), str(role))
    except (ValueError, TypeError):
        return str(role)


def _parse_role(value: str) -> UserRole:
    try:
        role = UserRole(value)
    except (ValueError, TypeError):
        raise ElevationError("Unknown role")
    if role not in REQUESTABLE:
        raise ElevationError("You can only request Operational analyst or Admin")
    return role


def _grant_active(user: User, now: Optional[datetime] = None) -> bool:
    now = now or datetime.utcnow()
    return (user.temp_role is not None and user.temp_role_expires is not None
            and user.temp_role_expires > now)


def create_request(db, user: User, role_value: str, duration_hours, reason: str = "") -> RoleRequest:
    role = _parse_role(role_value)
    try:
        duration = int(duration_hours)
    except (ValueError, TypeError):
        raise ElevationError("Invalid duration")
    if duration not in ALLOWED_DURATIONS:
        raise ElevationError(f"Duration must be one of {', '.join(f'{h}h' for h in ALLOWED_DURATIONS)}")
    if role_rank(role) <= role_rank(user.role):
        raise ElevationError(f"You already have {role_label(user.role)} or higher")
    # One at a time: no open request, no grant still in force
    open_req = (db.query(RoleRequest)
                .filter(RoleRequest.user_id == user.id, RoleRequest.status.in_(("pending", "approved")))
                .order_by(RoleRequest.id.desc()).first())
    if open_req and (open_req.status == "pending" or (open_req.expires_at and open_req.expires_at > datetime.utcnow())):
        raise ElevationError("You already have a pending or active access request")
    req = RoleRequest(user_id=user.id, requested_role=role, duration_hours=duration,
                      reason=(reason or "").strip()[:500] or None, status="pending",
                      requested_at=datetime.utcnow())
    db.add(req)
    db.commit()
    db.refresh(req)
    return req


def decide(db, approver: User, request_id: int, approve: bool) -> RoleRequest:
    req = db.query(RoleRequest).filter(RoleRequest.id == request_id).first()
    if not req:
        raise ElevationError("No such request", 404)
    if req.status != "pending":
        raise ElevationError("That request has already been decided")
    if req.user_id == approver.id:
        raise ElevationError("You can't approve your own request", 403)
    if not at_least(approver, req.requested_role):
        raise ElevationError(f"Approving a {role_label(req.requested_role)} request needs that role or higher", 403)
    now = datetime.utcnow()
    req.approver_id = approver.id
    req.decided_at = now
    if not approve:
        req.status = "denied"
        db.commit()
        db.refresh(req)
        return req
    req.status = "approved"
    req.starts_at = now + ACTIVATION_DELAY
    req.expires_at = req.starts_at + timedelta(hours=req.duration_hours)
    requester = db.query(User).filter(User.id == req.user_id).first()
    requester.temp_role = req.requested_role
    requester.temp_role_starts = req.starts_at
    requester.temp_role_expires = req.expires_at
    db.commit()
    db.refresh(req)
    return req


def revoke(db, actor: User, request_id: int) -> RoleRequest:
    req = db.query(RoleRequest).filter(RoleRequest.id == request_id).first()
    if not req:
        raise ElevationError("No such request", 404)
    if req.status != "approved":
        raise ElevationError("Only an active grant can be revoked")
    allowed = actor.id in (req.user_id, req.approver_id) or at_least(actor, UserRole.ADMIN)
    if not allowed:
        raise ElevationError("Only the requester, the approver or an admin can revoke this", 403)
    req.status = "revoked"
    req.revoked_at = datetime.utcnow()
    req.revoked_by = actor.id
    requester = db.query(User).filter(User.id == req.user_id).first()
    # Clear the materialised grant only if it's still this one
    if requester and requester.temp_role_expires == req.expires_at:
        requester.temp_role = requester.temp_role_starts = requester.temp_role_expires = None
    db.commit()
    db.refresh(req)
    return req


def pending_for(db, approver: User) -> List[RoleRequest]:
    """Pending requests this approver may act on: not their own, and at or below their level."""
    rows = db.query(RoleRequest).filter(RoleRequest.status == "pending",
                                        RoleRequest.user_id != approver.id).order_by(RoleRequest.id.desc()).all()
    return [r for r in rows if at_least(approver, r.requested_role)]


def my_requests(db, user: User, limit: int = 10) -> List[RoleRequest]:
    return (db.query(RoleRequest).filter(RoleRequest.user_id == user.id)
            .order_by(RoleRequest.id.desc()).limit(limit).all())


def active_grants_for(db, viewer: User) -> List[RoleRequest]:
    """Live grants (approved, not yet expired) this viewer may revoke: ones they approved, or any if admin."""
    now = datetime.utcnow()
    rows = (db.query(RoleRequest)
            .filter(RoleRequest.status == "approved", RoleRequest.expires_at > now,
                    RoleRequest.user_id != viewer.id)
            .order_by(RoleRequest.id.desc()).all())
    is_admin = at_least(viewer, UserRole.ADMIN)
    return [r for r in rows if is_admin or r.approver_id == viewer.id]


def serialize(req: RoleRequest, db=None) -> dict:
    def _name(uid):
        if uid is None or db is None:
            return None
        u = db.query(User).filter(User.id == uid).first()
        return u.full_name if u else None

    now = datetime.utcnow()
    state = req.status
    if state == "approved" and req.expires_at and req.expires_at <= now:
        state = "expired"
    elif state == "approved" and req.starts_at and req.starts_at > now:
        state = "scheduled"  # approved, waiting out the activation delay
    return {
        "id": req.id, "role": req.requested_role.value if isinstance(req.requested_role, UserRole) else req.requested_role,
        "role_label": role_label(req.requested_role), "duration_hours": req.duration_hours,
        "reason": req.reason, "status": state, "requester": _name(req.user_id), "approver": _name(req.approver_id),
        "requested_at": req.requested_at.isoformat() if req.requested_at else None,
        "starts_at": req.starts_at.isoformat() if req.starts_at else None,
        "expires_at": req.expires_at.isoformat() if req.expires_at else None,
    }


# --- HTTP ---

def _me(shikari_session: Optional[str]):
    if not shikari_session:
        return None, None
    db = next(get_db())
    user = get_user_from_session_id(shikari_session, db)
    if not user:
        db.close()
        return None, None
    return user, db


def _need_login():
    return JSONResponse({"error": "Please log in"}, status_code=401)


@router.get("/mine")
def mine(shikari_session: Optional[str] = Cookie(None)):
    user, db = _me(shikari_session)
    if not user:
        return _need_login()
    try:
        return {"base_role": user.role.value, "base_role_label": role_label(user.role),
                "effective_role": effective_role(user).value if effective_role(user) else None,
                "elevated": _grant_active(user) and role_rank(effective_role(user)) > role_rank(user.role),
                "can_approve": at_least(user, UserRole.OPERATOR),
                "requests": [serialize(r, db) for r in my_requests(db, user)]}
    finally:
        db.close()


@router.get("/pending")
def pending(shikari_session: Optional[str] = Cookie(None)):
    user, db = _me(shikari_session)
    if not user:
        return _need_login()
    try:
        return {"requests": [serialize(r, db) for r in pending_for(db, user)]}
    finally:
        db.close()


@router.get("/active")
def active(shikari_session: Optional[str] = Cookie(None)):
    user, db = _me(shikari_session)
    if not user:
        return _need_login()
    try:
        return {"requests": [serialize(r, db) for r in active_grants_for(db, user)]}
    finally:
        db.close()


@router.post("/request")
async def request_access(request: Request, shikari_session: Optional[str] = Cookie(None)):
    user, db = _me(shikari_session)
    if not user:
        return _need_login()
    try:
        data = await request.json()
        req = create_request(db, user, data.get("role", ""), data.get("duration", 0), data.get("reason", ""))
        return {"ok": True, "request": serialize(req, db)}
    except ElevationError as e:
        return JSONResponse({"error": e.message}, status_code=e.status)
    finally:
        db.close()


async def _decide_route(request_id: int, approve: bool, shikari_session: Optional[str]):
    user, db = _me(shikari_session)
    if not user:
        return _need_login()
    try:
        req = decide(db, user, request_id, approve)
        return {"ok": True, "request": serialize(req, db)}
    except ElevationError as e:
        return JSONResponse({"error": e.message}, status_code=e.status)
    finally:
        db.close()


@router.post("/{request_id}/approve")
async def approve(request_id: int, shikari_session: Optional[str] = Cookie(None)):
    return await _decide_route(request_id, True, shikari_session)


@router.post("/{request_id}/deny")
async def deny(request_id: int, shikari_session: Optional[str] = Cookie(None)):
    return await _decide_route(request_id, False, shikari_session)


@router.post("/{request_id}/revoke")
async def revoke_route(request_id: int, shikari_session: Optional[str] = Cookie(None)):
    user, db = _me(shikari_session)
    if not user:
        return _need_login()
    try:
        req = revoke(db, user, request_id)
        return {"ok": True, "request": serialize(req, db)}
    except ElevationError as e:
        return JSONResponse({"error": e.message}, status_code=e.status)
    finally:
        db.close()
