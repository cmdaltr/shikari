"""
Invitations: how a Shikari server gets new accounts. An admin (Settings → Users → Invite) or the server
(`shikari invite <email> --role …`, `scripts/admin/create_admin.py <email>` for an admin) issues a
one-time link, /accept-invite#<token>. Opening it, the person gives their name, chooses a password and
enrols an authenticator (MFA is always on for an invited account); the account is created, with the
invited role, only once a code from that authenticator checks out. They finish signed in, with backup
codes shown once.

The same flow as reset access (shikari/auth/reset_access.py) and the same link rules
(shikari/auth/links.py), except that it makes the account at the end. There's no account to lock while
it's pending, so wrong codes count on the invitation itself: each is audited, and the fifth closes the
link, so an admin has to issue a new one.
"""

from datetime import datetime, timedelta
from typing import List, Optional, Tuple

from sqlalchemy.orm import Session as SQLAlchemySession

from shikari.auth import links
from shikari.database.models import Invitation, User, UserRole

INVITATION_EXPIRY_HOURS = links.LINK_EXPIRY_HOURS

EVENT_INVITATION_CREATED = "invitation_created"
EVENT_INVITATION_REVOKED = "invitation_revoked"
EVENT_ACCOUNT_CREATED = "account_created"
EVENT_INVITATION_WRONG_CODE = "invitation_wrong_code"
EVENT_INVITATION_CLOSED = "invitation_closed"

# Wrong codes an invitation takes before it closes
WRONG_CODES_ALLOWED = 5


class InvitationError(ValueError):
    """Why an invitation can't be made or accepted, worded for the person reading it."""


class AccountExists(InvitationError):
    """The email already has an account: it needs Reset access, not an invitation."""


class SeatsFull(InvitationError):
    """The licence's seats are taken."""


class AdminExists(InvitationError):
    """create_admin.py without --force while an active admin exists."""


class InvitationClosed(InvitationError):
    """The fifth wrong code: the link no longer works."""


def invitation_link(token: str, base: Optional[str] = None) -> str:
    return links.link("/accept-invite", token, base)


def _open_ones(db, now: datetime):
    return db.query(Invitation).filter(Invitation.accepted_at.is_(None), Invitation.revoked_at.is_(None),
                                       Invitation.expires_at > now)


def _seat_problem(db, *, pending_too: bool, except_email: Optional[str] = None) -> Optional[str]:
    """Whether another account fits the licence: active accounts, and (when issuing) the open
    invitations that would each add one."""
    from shikari import licence

    taken = db.query(User).filter(User.is_active.is_(True)).count()
    if pending_too:
        open_ones = _open_ones(db, datetime.utcnow())
        if except_email:
            open_ones = open_ones.filter(Invitation.email != except_email)
        taken += open_ones.count()
    if licence.can_add_user(taken):
        return None
    return (f"This install allows {licence.seats_allowed()} accounts, counting open invitations. Add a Pro "
            "or Services licence with more seats (Report branding → Licence), or revoke an invitation.")


def _revoke_replaced(db, query, actor: Optional[User], **kw) -> None:
    """Revoke the open invitations in `query` because a new one replaces them, each audited."""
    now = datetime.utcnow()
    replaced = query.filter(Invitation.accepted_at.is_(None), Invitation.revoked_at.is_(None)).all()
    for old in replaced:
        old.revoked_at = now
        links.clear_choice(old)
    db.commit()
    for old in replaced:
        links.audit(db, EVENT_INVITATION_REVOKED, user_id=actor.id if actor else None, email=old.email,
                    invitation_id=old.id, actor_email=actor.email if actor else None, reason="replaced", **kw)


def create_invitation(db: SQLAlchemySession, *, email: str, role, full_name: Optional[str] = None,
                      actor: Optional[User] = None, via: Optional[str] = None, check_seats: bool = True,
                      ip_address: Optional[str] = None, user_agent: Optional[str] = None,
                      base_url: Optional[str] = None) -> Tuple[Invitation, str]:
    """A new invitation and its link. An earlier open invitation for the same email is revoked, so only
    the newest link works. `actor` is the admin who asked; None means the command line (`via` says
    which). Raises InvitationError (AccountExists, SeatsFull) with the reason."""
    from shikari.security import sanitize_full_name, validate_email

    ok, email_or_problem = validate_email(email or "")
    if not ok:
        raise InvitationError(email_or_problem)
    email = email_or_problem
    try:
        role = role if isinstance(role, UserRole) else UserRole(str(role).strip().lower())
    except ValueError:
        raise InvitationError(f"Role must be one of: {', '.join(r.value for r in UserRole)}.") from None
    if full_name and full_name.strip():
        ok, name_or_problem = sanitize_full_name(full_name)
        if not ok:
            raise InvitationError(name_or_problem)
        full_name = name_or_problem
    else:
        full_name = None
    if db.query(User.id).filter(User.email == email).first():
        raise AccountExists(f"{email} already has an account. To get them back in, use Reset access.")
    if check_seats and (problem := _seat_problem(db, pending_too=True, except_email=email)):
        raise SeatsFull(problem)

    now = datetime.utcnow()
    _revoke_replaced(db, db.query(Invitation).filter(Invitation.email == email), actor,
                     ip_address=ip_address, user_agent=user_agent)
    token = links.new_token()
    invitation = Invitation(email=email, role=role, full_name=full_name, token_hash=links.token_hash(token),
                            invited_by=actor.id if actor else None,
                            expires_at=now + timedelta(hours=INVITATION_EXPIRY_HOURS))
    db.add(invitation)
    db.commit()
    links.audit(db, EVENT_INVITATION_CREATED, user_id=actor.id if actor else None, email=email,
                ip_address=ip_address, user_agent=user_agent, invitation_id=invitation.id, role=role.value,
                actor_email=actor.email if actor else None, via=via or ("admin" if actor else "cli"),
                expires_in_hours=INVITATION_EXPIRY_HOURS)
    return invitation, invitation_link(token, base_url)


def bootstrap_admin(db: SQLAlchemySession, email: str, *, force: bool = False) -> Tuple[Invitation, str]:
    """An admin invitation from the server (scripts/admin/create_admin.py), for a first admin or for
    when none can sign in. Refused while an active admin exists, unless forced. Only the newest such
    link works, whatever email the earlier ones were for."""
    admins = db.query(User).filter(User.role == UserRole.ADMIN, User.is_active.is_(True)).count()
    if admins and not force:
        raise AdminExists("Shikari already has an active admin. Ask them to invite you (Settings → Users "
                          "→ Invite), or run this again with --force.")
    _revoke_replaced(db, db.query(Invitation).filter(Invitation.invited_by.is_(None),
                                                     Invitation.role == UserRole.ADMIN), None)
    # Getting back in when no admin is left always works; adding one beside them takes a seat
    return create_invitation(db, email=email, role=UserRole.ADMIN, via="bootstrap", check_seats=bool(admins))


def pending(db: SQLAlchemySession) -> List[Invitation]:
    """Invitations not yet accepted or revoked, newest first (expired ones too, so they can be seen)."""
    return (db.query(Invitation).filter(Invitation.accepted_at.is_(None), Invitation.revoked_at.is_(None))
            .order_by(Invitation.created_at.desc(), Invitation.id.desc()).all())


def revoke(db: SQLAlchemySession, invitation_id: int, actor: User, ip_address: Optional[str] = None,
           user_agent: Optional[str] = None) -> bool:
    """Stop an open invitation's link working. False if there's no such open invitation."""
    invitation = db.query(Invitation).filter(Invitation.id == invitation_id, Invitation.accepted_at.is_(None),
                                             Invitation.revoked_at.is_(None)).first()
    if invitation is None:
        return False
    invitation.revoked_at = datetime.utcnow()
    links.clear_choice(invitation)
    db.commit()
    links.audit(db, EVENT_INVITATION_REVOKED, user_id=actor.id, email=invitation.email, ip_address=ip_address,
                user_agent=user_agent, invitation_id=invitation.id, actor_email=actor.email)
    return True


def find_invitation(db: SQLAlchemySession, token: str) -> Tuple[Optional[Invitation], str]:
    """The invitation for this token and what it is: links.OPEN, links.EXPIRED (neither accepted nor
    revoked, but past its time; anything chosen on it is cleared now) or links.INVALID (accepted,
    revoked, replaced, closed by wrong codes, or unknown), with the invitation only when open."""
    if not token:
        return None, links.INVALID
    invitation = db.query(Invitation).filter(Invitation.token_hash == links.token_hash(token),
                                             Invitation.accepted_at.is_(None),
                                             Invitation.revoked_at.is_(None)).first()
    if invitation is None:
        return None, links.INVALID
    if datetime.utcnow() >= invitation.expires_at:
        if invitation.pending_password_hash or invitation.pending_mfa_secret or invitation.pending_full_name:
            links.clear_choice(invitation)
            db.commit()
        return None, links.EXPIRED
    return invitation, links.OPEN


def open_invitation(db: SQLAlchemySession, token: str) -> Optional[Invitation]:
    """The open, unexpired invitation for this token, if any."""
    return find_invitation(db, token)[0]


def start_invitation(db: SQLAlchemySession, invitation: Invitation, full_name: str, new_password: str) -> str:
    """Their name and password, held on the invitation, and a new authenticator secret to scan."""
    from shikari.security import sanitize_full_name

    ok, name_or_problem = sanitize_full_name(full_name or "")
    if not ok:
        raise InvitationError(name_or_problem)
    try:
        secret = links.hold_choice(invitation, new_password)
    except ValueError as e:
        raise InvitationError(str(e)) from e
    invitation.pending_full_name = name_or_problem
    db.commit()
    return secret


def _bootstrap_with_no_admin(db, invitation: Invitation) -> bool:
    """The server's admin invitation while no admin is left, which bootstrap_admin issued without a
    seat: getting back in always works, so it completes without one too."""
    return (invitation.invited_by is None and invitation.role == UserRole.ADMIN
            and not db.query(User).filter(User.role == UserRole.ADMIN, User.is_active.is_(True)).count())


def _wrong_code(db, invitation: Invitation, **kw) -> None:
    """Count and audit a wrong code; the fifth closes the link (claimed as the completion is, so two
    at once can't both slip past the limit) and clears what was chosen. Always raises."""
    attempts = (invitation.failed_attempts or 0) + 1
    invitation.failed_attempts = attempts
    db.commit()
    links.audit(db, EVENT_INVITATION_WRONG_CODE, user_id=None, email=invitation.email, success=False,
                invitation_id=invitation.id, attempt=attempts, allowed=WRONG_CODES_ALLOWED, **kw)
    if attempts < WRONG_CODES_ALLOWED:
        left = WRONG_CODES_ALLOWED - attempts
        raise InvitationError(f"{links.WRONG_CODE} {left} {'try' if left == 1 else 'tries'} left.")
    closed = db.query(Invitation).filter(Invitation.id == invitation.id, Invitation.accepted_at.is_(None),
                                         Invitation.revoked_at.is_(None)
                                         ).update({"revoked_at": datetime.utcnow(), **links.CLEARED,
                                                   "pending_full_name": None}, synchronize_session=False)
    db.commit()
    if closed:
        links.audit(db, EVENT_INVITATION_CLOSED, user_id=None, email=invitation.email, success=False,
                    invitation_id=invitation.id, reason=f"{WRONG_CODES_ALLOWED} wrong codes", **kw)
    raise InvitationClosed(f"That code didn't match either, and after {WRONG_CODES_ALLOWED} wrong codes this "
                           "invitation no longer works. Ask an admin for a new one.")


def complete_invitation(db: SQLAlchemySession, invitation: Invitation, code: str,
                        ip_address: Optional[str] = None, user_agent: Optional[str] = None
                        ) -> Tuple[User, List[str]]:
    """A code from the new authenticator proves it works. Only then is the account made, with the
    invited role and MFA on; the link is spent and the backup codes returned to show once. The caller
    signs in."""
    if not (links.has_choice(invitation) and invitation.pending_full_name):
        raise InvitationError("Choose a password first.")
    if not links.code_matches(invitation, code):
        _wrong_code(db, invitation, ip_address=ip_address, user_agent=user_agent)
    if db.query(User.id).filter(User.email == invitation.email).first():
        raise AccountExists(f"{invitation.email} already has an account. Sign in, or ask an admin to "
                            "reset your access.")
    if invitation.invited_by is not None:
        inviter = db.query(User).filter(User.id == invitation.invited_by).first()
        if not (inviter and inviter.is_active and inviter.role == UserRole.ADMIN):
            raise InvitationError("The admin who invited you no longer can. Ask an admin for a new invitation.")
    if not _bootstrap_with_no_admin(db, invitation) and (problem := _seat_problem(db, pending_too=False)):
        raise SeatsFull(problem)
    # Claim the invitation before making the account: of two acceptances at once, only one gets through
    claimed = db.query(Invitation).filter(Invitation.id == invitation.id, Invitation.accepted_at.is_(None),
                                          Invitation.revoked_at.is_(None)
                                          ).update({"accepted_at": datetime.utcnow()}, synchronize_session=False)
    if not claimed:
        db.rollback()
        raise InvitationError("This invitation has already been used.")

    user = User(email=invitation.email, full_name=invitation.pending_full_name, role=invitation.role,
                is_active=True, password_hash=invitation.pending_password_hash, failed_login_attempts=0)
    codes = links.apply_choice(invitation, user)
    invitation.pending_full_name = None
    db.add(user)
    db.flush()
    invitation.accepted_at = datetime.utcnow()
    invitation.user_id = user.id
    db.commit()
    links.audit(db, EVENT_ACCOUNT_CREATED, user_id=user.id, email=user.email, ip_address=ip_address,
                user_agent=user_agent, invitation_id=invitation.id, role=user.role.value,
                invited_by=invitation.invited_by)
    return user, codes
