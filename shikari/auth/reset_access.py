"""
Reset access: for someone who has lost their password, their authenticator or their backup codes.

An admin (Settings → Users → Reset access) or the server (`shikari reset-access <email>`) issues a
one-time link, or the person asks for one by email (Forgot password on the sign-in page, when email is
set up). An admin's or the server's link ends the person's sessions, revokes their API tokens, makes
any earlier reset link useless and clears a lockout. A self-service one does none of that, since anyone
can ask for one: it only replaces an earlier self-service link, and never an open admin-issued one.
The old password and authenticator keep working until the reset is completed.

Opening the link, they choose a new password and enrol a new authenticator, which is required here
even though MFA is otherwise optional: until a code from it checks out nothing about the account
changes, and wrong codes count towards the sign-in lockout (shikari/auth/lockout.py). They finish
signed in, with fresh backup codes shown once; their sessions end and API tokens are revoked then too.

The link is /reset-access#<token> (shikari/auth/links.py). The token is stored only as its SHA-256
hash, in PasswordReset.reset_token with kind "access". Rows of the old 1-hour emailed password reset
(kind NULL) are never accepted.
"""

from datetime import datetime, timedelta
from typing import List, Optional, Tuple

from sqlalchemy import or_
from sqlalchemy.orm import Session as SQLAlchemySession

from shikari.auth import links, lockout
from shikari.auth.tokens import revoke_all
from shikari.database.models import PasswordReset, Session, User

RESET_ACCESS_KIND = "access"
# A day, not the email reset's hour: the link goes from an admin to the person by hand
RESET_ACCESS_EXPIRY_HOURS = links.LINK_EXPIRY_HOURS

EVENT_ACCESS_RESET_ISSUED = "access_reset_issued"
EVENT_ACCESS_RESET_COMPLETED = "access_reset_completed"
EVENT_ACCESS_RESET_FAILED = "access_reset_failed"  # a wrong code, or locked: the names Ostraka and Rowanholt use

VIA_SELF_SERVICE = "self-service"


class ResetAccessError(ValueError):
    """Why a reset can't be issued or completed, worded for the person reading it."""


class NoSuchAccount(ResetAccessError):
    """No account has that email or id."""


class AccountLocked(ResetAccessError):
    """Too many wrong codes: the account is locked, as after wrong passwords at sign-in."""


token_hash = links.token_hash


def reset_link(token: str, base: Optional[str] = None) -> str:
    return links.link("/reset-access", token, base)


def _audit(db, event: str, user: User, **kw) -> None:
    links.audit(db, event, user_id=user.id, email=user.email, **kw)


def _find_account(db, email: Optional[str], user_id: Optional[int]) -> Tuple[Optional[User], str]:
    if user_id is not None:
        return db.query(User).filter(User.id == user_id).first(), f"user {user_id}"
    email = (email or "").strip().lower()
    return (db.query(User).filter(User.email == email).first() if email else None), email or "that email"


def _new_row(db, user: User, via: Optional[str]) -> str:
    token = links.new_token()
    db.add(PasswordReset(user_id=user.id, reset_token=token_hash(token), kind=RESET_ACCESS_KIND, via=via,
                         expires_at=datetime.utcnow() + timedelta(hours=RESET_ACCESS_EXPIRY_HOURS)))
    return token


def issue_reset_access(db: SQLAlchemySession, *, email: Optional[str] = None, user_id: Optional[int] = None,
                       actor: Optional[User] = None, ip_address: Optional[str] = None,
                       user_agent: Optional[str] = None, base_url: Optional[str] = None) -> Tuple[User, str]:
    """A one-time reset-access link for the account with this email or id, from an admin or the
    server. The account's sessions end now, its API tokens are revoked, earlier unused reset links
    (any kind, self-service ones too) stop working, and a lockout is cleared.
    `actor` is the admin who asked; None means the server's command line.

    Raises NoSuchAccount for an unknown account, ResetAccessError for a deactivated one.
    """
    user, who = _find_account(db, email, user_id)
    if user is None:
        raise NoSuchAccount(f"There's no account for {who}.")
    if not user.is_active:
        raise ResetAccessError(f"{user.email} is deactivated. Reactivate the account first.")

    db.query(PasswordReset).filter(PasswordReset.user_id == user.id,
                                   PasswordReset.used == False).update({"used": True, **links.CLEARED})  # noqa: E712
    token = _new_row(db, user, "admin" if actor else "cli")
    db.query(Session).filter(Session.user_id == user.id).delete()
    tokens_revoked = revoke_all(db, user.id)
    lockout.clear(user)
    db.commit()

    _audit(db, EVENT_ACCESS_RESET_ISSUED, user, ip_address=ip_address, user_agent=user_agent,
           actor_id=actor.id if actor else None, actor_email=actor.email if actor else None,
           via="admin" if actor else "cli", expires_in_hours=RESET_ACCESS_EXPIRY_HOURS,
           tokens_revoked=tokens_revoked)
    return user, reset_link(token, base_url)


def _admin_reset_open(db, user_id: int) -> bool:
    return db.query(PasswordReset.id).filter(PasswordReset.user_id == user_id,
                                             PasswordReset.kind == RESET_ACCESS_KIND,
                                             # None: issued before `via` was recorded, by an admin or the CLI
                                             or_(PasswordReset.via.is_(None), PasswordReset.via != VIA_SELF_SERVICE),
                                             PasswordReset.used == False,  # noqa: E712
                                             PasswordReset.expires_at > datetime.utcnow()).first() is not None


def request_self_service(db: SQLAlchemySession, login: str, *, ip_address: Optional[str] = None,
                         user_agent: Optional[str] = None, base_url: Optional[str] = None
                         ) -> Optional[Tuple[User, str]]:
    """Forgot password: a reset-access link to email to the active account signing in as `login`, or
    None (no such active account, no email address to send to, or an admin-issued reset is already
    open, which a self-service request must never replace). Sessions, API tokens and any lockout are
    left alone: anyone can ask, so those happen only when the link is completed."""
    from shikari.security import validate_email

    user, _ = _find_account(db, login, None)
    if user is None or not user.is_active or not validate_email(user.email)[0]:
        return None
    if _admin_reset_open(db, user.id):
        _audit(db, EVENT_ACCESS_RESET_ISSUED, user, success=False, ip_address=ip_address,
               user_agent=user_agent, via=VIA_SELF_SERVICE, reason="an admin-issued reset is open")
        return None
    db.query(PasswordReset).filter(PasswordReset.user_id == user.id, PasswordReset.via == VIA_SELF_SERVICE,
                                   PasswordReset.used == False).update({"used": True, **links.CLEARED})  # noqa: E712
    token = _new_row(db, user, VIA_SELF_SERVICE)
    db.commit()
    _audit(db, EVENT_ACCESS_RESET_ISSUED, user, ip_address=ip_address, user_agent=user_agent,
           actor_id=None, actor_email=None, via=VIA_SELF_SERVICE,
           expires_in_hours=RESET_ACCESS_EXPIRY_HOURS, tokens_revoked=0)
    return user, reset_link(token, base_url)


def find_reset(db: SQLAlchemySession, token: str) -> Tuple[Optional[PasswordReset], str]:
    """The reset-access row for this token and what it is: links.OPEN (unused, unexpired, its account
    active), links.EXPIRED (unused but past its time; anything chosen on it is cleared now) or
    links.INVALID (used, replaced, unknown, or its account deactivated), with the row only when open."""
    if not token:
        return None, links.INVALID
    row = db.query(PasswordReset).filter(PasswordReset.reset_token == token_hash(token),
                                         PasswordReset.kind == RESET_ACCESS_KIND,
                                         PasswordReset.used == False).first()  # noqa: E712
    if row is None:
        return None, links.INVALID
    if not db.query(User.id).filter(User.id == row.user_id, User.is_active == True).first():  # noqa: E712
        return None, links.INVALID
    if datetime.utcnow() >= row.expires_at:
        if row.pending_password_hash or row.pending_mfa_secret:
            links.clear_choice(row)
            db.commit()
        return None, links.EXPIRED
    return row, links.OPEN


def open_reset(db: SQLAlchemySession, token: str) -> Optional[PasswordReset]:
    """The unused, unexpired reset-access row for this token, if its account is still active."""
    return find_reset(db, token)[0]


def start_reset(db: SQLAlchemySession, row: PasswordReset, new_password: str) -> Tuple[User, str]:
    """The new password, checked by the full rule and held (hashed) on the link until the code checks
    out, and a new authenticator secret to scan. Starting again replaces both."""
    try:
        secret = links.hold_choice(row, new_password)
    except ValueError as e:
        raise ResetAccessError(str(e)) from e
    db.commit()
    return db.query(User).filter(User.id == row.user_id).one(), secret


def complete_reset(db: SQLAlchemySession, row: PasswordReset, code: str, ip_address: Optional[str] = None,
                   user_agent: Optional[str] = None) -> Tuple[User, List[str]]:
    """A code from the new authenticator proves it works. Only then: the new password, MFA on with the
    new secret, fresh backup codes (returned to show once), API tokens revoked again, and the link
    spent. The caller signs in. A locked account is refused before the code is looked at; a wrong code
    counts towards the lock."""
    if not links.has_choice(row):
        raise ResetAccessError("Choose a new password first.")
    user = db.query(User).filter(User.id == row.user_id).one()
    if lockout.is_locked(user):
        _audit(db, EVENT_ACCESS_RESET_FAILED, user, success=False, ip_address=ip_address,
               user_agent=user_agent, reason=f"account locked until {user.locked_until}")
        raise AccountLocked("Account is temporarily locked due to multiple failed attempts. "
                            "Please try again later.")
    if not links.code_matches(row, code):
        locked = lockout.record_failure(user)
        db.commit()
        _audit(db, EVENT_ACCESS_RESET_FAILED, user, success=False, ip_address=ip_address,
               user_agent=user_agent, reason="code did not match",
               attempt=user.failed_login_attempts, locked=locked)
        if locked:
            lockout.audit_lock(db, user, via="reset-access", ip_address=ip_address, user_agent=user_agent)
            raise AccountLocked(f"Account locked due to multiple failed attempts. Please try again in "
                                f"{lockout.LOCK_MINUTES} minutes.")
        raise ResetAccessError(links.WRONG_CODE)

    # Claim the link before using it: of two completions at once, only one gets through
    claimed = db.query(PasswordReset).filter(PasswordReset.id == row.id, PasswordReset.used == False  # noqa: E712
                                             ).update({"used": True}, synchronize_session=False)
    if not claimed:
        db.rollback()
        raise ResetAccessError("This link has already been used.")
    codes = links.apply_choice(row, user)
    row.used = True
    db.query(Session).filter(Session.user_id == user.id).delete()
    tokens_revoked = revoke_all(db, user.id)
    db.commit()
    _audit(db, EVENT_ACCESS_RESET_COMPLETED, user, ip_address=ip_address, user_agent=user_agent,
           via=row.via or "admin", tokens_revoked=tokens_revoked)
    return user, codes
