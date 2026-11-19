"""
Reset access: for someone who has lost their password, their authenticator or their backup codes.

An admin (Settings → Users → Reset access) or the server (`shikari reset-access <email>`) issues a
one-time link. Issuing it ends the person's sessions, revokes their API tokens, makes any earlier
reset link useless and clears a lockout. Opening it, they choose a new password and enrol a new
authenticator, which is required here even though MFA is otherwise optional: until a code from it checks out
nothing about the account changes, and wrong codes count towards the sign-in lockout
(shikari/auth/lockout.py). They finish signed in, with fresh backup codes shown once; API tokens made
in the meantime are revoked then too.

The link is /reset-access#<token> (shikari/auth/links.py). The token is stored only as its SHA-256
hash, in PasswordReset.reset_token with kind "access";
the 1-hour email reset (shikari/auth/password_reset.py) keeps kind NULL and never accepts one of these.
"""

from datetime import datetime, timedelta
from typing import List, Optional, Tuple

from sqlalchemy.orm import Session as SQLAlchemySession

from shikari.auth import links, lockout
from shikari.auth.tokens import revoke_all
from shikari.database.models import PasswordReset, Session, User

RESET_ACCESS_KIND = "access"
# A day, not the email reset's hour: the link goes from an admin to the person by hand
RESET_ACCESS_EXPIRY_HOURS = links.LINK_EXPIRY_HOURS

EVENT_ACCESS_RESET_ISSUED = "access_reset_issued"
EVENT_ACCESS_RESET_COMPLETED = "access_reset_completed"


class ResetAccessError(ValueError):
    """Why a reset can't be issued or completed, worded for the person reading it."""


class NoSuchAccount(ResetAccessError):
    """No account has that email or id."""


class AccountLocked(ResetAccessError):
    """Too many wrong codes: the account is locked, as after wrong passwords at sign-in."""


token_hash = links.token_hash


def reset_link(token: str) -> str:
    return links.link("/reset-access", token)


def _audit(db, event: str, user: User, **kw) -> None:
    links.audit(db, event, user_id=user.id, email=user.email, **kw)


def issue_reset_access(db: SQLAlchemySession, *, email: Optional[str] = None, user_id: Optional[int] = None,
                       actor: Optional[User] = None, ip_address: Optional[str] = None,
                       user_agent: Optional[str] = None) -> Tuple[User, str]:
    """A one-time reset-access link for the account with this email or id. The account's sessions
    end now, its API tokens are revoked, earlier unused reset links (either kind) stop working, and a
    lockout is cleared.
    `actor` is the admin who asked; None means the server's command line.

    Raises NoSuchAccount for an unknown account, ResetAccessError for a deactivated one.
    """
    if user_id is not None:
        user = db.query(User).filter(User.id == user_id).first()
        who = f"user {user_id}"
    else:
        email = (email or "").strip().lower()
        user = db.query(User).filter(User.email == email).first() if email else None
        who = email or "that email"
    if user is None:
        raise NoSuchAccount(f"There's no account for {who}.")
    if not user.is_active:
        raise ResetAccessError(f"{user.email} is deactivated. Reactivate the account first.")

    token = links.new_token()
    db.query(PasswordReset).filter(PasswordReset.user_id == user.id,
                                   PasswordReset.used == False).update({"used": True})  # noqa: E712
    db.add(PasswordReset(user_id=user.id, reset_token=token_hash(token), kind=RESET_ACCESS_KIND,
                         expires_at=datetime.utcnow() + timedelta(hours=RESET_ACCESS_EXPIRY_HOURS)))
    db.query(Session).filter(Session.user_id == user.id).delete()
    tokens_revoked = revoke_all(db, user.id)
    lockout.clear(user)
    db.commit()

    _audit(db, EVENT_ACCESS_RESET_ISSUED, user, ip_address=ip_address, user_agent=user_agent,
           actor_id=actor.id if actor else None, actor_email=actor.email if actor else None,
           via="admin" if actor else "cli", expires_in_hours=RESET_ACCESS_EXPIRY_HOURS,
           tokens_revoked=tokens_revoked)
    return user, reset_link(token)


def open_reset(db: SQLAlchemySession, token: str) -> Optional[PasswordReset]:
    """The unused, unexpired reset-access row for this token, if its account is still active."""
    if not token:
        return None
    row = db.query(PasswordReset).filter(PasswordReset.reset_token == token_hash(token),
                                         PasswordReset.kind == RESET_ACCESS_KIND,
                                         PasswordReset.used == False).first()  # noqa: E712
    if row is None or datetime.utcnow() >= row.expires_at:
        return None
    user = db.query(User).filter(User.id == row.user_id, User.is_active == True).first()  # noqa: E712
    return row if user else None


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
        _audit(db, EVENT_ACCESS_RESET_COMPLETED, user, success=False, ip_address=ip_address,
               user_agent=user_agent, reason=f"account locked until {user.locked_until}")
        raise AccountLocked("Account is temporarily locked due to multiple failed attempts. "
                            "Please try again later.")
    if not links.code_matches(row, code):
        locked = lockout.record_failure(user)
        db.commit()
        _audit(db, EVENT_ACCESS_RESET_COMPLETED, user, success=False, ip_address=ip_address,
               user_agent=user_agent, reason="code did not match",
               attempt=user.failed_login_attempts, locked=locked)
        if locked:
            raise AccountLocked(f"Account locked due to multiple failed attempts. Please try again in "
                                f"{lockout.LOCK_MINUTES} minutes.")
        raise ResetAccessError(links.WRONG_CODE)

    codes = links.apply_choice(row, user)
    row.used = True
    db.query(Session).filter(Session.user_id == user.id).delete()
    tokens_revoked = revoke_all(db, user.id)
    db.commit()
    _audit(db, EVENT_ACCESS_RESET_COMPLETED, user, ip_address=ip_address, user_agent=user_agent,
           tokens_revoked=tokens_revoked)
    return user, codes
