"""
The per-account lockout: five wrong passwords at sign-in (or wrong codes on a reset-access link) lock
the account for 15 minutes. Stored on the user (failed_login_attempts, locked_until), so it holds across
addresses and restarts. The caller commits.
"""

from datetime import datetime, timedelta

LOCK_AFTER_ATTEMPTS = 5
LOCK_MINUTES = 15


def is_locked(user) -> bool:
    return bool(user.locked_until and user.locked_until > datetime.utcnow())


def record_failure(user) -> bool:
    """Count a wrong attempt; True when this one locks the account."""
    user.failed_login_attempts = (user.failed_login_attempts or 0) + 1
    if user.failed_login_attempts >= LOCK_AFTER_ATTEMPTS:
        user.locked_until = datetime.utcnow() + timedelta(minutes=LOCK_MINUTES)
        return True
    return False


def clear(user) -> None:
    user.failed_login_attempts = 0
    user.locked_until = None


def audit_lock(db, user, *, via: str, ip_address=None, user_agent=None) -> None:
    """The account_locked event, recorded wherever a lock is applied (`via` says where: sign-in or a
    reset-access link), on top of the failure that caused it."""
    import json

    from shikari.database.audit import EVENT_ACCOUNT_LOCKED, log_audit_event

    log_audit_event(db, EVENT_ACCOUNT_LOCKED, user_id=user.id, email=user.email, ip_address=ip_address,
                    user_agent=user_agent, success=True,
                    details=json.dumps({"via": via, "attempts": user.failed_login_attempts,
                                        "locked_until": f"{user.locked_until:%Y-%m-%d %H:%M:%S}",
                                        "minutes": LOCK_MINUTES}))
