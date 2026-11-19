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
