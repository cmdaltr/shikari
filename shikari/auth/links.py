"""
One-time links that let someone in without signing in first: reset access (shikari/auth/reset_access.py)
and invitations (shikari/auth/invitations.py). Both have the same lifetime and the same shape: the
token after # in the link, which browsers never send to a server, so it stays out of access logs,
proxies and Referer headers; the page posts it in a request body. Only its SHA-256 hash is stored.
"""

import hashlib
import json
import secrets
from typing import Optional

# Every such link works once, within this many hours
LINK_EXPIRY_HOURS = 24


def new_token() -> str:
    return secrets.token_urlsafe(32)


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def link(path: str, token: str) -> str:
    """<BASE_URL><path>#<token>, BASE_URL as the reset emails use it."""
    from shikari.auth.email import BASE_URL

    return f"{BASE_URL.rstrip('/')}{path}#{token}"


def audit(db, event: str, *, user_id: Optional[int], email: Optional[str], success: bool = True,
          ip_address: Optional[str] = None, user_agent: Optional[str] = None, **details) -> None:
    from shikari.database.audit import log_audit_event

    log_audit_event(db, event, user_id=user_id, email=email, ip_address=ip_address,
                    user_agent=user_agent, success=success, details=json.dumps(details))


# The page flow both kinds share: a password, then a new authenticator, then a code from it. What the
# person chooses waits on the link's row (pending_password_hash, pending_mfa_secret) until the code checks
# out; nothing is trusted from the client or held in memory.

WRONG_CODE = "That code didn't match. Try the current one from the new authenticator."


def hold_choice(row, new_password: str) -> str:
    """Check the password by the full rule and keep its hash, with a new TOTP secret, on the row;
    returns the secret to scan. Starting again replaces both. Raises ValueError with the rule broken."""
    from shikari.auth.mfa import generate_totp_secret
    from shikari.auth.password import hash_password, validate_password

    ok, problem = validate_password(new_password)
    if not ok:
        raise ValueError(problem)
    secret = generate_totp_secret()
    row.pending_password_hash = hash_password(new_password)
    row.pending_mfa_secret = secret
    return secret


def has_choice(row) -> bool:
    return bool(row.pending_password_hash and row.pending_mfa_secret)


def code_matches(row, code: str) -> bool:
    from shikari.auth.mfa import verify_totp_code

    return verify_totp_code(row.pending_mfa_secret, (code or "").replace(" ", ""))


def apply_choice(row, user) -> list:
    """The held password and authenticator onto the account, MFA on, fresh backup codes (returned, to
    show once); the row's pending values cleared. The caller marks the link spent and commits."""
    from shikari.auth import lockout
    from shikari.auth.mfa import generate_backup_codes

    codes, hashed = generate_backup_codes()
    user.password_hash = row.pending_password_hash
    user.mfa_secret = row.pending_mfa_secret
    user.mfa_enabled = True
    user.backup_codes = hashed
    lockout.clear(user)
    row.pending_password_hash = row.pending_mfa_secret = None
    return codes
