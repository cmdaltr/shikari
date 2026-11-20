"""
One-time links that let someone in without signing in first: reset access (shikari/auth/reset_access.py)
and invitations (shikari/auth/invitations.py). Both have the same lifetime and the same shape: the
token after # in the link, which browsers never send to a server, so it stays out of access logs,
proxies and Referer headers; the page posts it in a request body. Only its SHA-256 hash is stored.
"""

import hashlib
import json
import re
import secrets
from typing import Optional

# Every such link works once, within this many hours
LINK_EXPIRY_HOURS = 24


def new_token() -> str:
    return secrets.token_urlsafe(32)


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def base_url_set() -> bool:
    import os

    return bool(os.getenv("BASE_URL"))


NO_BASE_URL_WARNING = ("BASE_URL isn't set, so this link names localhost. Set BASE_URL to the address people "
                       "open Shikari at, or change the start of the link by hand.")


def warn_if_no_base_url() -> None:
    """On stderr, every time the command line or start-up prints a link while BASE_URL is unset."""
    import sys

    if not base_url_set():
        print(NO_BASE_URL_WARNING, file=sys.stderr)


# An origin or host as a browser or proxy sends it: nothing after the port, so a header can't add a path
_ORIGIN = re.compile(r"^https?://([A-Za-z0-9.\-]+|\[[0-9A-Fa-f:.]+\])(:\d{1,5})?$")
_HOST = re.compile(r"^([A-Za-z0-9.\-]+|\[[0-9A-Fa-f:.]+\])(:\d{1,5})?$")


def request_origin(request) -> str:
    """The address an admin's request came to, for their links when BASE_URL isn't set, as Ostraka and
    Rowanholt find it: the page's Origin (a browser sends it with every POST, and it's the address in the
    address bar, whatever proxies sit between), else the proxy's X-Forwarded-Host with the scheme uvicorn
    took from its trusted proxies, else the request's own. Never used for an emailed link."""
    origin = (request.headers.get("origin") or "").strip()
    if _ORIGIN.match(origin):
        return origin
    forwarded = (request.headers.get("x-forwarded-host") or "").split(",")[0].strip()
    if _HOST.match(forwarded):
        return f"{request.url.scheme}://{forwarded}"
    return str(request.base_url).rstrip("/")


def link(path: str, token: str, base: Optional[str] = None) -> str:
    """<base><path>#<token>. BASE_URL when it's set; otherwise `base`, the address the admin asked from,
    so a server without BASE_URL doesn't hand out a localhost link; the email default last."""
    from shikari.auth.email import BASE_URL

    root = BASE_URL if base_url_set() or not base else base
    return f"{root.rstrip('/')}{path}#{token}"


# What a dead link's row still holds: cleared when it's replaced, revoked, claimed, closed or found expired
CLEARED = {"pending_password_hash": None, "pending_mfa_secret": None}

# What a link is when someone opens it. Only an expired one says so (for as long as its row is kept);
# used, revoked, replaced and unknown links all get the same "not valid", so the page can't be used to
# learn which tokens were ever real
OPEN, EXPIRED, INVALID = "open", "expired", "invalid"


def clear_choice(row) -> None:
    """Forget what the person chose on a link that can no longer be completed. The caller commits."""
    for column in CLEARED:
        setattr(row, column, None)
    if hasattr(row, "pending_full_name"):
        row.pending_full_name = None


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
    """Check the password by the full rule and keep its hash, with the link's TOTP secret, on the row;
    returns the secret to scan. The first start makes the secret and later ones reuse it, so a second
    tab or the link opened again shows the authenticator already scanned; a later password replaces the
    earlier one. Raises ValueError with the rule broken."""
    from shikari.auth.mfa import generate_totp_secret
    from shikari.auth.password import hash_password, validate_password

    ok, problem = validate_password(new_password)
    if not ok:
        raise ValueError(problem)
    row.pending_password_hash = hash_password(new_password)
    if not row.pending_mfa_secret:
        row.pending_mfa_secret = generate_totp_secret()
    return row.pending_mfa_secret


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
