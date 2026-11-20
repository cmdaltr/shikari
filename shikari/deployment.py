"""
Whether this Shikari is a team server or a local one, and what each does about its first admin.

A server says so: SHIKARI_MODE=server, set by every server deployment (docker-compose.yml,
deploy/linux/install.sh and its shikari.env, deploy/windows/install-service.ps1 and the Windows
service's shikari.env). Anything else is local: the desktop app's own Shikari, and `shikari start`,
`shikari serve` or `shikari app` from a checkout. (SHIKARI_SERVER is taken: it's the desktop app's
choice of server URL, shikari/desktop_client.py.)

  Server  accounts by invitation only (no /register), and no seeded account. With no active admin, the
          first start issues a first-admin invitation for SHIKARI_ADMIN_EMAIL and prints its link;
          `shikari first-admin <email>` issues one on demand.
  Local   while Shikari listens on this machine alone, /register is open and an empty database gets
          the default admin, signing in as `admin` with the password BigGameHunter (audited). On a
          network address neither: a known password, or open registration, is anyone's account
          there, so it's invitation-only like a server.
"""

import ipaddress
import logging
import os
import sys
from typing import Optional

logger = logging.getLogger(__name__)

MODE_ENV = "SHIKARI_MODE"
ADMIN_EMAIL_ENV = "SHIKARI_ADMIN_EMAIL"

# The default admin of a local Shikari signs in with this, not an email: it's the one account whose
# "email" isn't one, and nothing that validates an email (invitations, an admin editing an account)
# will set it on anyone else
DEFAULT_ADMIN_LOGIN = "admin"
DEFAULT_ADMIN_PASSWORD = "BigGameHunter"
LEGACY_DEFAULT_ADMIN_EMAIL = "admin@shikari.app"


def is_server() -> bool:
    return os.environ.get(MODE_ENV, "").strip().lower() == "server"


def bind_host(argv=None) -> Optional[str]:
    """The address uvicorn was told to listen on, as uvicorn itself decides it: --host in the command
    line (every launcher passes it: shikari start/serve/app, the systemd unit, the Windows service and
    its Scheduled Task, the Dockerfile, `python -m shikari.app`), else UVICORN_HOST (uvicorn's own
    setting for its CLI). uvicorn's --reload and --workers children are spawned with the same argv, so
    they see it too. Failing both, SHIKARI_HOST, which the server launchers pass as --host anyway. The
    desktop app runs uvicorn in-process on 127.0.0.1 and passes nothing. None when nothing says, which
    is uvicorn's own default, 127.0.0.1."""
    argv = sys.argv if argv is None else argv
    # uvicorn listens on --uds, else --fd, else --host: a socket handed over says nothing about who can
    # reach it (a proxy, or systemd socket activation on any address), so it never counts as loopback
    uds, fd = _option(argv, "--uds", "UVICORN_UDS"), _option(argv, "--fd", "UVICORN_FD")
    if uds:
        return f"unix:{uds}"
    if fd:
        return f"fd:{fd}"
    return _option(argv, "--host", "UVICORN_HOST") or os.environ.get("SHIKARI_HOST") or None


def _option(argv, flag: str, env: str) -> Optional[str]:
    for i, arg in enumerate(argv):
        if arg == flag and i + 1 < len(argv):
            return argv[i + 1]
        if arg.startswith(f"{flag}="):
            return arg.split("=", 1)[1]
    return os.environ.get(env) or None


def loopback_only(host: Optional[str]) -> bool:
    """Whether a bind address reaches this machine alone. 0.0.0.0, ::, a LAN or tailnet address, a socket
    handed over with --uds or --fd, and any name other than localhost don't."""
    if host is None:
        return True
    host = host.strip().strip("[]")
    if host.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def local_and_loopback(argv=None) -> bool:
    """Not a server, and listening on this machine alone: the only Shikari that seeds the default admin
    or lets people register."""
    return not is_server() and loopback_only(bind_host(argv))


def registration_open(argv=None) -> bool:
    """Whether /register works. A server, or a local Shikari on a network address, is invitation-only."""
    return local_and_loopback(argv)


EVENT_DEFAULT_ADMIN_RENAMED = "default_admin_renamed"
EVENT_DEFAULT_ADMIN_SEEDED = "default_admin_seeded"


def _say(message: str) -> None:
    # Printed as well as logged: it's what an operator reads in journalctl or docker compose logs
    print(message)
    logger.info(message)


def ensure_first_admin(db, argv=None) -> str:
    """At start-up: a server's first-admin invitation, or a local Shikari's default admin. Returns what
    it did ("seeded", "renamed", "invited", "pending", "refused-network", "waiting" or "nothing")."""
    return _server_first_admin(db) if is_server() else _local_default_admin(db, argv)


def _local_default_admin(db, argv=None) -> str:
    from shikari.auth.password import hash_password
    from shikari.database.models import User, UserRole

    legacy = db.query(User).filter(User.email == LEGACY_DEFAULT_ADMIN_EMAIL).first()
    if legacy and not db.query(User.id).filter(User.email == DEFAULT_ADMIN_LOGIN).first():
        # The default admin used to sign in as admin@shikari.app; now it's `admin`
        legacy.email = DEFAULT_ADMIN_LOGIN
        db.commit()
        from shikari.database.audit import log_audit_event

        log_audit_event(db, EVENT_DEFAULT_ADMIN_RENAMED, user_id=legacy.id, email=DEFAULT_ADMIN_LOGIN,
                        details=f"{LEGACY_DEFAULT_ADMIN_EMAIL} now signs in as {DEFAULT_ADMIN_LOGIN}")
        _say(f"✓ The default admin {LEGACY_DEFAULT_ADMIN_EMAIL} now signs in as '{DEFAULT_ADMIN_LOGIN}'")
        return "renamed"

    if db.query(User).count():
        return "nothing"
    host = bind_host(argv)
    if not loopback_only(host):
        _say("=" * 60 + f"\nNo default admin: Shikari is listening on {host}, not just this machine, and the "
             f"default admin's password is public.\nGet a first admin with an invitation:\n"
             f"  shikari first-admin you@example.org\nor run Shikari on 127.0.0.1 (shikari start --host 127.0.0.1) "
             f"to have the default one.\n" + "=" * 60)
        return "refused-network"
    admin = User(email=DEFAULT_ADMIN_LOGIN, full_name="Admin User", password_hash=hash_password(DEFAULT_ADMIN_PASSWORD),
                 role=UserRole.ADMIN, is_active=True, failed_login_attempts=0)
    db.add(admin)
    db.commit()
    from shikari.database.audit import log_audit_event

    log_audit_event(db, EVENT_DEFAULT_ADMIN_SEEDED, user_id=admin.id, email=DEFAULT_ADMIN_LOGIN,
                    details=f"the local default admin, on {host or '127.0.0.1'}")
    _say("=" * 60 + f"\n✓ Default admin account created\n  Sign in as: {DEFAULT_ADMIN_LOGIN}\n"
         f"  Password:   {DEFAULT_ADMIN_PASSWORD}\n\n  Change this password after signing in (Profile → Security): "
         "it's public.\n" + "=" * 60)
    return "seeded"


def _server_first_admin(db) -> str:
    from datetime import datetime

    from shikari.auth.invitations import InvitationError, bootstrap_admin
    from shikari.auth.password import verify_password
    from shikari.database.models import Invitation, User, UserRole

    for old in db.query(User).filter(User.email.in_([DEFAULT_ADMIN_LOGIN, LEGACY_DEFAULT_ADMIN_EMAIL]),
                                     User.is_active.is_(True)).all():
        if verify_password(DEFAULT_ADMIN_PASSWORD, old.password_hash):
            _say(f"WARNING: the account '{old.email}' still has the public default password. Change it "
                 "(Profile → Security) or deactivate it (Settings → Users).")

    if db.query(User).filter(User.role == UserRole.ADMIN, User.is_active.is_(True)).count():
        return "nothing"
    waiting = db.query(Invitation).filter(Invitation.invited_by.is_(None), Invitation.role == UserRole.ADMIN,
                                          Invitation.accepted_at.is_(None), Invitation.revoked_at.is_(None),
                                          Invitation.expires_at > datetime.utcnow()).first()
    if waiting:
        _say(f"Shikari has no admin yet. A first-admin invitation for {waiting.email} is open until "
             f"{waiting.expires_at:%Y-%m-%d %H:%M} UTC. Lost the link? Issue a new one: "
             "shikari first-admin <email>")
        return "pending"
    email = os.environ.get(ADMIN_EMAIL_ENV, "").strip()
    if not email:
        _say(f"Shikari has no admin yet. Set {ADMIN_EMAIL_ENV} and restart, or issue a first-admin "
             "invitation: shikari first-admin you@example.org")
        return "waiting"
    try:
        invitation, link = bootstrap_admin(db, email)
    except InvitationError as e:
        _say(f"Couldn't make the first-admin invitation for {email}: {e}")
        return "waiting"
    from shikari.auth.links import warn_if_no_base_url

    warn_if_no_base_url()
    _say("=" * 60 + f"\nFirst admin: an invitation for {invitation.email}. Open it within 24 hours to choose a "
         f"password and set up an authenticator:\n\n  {link}\n\n" + "=" * 60)
    return "invited"
