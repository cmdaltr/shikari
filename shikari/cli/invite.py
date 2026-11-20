"""`shikari invite <email> --role standard|operator|admin [--name …]`: an invitation from the server, for
when no admin can sign in to send one (the admin's own way is Settings → Users → Invite). Prints a
one-time link; the account is made when they accept it. See shikari/auth/invitations.py.

A first admin's invitation is `shikari first-admin <email>` (shikari/cli/first_admin.py), which runs
invite(..., bootstrap=True).

In Docker: docker compose exec shikari python shikari/service.py invite <email> --role …
"""

from __future__ import annotations

import argparse
import sys

# The exit status for a first-admin link refused because an active admin exists (the same in
# Ostraka and Rowanholt)
ADMIN_EXISTS = 5


def invite(email: str, role: str, name: str | None = None, *, bootstrap: bool = False,
           force: bool = False, link_only: bool = False) -> int:
    from shikari.auth import links
    from shikari.auth.invitations import (INVITATION_EXPIRY_HOURS, AdminExists, InvitationError,
                                          bootstrap_admin, create_invitation)
    from shikari.database.audit import Base as AuditBase
    from shikari.database.db import Base, SessionLocal, _add_missing_columns, engine

    # A server not yet restarted on this code hasn't made the invitations table
    Base.metadata.create_all(bind=engine)
    AuditBase.metadata.create_all(bind=engine)
    _add_missing_columns(Base)
    db = SessionLocal()
    try:
        if bootstrap:
            invitation, link = bootstrap_admin(db, email, force=force)
        else:
            invitation, link = create_invitation(db, email=email, role=role, full_name=name)
        email, role = invitation.email, invitation.role.value
    except AdminExists as exc:
        print(exc, file=sys.stderr)
        return ADMIN_EXISTS
    except InvitationError as exc:
        print(exc, file=sys.stderr)
        return 1
    finally:
        db.close()
    links.warn_if_no_base_url()
    if link_only:
        print(link)
    else:
        print(f"Invitation for {email} ({role}). Give them this link, which works once within "
              f"{INVITATION_EXPIRY_HOURS} hours:\n\n  {link}\n")
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="shikari invite",
                                     description="A one-time link that opens an account with this role.")
    parser.add_argument("email", help="who to invite")
    parser.add_argument("--role", choices=["standard", "operator", "admin"], default="standard",
                        help="standard (Analyst), operator (Operational analyst) or admin; default standard")
    parser.add_argument("--name", help="their full name (they can change it when they accept)")
    args = parser.parse_args(sys.argv[1:] if argv is None else argv)
    return invite(args.email, args.role, args.name)


if __name__ == "__main__":
    sys.exit(main())
