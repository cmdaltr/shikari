"""`shikari invite <email> --role standard|operator|admin [--name …]`: an invitation from the server, for
when no admin can sign in to send one (the admin's own way is Settings → Users → Invite). Prints a
one-time link; the account is made when they accept it. See shikari/auth/invitations.py.

`--bootstrap` (what scripts/admin/create_admin.py runs) is an admin invitation for a first admin, or for
getting back in when no admin is left: refused while an active admin exists, unless --force.

In Docker: docker compose exec shikari python shikari/service.py invite <email> --role …
"""

from __future__ import annotations

import argparse
import sys

ADMIN_EXISTS = 3


def invite(email: str, role: str, name: str | None = None, *, bootstrap: bool = False,
           force: bool = False) -> int:
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
    if not links.base_url_set():
        print("BASE_URL isn't set, so this link names localhost. Set BASE_URL to the address people "
              "open Shikari at, or change the start of the link by hand.", file=sys.stderr)
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
    parser.add_argument("--bootstrap", action="store_true",
                        help="an admin invitation from the server; refused while an active admin exists")
    parser.add_argument("--force", action="store_true", help="with --bootstrap: even though an admin exists")
    args = parser.parse_args(sys.argv[1:] if argv is None else argv)
    return invite(args.email, args.role, args.name, bootstrap=args.bootstrap, force=args.force)


if __name__ == "__main__":
    sys.exit(main())
