"""`shikari reset-access <email>`: a one-time link for someone who can't sign in, from the server, for
when no admin can (the admin's own way is Settings → Users → Reset access). The link chooses a new
password and a new authenticator; the account's sessions end now. See shikari/auth/reset_access.py.

In Docker: docker compose exec shikari python shikari/service.py reset-access <email>
"""

from __future__ import annotations

import argparse
import sys


def reset_access(email: str) -> int:
    from shikari.auth.reset_access import RESET_ACCESS_EXPIRY_HOURS, ResetAccessError, issue_reset_access
    from shikari.database.db import Base, SessionLocal, _add_missing_columns, engine

    # A server not yet restarted on this code hasn't added the reset-access columns
    Base.metadata.create_all(bind=engine)
    _add_missing_columns(Base)
    db = SessionLocal()
    try:
        user, link = issue_reset_access(db, email=email)
        email = user.email
    except ResetAccessError as exc:
        print(exc, file=sys.stderr)
        return 1
    finally:
        db.close()
    print(f"Access reset for {email}; their sessions have ended. Give them this link, which works once "
          f"within {RESET_ACCESS_EXPIRY_HOURS} hours:\n\n  {link}\n")
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="shikari reset-access",
        description="A one-time link to choose a new password and set up a new authenticator.")
    parser.add_argument("email", help="the account's email address")
    args = parser.parse_args(sys.argv[1:] if argv is None else argv)
    return reset_access(args.email)


if __name__ == "__main__":
    sys.exit(main())
