"""`shikari first-admin <email> [--force] [--link-only]`: the first admin's invitation, Ostraka's way. A
team server seeds no account (shikari/deployment.py): its first start prints one of these for
SHIKARI_ADMIN_EMAIL, and this issues one on demand, for a fresh server or for getting back in when no
admin is left. Refused while an active admin exists, unless --force; only the newest such link works;
24 hours, the token after #. scripts/admin/create_admin.py runs this.

In Docker: docker compose exec shikari python shikari/service.py first-admin <email>
"""

from __future__ import annotations

import argparse
import sys

from shikari.cli.invite import ADMIN_EXISTS, invite

__all__ = ["ADMIN_EXISTS", "main"]


def main(argv=None, prog: str = "shikari first-admin") -> int:
    parser = argparse.ArgumentParser(prog=prog, description="A one-time link that opens the first admin account.")
    parser.add_argument("email", help="the admin's email address")
    parser.add_argument("--force", action="store_true", help="even though an active admin exists")
    parser.add_argument("--link-only", action="store_true", help="print only the link (for install scripts)")
    args = parser.parse_args(sys.argv[1:] if argv is None else argv)
    return invite(args.email, "admin", bootstrap=True, force=args.force, link_only=args.link_only)


if __name__ == "__main__":
    sys.exit(main())
