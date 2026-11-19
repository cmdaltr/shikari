#!/usr/bin/env python3
"""
An admin invitation from the server: prints a one-time link for this email to open an admin account
(choosing a password and setting up an authenticator). For a first admin, or for getting back in when
no admin is left; refused while an active admin exists, unless --force. The same as
`shikari invite <email> --bootstrap` (shikari/cli/invite.py).

Usage:
    python scripts/admin/create_admin.py <email> [--force]
    docker compose exec shikari python scripts/admin/create_admin.py <email> [--force]
"""

import argparse
import os
import sys
from pathlib import Path

# The project root (parent of scripts/), and its data/ for the database
ROOT = Path(__file__).parents[2]
sys.path.insert(0, str(ROOT))
os.chdir(ROOT)

from shikari.cli.invite import invite  # noqa: E402


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="create_admin.py", description="An admin invitation link.")
    parser.add_argument("email", help="the new admin's email address")
    parser.add_argument("--force", action="store_true", help="even though an active admin exists")
    args = parser.parse_args(argv)
    return invite(args.email, "admin", bootstrap=True, force=args.force)


if __name__ == "__main__":
    sys.exit(main())
