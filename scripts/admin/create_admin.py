#!/usr/bin/env python3
"""
The first admin's invitation: prints a one-time link for this email to open an admin account (choosing a
password and setting up an authenticator). For a fresh team server, or for getting back in when no admin
is left; refused while an active admin exists, unless --force. The same as `shikari first-admin <email>`
(shikari/cli/first_admin.py).

Usage:
    python scripts/admin/create_admin.py <email> [--force] [--link-only]
    docker compose exec shikari python scripts/admin/create_admin.py <email> [--force]
"""

import os
import sys
from pathlib import Path

# The project root (parent of scripts/), and its data/ for the database
ROOT = Path(__file__).parents[2]
sys.path.insert(0, str(ROOT))
os.chdir(ROOT)

from shikari.cli.first_admin import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main(prog="create_admin.py"))
