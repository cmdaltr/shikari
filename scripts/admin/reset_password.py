#!/usr/bin/env python3
"""
Reset access for an account that can't sign in: prints a one-time link to choose a new password and
set up a new authenticator, and ends the account's sessions. The same as `shikari reset-access <email>`
(shikari/cli/reset_access.py), kept for the docs and habits that name this script.

Usage:
    python scripts/admin/reset_password.py <email>
    docker compose exec shikari python scripts/admin/reset_password.py <email>
"""

import os
import sys
from pathlib import Path

# The project root (parent of scripts/), and its data/ for the database
ROOT = Path(__file__).parents[2]
sys.path.insert(0, str(ROOT))
os.chdir(ROOT)

from shikari.cli.reset_access import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
