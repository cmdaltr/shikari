#!/usr/bin/env python3
"""
Reset password for an existing admin account.

Usage:
    python scripts/admin/reset_password.py
"""

import sys
import getpass
from pathlib import Path

# Add project root to path (parent of scripts directory)
sys.path.insert(0, str(Path(__file__).parents[2]))

from shikari.database.db import init_db, get_db_session
from shikari.database.models import User
from shikari.auth.password import hash_password, validate_password


def reset_password():
    """Reset admin password."""
    print("=" * 60)
    print("Shikari - Reset Admin Password")
    print("=" * 60)
    print()

    # Initialize database
    print("Initializing database...")
    init_db()
    print()

    # Get email
    email = input("Email address: ").strip()

    if not email or '@' not in email:
        print("❌ Invalid email address")
        sys.exit(1)

    # Get and validate new password
    while True:
        password = getpass.getpass("New password: ")
        password_confirm = getpass.getpass("Confirm new password: ")

        if password != password_confirm:
            print("❌ Passwords do not match. Please try again.\n")
            continue

        # Validate password
        is_valid, error_msg = validate_password(password)

        if not is_valid:
            print(f"❌ {error_msg}\n")
            print("Password requirements:")
            print("  - Minimum 16 characters")
            print("  - Maximum 40 characters")
            print("  - At least one letter")
            print("  - At least one number")
            print("  - At least one special character: !@£$%^&()-_+=[]{}:|<>?")
            print()
            continue

        break

    # Update password
    db = get_db_session()

    try:
        # Find user
        user = db.query(User).filter(User.email == email).first()

        if not user:
            print(f"❌ User with email '{email}' not found")
            sys.exit(1)

        # Hash and update password
        user.password_hash = hash_password(password)
        db.commit()

        print()
        print("=" * 60)
        print("✓ Password updated successfully!")
        print("=" * 60)
        print(f"Email: {email}")
        print(f"Name: {user.full_name}")
        print(f"Role: {user.role.value}")
        print()
        print("You can now log in at: http://localhost:32453/login")
        print("=" * 60)

    except Exception as e:
        print(f"❌ Error updating password: {e}")
        sys.exit(1)

    finally:
        db.close()


if __name__ == "__main__":
    try:
        reset_password()
    except KeyboardInterrupt:
        print("\n\n❌ Cancelled by user")
        sys.exit(1)
