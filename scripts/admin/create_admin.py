#!/usr/bin/env python3
"""
Create initial admin account for Shikari.

Usage:
    python create_admin.py

This script will prompt for admin email, full name, and password.
The password must meet the following requirements:
- Minimum 16 characters
- Maximum 40 characters
- Must contain at least one letter
- Must contain at least one number
- Must contain at least one special character: !@£$%^&()-_+=[]{}:|<>?
"""

import sys
import getpass
from pathlib import Path

# Add project root to path (parent of scripts directory)
sys.path.insert(0, str(Path(__file__).parent.parent))

from shikari.database.db import init_db, get_db_session
from shikari.database.models import User, UserRole
from shikari.auth.password import hash_password, validate_password


def create_admin():
    """Create admin account interactively."""
    print("=" * 60)
    print("Shikari - Create Admin Account")
    print("=" * 60)
    print()

    # Initialize database
    print("Initializing database...")
    init_db()
    print()

    # Get admin details
    email = input("Admin email: ").strip()

    if not email or '@' not in email:
        print("❌ Invalid email address")
        sys.exit(1)

    full_name = input("Full name: ").strip()

    if not full_name:
        print("❌ Full name cannot be empty")
        sys.exit(1)

    # Get and validate password
    while True:
        password = getpass.getpass("Password: ")
        password_confirm = getpass.getpass("Confirm password: ")

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

    # Create admin user
    db = get_db_session()

    try:
        # Check if user already exists
        existing_user = db.query(User).filter(User.email == email).first()

        if existing_user:
            print(f"❌ User with email '{email}' already exists")
            sys.exit(1)

        # Hash password
        password_hash = hash_password(password)

        # Create admin user
        admin = User(
            email=email,
            full_name=full_name,
            password_hash=password_hash,
            role=UserRole.ADMIN,
            is_active=True
        )

        db.add(admin)
        db.commit()

        print()
        print("=" * 60)
        print("✓ Admin account created successfully!")
        print("=" * 60)
        print(f"Email: {email}")
        print(f"Name: {full_name}")
        print(f"Role: Admin")
        print()
        print("You can now log in at: http://localhost:32453/login")
        print("=" * 60)

    except Exception as e:
        print(f"❌ Error creating admin account: {e}")
        sys.exit(1)

    finally:
        db.close()


if __name__ == "__main__":
    try:
        create_admin()
    except KeyboardInterrupt:
        print("\n\n❌ Cancelled by user")
        sys.exit(1)
