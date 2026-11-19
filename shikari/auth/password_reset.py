"""
Password reset functionality for Shikari.

Provides token generation, validation, and password reset workflows. Resetting someone else's
access (password and authenticator) is shikari/auth/reset_access.py.
"""

import secrets
from datetime import datetime, timedelta
from typing import Optional
from sqlalchemy.orm import Session as SQLAlchemySession

from shikari.database.models import PasswordReset, Session, User
from shikari.auth.password import hash_password


# Token expiry time (1 hour)
TOKEN_EXPIRY_HOURS = 1


def generate_reset_token() -> str:
    """
    Generate a secure random token for password reset.

    Returns:
        A URL-safe random token string (32 bytes = 64 hex characters)
    """
    return secrets.token_urlsafe(32)


def create_password_reset_request(email: str, db: SQLAlchemySession) -> Optional[str]:
    """
    Create a password reset request for a user.

    Args:
        email: User's email address
        db: Database session

    Returns:
        Reset token if successful, None if user not found
    """
    # Find user by email
    user = db.query(User).filter(User.email == email, User.is_active == True).first()

    if not user:
        return None

    # Generate reset token
    token = generate_reset_token()

    # Calculate expiry time
    expires_at = datetime.utcnow() + timedelta(hours=TOKEN_EXPIRY_HOURS)

    # Invalidate any existing emailed reset tokens for this user (not a reset-access link an admin
    # issued: anyone can ask for an email, and that mustn't cancel it)
    db.query(PasswordReset).filter(
        PasswordReset.user_id == user.id,
        PasswordReset.used == False,
        PasswordReset.kind.is_(None)
    ).update({"used": True})

    # Create new reset request
    reset_request = PasswordReset(
        user_id=user.id,
        reset_token=token,
        expires_at=expires_at
    )

    db.add(reset_request)
    db.commit()

    return token


def validate_reset_token(token: str, db: SQLAlchemySession) -> Optional[User]:
    """
    Validate a password reset token and return the associated user.

    Args:
        token: Reset token to validate
        db: Database session

    Returns:
        User object if token is valid, None otherwise
    """
    # Find reset request
    reset_request = db.query(PasswordReset).filter(
        PasswordReset.reset_token == token,
        PasswordReset.used == False,
        PasswordReset.kind.is_(None)
    ).first()

    if not reset_request:
        return None

    # Check if token has expired
    if datetime.utcnow() > reset_request.expires_at:
        return None

    # Get user
    user = db.query(User).filter(
        User.id == reset_request.user_id,
        User.is_active == True
    ).first()

    return user


def reset_password_with_token(token: str, new_password: str, db: SQLAlchemySession) -> bool:
    """
    Reset a user's password using a valid reset token.

    Args:
        token: Reset token
        new_password: New password to set
        db: Database session

    Returns:
        True if password was reset successfully, False otherwise
    """
    # Validate token and get user
    user = validate_reset_token(token, db)

    if not user:
        return False

    # Hash new password
    hashed_password = hash_password(new_password)

    # Update user's password
    user.password_hash = hashed_password

    # Mark token as used
    db.query(PasswordReset).filter(
        PasswordReset.reset_token == token,
        PasswordReset.kind.is_(None)
    ).update({"used": True})
    # A new password ends every session the old one opened
    db.query(Session).filter(Session.user_id == user.id).delete()

    db.commit()

    return True

