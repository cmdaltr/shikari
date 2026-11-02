"""
Password hashing and validation utilities.

Uses bcrypt for secure password hashing.
Implements password strength validation according to requirements:
- Max 40 characters
- Must contain letters, numbers, and at least one special character
- Special characters: !@£$%^&()-_+=[]{}:|<>?
"""

import bcrypt
import re
from typing import Tuple


def hash_password(password: str) -> str:
    """
    Hash a password using bcrypt.

    Args:
        password: Plain text password

    Returns:
        Bcrypt hash as string
    """
    # Generate salt and hash password
    salt = bcrypt.gensalt(rounds=12)
    hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed.decode('utf-8')


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verify a password against its bcrypt hash.

    Args:
        plain_password: Plain text password to verify
        hashed_password: Bcrypt hash to check against

    Returns:
        True if password matches, False otherwise
    """
    try:
        return bcrypt.checkpw(
            plain_password.encode('utf-8'),
            hashed_password.encode('utf-8')
        )
    except Exception:
        return False


def validate_password(password: str) -> Tuple[bool, str]:
    """
    Validate password strength according to requirements.

    Requirements:
    - Minimum 16 characters
    - Maximum 40 characters
    - Must contain at least one letter
    - Must contain at least one number
    - Must contain at least one special character from: !@£$%^&()-_+=[]{}:|<>?

    Args:
        password: Password to validate

    Returns:
        Tuple of (is_valid, error_message)
    """
    # Check length
    if len(password) == 0:
        return False, "Password cannot be empty"

    if len(password) < 16:
        return False, "Password must be at least 16 characters"

    if len(password) > 40:
        return False, "Password must be 40 characters or less"

    # bcrypt 4.x raises on input over 72 bytes; multi-byte characters can get there within 40 characters
    if len(password.encode("utf-8")) > 72:
        return False, "Password is too long once encoded (72 bytes maximum); use fewer non-ASCII characters"

    # Check for at least one letter
    if not re.search(r'[a-zA-Z]', password):
        return False, "Password must contain at least one letter"

    # Check for at least one number
    if not re.search(r'\d', password):
        return False, "Password must contain at least one number"

    # Check for at least one special character from the allowed set
    # Special characters: !@£$%^&()-_+=[]{}:|<>?
    allowed_special_chars = r'[!@£$%^&()\-_+=\[\]{}:|<>?]'
    if not re.search(allowed_special_chars, password):
        return False, "Password must contain at least one special character (!@£$%^&()-_+=[]{}:|<>?)"

    return True, ""

