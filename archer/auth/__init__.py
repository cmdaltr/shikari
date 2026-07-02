"""
Authentication module for Archer.

Provides password hashing, session management, and authentication utilities.
"""

from archer.auth.password import hash_password, verify_password, validate_password
from archer.auth.session import create_session, get_current_user, get_user_from_session_id, delete_session
from archer.auth.encryption import encrypt_api_key, decrypt_api_key
from archer.auth.password_reset import (
    create_password_reset_request,
    validate_reset_token,
    reset_password_with_token,
    admin_reset_password
)

__all__ = [
    "hash_password",
    "verify_password",
    "validate_password",
    "create_session",
    "get_current_user",
    "get_user_from_session_id",
    "delete_session",
    "encrypt_api_key",
    "decrypt_api_key",
    "create_password_reset_request",
    "validate_reset_token",
    "reset_password_with_token",
    "admin_reset_password"
]
