"""
Authentication module for Shikari.

Provides password hashing, session management, and authentication utilities.
"""

from shikari.auth.password import hash_password, verify_password, validate_password
from shikari.auth.session import create_session, get_current_user, get_user_from_session_id, delete_session
from shikari.auth.encryption import encrypt_api_key, decrypt_api_key

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
]
