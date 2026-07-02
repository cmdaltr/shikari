"""
CSRF (Cross-Site Request Forgery) Protection.

Provides token-based CSRF protection for forms.
"""

import secrets
from datetime import datetime, timedelta
from typing import Dict
import threading

# Secret key for signing CSRF tokens
# In production, this should be loaded from environment variable
import os
CSRF_SECRET_KEY = os.getenv("CSRF_SECRET_KEY", secrets.token_hex(32))

# In-memory store for CSRF tokens
# Format: {token: {"session_id": str, "created_at": datetime}}
csrf_tokens: Dict[str, dict] = {}
csrf_lock = threading.Lock()

# CSRF token expiry time (in minutes)
CSRF_TOKEN_EXPIRY = 60  # 1 hour


def generate_csrf_token(session_id: str) -> str:
    """
    Generate a new CSRF token for a session.

    Args:
        session_id: The user's session ID

    Returns:
        CSRF token string
    """
    # Generate random token
    token = secrets.token_urlsafe(32)

    # Store token with session ID
    with csrf_lock:
        csrf_tokens[token] = {
            "session_id": session_id,
            "created_at": datetime.utcnow()
        }

    return token


def validate_csrf_token(token: str, session_id: str) -> bool:
    """
    Validate a CSRF token.

    Args:
        token: The CSRF token to validate
        session_id: The user's current session ID

    Returns:
        True if token is valid, False otherwise
    """
    if not token or not session_id:
        return False

    with csrf_lock:
        # Check if token exists
        token_data = csrf_tokens.get(token)

        if not token_data:
            return False

        # Check if token belongs to the session
        if token_data["session_id"] != session_id:
            return False

        # Check if token has expired
        created_at = token_data["created_at"]
        expiry_time = created_at + timedelta(minutes=CSRF_TOKEN_EXPIRY)

        if datetime.utcnow() > expiry_time:
            # Token expired - remove it
            del csrf_tokens[token]
            return False

        return True


def consume_csrf_token(token: str) -> None:
    """
    Consume (delete) a CSRF token after successful validation.
    This prevents token reuse.

    Args:
        token: The CSRF token to consume
    """
    with csrf_lock:
        if token in csrf_tokens:
            del csrf_tokens[token]


def cleanup_expired_tokens() -> int:
    """
    Remove all expired CSRF tokens from memory.

    Returns:
        Number of tokens removed
    """
    current_time = datetime.utcnow()
    removed_count = 0

    with csrf_lock:
        # Find expired tokens
        expired_tokens = [
            token for token, data in csrf_tokens.items()
            if current_time > data["created_at"] + timedelta(minutes=CSRF_TOKEN_EXPIRY)
        ]

        # Remove expired tokens
        for token in expired_tokens:
            del csrf_tokens[token]
            removed_count += 1

    return removed_count


def get_csrf_token_count() -> int:
    """
    Get the number of active CSRF tokens in memory.

    Returns:
        Count of active tokens
    """
    with csrf_lock:
        return len(csrf_tokens)
