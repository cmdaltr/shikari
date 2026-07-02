"""
Rate limiting for Archer endpoints.

Simple in-memory rate limiting to prevent brute force attacks.
For production with multiple servers, consider Redis-based solution.
"""

import time
from collections import defaultdict
from threading import Lock
import logging

logger = logging.getLogger(__name__)

# In-memory storage for rate limiting
# Structure: {key: [(timestamp1, timestamp2, ...)]}
_rate_limit_storage = defaultdict(list)
_storage_lock = Lock()

# Configuration
MAX_LOGIN_ATTEMPTS = 5  # Maximum attempts
LOGIN_WINDOW_SECONDS = 300  # 5 minutes
LOCKOUT_DURATION_SECONDS = 900  # 15 minutes


def check_rate_limit(key: str, max_attempts: int = MAX_LOGIN_ATTEMPTS, window_seconds: int = LOGIN_WINDOW_SECONDS) -> tuple[bool, int]:
    """
    Check if a key has exceeded the rate limit.

    Args:
        key: Unique identifier (e.g., email or IP address)
        max_attempts: Maximum number of attempts allowed
        window_seconds: Time window in seconds

    Returns:
        Tuple of (is_allowed, attempts_remaining)
    """
    with _storage_lock:
        current_time = time.time()
        cutoff_time = current_time - window_seconds

        # Get attempts for this key
        attempts = _rate_limit_storage[key]

        # Remove old attempts outside the window
        attempts = [t for t in attempts if t > cutoff_time]
        _rate_limit_storage[key] = attempts

        # Check if limit exceeded
        if len(attempts) >= max_attempts:
            logger.warning(f"Rate limit exceeded for key: {key}")
            return False, 0

        attempts_remaining = max_attempts - len(attempts)
        return True, attempts_remaining


def record_attempt(key: str):
    """
    Record an attempt for rate limiting.

    Args:
        key: Unique identifier (e.g., email or IP address)
    """
    with _storage_lock:
        current_time = time.time()
        _rate_limit_storage[key].append(current_time)


def reset_rate_limit(key: str):
    """
    Reset rate limit for a key (e.g., after successful login).

    Args:
        key: Unique identifier to reset
    """
    with _storage_lock:
        if key in _rate_limit_storage:
            del _rate_limit_storage[key]
            logger.info(f"Rate limit reset for key: {key}")


def cleanup_old_entries():
    """
    Clean up old entries from storage to prevent memory leaks.
    Should be called periodically.
    """
    with _storage_lock:
        current_time = time.time()
        cutoff_time = current_time - (LOGIN_WINDOW_SECONDS * 2)

        keys_to_remove = []
        for key, attempts in _rate_limit_storage.items():
            # Remove old timestamps
            attempts = [t for t in attempts if t > cutoff_time]
            if not attempts:
                keys_to_remove.append(key)
            else:
                _rate_limit_storage[key] = attempts

        # Remove empty keys
        for key in keys_to_remove:
            del _rate_limit_storage[key]

        if keys_to_remove:
            logger.debug(f"Cleaned up {len(keys_to_remove)} old rate limit entries")


def get_lockout_time_remaining(locked_until: float) -> int:
    """
    Get seconds remaining until lockout expires.

    Args:
        locked_until: Timestamp when lockout expires

    Returns:
        Seconds remaining (0 if expired)
    """
    if not locked_until:
        return 0

    remaining = int(locked_until - time.time())
    return max(0, remaining)
