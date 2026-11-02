"""
Security validation utilities for Shikari.

Provides input validation and sanitization functions to prevent common security vulnerabilities.
"""

import os
import re
from pathlib import Path
from typing import Optional


def sanitize_filename(filename: str) -> str:
    """
    Sanitize a filename to prevent path traversal and injection attacks.

    Args:
        filename: The filename to sanitize

    Returns:
        Sanitized filename safe for file operations
    """
    # Remove any path components
    filename = os.path.basename(filename)

    # Replace dangerous characters with underscores
    # Keep only alphanumeric, spaces, hyphens, underscores, and periods
    filename = re.sub(r'[^\w\s\-\.]', '_', filename)

    # Remove leading/trailing spaces and dots
    filename = filename.strip('. ')

    # Prevent empty filename
    if not filename:
        filename = 'unnamed_file'

    return filename


def sanitize_path_component(component: str) -> str:
    """
    Sanitize a path component (like group_name or domain) to prevent path traversal.

    Args:
        component: The path component to sanitize

    Returns:
        Sanitized component safe for use in file paths
    """
    # Remove any path separators
    component = component.replace('/', '_').replace('\\', '_')

    # Remove parent directory references
    component = component.replace('..', '_')

    # Replace dangerous characters
    component = re.sub(r'[^\w\-\.]', '_', component)

    # Remove leading/trailing spaces, dots, and underscores
    component = component.strip('_. ')

    # Prevent empty component
    if not component:
        component = 'default'

    # Limit length to prevent issues
    if len(component) > 200:
        component = component[:200]

    return component


def validate_safe_path(base_dir: str, requested_path: str) -> Optional[str]:
    """
    Validate that a requested path is within the allowed base directory.
    Prevents path traversal attacks.

    Args:
        base_dir: The base directory that should contain the requested path
        requested_path: The path to validate

    Returns:
        The validated absolute path if safe, None if unsafe
    """
    # Resolve to absolute paths
    base = Path(base_dir).resolve()
    target = Path(requested_path).resolve()

    # Check if target is within base directory
    try:
        target.relative_to(base)
        return str(target)
    except ValueError:
        # Path is outside base directory
        return None


def validate_url(url: str) -> bool:
    """
    Validate that a URL is safe for fetching (basic validation).

    Args:
        url: The URL to validate

    Returns:
        True if URL appears safe, False otherwise
    """
    from urllib.parse import urlparse

    try:
        parsed = urlparse(url)

        # Must have http or https scheme
        if parsed.scheme not in ['http', 'https']:
            return False

        # Must have a hostname
        if not parsed.hostname:
            return False

        # URL must not be excessively long
        if len(url) > 2048:
            return False

        return True
    except Exception:
        return False


def validate_json_size(data: bytes, max_size_mb: int = 10) -> bool:
    """
    Validate that JSON data is not too large.

    Args:
        data: The JSON data as bytes
        max_size_mb: Maximum allowed size in megabytes

    Returns:
        True if size is acceptable, False otherwise
    """
    max_bytes = max_size_mb * 1024 * 1024
    return len(data) <= max_bytes


def sanitize_group_name(group_name: str) -> str:
    """
    Sanitize a group name for safe use in file operations and URLs.

    Args:
        group_name: The group name to sanitize

    Returns:
        Sanitized group name
    """
    # Replace spaces with underscores
    group_name = group_name.replace(' ', '_')

    # Use the path component sanitizer
    return sanitize_path_component(group_name)


def validate_email(email: str) -> tuple[bool, str]:
    """
    Validate and normalize email address format.

    Requirements:
    - MUST contain @ symbol
    - Minimum 10 characters total
    - Maximum 64 characters total
    - Valid email format

    Args:
        email: Email address to validate

    Returns:
        Tuple of (is_valid, normalized_email_or_error_message)
    """
    if not email or not isinstance(email, str):
        return False, "Email is required"

    # Normalize: strip whitespace and convert to lowercase
    email = email.strip().lower()

    # MUST have @ symbol
    if '@' not in email:
        return False, "Email must contain @ symbol"

    # Check length - minimum 10 characters
    if len(email) < 10:
        return False, "Email is too short (minimum 10 characters)"

    # Check length - MUST be limited to 64 characters
    if len(email) > 64:
        return False, "Email is too long (maximum 64 characters)"

    # Basic email format validation
    email_pattern = r'^[a-z0-9][a-z0-9._+-]*@[a-z0-9][a-z0-9.-]*\.[a-z]{2,}$'

    if not re.match(email_pattern, email):
        return False, "Invalid email format"

    # Split and validate parts
    local_part, domain = email.rsplit('@', 1)

    # Prevent consecutive dots
    if '..' in email:
        return False, "Invalid email format"

    # Check for dangerous patterns
    dangerous_patterns = ['<', '>', '(', ')', '[', ']', '\\', ',', ';', ':', '"', '\n', '\r']
    if any(char in email for char in dangerous_patterns):
        return False, "Email contains invalid characters"

    return True, email


def sanitize_full_name(full_name: str) -> tuple[bool, str]:
    """
    Validate and sanitize full name input.

    Requirements:
    - ONLY uppercase and lowercase letters (a-z, A-Z)
    - Hyphens/dashes (-)
    - Spaces
    - Maximum 64 characters

    Args:
        full_name: Full name to sanitize

    Returns:
        Tuple of (is_valid, sanitized_name_or_error_message)
    """
    if not full_name or not isinstance(full_name, str):
        return False, "Full name is required"

    # Normalize: strip leading/trailing whitespace
    full_name = full_name.strip()

    # Collapse multiple spaces into single space
    full_name = re.sub(r'\s+', ' ', full_name)

    # Check length
    if len(full_name) < 1:
        return False, "Full name is required"

    # MUST be limited to 64 characters
    if len(full_name) > 64:
        return False, "Full name is too long (maximum 64 characters)"

    # ONLY allow uppercase/lowercase letters, hyphens, and spaces
    allowed_pattern = r'^[a-zA-Z\s\-]+$'
    if not re.match(allowed_pattern, full_name):
        return False, "Full name can only contain letters, hyphens, and spaces"

    return True, full_name


def sanitize_api_key(api_key: str, key_name: str = "API key") -> tuple[bool, str]:
    """
    Validate and sanitize API key input.

    Args:
        api_key: API key to validate
        key_name: Name of the key for error messages

    Returns:
        Tuple of (is_valid, sanitized_key_or_error_message)
    """
    if not api_key or not isinstance(api_key, str):
        # Empty API keys are allowed (user might not have all keys)
        return True, ""

    # Normalize: strip whitespace
    api_key = api_key.strip()

    # If empty after stripping, return empty (valid)
    if not api_key:
        return True, ""

    # Check length (most API keys are 20-100 characters)
    if len(api_key) < 10:
        return False, f"{key_name} is too short (minimum 10 characters)"

    if len(api_key) > 500:
        return False, f"{key_name} is too long (maximum 500 characters)"

    # Allow alphanumeric, hyphens, underscores, and common API key characters
    # Most API keys use base64, hex, or similar encodings
    if not re.match(r'^[a-zA-Z0-9_\-\.=+/]+$', api_key):
        return False, f"{key_name} contains invalid characters"

    # Prevent obviously invalid keys
    if api_key.lower() in ['test', 'example', 'placeholder', 'your-api-key', 'your_api_key']:
        return False, f"{key_name} appears to be a placeholder value"

    return True, api_key


def sanitize_text_input(text: str, field_name: str = "Input", max_length: int = 1000) -> tuple[bool, str]:
    """
    General text input sanitization for forms.

    Args:
        text: Text to sanitize
        field_name: Name of the field for error messages
        max_length: Maximum allowed length

    Returns:
        Tuple of (is_valid, sanitized_text_or_error_message)
    """
    if not isinstance(text, str):
        return False, f"{field_name} must be text"

    # Normalize: strip whitespace
    text = text.strip()

    # Check length
    if len(text) > max_length:
        return False, f"{field_name} is too long (maximum {max_length} characters)"

    # Check for null bytes (security risk)
    if '\x00' in text:
        return False, f"{field_name} contains invalid characters"

    # Check for dangerous control characters (except newlines and tabs for multi-line input)
    dangerous_chars = ['\x00', '\x01', '\x02', '\x03', '\x04', '\x05', '\x06', '\x07', '\x08',
                      '\x0b', '\x0c', '\x0e', '\x0f', '\x10', '\x11', '\x12', '\x13', '\x14',
                      '\x15', '\x16', '\x17', '\x18', '\x19', '\x1a', '\x1b', '\x1c', '\x1d',
                      '\x1e', '\x1f', '\x7f']

    if any(char in text for char in dangerous_chars):
        return False, f"{field_name} contains invalid control characters"

    return True, text
