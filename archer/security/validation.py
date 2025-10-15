"""
Security validation utilities for Archer.

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
