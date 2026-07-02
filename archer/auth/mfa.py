"""
Multi-Factor Authentication (MFA) utilities for Archer.

Provides TOTP-based 2FA functionality with QR code generation and backup codes.
"""

import pyotp
import qrcode
import io
import base64
import secrets
import json
from typing import List, Tuple
from archer.auth.password import hash_password, verify_password


def generate_totp_secret() -> str:
    """
    Generate a new TOTP secret key.

    Returns:
        Base32-encoded secret string (32 characters)
    """
    return pyotp.random_base32()


def generate_qr_code(email: str, secret: str, issuer: str = "Archer") -> str:
    """
    Generate a QR code for TOTP setup.

    Args:
        email: User's email address
        secret: TOTP secret key
        issuer: Application name (default: "Archer")

    Returns:
        Base64-encoded PNG image data URL
    """
    # Create TOTP URI
    totp = pyotp.TOTP(secret)
    uri = totp.provisioning_uri(name=email, issuer_name=issuer)

    # Generate QR code
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(uri)
    qr.make(fit=True)

    # Create image
    img = qr.make_image(fill_color="black", back_color="white")

    # Convert to base64
    buffer = io.BytesIO()
    img.save(buffer, format="PNG")
    buffer.seek(0)
    img_str = base64.b64encode(buffer.getvalue()).decode()

    return f"data:image/png;base64,{img_str}"


def verify_totp_code(secret: str, code: str) -> bool:
    """
    Verify a TOTP code against a secret.

    Args:
        secret: TOTP secret key
        code: 6-digit code to verify

    Returns:
        True if code is valid, False otherwise
    """
    if not secret or not code:
        return False

    try:
        totp = pyotp.TOTP(secret)
        # Allow 1 time step before/after for clock drift (30 second window)
        return totp.verify(code, valid_window=1)
    except Exception:
        return False


def generate_backup_codes(count: int = 10) -> Tuple[List[str], str]:
    """
    Generate backup recovery codes.

    Args:
        count: Number of codes to generate (default: 10)

    Returns:
        Tuple of (plain_codes, hashed_codes_json)
        - plain_codes: List of readable backup codes
        - hashed_codes_json: JSON string of hashed codes for storage
    """
    plain_codes = []
    hashed_codes = []

    for _ in range(count):
        # Generate 8-character alphanumeric code
        code = secrets.token_hex(4).upper()
        formatted_code = f"{code[:4]}-{code[4:8]}"
        plain_codes.append(formatted_code)

        # Hash the code for storage
        hashed_codes.append({
            "hash": hash_password(formatted_code),
            "used": False
        })

    return plain_codes, json.dumps(hashed_codes)


def verify_backup_code(stored_codes_json: str, code: str) -> Tuple[bool, str]:
    """
    Verify a backup code and mark it as used.

    Args:
        stored_codes_json: JSON string of stored backup codes
        code: Code to verify

    Returns:
        Tuple of (is_valid, updated_json)
        - is_valid: True if code is valid and unused
        - updated_json: Updated JSON with code marked as used
    """
    if not stored_codes_json or not code:
        return False, stored_codes_json

    try:
        codes = json.loads(stored_codes_json)

        for backup_code in codes:
            if not backup_code["used"]:
                if verify_password(code, backup_code["hash"]):
                    # Mark as used
                    backup_code["used"] = True
                    return True, json.dumps(codes)

        return False, stored_codes_json
    except Exception:
        return False, stored_codes_json


def count_remaining_backup_codes(stored_codes_json: str) -> int:
    """
    Count how many backup codes are still unused.

    Args:
        stored_codes_json: JSON string of stored backup codes

    Returns:
        Number of unused backup codes
    """
    if not stored_codes_json:
        return 0

    try:
        codes = json.loads(stored_codes_json)
        return sum(1 for code in codes if not code["used"])
    except Exception:
        return 0
