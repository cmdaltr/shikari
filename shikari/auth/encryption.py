"""
API key encryption utilities.

Uses Fernet symmetric encryption to encrypt API keys at rest.
"""

from cryptography.fernet import Fernet
import os
from pathlib import Path


def get_encryption_key() -> bytes:
    """
    Get or create the encryption key for API keys.

    The key is stored in data/.encryption_key
    If it doesn't exist, a new key is generated.

    Returns:
        Encryption key as bytes
    """
    key_file = Path("data/.encryption_key")

    # Create directory if it doesn't exist
    key_file.parent.mkdir(parents=True, exist_ok=True)

    if key_file.exists():
        # Read existing key
        with open(key_file, 'rb') as f:
            return f.read()
    else:
        # Generate new key
        key = Fernet.generate_key()
        with open(key_file, 'wb') as f:
            f.write(key)
        # Set restrictive permissions (owner read/write only)
        os.chmod(key_file, 0o600)
        return key


def encrypt_api_key(plain_key: str) -> str:
    """
    Encrypt an API key for storage.

    Args:
        plain_key: Plain text API key

    Returns:
        Encrypted key as string
    """
    encryption_key = get_encryption_key()
    fernet = Fernet(encryption_key)
    encrypted = fernet.encrypt(plain_key.encode('utf-8'))
    return encrypted.decode('utf-8')


def decrypt_api_key(encrypted_key: str) -> str:
    """
    Decrypt an API key from storage.

    Args:
        encrypted_key: Encrypted API key

    Returns:
        Plain text API key
    """
    encryption_key = get_encryption_key()
    fernet = Fernet(encryption_key)
    decrypted = fernet.decrypt(encrypted_key.encode('utf-8'))
    return decrypted.decode('utf-8')
