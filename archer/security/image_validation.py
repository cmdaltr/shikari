"""
Secure image file validation for profile pictures.

Validates:
- File extension (.jpg, .jpeg, .png)
- Magic bytes (file signature) to verify actual file type
- File size (maximum 5MB)
"""

from typing import Tuple
import os


# Maximum file size: 5MB
MAX_FILE_SIZE = 5 * 1024 * 1024  # 5MB in bytes

# Allowed extensions
ALLOWED_EXTENSIONS = {'.jpg', '.jpeg', '.png'}

# Magic bytes for image file formats
# These are the first few bytes that identify the file type
MAGIC_BYTES = {
    'jpeg': [
        b'\xFF\xD8\xFF\xE0',  # JPEG/JFIF
        b'\xFF\xD8\xFF\xE1',  # JPEG/Exif
        b'\xFF\xD8\xFF\xE2',  # JPEG/Canon
        b'\xFF\xD8\xFF\xE3',  # JPEG/Samsung
        b'\xFF\xD8\xFF\xE8',  # JPEG/SPIFF
        b'\xFF\xD8\xFF\xDB',  # JPEG raw
        b'\xFF\xD8\xFF\xEE',  # JPEG/Adobe
    ],
    'png': [
        b'\x89PNG\r\n\x1a\n',  # PNG
    ]
}


def validate_image_file(file_content: bytes, filename: str) -> Tuple[bool, str]:
    """
    Validate image file for security.

    Performs three levels of validation:
    1. File extension check
    2. Magic bytes verification (file signature)
    3. File size limit

    Args:
        file_content: The file content as bytes
        filename: Original filename

    Returns:
        Tuple of (is_valid, error_message_or_file_type)
        If valid: (True, 'jpeg' or 'png')
        If invalid: (False, error_message)
    """
    # 1. Check file extension
    file_ext = os.path.splitext(filename)[1].lower()

    if not file_ext:
        return False, "File has no extension"

    if file_ext not in ALLOWED_EXTENSIONS:
        return False, f"Invalid file type. Only JPG and PNG images are allowed"

    # 2. Check file size
    file_size = len(file_content)

    if file_size == 0:
        return False, "File is empty"

    if file_size > MAX_FILE_SIZE:
        max_size_mb = MAX_FILE_SIZE / (1024 * 1024)
        actual_size_mb = file_size / (1024 * 1024)
        return False, f"File too large ({actual_size_mb:.1f}MB). Maximum size is {max_size_mb:.0f}MB"

    # 3. Verify magic bytes (file signature)
    # This prevents someone from renaming a .exe to .jpg
    detected_type = None

    # Check JPEG magic bytes
    for magic in MAGIC_BYTES['jpeg']:
        if file_content.startswith(magic):
            detected_type = 'jpeg'
            break

    # Check PNG magic bytes
    if not detected_type:
        for magic in MAGIC_BYTES['png']:
            if file_content.startswith(magic):
                detected_type = 'png'
                break

    if not detected_type:
        return False, "File is not a valid image (invalid file signature)"

    # Verify extension matches detected type
    if file_ext in {'.jpg', '.jpeg'} and detected_type != 'jpeg':
        return False, "File extension doesn't match file content"

    if file_ext == '.png' and detected_type != 'png':
        return False, "File extension doesn't match file content"

    # All checks passed!
    return True, detected_type


def get_safe_filename(filename: str, user_id: int) -> str:
    """
    Generate a safe filename for storing the profile picture.

    Args:
        filename: Original filename
        user_id: User ID for uniqueness

    Returns:
        Safe filename in format: profile_{user_id}.{ext}
    """
    file_ext = os.path.splitext(filename)[1].lower()

    # Normalize .jpeg to .jpg
    if file_ext == '.jpeg':
        file_ext = '.jpg'

    return f"profile_{user_id}{file_ext}"


def validate_image_dimensions(file_content: bytes) -> Tuple[bool, str]:
    """
    Optional: Validate image dimensions using PIL (if available).

    This is an additional check to ensure the image is not too large
    or suspiciously small.

    Args:
        file_content: The image file content

    Returns:
        Tuple of (is_valid, error_message_or_dimensions)
    """
    try:
        from PIL import Image
        import io

        # Try to open the image
        image = Image.open(io.BytesIO(file_content))

        width, height = image.size

        # Check minimum dimensions (at least 50x50)
        if width < 50 or height < 50:
            return False, f"Image too small ({width}x{height}). Minimum size is 50x50 pixels"

        # Check maximum dimensions (max 4096x4096)
        if width > 4096 or height > 4096:
            return False, f"Image too large ({width}x{height}). Maximum size is 4096x4096 pixels"

        return True, f"{width}x{height}"

    except ImportError:
        # PIL not installed, skip dimension check
        return True, "dimensions_not_checked"
    except Exception as e:
        # Image cannot be opened - invalid image
        return False, f"Invalid image file: {str(e)}"
