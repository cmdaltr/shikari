"""
Integration tests for security validation functions.

Tests validation functions with various inputs including:
- Email validation
- Full name validation
- Password validation
- API key validation
"""

import pytest
from archer.security.validation import (
    validate_email,
    sanitize_full_name,
    sanitize_api_key
)
from archer.auth.password import validate_password


class TestEmailValidation:
    """Test email validation with various inputs."""

    def test_valid_emails(self):
        """Test valid email addresses."""
        valid_emails = [
            "user@example.com",  # 17 chars
            "test.user@domain.com",  # 21 chars
            "abc@test.co",  # 12 chars (minimum 10)
            "user+tag@example.com",  # 21 chars
            "user_name@example.com",  # 22 chars
            "123@example.com",  # 16 chars
            "user@sub.domain.com",  # 20 chars
            "a" * 50 + "@example.com",  # 62 chars
        ]

        for email in valid_emails:
            is_valid, normalized = validate_email(email)
            assert is_valid, f"Email '{email}' (len={len(email)}) should be valid"
            assert normalized == email.lower(), "Email should be normalized to lowercase"

    def test_missing_at_symbol(self):
        """Test email without @ symbol."""
        invalid_emails = [
            "userexample.com",
            "user.example.com",
            "user",
            "example.com",
        ]

        for email in invalid_emails:
            is_valid, error = validate_email(email)
            assert not is_valid, f"Email '{email}' should be invalid (missing @)"
            assert "must contain @ symbol" in error.lower()

    def test_email_too_long(self):
        """Test email exceeding 64 character limit."""
        # Create email with exactly 65 characters
        long_email = "a" * 53 + "@example.com"  # 65 chars (53 + 12)
        is_valid, error = validate_email(long_email)
        assert not is_valid, "Email should be invalid (too long)"
        assert "too long" in error.lower()
        assert "64" in error

    def test_email_max_length(self):
        """Test email at exactly 64 characters (should be valid)."""
        # Create email with exactly 64 characters
        max_email = "a" * 52 + "@example.com"  # 64 chars (52 + 12)
        is_valid, normalized = validate_email(max_email)
        assert is_valid, "Email at 64 chars should be valid"

    def test_empty_email(self):
        """Test empty email."""
        is_valid, error = validate_email("")
        assert not is_valid, "Empty email should be invalid"

    def test_whitespace_email(self):
        """Test email with whitespace."""
        emails_with_whitespace = [
            " user@example.com",
            "user@example.com ",
            " user@example.com ",
            "user @example.com",
        ]

        for email in emails_with_whitespace:
            is_valid, result = validate_email(email)
            # Should either be invalid or strip whitespace
            if is_valid:
                assert " " not in result

    def test_email_normalization(self):
        """Test that emails are normalized to lowercase."""
        test_cases = [
            ("User@Example.Com", "user@example.com"),
            ("ADMIN@EXAMPLE.COM", "admin@example.com"),
            ("TeSt@DoMaIn.CoM", "test@domain.com"),
        ]

        for input_email, expected in test_cases:
            is_valid, normalized = validate_email(input_email)
            assert is_valid
            assert normalized == expected


class TestFullNameValidation:
    """Test full name validation with various inputs."""

    def test_valid_names(self):
        """Test valid full names."""
        valid_names = [
            "John Doe",
            "Mary Jane",
            "Anne-Marie Smith",
            "Jean-Paul",
            "A B",
            "SingleName",
            "Name With Spaces",
            "Anne-Marie Le-Blanc",
            "a" * 64,  # Exactly 64 chars
        ]

        for name in valid_names:
            is_valid, sanitized = sanitize_full_name(name)
            assert is_valid, f"Name '{name}' should be valid"
            assert sanitized == name

    def test_name_too_long(self):
        """Test name exceeding 64 character limit."""
        long_name = "a" * 65
        is_valid, error = sanitize_full_name(long_name)
        assert not is_valid, "Name should be invalid (too long)"
        assert "too long" in error.lower()
        assert "64" in error

    def test_name_max_length(self):
        """Test name at exactly 64 characters (should be valid)."""
        max_name = "a" * 64
        is_valid, sanitized = sanitize_full_name(max_name)
        assert is_valid, "Name at 64 chars should be valid"

    def test_invalid_characters(self):
        """Test names with invalid characters."""
        invalid_names = [
            "John123",  # Numbers
            "John@Doe",  # Special chars
            "John.Doe",  # Period
            "John_Doe",  # Underscore
            "John+Doe",  # Plus
            "John#Doe",  # Hash
            "John$Doe",  # Dollar
            "名前",  # Non-ASCII characters
            "José",  # Accented characters
            "Müller",  # Umlaut
        ]

        for name in invalid_names:
            is_valid, error = sanitize_full_name(name)
            assert not is_valid, f"Name '{name}' should be invalid"
            assert "can only contain" in error.lower()

    def test_valid_hyphens(self):
        """Test that hyphens are allowed."""
        names_with_hyphens = [
            "Anne-Marie",
            "Jean-Paul",
            "Mary-Jane-Smith",
            "A-B-C",
        ]

        for name in names_with_hyphens:
            is_valid, sanitized = sanitize_full_name(name)
            assert is_valid, f"Name with hyphens '{name}' should be valid"

    def test_valid_spaces(self):
        """Test that spaces are allowed."""
        names_with_spaces = [
            "First Last",
            "First Middle Last",
            "A B C D",
        ]

        for name in names_with_spaces:
            is_valid, sanitized = sanitize_full_name(name)
            assert is_valid, f"Name with spaces '{name}' should be valid"

    def test_empty_name(self):
        """Test empty name."""
        is_valid, error = sanitize_full_name("")
        assert not is_valid, "Empty name should be invalid"

    def test_mixed_case(self):
        """Test that mixed case is preserved."""
        test_cases = [
            "John Doe",
            "JOHN DOE",
            "john doe",
            "JoHn DoE",
        ]

        for name in test_cases:
            is_valid, sanitized = sanitize_full_name(name)
            assert is_valid
            assert sanitized == name, "Case should be preserved"


class TestPasswordValidation:
    """Test password validation with various inputs."""

    def test_valid_passwords(self):
        """Test valid passwords."""
        valid_passwords = [
            "SecurePass123!@#",  # 16 chars (minimum)
            "MyP@ssw0rdIsStrong",  # 18 chars
            "Str0ng!PassSecure1",  # 18 chars
            "C0mplex@Password99",  # 18 chars
            "ValidSecure1$Pass",  # 17 chars
            "A1b2C3!SecurePass",  # 17 chars
            "p@ssW0rdIsSecure1",  # 17 chars
            "a" * 37 + "1B!",  # 40 chars (max length)
        ]

        for password in valid_passwords:
            is_valid, error = validate_password(password)
            assert is_valid, f"Password '{password}' (len={len(password)}) should be valid. Error: {error}"

    def test_password_too_short(self):
        """Test passwords shorter than 16 characters."""
        short_passwords = [
            ("Pass123!", "at least 16"),  # 8 chars
            ("MyP@ssw0rd", "at least 16"),  # 10 chars
            ("Secure1!", "at least 16"),  # 8 chars
            ("Test1!", "at least 16"),  # 6 chars
            ("", "cannot be empty"),  # Empty - different message
        ]

        for password, expected_error in short_passwords:
            is_valid, error = validate_password(password)
            assert not is_valid, f"Password '{password}' (len={len(password)}) should be invalid (too short)"
            assert expected_error in error.lower(), f"Expected '{expected_error}' in error, got: {error}"

    def test_password_too_long(self):
        """Test passwords longer than 40 characters."""
        long_password = "a" * 38 + "1B!"  # 41 chars
        is_valid, error = validate_password(long_password)
        assert not is_valid, "Password should be invalid (too long)"
        assert "40 characters" in error.lower()

    def test_password_max_length(self):
        """Test password at exactly 40 characters (should be valid)."""
        max_password = "a" * 37 + "1B!"  # 40 chars
        is_valid, error = validate_password(max_password)
        assert is_valid, "Password at 40 chars should be valid"

    def test_password_missing_letter(self):
        """Test passwords without letters."""
        passwords_no_letters = [
            "1234567890123!@#",  # 16 chars, no letters
            "98765432109876@!",  # 16 chars, no letters
            "123!@#456789!@#$",  # 16 chars, no letters
        ]

        for password in passwords_no_letters:
            is_valid, error = validate_password(password)
            assert not is_valid, f"Password '{password}' should be invalid (no letters)"
            assert "letter" in error.lower()

    def test_password_missing_number(self):
        """Test passwords without numbers."""
        passwords_no_numbers = [
            "PasswordSecure!@",  # 16 chars, no numbers
            "AbcdefghSecure@!",  # 16 chars, no numbers
            "Test!PassSecure@",  # 16 chars, no numbers
        ]

        for password in passwords_no_numbers:
            is_valid, error = validate_password(password)
            assert not is_valid, f"Password '{password}' should be invalid (no numbers)"
            assert "number" in error.lower()

    def test_password_missing_special(self):
        """Test passwords without special characters."""
        passwords_no_special = [
            "Password12345678",  # 16 chars, no special
            "Abcdefg123456789",  # 16 chars, no special
            "Test1Pass9876543",  # 16 chars, no special
        ]

        for password in passwords_no_special:
            is_valid, error = validate_password(password)
            assert not is_valid, f"Password '{password}' should be invalid (no special chars)"
            assert "special character" in error.lower()

    def test_valid_special_characters(self):
        """Test all valid special characters."""
        special_chars = "!@£$%^&()-_+=[]{}:|<>?"

        for char in special_chars:
            password = f"Pass1{char}wordSecure"  # 17+ chars
            is_valid, error = validate_password(password)
            assert is_valid, f"Password with '{char}' should be valid. Error: {error}"


class TestAPIKeyValidation:
    """Test API key validation with various inputs."""

    def test_valid_api_keys(self):
        """Test valid API keys."""
        valid_keys = [
            "a" * 10,  # Minimum length
            "a" * 100,
            "sk-1234567890",  # Hyphens are allowed
            "key_abcdef123456",  # Underscores are allowed
            "Bearer+token123",  # Plus is allowed
            "abcd1234567890",  # Alphanumeric
            "a" * 500,  # Maximum length
        ]

        for key in valid_keys:
            is_valid, sanitized = sanitize_api_key(key)
            assert is_valid, f"API key '{key[:20]}...' (length: {len(key)}) should be valid. Error: {sanitized if not is_valid else 'N/A'}"
            if is_valid:
                assert sanitized == key.strip()

    def test_empty_api_key(self):
        """Test that empty API key is allowed."""
        is_valid, sanitized = sanitize_api_key("")
        assert is_valid, "Empty API key should be valid"
        assert sanitized == ""

    def test_api_key_too_short(self):
        """Test API keys shorter than 10 characters (when not empty)."""
        short_keys = [
            "a" * 9,
            "key",
            "123",
        ]

        for key in short_keys:
            is_valid, error = sanitize_api_key(key)
            assert not is_valid, f"API key '{key}' should be invalid (too short)"
            assert "minimum 10 characters" in error.lower()

    def test_api_key_too_long(self):
        """Test API keys longer than 500 characters."""
        long_key = "a" * 501
        is_valid, error = sanitize_api_key(long_key)
        assert not is_valid, "API key should be invalid (too long)"
        assert "500 characters" in error.lower()

    def test_api_key_max_length(self):
        """Test API key at exactly 500 characters (should be valid)."""
        max_key = "a" * 500
        is_valid, sanitized = sanitize_api_key(max_key)
        assert is_valid, "API key at 500 chars should be valid"

    def test_api_key_whitespace_trimming(self):
        """Test that API keys are trimmed."""
        test_cases = [
            (" " + "a" * 10, "a" * 10),
            ("a" * 10 + " ", "a" * 10),
            (" " + "a" * 10 + " ", "a" * 10),
        ]

        for input_key, expected in test_cases:
            is_valid, sanitized = sanitize_api_key(input_key)
            assert is_valid
            assert sanitized == expected


class TestEdgeCases:
    """Test edge cases and boundary conditions."""

    def test_exact_boundary_lengths(self):
        """Test exact boundary conditions for all validators."""
        # Email: exactly 10 chars (min)
        email_10 = "ab@test.co"  # 10 chars
        assert len(email_10) == 10
        is_valid, _ = validate_email(email_10)
        assert is_valid

        # Email: exactly 64 chars (max)
        email_64 = "a" * 52 + "@example.com"  # 64 chars (52 + 12)
        assert len(email_64) == 64
        is_valid, _ = validate_email(email_64)
        assert is_valid

        # Email: exactly 65 chars (should fail)
        email_65 = "a" * 53 + "@example.com"  # 65 chars (53 + 12)
        assert len(email_65) == 65
        is_valid, _ = validate_email(email_65)
        assert not is_valid

        # Name: exactly 64 chars
        name_64 = "a" * 64
        is_valid, _ = sanitize_full_name(name_64)
        assert is_valid

        # Name: exactly 65 chars (should fail)
        name_65 = "a" * 65
        is_valid, _ = sanitize_full_name(name_65)
        assert not is_valid

        # Password: exactly 16 chars (min)
        pass_16 = "SecurePass123!@#"  # 16 chars
        assert len(pass_16) == 16
        is_valid, _ = validate_password(pass_16)
        assert is_valid

        # Password: exactly 40 chars (max)
        pass_40 = "a" * 37 + "1B!"
        assert len(pass_40) == 40
        is_valid, _ = validate_password(pass_40)
        assert is_valid

        # Password: exactly 41 chars (should fail)
        pass_41 = "a" * 38 + "1B!"
        assert len(pass_41) == 41
        is_valid, _ = validate_password(pass_41)
        assert not is_valid

    def test_unicode_and_special_inputs(self):
        """Test Unicode and special inputs."""
        # Names with Unicode should fail
        unicode_names = ["José", "Müller", "名前", "Владимир"]
        for name in unicode_names:
            is_valid, _ = sanitize_full_name(name)
            assert not is_valid, f"Unicode name '{name}' should be invalid"

        # Emails with Unicode in domain (unusual but let's test)
        # Note: Our validator may or may not handle this
        # Just documenting behavior

    def test_sql_injection_attempts(self):
        """Test that validation prevents SQL injection patterns."""
        injection_attempts = [
            "admin'--",
            "' OR '1'='1",
            "admin'; DROP TABLE users;--",
            "1' UNION SELECT * FROM users--",
        ]

        # These should fail validation rules
        for attempt in injection_attempts:
            # Try as name
            is_valid, _ = sanitize_full_name(attempt)
            assert not is_valid, f"Injection attempt '{attempt}' should fail name validation"

    def test_xss_attempts(self):
        """Test that validation prevents XSS patterns."""
        xss_attempts = [
            "<script>alert('xss')</script>",
            "javascript:alert(1)",
            "<img src=x onerror=alert(1)>",
            "';alert(String.fromCharCode(88,83,83))//",
        ]

        # These should fail validation rules
        for attempt in xss_attempts:
            # Try as name
            is_valid, _ = sanitize_full_name(attempt)
            assert not is_valid, f"XSS attempt '{attempt}' should fail name validation"
