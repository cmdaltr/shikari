"""
Integration tests for security modules.

Tests for:
- Rate limiting
- CSRF protection
- Audit logging
- Account lockout
"""

import pytest
import time
from datetime import datetime, timedelta
from archer.security.rate_limit import (
    check_rate_limit,
    record_attempt,
    reset_rate_limit,
    cleanup_old_entries,
    rate_limit_attempts
)
from archer.security.csrf import (
    generate_csrf_token,
    validate_csrf_token,
    consume_csrf_token,
    cleanup_expired_tokens,
    csrf_tokens
)
from archer.database.audit import (
    log_audit_event,
    get_audit_logs,
    get_failed_login_attempts,
    EVENT_LOGIN_SUCCESS,
    EVENT_LOGIN_FAILURE,
    EVENT_PASSWORD_RESET_REQUEST,
    EVENT_PASSWORD_RESET_COMPLETED
)
from archer.database.db import get_db
from archer.database.models import User


class TestRateLimiting:
    """Test rate limiting functionality."""

    def setup_method(self):
        """Clear rate limit data before each test."""
        rate_limit_attempts.clear()

    def test_rate_limit_allows_within_limit(self):
        """Test that requests within limit are allowed."""
        key = "test_user_1"

        # First 5 attempts should be allowed
        for i in range(5):
            is_allowed, remaining = check_rate_limit(key, max_attempts=5, window_seconds=60)
            assert is_allowed, f"Attempt {i+1} should be allowed"
            assert remaining >= 0
            record_attempt(key)

    def test_rate_limit_blocks_after_limit(self):
        """Test that requests are blocked after exceeding limit."""
        key = "test_user_2"

        # Record 5 attempts
        for _ in range(5):
            record_attempt(key)

        # 6th attempt should be blocked
        is_allowed, remaining = check_rate_limit(key, max_attempts=5, window_seconds=60)
        assert not is_allowed, "Should be blocked after exceeding limit"
        assert remaining == 0

    def test_rate_limit_reset(self):
        """Test that rate limit can be reset."""
        key = "test_user_3"

        # Record 5 attempts
        for _ in range(5):
            record_attempt(key)

        # Should be blocked
        is_allowed, _ = check_rate_limit(key, max_attempts=5, window_seconds=60)
        assert not is_allowed

        # Reset rate limit
        reset_rate_limit(key)

        # Should be allowed again
        is_allowed, remaining = check_rate_limit(key, max_attempts=5, window_seconds=60)
        assert is_allowed, "Should be allowed after reset"
        assert remaining == 5

    def test_rate_limit_window_expiry(self):
        """Test that rate limit expires after time window."""
        key = "test_user_4"

        # Use very short window for testing (1 second)
        for _ in range(5):
            record_attempt(key)

        # Should be blocked
        is_allowed, _ = check_rate_limit(key, max_attempts=5, window_seconds=1)
        assert not is_allowed

        # Wait for window to expire
        time.sleep(1.1)

        # Should be allowed again after window expires
        is_allowed, remaining = check_rate_limit(key, max_attempts=5, window_seconds=1)
        assert is_allowed, "Should be allowed after window expires"

    def test_rate_limit_cleanup(self):
        """Test that old entries are cleaned up."""
        # Record some attempts
        for i in range(10):
            record_attempt(f"user_{i}")

        initial_count = len(rate_limit_attempts)
        assert initial_count > 0

        # Cleanup shouldn't remove recent entries
        removed = cleanup_old_entries()
        assert len(rate_limit_attempts) == initial_count, "Recent entries should not be removed"

    def test_rate_limit_different_keys(self):
        """Test that different keys are tracked independently."""
        key1 = "user_a"
        key2 = "user_b"

        # Exhaust limit for key1
        for _ in range(5):
            record_attempt(key1)

        # key1 should be blocked
        is_allowed, _ = check_rate_limit(key1, max_attempts=5, window_seconds=60)
        assert not is_allowed

        # key2 should still be allowed
        is_allowed, remaining = check_rate_limit(key2, max_attempts=5, window_seconds=60)
        assert is_allowed, "Different key should have independent limit"
        assert remaining == 5


class TestCSRFProtection:
    """Test CSRF token functionality."""

    def setup_method(self):
        """Clear CSRF tokens before each test."""
        csrf_tokens.clear()

    def test_generate_csrf_token(self):
        """Test CSRF token generation."""
        session_id = "test_session_123"
        token = generate_csrf_token(session_id)

        assert token is not None
        assert len(token) > 0
        assert token in csrf_tokens
        assert csrf_tokens[token]["session_id"] == session_id

    def test_validate_valid_token(self):
        """Test validation of valid CSRF token."""
        session_id = "test_session_456"
        token = generate_csrf_token(session_id)

        is_valid = validate_csrf_token(token, session_id)
        assert is_valid, "Valid token should pass validation"

    def test_validate_invalid_token(self):
        """Test validation of invalid CSRF token."""
        session_id = "test_session_789"

        # Generate token for different session
        token = generate_csrf_token("different_session")

        # Should fail validation with different session ID
        is_valid = validate_csrf_token(token, session_id)
        assert not is_valid, "Token should fail validation with wrong session ID"

    def test_validate_nonexistent_token(self):
        """Test validation of nonexistent token."""
        is_valid = validate_csrf_token("nonexistent_token", "any_session")
        assert not is_valid, "Nonexistent token should fail validation"

    def test_consume_csrf_token(self):
        """Test that consuming a token removes it."""
        session_id = "test_session_abc"
        token = generate_csrf_token(session_id)

        # Token should exist
        assert token in csrf_tokens

        # Consume token
        consume_csrf_token(token)

        # Token should be removed
        assert token not in csrf_tokens

    def test_csrf_token_expiry(self):
        """Test that expired tokens fail validation."""
        session_id = "test_session_def"
        token = generate_csrf_token(session_id)

        # Manually set token to be expired (created 2 hours ago)
        csrf_tokens[token]["created_at"] = datetime.utcnow() - timedelta(hours=2)

        # Should fail validation due to expiry
        is_valid = validate_csrf_token(token, session_id)
        assert not is_valid, "Expired token should fail validation"

        # Token should be removed after failed validation
        assert token not in csrf_tokens

    def test_cleanup_expired_tokens(self):
        """Test cleanup of expired tokens."""
        # Generate some tokens
        tokens = []
        for i in range(5):
            token = generate_csrf_token(f"session_{i}")
            tokens.append(token)

        # Make first 3 tokens expired
        for token in tokens[:3]:
            csrf_tokens[token]["created_at"] = datetime.utcnow() - timedelta(hours=2)

        # Cleanup
        removed_count = cleanup_expired_tokens()

        assert removed_count == 3, "Should remove 3 expired tokens"
        assert len(csrf_tokens) == 2, "Should have 2 tokens remaining"

    def test_empty_token_validation(self):
        """Test validation with empty token."""
        is_valid = validate_csrf_token("", "session")
        assert not is_valid, "Empty token should fail validation"

    def test_empty_session_validation(self):
        """Test validation with empty session."""
        token = generate_csrf_token("session")
        is_valid = validate_csrf_token(token, "")
        assert not is_valid, "Empty session should fail validation"


class TestAuditLogging:
    """Test audit logging functionality."""

    def setup_method(self):
        """Setup test database."""
        self.db = next(get_db())

    def teardown_method(self):
        """Cleanup test database."""
        # Clean up test audit logs
        from archer.database.audit import AuditLog
        self.db.query(AuditLog).delete()
        self.db.commit()
        self.db.close()

    def test_log_audit_event(self):
        """Test logging an audit event."""
        log_audit_event(
            db=self.db,
            event_type=EVENT_LOGIN_SUCCESS,
            user_id=1,
            email="test@example.com",
            ip_address="127.0.0.1",
            user_agent="Test Browser",
            success=True,
            details="Test login"
        )

        # Retrieve the log
        logs = get_audit_logs(db=self.db, limit=1)
        assert len(logs) == 1

        log = logs[0]
        assert log.event_type == EVENT_LOGIN_SUCCESS
        assert log.user_id == 1
        assert log.email == "test@example.com"
        assert log.ip_address == "127.0.0.1"
        assert log.success is True
        assert log.details == "Test login"

    def test_log_multiple_events(self):
        """Test logging multiple events."""
        events = [
            (EVENT_LOGIN_SUCCESS, True, "Login 1"),
            (EVENT_LOGIN_FAILURE, False, "Failed login"),
            (EVENT_PASSWORD_RESET_REQUEST, True, "Reset request"),
        ]

        for event_type, success, details in events:
            log_audit_event(
                db=self.db,
                event_type=event_type,
                email="test@example.com",
                success=success,
                details=details
            )

        # Retrieve all logs
        logs = get_audit_logs(db=self.db, limit=10)
        assert len(logs) == 3

    def test_get_audit_logs_with_filters(self):
        """Test retrieving audit logs with filters."""
        # Log events for different users
        log_audit_event(self.db, EVENT_LOGIN_SUCCESS, user_id=1, email="user1@example.com", success=True)
        log_audit_event(self.db, EVENT_LOGIN_FAILURE, user_id=2, email="user2@example.com", success=False)
        log_audit_event(self.db, EVENT_LOGIN_SUCCESS, user_id=1, email="user1@example.com", success=True)

        # Get logs for user_id=1
        logs = get_audit_logs(db=self.db, user_id=1)
        assert len(logs) == 2
        assert all(log.user_id == 1 for log in logs)

        # Get failed login attempts
        logs = get_audit_logs(db=self.db, event_type=EVENT_LOGIN_FAILURE)
        assert len(logs) == 1
        assert logs[0].success is False

    def test_get_failed_login_attempts(self):
        """Test retrieving failed login attempts."""
        email = "test@example.com"

        # Log some failed attempts
        for i in range(3):
            log_audit_event(
                db=self.db,
                event_type=EVENT_LOGIN_FAILURE,
                email=email,
                success=False,
                details=f"Attempt {i+1}"
            )

        # Get failed attempts within last hour
        since = datetime.utcnow() - timedelta(hours=1)
        attempts = get_failed_login_attempts(db=self.db, email=email, since=since)

        assert attempts == 3

    def test_audit_log_without_user_id(self):
        """Test logging event without user_id (e.g., failed login)."""
        log_audit_event(
            db=self.db,
            event_type=EVENT_LOGIN_FAILURE,
            email="unknown@example.com",
            success=False,
            details="User not found"
        )

        logs = get_audit_logs(db=self.db, limit=1)
        assert len(logs) == 1
        assert logs[0].user_id is None
        assert logs[0].email == "unknown@example.com"

    def test_audit_log_timestamp(self):
        """Test that audit logs have timestamps."""
        before = datetime.utcnow()

        log_audit_event(
            db=self.db,
            event_type=EVENT_LOGIN_SUCCESS,
            email="test@example.com",
            success=True
        )

        after = datetime.utcnow()

        logs = get_audit_logs(db=self.db, limit=1)
        assert len(logs) == 1

        log_time = logs[0].timestamp
        assert before <= log_time <= after


class TestAccountLockout:
    """Test account lockout functionality."""

    def setup_method(self):
        """Setup test database with a test user."""
        self.db = next(get_db())

        # Create test user
        from archer.auth.password import hash_password
        self.test_user = User(
            email="lockout@example.com",
            password_hash=hash_password("Test123!"),
            full_name="Test User",
            role="standard",
            is_active=True,
            failed_login_attempts=0,
            locked_until=None
        )
        self.db.add(self.test_user)
        self.db.commit()

    def teardown_method(self):
        """Cleanup test database."""
        self.db.query(User).filter(User.email == "lockout@example.com").delete()
        self.db.commit()
        self.db.close()

    def test_increment_failed_attempts(self):
        """Test incrementing failed login attempts."""
        assert self.test_user.failed_login_attempts == 0

        # Increment attempts
        self.test_user.failed_login_attempts += 1
        self.db.commit()

        # Verify
        user = self.db.query(User).filter(User.email == "lockout@example.com").first()
        assert user.failed_login_attempts == 1

    def test_account_lockout_after_max_attempts(self):
        """Test that account gets locked after max attempts."""
        # Set to 4 failed attempts
        self.test_user.failed_login_attempts = 4
        self.db.commit()

        # One more attempt should trigger lockout
        self.test_user.failed_login_attempts += 1

        if self.test_user.failed_login_attempts >= 5:
            self.test_user.locked_until = datetime.utcnow() + timedelta(minutes=15)

        self.db.commit()

        # Verify lockout
        user = self.db.query(User).filter(User.email == "lockout@example.com").first()
        assert user.failed_login_attempts == 5
        assert user.locked_until is not None
        assert user.locked_until > datetime.utcnow()

    def test_locked_account_check(self):
        """Test checking if account is locked."""
        # Lock account
        self.test_user.locked_until = datetime.utcnow() + timedelta(minutes=15)
        self.db.commit()

        # Check if locked
        user = self.db.query(User).filter(User.email == "lockout@example.com").first()
        is_locked = user.locked_until and user.locked_until > datetime.utcnow()

        assert is_locked, "Account should be locked"

    def test_lockout_expiry(self):
        """Test that lockout expires after time."""
        # Lock account with expiry in the past
        self.test_user.locked_until = datetime.utcnow() - timedelta(minutes=1)
        self.db.commit()

        # Check if locked
        user = self.db.query(User).filter(User.email == "lockout@example.com").first()
        is_locked = user.locked_until and user.locked_until > datetime.utcnow()

        assert not is_locked, "Account should not be locked (expiry passed)"

    def test_reset_failed_attempts_on_success(self):
        """Test that failed attempts reset on successful login."""
        # Set some failed attempts
        self.test_user.failed_login_attempts = 3
        self.test_user.locked_until = None
        self.db.commit()

        # Simulate successful login
        self.test_user.failed_login_attempts = 0
        self.test_user.locked_until = None
        self.db.commit()

        # Verify reset
        user = self.db.query(User).filter(User.email == "lockout@example.com").first()
        assert user.failed_login_attempts == 0
        assert user.locked_until is None


class TestSecurityIntegration:
    """Integration tests combining multiple security features."""

    def setup_method(self):
        """Setup for integration tests."""
        self.db = next(get_db())
        rate_limit_attempts.clear()
        csrf_tokens.clear()

    def teardown_method(self):
        """Cleanup."""
        from archer.database.audit import AuditLog
        self.db.query(AuditLog).delete()
        self.db.commit()
        self.db.close()

    def test_failed_login_workflow(self):
        """Test complete failed login workflow with all security features."""
        email = "integration@example.com"
        ip = "192.168.1.100"
        rate_key = f"login:{ip}"

        # Simulate 5 failed login attempts
        for i in range(5):
            # Check rate limit
            is_allowed, _ = check_rate_limit(rate_key, max_attempts=5, window_seconds=300)
            assert is_allowed, f"Attempt {i+1} should be allowed"

            # Record attempt
            record_attempt(rate_key)

            # Log to audit
            log_audit_event(
                db=self.db,
                event_type=EVENT_LOGIN_FAILURE,
                email=email,
                ip_address=ip,
                success=False,
                details=f"Invalid password (attempt {i+1}/5)"
            )

        # 6th attempt should be rate limited
        is_allowed, _ = check_rate_limit(rate_key, max_attempts=5, window_seconds=300)
        assert not is_allowed, "Should be rate limited after 5 attempts"

        # Verify audit logs
        failed_attempts = get_failed_login_attempts(
            db=self.db,
            email=email,
            since=datetime.utcnow() - timedelta(hours=1)
        )
        assert failed_attempts == 5

    def test_successful_login_workflow(self):
        """Test complete successful login workflow."""
        email = "success@example.com"
        ip = "192.168.1.101"
        rate_key = f"login:{ip}"
        session_id = "test_session_success"

        # Generate CSRF token
        csrf_token = generate_csrf_token(session_id)

        # Validate CSRF
        is_valid = validate_csrf_token(csrf_token, session_id)
        assert is_valid

        # Consume CSRF
        consume_csrf_token(csrf_token)

        # Check rate limit (should be allowed)
        is_allowed, _ = check_rate_limit(rate_key, max_attempts=5, window_seconds=300)
        assert is_allowed

        # Log successful login
        log_audit_event(
            db=self.db,
            event_type=EVENT_LOGIN_SUCCESS,
            user_id=1,
            email=email,
            ip_address=ip,
            success=True,
            details="Login successful"
        )

        # Reset rate limit on success
        reset_rate_limit(rate_key)

        # Verify audit log
        logs = get_audit_logs(db=self.db, email=email, limit=1)
        assert len(logs) == 1
        assert logs[0].success is True
