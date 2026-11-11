"""
Audit logging for Shikari security events.

Logs sensitive operations for security monitoring and compliance.
"""

from sqlalchemy import Column, Integer, String, DateTime, Text, Boolean
from sqlalchemy.ext.declarative import declarative_base
from datetime import datetime
import logging

logger = logging.getLogger(__name__)

Base = declarative_base()


class AuditLog(Base):
    """Audit log entry for security events."""

    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    user_id = Column(Integer, index=True, nullable=True)  # None for failed login attempts
    email = Column(String(64), index=True, nullable=True)
    event_type = Column(String(50), index=True, nullable=False)  # login, logout, password_change, etc.
    ip_address = Column(String(45), nullable=True)  # IPv4 or IPv6
    user_agent = Column(String(500), nullable=True)
    success = Column(Boolean, default=True)
    details = Column(Text, nullable=True)  # JSON or additional info


# Event types
EVENT_LOGIN_SUCCESS = "login_success"
EVENT_LOGIN_FAILURE = "login_failure"
EVENT_LOGOUT = "logout"
EVENT_PASSWORD_CHANGE = "password_change"
EVENT_PASSWORD_RESET_REQUEST = "password_reset_request"
EVENT_PASSWORD_RESET_COMPLETE = "password_reset_complete"
EVENT_PROFILE_UPDATE = "profile_update"
EVENT_API_KEY_UPDATE = "api_key_update"
EVENT_USER_CREATED = "user_created"
EVENT_USER_UPDATED = "user_updated"
EVENT_USER_DEACTIVATED = "user_deactivated"
EVENT_SESSION_REVOKED = "session_revoked"
EVENT_ACCOUNT_LOCKED = "account_locked"
EVENT_ACCOUNT_UNLOCKED = "account_unlocked"
EVENT_LICENCE_INSTALLED = "licence_installed"
EVENT_LICENCE_REMOVED = "licence_removed"
EVENT_BRAND_CREATED = "brand_created"
EVENT_BRAND_UPDATED = "brand_updated"
EVENT_BRAND_DELETED = "brand_deleted"
EVENT_BRAND_LOGO_SET = "brand_logo_set"
EVENT_BRAND_LOGO_REMOVED = "brand_logo_removed"


def log_audit_event(
    db,
    event_type: str,
    user_id: int = None,
    email: str = None,
    ip_address: str = None,
    user_agent: str = None,
    success: bool = True,
    details: str = None
):
    """
    Log an audit event to the database.

    Args:
        db: Database session
        event_type: Type of event (use EVENT_* constants)
        user_id: ID of user performing action (None for unauthenticated)
        email: Email of user (for failed logins)
        ip_address: IP address of request
        user_agent: User agent string
        success: Whether the operation succeeded
        details: Additional details in JSON format
    """
    try:
        audit_entry = AuditLog(
            user_id=user_id,
            email=email,
            event_type=event_type,
            ip_address=ip_address,
            user_agent=user_agent,
            success=success,
            details=details
        )
        db.add(audit_entry)
        db.commit()

        # Also log to application logger
        log_level = logging.INFO if success else logging.WARNING
        logger.log(
            log_level,
            f"AUDIT: {event_type} | User: {email or user_id} | IP: {ip_address} | Success: {success}"
        )

    except Exception as e:
        logger.error(f"Failed to log audit event: {e}")
        db.rollback()


def get_audit_logs(db, user_id: int = None, event_type: str = None, limit: int = 100):
    """
    Retrieve audit logs with optional filtering.

    Args:
        db: Database session
        user_id: Filter by user ID
        event_type: Filter by event type
        limit: Maximum number of records to return

    Returns:
        List of audit log entries
    """
    query = db.query(AuditLog).order_by(AuditLog.timestamp.desc())

    if user_id:
        query = query.filter(AuditLog.user_id == user_id)

    if event_type:
        query = query.filter(AuditLog.event_type == event_type)

    return query.limit(limit).all()


def get_failed_login_attempts(db, email: str, since_minutes: int = 15):
    """
    Get count of failed login attempts for an email in the last N minutes.

    Args:
        db: Database session
        email: Email to check
        since_minutes: Time window in minutes

    Returns:
        Count of failed attempts
    """
    from datetime import timedelta

    cutoff_time = datetime.utcnow() - timedelta(minutes=since_minutes)

    count = db.query(AuditLog).filter(
        AuditLog.email == email,
        AuditLog.event_type == EVENT_LOGIN_FAILURE,
        AuditLog.timestamp >= cutoff_time
    ).count()

    return count
