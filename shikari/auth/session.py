"""
Session management utilities.

Handles session creation, validation, and user authentication.
Session duration: 16 hours (default) or 7 days (with Remember Me)
"""

import secrets
from datetime import datetime, timedelta
from typing import Optional
from sqlalchemy.orm import Session as SQLAlchemySession
from fastapi import Request, HTTPException, status

from shikari.database.models import User, Session
from shikari.database.db import get_db_session


# Session configuration
SESSION_DURATION_HOURS = 16  # Default session duration
REMEMBER_ME_DAYS = 7  # Remember me duration
SESSION_COOKIE_NAME = "shikari_session"


def create_session(user_id: int, remember_me: bool = False, db: Optional[SQLAlchemySession] = None) -> str:
    """
    Create a new session for a user.

    Args:
        user_id: User ID
        remember_me: Whether to use extended session duration
        db: Database session (optional, will create if not provided)

    Returns:
        Session ID (UUID)
    """
    should_close_db = False
    if db is None:
        db = get_db_session()
        should_close_db = True

    try:
        # Generate unique session ID
        session_id = secrets.token_hex(32)

        # Calculate expiration
        if remember_me:
            expires_at = datetime.utcnow() + timedelta(days=REMEMBER_ME_DAYS)
        else:
            expires_at = datetime.utcnow() + timedelta(hours=SESSION_DURATION_HOURS)

        # Create session record
        session = Session(
            session_id=session_id,
            user_id=user_id,
            expires_at=expires_at,
            remember_me=remember_me
        )

        db.add(session)
        db.commit()

        return session_id

    finally:
        if should_close_db:
            db.close()


def get_session(session_id: str, db: Optional[SQLAlchemySession] = None) -> Optional[Session]:
    """
    Get session by ID and validate it's not expired.

    Args:
        session_id: Session ID
        db: Database session (optional)

    Returns:
        Session object if valid, None otherwise
    """
    should_close_db = False
    if db is None:
        db = get_db_session()
        should_close_db = True

    try:
        session = db.query(Session).filter(Session.session_id == session_id).first()

        if session and session.is_valid():
            return session

        # Delete expired session if found
        if session:
            db.delete(session)
            db.commit()

        return None

    finally:
        if should_close_db:
            db.close()


def delete_session(session_id: str, db: Optional[SQLAlchemySession] = None) -> bool:
    """
    Delete a session (logout).

    Args:
        session_id: Session ID to delete
        db: Database session (optional)

    Returns:
        True if session was deleted, False if not found
    """
    should_close_db = False
    if db is None:
        db = get_db_session()
        should_close_db = True

    try:
        session = db.query(Session).filter(Session.session_id == session_id).first()

        if session:
            db.delete(session)
            db.commit()
            return True

        return False

    finally:
        if should_close_db:
            db.close()


def get_user_from_session_id(session_id: str, db: SQLAlchemySession) -> Optional[User]:
    """
    Get user from session ID string.

    Args:
        session_id: Session ID string
        db: Database session

    Returns:
        User object if authenticated, None otherwise
    """
    if not session_id:
        return None

    # Get and validate session
    session = get_session(session_id, db)

    if not session:
        return None

    # Get user
    user = db.query(User).filter(User.id == session.user_id, User.is_active == True).first()

    return user


def get_current_user(request: Request, db: Optional[SQLAlchemySession] = None) -> Optional[User]:
    """
    Get current authenticated user from request.

    Args:
        request: FastAPI request object
        db: Database session (optional)

    Returns:
        User object if authenticated, None otherwise
    """
    # Get session ID from cookie
    session_id = request.cookies.get(SESSION_COOKIE_NAME)

    if not session_id:
        return None

    should_close_db = False
    if db is None:
        db = get_db_session()
        should_close_db = True

    try:
        return get_user_from_session_id(session_id, db)

    finally:
        if should_close_db:
            db.close()


def require_auth(request: Request, db: Optional[SQLAlchemySession] = None) -> User:
    """
    Require authentication - raises exception if not authenticated.

    Args:
        request: FastAPI request object
        db: Database session (optional)

    Returns:
        Authenticated user

    Raises:
        HTTPException: 401 if not authenticated
    """
    user = get_current_user(request, db)

    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required"
        )

    return user


def require_admin(request: Request, db: Optional[SQLAlchemySession] = None) -> User:
    """
    Require admin authentication - raises exception if not admin.

    Args:
        request: FastAPI request object
        db: Database session (optional)

    Returns:
        Authenticated admin user

    Raises:
        HTTPException: 401 if not authenticated, 403 if not admin
    """
    user = require_auth(request, db)

    if user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required"
        )

    return user


def cleanup_expired_sessions(db: Optional[SQLAlchemySession] = None):
    """
    Clean up expired sessions from database.

    Should be run periodically (e.g., daily cron job).

    Args:
        db: Database session (optional)
    """
    should_close_db = False
    if db is None:
        db = get_db_session()
        should_close_db = True

    try:
        # Delete all expired sessions
        expired_count = db.query(Session).filter(
            Session.expires_at < datetime.utcnow()
        ).delete()

        db.commit()

        if expired_count > 0:
            print(f"✓ Cleaned up {expired_count} expired sessions")

    finally:
        if should_close_db:
            db.close()
