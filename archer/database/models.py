"""
Database models for Archer authentication and user management.

This module defines SQLAlchemy models for:
- Users: Email, password hash, role (admin/standard)
- Sessions: Session management with expiration
- APIKeys: User-specific encrypted API keys for SIEM/AI platforms
- SecurityQuestions: For password reset fallback
"""

from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Boolean, Text, Enum
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from datetime import datetime, timedelta
import enum

Base = declarative_base()


class UserRole(str, enum.Enum):
    """User role enumeration"""
    ADMIN = "admin"
    STANDARD = "standard"


class User(Base):
    """
    User account model.

    Stores user credentials and profile information.
    Password is NEVER stored in plain text - only bcrypt hash.
    """
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(255), unique=True, nullable=False, index=True)
    full_name = Column(String(255), nullable=False)
    password_hash = Column(String(255), nullable=False)  # bcrypt hash
    role = Column(Enum(UserRole), nullable=False, default=UserRole.STANDARD)
    is_active = Column(Boolean, default=True, nullable=False)

    # Account lockout fields
    failed_login_attempts = Column(Integer, default=0, nullable=False)
    locked_until = Column(DateTime, nullable=True)  # None if not locked

    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    # Relationships
    sessions = relationship("Session", back_populates="user", cascade="all, delete-orphan")
    api_keys = relationship("APIKey", back_populates="user", cascade="all, delete-orphan")
    security_questions = relationship("SecurityQuestion", back_populates="user", cascade="all, delete-orphan")
    password_resets = relationship("PasswordReset", back_populates="user", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<User(id={self.id}, email='{self.email}', role='{self.role}')>"


class Session(Base):
    """
    Session model for authentication.

    Tracks active user sessions with expiration times.
    Default: 16 hours
    Remember Me: 7 days
    """
    __tablename__ = "sessions"

    id = Column(Integer, primary_key=True, index=True)
    session_id = Column(String(64), unique=True, nullable=False, index=True)  # UUID
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    expires_at = Column(DateTime, nullable=False)
    remember_me = Column(Boolean, default=False, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    # Relationships
    user = relationship("User", back_populates="sessions")

    def is_valid(self):
        """Check if session is still valid"""
        return datetime.utcnow() < self.expires_at

    def __repr__(self):
        return f"<Session(id={self.id}, user_id={self.user_id}, expires_at={self.expires_at})>"


class APIKey(Base):
    """
    API key storage model.

    Stores user-specific API keys for SIEM platforms, AI models, and emulation tools.
    Keys are encrypted at rest using Fernet symmetric encryption.
    """
    __tablename__ = "api_keys"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    platform = Column(String(50), nullable=False)  # splunk, mde, elastic, openai, anthropic
    encrypted_key = Column(Text, nullable=False)  # Fernet encrypted
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    # Relationships
    user = relationship("User", back_populates="api_keys")

    def __repr__(self):
        return f"<APIKey(id={self.id}, user_id={self.user_id}, platform='{self.platform}')>"


class SecurityQuestion(Base):
    """
    Security questions for password reset fallback.

    Stores hashed answers to security questions for password recovery.
    """
    __tablename__ = "security_questions"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    question = Column(String(255), nullable=False)
    answer_hash = Column(String(255), nullable=False)  # bcrypt hash
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    # Relationships
    user = relationship("User", back_populates="security_questions")

    def __repr__(self):
        return f"<SecurityQuestion(id={self.id}, user_id={self.user_id})>"


class PasswordReset(Base):
    """
    Password reset tokens for email-based password recovery.

    Stores temporary tokens sent via email for password reset.
    Tokens expire after 1 hour.
    """
    __tablename__ = "password_resets"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    reset_token = Column(String(64), unique=True, nullable=False, index=True)  # UUID
    expires_at = Column(DateTime, nullable=False)
    used = Column(Boolean, default=False, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    # Relationships
    user = relationship("User", back_populates="password_resets")

    def is_valid(self):
        """Check if reset token is still valid and unused"""
        return not self.used and datetime.utcnow() < self.expires_at

    def __repr__(self):
        return f"<PasswordReset(id={self.id}, user_id={self.user_id}, used={self.used})>"
