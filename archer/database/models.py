"""
Database models for Archer authentication and user management.

This module defines SQLAlchemy models for:
- Users: Email, password hash, role (admin/standard)
- Sessions: Session management with expiration
- APIKeys: User-specific encrypted API keys for SIEM/AI platforms
- AISettings: Per-user AI provider models and job assignments
- ApiTokens: Personal API tokens (hashed) for the CLI, MCP server and scripts
- AgentRuns: Agent session traces
- SecurityQuestions: For password reset fallback
"""

from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Boolean, Text, Enum, UniqueConstraint
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from datetime import datetime
import enum

Base = declarative_base()


class UserRole(str, enum.Enum):
    """User roles, in increasing privilege. Each inherits the abilities of the ones below it —
    gate on at_least(user, role), never role equality, so a higher role passes a lower gate.

      STANDARD  Analyst — hunt, view, author detections, watchlists
      OPERATOR  Operational analyst — the above + lab (own machines), telemetry rebuild, source edits
      ADMIN     the above + user/role management and secrets & integration settings
    """
    ADMIN = "admin"
    OPERATOR = "operator"
    STANDARD = "standard"


# Privilege order, low → high. The gate is at_least(), so adding a tier here is all it takes.
ROLE_RANK = {UserRole.STANDARD: 1, UserRole.OPERATOR: 2, UserRole.ADMIN: 3}


def role_rank(role) -> int:
    """Privilege level of a role (a UserRole, its value, or its name); 0 if unknown."""
    if isinstance(role, UserRole):
        return ROLE_RANK.get(role, 0)
    try:
        return ROLE_RANK.get(UserRole(role), 0)
    except (ValueError, TypeError):
        try:
            return ROLE_RANK.get(UserRole[str(role)], 0)  # accept the stored NAME too (e.g. "ADMIN")
        except (KeyError, ValueError):
            return 0


def effective_role(user):
    """The user's role in force right now: their base role, raised to a temporary grant that
    hasn't expired. A grant only ever elevates — a lower temp role than the base is ignored."""
    base = getattr(user, "role", None)
    temp = getattr(user, "temp_role", None)
    expires = getattr(user, "temp_role_expires", None)
    if temp is not None and expires is not None and expires > datetime.utcnow() \
            and role_rank(temp) > role_rank(base):
        return temp
    return base


def at_least(user, role: "UserRole") -> bool:
    """True when the user's effective role is `role` or higher — the canonical capability check."""
    return bool(user) and role_rank(effective_role(user)) >= ROLE_RANK[role]


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
    team = Column(String(255), nullable=True)  # User's team/department
    country = Column(String(80), nullable=True)  # Map name (archer.intelligence.cyber_powers.countries); green on Cyber Powers
    industries = Column(Text, nullable=True)  # JSON array: threat feed industries (archer.intelligence.feed)
    siem_platforms = Column(Text, nullable=True)  # JSON array: SIEMs hunts generate for (empty: all)
    tech_stack = Column(Text, nullable=True)  # JSON array: product ids (archer.intelligence.tech_stack; empty: everything applies)
    password_hash = Column(String(255), nullable=False)  # bcrypt hash
    role = Column(Enum(UserRole), nullable=False, default=UserRole.STANDARD)
    # A time-boxed elevation above `role` (just-in-time privilege): effective_role() uses it only
    # while temp_role_expires is in the future, and only when it's higher than the base role.
    temp_role = Column(Enum(UserRole), nullable=True)
    temp_role_expires = Column(DateTime, nullable=True)
    is_active = Column(Boolean, default=True, nullable=False)

    # Account lockout fields
    failed_login_attempts = Column(Integer, default=0, nullable=False)
    locked_until = Column(DateTime, nullable=True)  # None if not locked

    # Multi-Factor Authentication fields
    mfa_secret = Column(String(32), nullable=True)  # TOTP secret (base32 encoded)
    mfa_enabled = Column(Boolean, default=False, nullable=False)
    backup_codes = Column(Text, nullable=True)  # JSON array of hashed backup codes

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
    platform = Column(String(50), nullable=False)  # secops, splunk, mde, elastic, openai, anthropic, ...
    encrypted_key = Column(Text, nullable=False)  # Fernet encrypted
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    # Relationships
    user = relationship("User", back_populates="api_keys")

    def __repr__(self):
        return f"<APIKey(id={self.id}, user_id={self.user_id}, platform='{self.platform}')>"


class AISettings(Base):
    """
    A user's AI configuration apart from the keys themselves (those stay encrypted in
    api_keys): model per provider, the local endpoint, which provider Ask Archer and
    detection generation each use, and the Hunt prompt's remembered choice.
    JSON, shaped by archer.ai.assignment.
    """
    __tablename__ = "ai_settings"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, unique=True)
    settings = Column(Text, nullable=False, default="{}")
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)


class ApiToken(Base):
    """
    A personal API token for the console, the MCP server and scripts: they sign in with it
    instead of a password, so accounts with MFA can use them too. Only a hash is stored;
    the token is shown once, when it's created.
    """
    __tablename__ = "api_tokens"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    name = Column(String(100), nullable=False)
    token_hash = Column(String(64), unique=True, nullable=False, index=True)  # sha256 hex
    prefix = Column(String(16), nullable=False)  # first characters, to tell tokens apart
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    last_used_at = Column(DateTime, nullable=True)


class AgentRun(Base):
    """
    One agent session (archer/agents): the trace a person watched, kept after the server
    restarts. Doubles as an audit log of what each agent did and who allowed it.
    """
    __tablename__ = "agent_runs"

    id = Column(String(32), primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    agent = Column(String(32), nullable=False)
    model = Column(String(128), nullable=False, default="")
    status = Column(String(20), nullable=False)
    task = Column(Text, nullable=False, default="")
    answer = Column(Text, nullable=False, default="")
    events = Column(Text, nullable=False, default="[]")  # JSON, as Session.events
    provider = Column(String(32), nullable=True)
    conversation = Column(Text, nullable=True)  # JSON: the model's messages, to resume from
    turns = Column(Integer, nullable=False, default=0)
    input_tokens = Column(Integer, nullable=False, default=0)
    output_tokens = Column(Integer, nullable=False, default=0)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)


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


class DetectionType(str, enum.Enum):
    """Detection type enumeration"""
    DETECTION = "detection"
    SOLE_CORRELATION = "sole_correlation"
    CROSS_VENDOR_CORRELATION = "cross_vendor_correlation"


class VisibilityType(str, enum.Enum):
    """Visibility type enumeration"""
    PRIVATE = "private"
    SHARED = "shared"


class LibraryDetection(Base):
    """
    Library detection model for storing user-created queries.

    Stores all detections and correlations created by users for sharing and reuse.
    """
    __tablename__ = "library_detections"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    title = Column(String(500), nullable=False)
    detection_type = Column(Enum(DetectionType), nullable=False)
    visibility = Column(Enum(VisibilityType), nullable=False, default=VisibilityType.PRIVATE)

    # Store the actual detection/correlation content
    content = Column(Text, nullable=False)  # JSON-encoded detection content
    platform = Column(String(50), nullable=True)  # splunk, mde, elastic, etc.

    # Custom tags for hunts/incidents (JSON array of strings)
    tags = Column(Text, nullable=True)  # JSON-encoded array: ["Hunt-2024-01", "Incident-123"]

    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    # Relationships
    user = relationship("User", backref="library_detections")

    def __repr__(self):
        return f"<LibraryDetection(id={self.id}, title='{self.title}', user_id={self.user_id})>"


class LibraryCorrelation(Base):
    """
    Library correlation model for storing user-created correlations.

    Stores correlations separately from detections to allow independent management.
    """
    __tablename__ = "library_correlations"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    title = Column(String(500), nullable=False)
    visibility = Column(Enum(VisibilityType), nullable=False, default=VisibilityType.PRIVATE)

    # Store the actual correlation content
    content = Column(Text, nullable=False)  # JSON-encoded correlation content
    platform = Column(String(50), nullable=True)  # splunk, mde, elastic, etc.

    # Custom tags for hunts/incidents (JSON array of strings)
    tags = Column(Text, nullable=True)  # JSON-encoded array: ["Hunt-2024-01", "Incident-123"]

    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    # Relationships
    user = relationship("User", backref="library_correlations")

    def __repr__(self):
        return f"<LibraryCorrelation(id={self.id}, title='{self.title}', user_id={self.user_id})>"


class FlowLayout(Base):
    """
    A user's edits to a group's ATT&CK Flow: hidden techniques, removed links,
    dragged positions, orientation and filters. Kept once the group's results
    are in that user's library.
    """
    __tablename__ = "flow_layouts"
    __table_args__ = (UniqueConstraint("user_id", "group_name", name="uq_flow_layout_user_group"),)

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    group_name = Column(String(255), nullable=False)
    state = Column(Text, nullable=False)  # JSON, see archer/visualization/flow_layouts.py
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    def __repr__(self):
        return f"<FlowLayout(user_id={self.user_id}, group_name='{self.group_name}')>"


class ActivityType(str, enum.Enum):
    """Activity type enumeration"""
    GENERATE = "generate"
    CORRELATE = "correlate"
    UPLOAD = "upload"
    LIBRARY_SAVE = "library_save"
    LIBRARY_EXPORT = "library_export"


class ActivityLog(Base):
    """
    Activity log model for tracking user actions.

    Records user activities such as detection generation, correlation building,
    file uploads, and library operations for display in the Timeline tab.
    """
    __tablename__ = "activity_logs"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    activity_type = Column(Enum(ActivityType), nullable=False)

    # Activity details
    title = Column(String(500), nullable=False)  # e.g., "Generated detections for APT29"
    description = Column(Text, nullable=True)  # Additional details
    activity_metadata = Column(Text, nullable=True)  # JSON-encoded metadata (detection count, file paths, etc.)

    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    # Relationships
    user = relationship("User", backref="activity_logs")

    def __repr__(self):
        return f"<ActivityLog(id={self.id}, user_id={self.user_id}, activity_type='{self.activity_type}', title='{self.title}')>"
