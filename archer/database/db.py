"""
Database connection and initialization.

Manages SQLite database connection and session factory.
Database stored at: data/archer.db
"""

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session as SQLAlchemySession
from pathlib import Path
from archer.database.models import Base
from archer.database.audit import Base as AuditBase

# Database file path
DB_PATH = Path("data/archer.db")

# Create database directory if it doesn't exist
DB_PATH.parent.mkdir(parents=True, exist_ok=True)

# Create SQLAlchemy engine
DATABASE_URL = f"sqlite:///{DB_PATH}"
engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False},  # Needed for SQLite
    echo=False  # Set to True for SQL debug logging
)

# Create session factory
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def init_db():
    """
    Initialize database tables.

    Creates all tables defined in models if they don't exist.
    """
    Base.metadata.create_all(bind=engine)
    AuditBase.metadata.create_all(bind=engine)
    print(f"✓ Database initialized at {DB_PATH}")


def get_db() -> SQLAlchemySession:
    """
    Get database session.

    Yields:
        Database session

    Usage:
        with get_db() as db:
            # Use db session
            pass
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def get_db_session() -> SQLAlchemySession:
    """
    Get database session (non-generator version).

    Returns:
        Database session

    Note: Caller is responsible for closing the session.
    """
    return SessionLocal()
