"""
Database connection and initialization.

Manages SQLite database connection and session factory.
Database stored at: data/shikari.db
"""

from sqlalchemy import create_engine
from sqlalchemy.pool import NullPool
from sqlalchemy.orm import sessionmaker, Session as SQLAlchemySession
from pathlib import Path
from shikari.database.models import Base
from shikari.database.audit import Base as AuditBase

# Database file path
DB_PATH = Path("data/shikari.db")

# Create database directory if it doesn't exist
DB_PATH.parent.mkdir(parents=True, exist_ok=True)

# Create SQLAlchemy engine
DATABASE_URL = f"sqlite:///{DB_PATH}"
engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False},  # Needed for SQLite
    # OneDrive syncs data/ by swapping shikari.db for a new file. A pooled connection
    # still points at the old one, and SQLite then refuses its writes ("attempt to
    # write a readonly database"). A fresh connection per session opens the current file.
    poolclass=NullPool,
    echo=False  # Set to True for SQL debug logging
)

# Create session factory
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def init_db():
    """
    Initialize database tables.

    Creates all tables defined in models if they don't exist, then the first admin: the default one
    on a local Shikari, an invitation on a server (shikari/deployment.py).
    """
    Base.metadata.create_all(bind=engine)
    AuditBase.metadata.create_all(bind=engine)
    _add_missing_columns(Base)
    print(f"✓ Database initialized at {DB_PATH}")

    _create_default_admin()


def _add_missing_columns(base) -> None:
    """
    create_all makes new tables but never changes existing ones: a nullable column added to
    a model since the database was made is added here (ALTER TABLE ... ADD COLUMN).
    """
    from sqlalchemy import inspect, text

    inspector = inspect(engine)
    with engine.begin() as conn:
        for table in base.metadata.sorted_tables:
            if not inspector.has_table(table.name):
                continue
            have = {c["name"] for c in inspector.get_columns(table.name)}
            for column in table.columns:
                if column.name not in have and column.nullable:
                    conn.execute(text(f'ALTER TABLE "{table.name}" ADD COLUMN "{column.name}" '
                                      f"{column.type.compile(dialect=engine.dialect)}"))
                    print(f"✓ Database: added {table.name}.{column.name}")


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


def _create_default_admin():
    """A local Shikari's default admin (`admin` / BigGameHunter, on loopback only), or a server's
    first-admin invitation: shikari/deployment.py."""
    from shikari.deployment import ensure_first_admin

    db = SessionLocal()
    try:
        ensure_first_admin(db)
    except Exception as e:
        print(f"Note: could not set up the first admin: {e}")
        db.rollback()
    finally:
        db.close()
