"""
Synchronous database session for Celery workers.

FastAPI uses async SQLAlchemy, but Celery workers need sync sessions
since subprocess calls (masscan, nmap) are blocking anyway.
"""
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker, Session
from contextlib import contextmanager
from ..core.config import settings

# Convert async URL to sync URL for Celery
sync_database_url = settings.DATABASE_URL.replace("sqlite+aiosqlite://", "sqlite://")

engine = create_engine(
    sync_database_url,
    connect_args={
        "check_same_thread": False,
        "timeout": 30  # Wait for locks instead of failing immediately
    } if "sqlite" in sync_database_url else {},
    pool_pre_ping=True,
    pool_size=1,  # Only one connection for SQLite
    max_overflow=0,  # No additional connections
    echo=settings.DEBUG
)

# Configure SQLite for better stability in Docker
@event.listens_for(engine, "connect")
def set_sqlite_pragma(dbapi_connection, connection_record):
    try:
        cursor = dbapi_connection.cursor()
        # Wait longer for locks - set this first as it doesn't require exclusive access
        cursor.execute("PRAGMA busy_timeout=30000")
        # Disable memory-mapped I/O which causes SIGBUS in containers
        cursor.execute("PRAGMA mmap_size=0")
        # Note: journal_mode change requires exclusive lock, skip if locked
        try:
            cursor.execute("PRAGMA journal_mode=DELETE")
        except Exception:
            pass  # If locked, keep existing journal mode
        cursor.close()
    except Exception as e:
        # If we can't set pragmas, continue anyway - they're optimizations
        import logging
        logging.warning(f"Could not set SQLite pragmas: {e}")

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

@contextmanager
def get_sync_db() -> Session:
    """Context manager for sync database sessions in Celery tasks"""
    db = SessionLocal()
    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()
