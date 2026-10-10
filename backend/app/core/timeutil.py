"""Time helpers."""
from datetime import datetime, timezone


def utcnow() -> datetime:
    """Current UTC time as a naive datetime.

    Drop-in replacement for the deprecated ``datetime.utcnow()``: PEEK stores
    naive UTC timestamps (SQLite DateTime columns), so the tzinfo is stripped.
    """
    return datetime.now(timezone.utc).replace(tzinfo=None)
