"""Single source of "now" (naive UTC, matching the DateTime columns in SQLite)."""

from datetime import datetime, timezone


def utcnow() -> datetime:
    # datetime.utcnow() is deprecated since Python 3.12; this is the drop-in replacement.
    return datetime.now(timezone.utc).replace(tzinfo=None)
