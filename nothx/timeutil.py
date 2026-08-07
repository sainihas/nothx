"""Timezone helpers.

Every datetime that nothx persists or does arithmetic on must be timezone-aware
UTC.  Mixing ``datetime.now()`` with ``datetime.now(UTC)`` is what produced
``TypeError: can't subtract offset-naive and offset-aware datetimes``, so new
code should call :func:`utcnow` instead of ``datetime.now`` and pass anything
read back from SQLite through :func:`ensure_utc`.
"""

from datetime import UTC, datetime


def utcnow() -> datetime:
    """Return the current time as a timezone-aware UTC datetime."""
    return datetime.now(UTC)


def ensure_utc(value: datetime) -> datetime:
    """Coerce a datetime to timezone-aware UTC.

    Naive values are adopted as UTC rather than rejected: rows written before
    this rule was enforced are naive, and the resulting offset is far smaller
    than the time scales any caller reasons about.
    """
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)
