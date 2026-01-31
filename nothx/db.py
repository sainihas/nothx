"""SQLite database management for nothx."""

import sqlite3
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Optional, Iterator

from .config import get_db_path
from .models import SenderStatus, UnsubMethod, RunStats


def get_connection() -> sqlite3.Connection:
    """Get a database connection."""
    db_path = get_db_path()
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn


@contextmanager
def get_db() -> Iterator[sqlite3.Connection]:
    """Context manager for database connections."""
    conn = get_connection()
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db() -> None:
    """Initialize the database schema."""
    with get_db() as conn:
        conn.executescript("""
            -- Track all senders we've seen
            CREATE TABLE IF NOT EXISTS senders (
                domain TEXT PRIMARY KEY,
                first_seen TEXT,
                last_seen TEXT,
                total_emails INTEGER DEFAULT 0,
                seen_emails INTEGER DEFAULT 0,
                status TEXT DEFAULT 'unknown',
                ai_classification TEXT,
                ai_confidence REAL,
                user_override TEXT,
                sample_subjects TEXT,
                has_unsubscribe INTEGER DEFAULT 0
            );

            -- Log every unsubscribe attempt
            CREATE TABLE IF NOT EXISTS unsub_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain TEXT,
                attempted_at TEXT,
                success INTEGER,
                method TEXT,
                http_status INTEGER,
                error TEXT,
                response_snippet TEXT,
                FOREIGN KEY (domain) REFERENCES senders(domain)
            );

            -- User corrections for AI learning
            CREATE TABLE IF NOT EXISTS corrections (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain TEXT,
                ai_decision TEXT,
                user_decision TEXT,
                timestamp TEXT,
                FOREIGN KEY (domain) REFERENCES senders(domain)
            );

            -- Track each run
            CREATE TABLE IF NOT EXISTS runs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ran_at TEXT,
                mode TEXT,
                emails_scanned INTEGER DEFAULT 0,
                unique_senders INTEGER DEFAULT 0,
                auto_unsubbed INTEGER DEFAULT 0,
                kept INTEGER DEFAULT 0,
                review_queued INTEGER DEFAULT 0,
                failed INTEGER DEFAULT 0
            );

            -- User rules (keep/unsub lists)
            CREATE TABLE IF NOT EXISTS rules (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                pattern TEXT UNIQUE,
                action TEXT,
                created_at TEXT
            );
        """)


def upsert_sender(
    domain: str,
    total_emails: int,
    seen_emails: int,
    sample_subjects: list[str],
    has_unsubscribe: bool,
    first_seen: Optional[datetime] = None,
    last_seen: Optional[datetime] = None,
) -> None:
    """Insert or update a sender record."""
    with get_db() as conn:
        now = datetime.now().isoformat()
        first = first_seen.isoformat() if first_seen else now
        last = last_seen.isoformat() if last_seen else now
        subjects_json = "|".join(sample_subjects[:5])  # Store up to 5 samples

        conn.execute("""
            INSERT INTO senders (domain, first_seen, last_seen, total_emails, seen_emails, sample_subjects, has_unsubscribe)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(domain) DO UPDATE SET
                last_seen = excluded.last_seen,
                total_emails = excluded.total_emails,
                seen_emails = excluded.seen_emails,
                sample_subjects = excluded.sample_subjects,
                has_unsubscribe = excluded.has_unsubscribe
        """, (domain, first, last, total_emails, seen_emails, subjects_json, int(has_unsubscribe)))


def update_sender_status(domain: str, status: SenderStatus) -> None:
    """Update the status of a sender."""
    with get_db() as conn:
        conn.execute(
            "UPDATE senders SET status = ? WHERE domain = ?",
            (status.value, domain)
        )


def update_sender_classification(
    domain: str,
    classification: str,
    confidence: float
) -> None:
    """Update the AI classification of a sender."""
    with get_db() as conn:
        conn.execute(
            "UPDATE senders SET ai_classification = ?, ai_confidence = ? WHERE domain = ?",
            (classification, confidence, domain)
        )


def set_user_override(domain: str, action: str) -> None:
    """Set a user override for a sender."""
    with get_db() as conn:
        conn.execute(
            "UPDATE senders SET user_override = ? WHERE domain = ?",
            (action, domain)
        )


def get_sender(domain: str) -> Optional[dict]:
    """Get a sender by domain."""
    with get_db() as conn:
        row = conn.execute(
            "SELECT * FROM senders WHERE domain = ?",
            (domain,)
        ).fetchone()
        return dict(row) if row else None


def get_senders_by_status(status: SenderStatus) -> list[dict]:
    """Get all senders with a specific status."""
    with get_db() as conn:
        rows = conn.execute(
            "SELECT * FROM senders WHERE status = ? ORDER BY total_emails DESC",
            (status.value,)
        ).fetchall()
        return [dict(row) for row in rows]


def get_senders_for_review() -> list[dict]:
    """Get senders that need manual review."""
    with get_db() as conn:
        rows = conn.execute("""
            SELECT * FROM senders
            WHERE status = 'unknown' AND user_override IS NULL
            ORDER BY total_emails DESC
        """).fetchall()
        return [dict(row) for row in rows]


def log_unsub_attempt(
    domain: str,
    success: bool,
    method: Optional[UnsubMethod],
    http_status: Optional[int] = None,
    error: Optional[str] = None,
    response_snippet: Optional[str] = None
) -> None:
    """Log an unsubscribe attempt."""
    with get_db() as conn:
        conn.execute("""
            INSERT INTO unsub_log (domain, attempted_at, success, method, http_status, error, response_snippet)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            domain,
            datetime.now().isoformat(),
            int(success),
            method.value if method else None,
            http_status,
            error,
            response_snippet
        ))


def log_correction(domain: str, ai_decision: str, user_decision: str) -> None:
    """Log a user correction to an AI decision."""
    with get_db() as conn:
        conn.execute("""
            INSERT INTO corrections (domain, ai_decision, user_decision, timestamp)
            VALUES (?, ?, ?, ?)
        """, (domain, ai_decision, user_decision, datetime.now().isoformat()))


def get_recent_corrections(limit: int = 20) -> list[dict]:
    """Get recent user corrections for AI learning."""
    with get_db() as conn:
        rows = conn.execute("""
            SELECT * FROM corrections
            ORDER BY timestamp DESC
            LIMIT ?
        """, (limit,)).fetchall()
        return [dict(row) for row in rows]


def log_run(stats: RunStats) -> int:
    """Log a run and return its ID."""
    with get_db() as conn:
        cursor = conn.execute("""
            INSERT INTO runs (ran_at, mode, emails_scanned, unique_senders, auto_unsubbed, kept, review_queued, failed)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            stats.ran_at.isoformat(),
            stats.mode,
            stats.emails_scanned,
            stats.unique_senders,
            stats.auto_unsubbed,
            stats.kept,
            stats.review_queued,
            stats.failed
        ))
        return cursor.lastrowid


def get_recent_runs(limit: int = 10) -> list[dict]:
    """Get recent runs."""
    with get_db() as conn:
        rows = conn.execute("""
            SELECT * FROM runs ORDER BY ran_at DESC LIMIT ?
        """, (limit,)).fetchall()
        return [dict(row) for row in rows]


def get_recent_unsubscribes(days: int = 30) -> list[dict]:
    """Get recent successful unsubscribes."""
    with get_db() as conn:
        rows = conn.execute("""
            SELECT s.domain, s.total_emails, u.attempted_at, u.method
            FROM unsub_log u
            JOIN senders s ON u.domain = s.domain
            WHERE u.success = 1
            AND datetime(u.attempted_at) > datetime('now', ?)
            ORDER BY u.attempted_at DESC
        """, (f"-{days} days",)).fetchall()
        return [dict(row) for row in rows]


def add_rule(pattern: str, action: str) -> None:
    """Add a user rule."""
    with get_db() as conn:
        conn.execute("""
            INSERT OR REPLACE INTO rules (pattern, action, created_at)
            VALUES (?, ?, ?)
        """, (pattern, action, datetime.now().isoformat()))


def get_rules() -> list[dict]:
    """Get all user rules."""
    with get_db() as conn:
        rows = conn.execute("SELECT * FROM rules ORDER BY created_at").fetchall()
        return [dict(row) for row in rows]


def delete_rule(pattern: str) -> bool:
    """Delete a user rule."""
    with get_db() as conn:
        cursor = conn.execute("DELETE FROM rules WHERE pattern = ?", (pattern,))
        return cursor.rowcount > 0


def get_stats() -> dict:
    """Get overall statistics."""
    with get_db() as conn:
        senders = conn.execute("SELECT COUNT(*) as count FROM senders").fetchone()
        unsubbed = conn.execute(
            "SELECT COUNT(*) as count FROM senders WHERE status = 'unsubscribed'"
        ).fetchone()
        kept = conn.execute(
            "SELECT COUNT(*) as count FROM senders WHERE status = 'keep'"
        ).fetchone()
        review = conn.execute(
            "SELECT COUNT(*) as count FROM senders WHERE status = 'unknown' AND user_override IS NULL"
        ).fetchone()
        runs = conn.execute("SELECT COUNT(*) as count FROM runs").fetchone()
        last_run = conn.execute(
            "SELECT ran_at FROM runs ORDER BY ran_at DESC LIMIT 1"
        ).fetchone()

        return {
            "total_senders": senders["count"],
            "unsubscribed": unsubbed["count"],
            "kept": kept["count"],
            "pending_review": review["count"],
            "total_runs": runs["count"],
            "last_run": last_run["ran_at"] if last_run else None,
        }
