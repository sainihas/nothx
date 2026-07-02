"""Tests for database schema migration."""

import sqlite3
import tempfile
from pathlib import Path
from unittest.mock import patch

from nothx import db

V0_SCHEMA = """
    CREATE TABLE senders (
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
    CREATE TABLE unsub_log (
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
"""


class TestMigration:
    def test_v0_database_upgraded_losslessly(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "old.db"

            # Build a pre-migration database with existing data
            conn = sqlite3.connect(db_path)
            conn.executescript(V0_SCHEMA)
            conn.execute(
                "INSERT INTO senders (domain, status, total_emails) VALUES (?, ?, ?)",
                ("old.com", "unsubscribed", 42),
            )
            conn.execute(
                "INSERT INTO unsub_log (domain, success, method) VALUES (?, ?, ?)",
                ("old.com", 1, "get"),
            )
            conn.commit()
            conn.close()

            with patch("nothx.db.get_db_path", return_value=db_path):
                db.init_db()

                # Old data intact
                sender = db.get_sender("old.com")
                assert sender["status"] == "unsubscribed"
                assert sender["total_emails"] == 42

                # New column exists and is usable
                db.log_unsub_attempt(
                    domain="old.com",
                    success=False,
                    method=None,
                    needs_confirmation=True,
                )
                with db.get_db() as conn:
                    row = conn.execute(
                        "SELECT needs_confirmation FROM unsub_log ORDER BY id DESC LIMIT 1"
                    ).fetchone()
                assert row["needs_confirmation"] == 1

                # Version stamped
                with db.get_db() as conn:
                    version = conn.execute("PRAGMA user_version").fetchone()[0]
                assert version == db.SCHEMA_VERSION

    def test_migration_idempotent(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "new.db"
            with patch("nothx.db.get_db_path", return_value=db_path):
                db.init_db()
                db.init_db()  # second run must not fail
                with db.get_db() as conn:
                    version = conn.execute("PRAGMA user_version").fetchone()[0]
                assert version == db.SCHEMA_VERSION
