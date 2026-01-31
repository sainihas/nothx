"""Tests for database operations."""

import pytest
import tempfile
import os
from datetime import datetime
from pathlib import Path
from unittest.mock import patch

from nothx.models import SenderStatus, RunStats
from nothx import db


@pytest.fixture
def temp_db():
    """Create a temporary database for testing."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test.db"
        with patch("nothx.db.get_db_path", return_value=db_path):
            db.init_db()
            yield db_path


class TestDatabaseInit:
    """Tests for database initialization."""

    def test_init_creates_tables(self, temp_db):
        """Test that init_db creates all required tables."""
        with db.get_db() as conn:
            # Check tables exist
            cursor = conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )
            tables = {row[0] for row in cursor.fetchall()}

            assert "senders" in tables
            assert "unsub_log" in tables
            assert "corrections" in tables
            assert "runs" in tables
            assert "rules" in tables


class TestSenderOperations:
    """Tests for sender-related database operations."""

    def test_upsert_sender(self, temp_db):
        """Test inserting and updating sender records."""
        db.upsert_sender(
            domain="test.com",
            total_emails=10,
            seen_emails=5,
            sample_subjects=["Subject 1", "Subject 2"],
            has_unsubscribe=True,
        )

        sender = db.get_sender("test.com")
        assert sender is not None
        assert sender["domain"] == "test.com"
        assert sender["total_emails"] == 10
        assert sender["seen_emails"] == 5
        assert sender["has_unsubscribe"] == 1

    def test_upsert_sender_update(self, temp_db):
        """Test that upsert updates existing records."""
        # Insert
        db.upsert_sender(
            domain="test.com",
            total_emails=5,
            seen_emails=2,
            sample_subjects=["Old Subject"],
            has_unsubscribe=False,
        )

        # Update
        db.upsert_sender(
            domain="test.com",
            total_emails=15,
            seen_emails=10,
            sample_subjects=["New Subject"],
            has_unsubscribe=True,
        )

        sender = db.get_sender("test.com")
        assert sender["total_emails"] == 15
        assert sender["seen_emails"] == 10
        assert sender["has_unsubscribe"] == 1

    def test_update_sender_status(self, temp_db):
        """Test updating sender status."""
        db.upsert_sender(
            domain="test.com",
            total_emails=5,
            seen_emails=2,
            sample_subjects=[],
            has_unsubscribe=True,
        )

        db.update_sender_status("test.com", SenderStatus.UNSUBSCRIBED)

        sender = db.get_sender("test.com")
        assert sender["status"] == "unsubscribed"

    def test_get_sender_not_found(self, temp_db):
        """Test getting a non-existent sender."""
        sender = db.get_sender("nonexistent.com")
        assert sender is None

    def test_get_senders_by_status(self, temp_db):
        """Test filtering senders by status."""
        # Create senders with different statuses
        db.upsert_sender("keep.com", 5, 5, [], False)
        db.update_sender_status("keep.com", SenderStatus.KEEP)

        db.upsert_sender("unsub.com", 10, 0, [], True)
        db.update_sender_status("unsub.com", SenderStatus.UNSUBSCRIBED)

        kept = db.get_senders_by_status(SenderStatus.KEEP)
        assert len(kept) == 1
        assert kept[0]["domain"] == "keep.com"

        unsubbed = db.get_senders_by_status(SenderStatus.UNSUBSCRIBED)
        assert len(unsubbed) == 1
        assert unsubbed[0]["domain"] == "unsub.com"


class TestRulesOperations:
    """Tests for rule management."""

    def test_add_rule(self, temp_db):
        """Test adding a rule."""
        db.add_rule("*.spam.com", "block")

        rules = db.get_rules()
        assert len(rules) == 1
        assert rules[0]["pattern"] == "*.spam.com"
        assert rules[0]["action"] == "block"

    def test_add_rule_replace(self, temp_db):
        """Test that adding a rule with same pattern replaces it."""
        db.add_rule("*.test.com", "keep")
        db.add_rule("*.test.com", "unsub")

        rules = db.get_rules()
        assert len(rules) == 1
        assert rules[0]["action"] == "unsub"

    def test_delete_rule(self, temp_db):
        """Test deleting a rule."""
        db.add_rule("*.test.com", "keep")

        result = db.delete_rule("*.test.com")
        assert result is True

        rules = db.get_rules()
        assert len(rules) == 0

    def test_delete_nonexistent_rule(self, temp_db):
        """Test deleting a rule that doesn't exist."""
        result = db.delete_rule("nonexistent")
        assert result is False


class TestRunLogging:
    """Tests for run statistics logging."""

    def test_log_run(self, temp_db):
        """Test logging a run."""
        stats = RunStats(
            ran_at=datetime.now(),
            mode="interactive",
            emails_scanned=100,
            unique_senders=25,
            auto_unsubbed=10,
            kept=10,
            review_queued=5,
            failed=0,
        )

        run_id = db.log_run(stats)
        assert run_id is not None

        runs = db.get_recent_runs(limit=1)
        assert len(runs) == 1
        assert runs[0]["emails_scanned"] == 100
        assert runs[0]["unique_senders"] == 25

    def test_get_recent_runs(self, temp_db):
        """Test getting recent runs with limit."""
        for i in range(5):
            stats = RunStats(
                ran_at=datetime.now(),
                mode="auto",
                emails_scanned=i * 10,
            )
            db.log_run(stats)

        runs = db.get_recent_runs(limit=3)
        assert len(runs) == 3


class TestCorrections:
    """Tests for AI correction logging."""

    def test_log_correction(self, temp_db):
        """Test logging a user correction."""
        db.log_correction("test.com", "unsub", "keep")

        corrections = db.get_recent_corrections(limit=10)
        assert len(corrections) == 1
        assert corrections[0]["domain"] == "test.com"
        assert corrections[0]["ai_decision"] == "unsub"
        assert corrections[0]["user_decision"] == "keep"


class TestStats:
    """Tests for statistics retrieval."""

    def test_get_stats_empty(self, temp_db):
        """Test getting stats from empty database."""
        stats = db.get_stats()
        assert stats["total_senders"] == 0
        assert stats["unsubscribed"] == 0
        assert stats["kept"] == 0
        assert stats["pending_review"] == 0
        assert stats["total_runs"] == 0
        assert stats["last_run"] is None

    def test_get_stats_with_data(self, temp_db):
        """Test getting stats with data."""
        # Add some senders
        db.upsert_sender("keep.com", 5, 5, [], False)
        db.update_sender_status("keep.com", SenderStatus.KEEP)

        db.upsert_sender("unsub.com", 10, 0, [], True)
        db.update_sender_status("unsub.com", SenderStatus.UNSUBSCRIBED)

        db.upsert_sender("review.com", 3, 1, [], True)
        # Status stays 'unknown' for review

        stats = db.get_stats()
        assert stats["total_senders"] == 3
        assert stats["unsubscribed"] == 1
        assert stats["kept"] == 1
        assert stats["pending_review"] == 1
