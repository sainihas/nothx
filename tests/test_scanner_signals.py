"""Tests for scanner aggregation of bulk/marketing signals."""

import tempfile
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import patch

import pytest

from nothx import db
from nothx.scanner import _agg_verdict, _most_common


class TestAggVerdict:
    def test_all_none(self):
        assert _agg_verdict([None, None]) is None

    def test_empty(self):
        assert _agg_verdict([]) is None

    def test_any_false_dominates(self):
        assert _agg_verdict([True, False, None]) is False

    def test_all_true(self):
        assert _agg_verdict([True, True, None]) is True


class TestMostCommon:
    def test_picks_most_frequent(self):
        assert _most_common(["a", "b", "a", None]) == "a"

    def test_all_none(self):
        assert _most_common([None, None]) is None

    def test_empty(self):
        assert _most_common([]) is None


@pytest.fixture
def temp_db():
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test.db"
        with patch("nothx.db.get_db_path", return_value=db_path):
            db.init_db()
            yield db_path


class TestScanAggregation:
    def test_aggregates_signals(self, temp_db):
        from unittest.mock import MagicMock

        from nothx.config import AccountConfig, Config
        from nothx.models import EmailHeader
        from nothx.scanner import scan_inbox

        config = Config(accounts={"main": AccountConfig("gmail", "me@x.com", "pw")})

        emails = [
            EmailHeader(
                sender="promo@shop.com",
                subject="Sale",
                date=datetime(2026, 1, 2, tzinfo=UTC),
                message_id="<1>",
                list_unsubscribe="<https://shop.com/u>",
                precedence="bulk",
                esp="sendgrid",
                list_id="<news.shop.com>",
                dkim_pass=True,
            ),
            EmailHeader(
                sender="promo@shop.com",
                subject="More",
                date=datetime(2026, 1, 1, tzinfo=UTC),
                message_id="<2>",
                list_unsubscribe="<https://shop.com/u>",
                dkim_pass=False,  # one failure -> aggregate False
            ),
        ]

        conn = MagicMock()
        conn.fetch_marketing_emails.return_value = iter(emails)
        conn.__enter__ = lambda s: conn
        conn.__exit__ = lambda *a: None

        with patch("nothx.scanner.IMAPConnection", return_value=conn):
            result = scan_inbox(config)

        stats = result.sender_stats["shop.com"]
        assert stats.bulk_precedence is True
        assert stats.esp_name == "sendgrid"
        assert stats.list_id == "<news.shop.com>"
        assert stats.dkim_pass is False  # fail-dominant
        assert stats.sample_senders == ["promo@shop.com"]

    def test_dry_run_does_not_write_senders(self, temp_db):
        """persist=False (dry-run) must not create any sender rows."""
        from unittest.mock import MagicMock

        from nothx.config import AccountConfig, Config
        from nothx.models import EmailHeader
        from nothx.scanner import scan_inbox

        config = Config(accounts={"main": AccountConfig("gmail", "me@x.com", "pw")})
        emails = [
            EmailHeader(
                sender="promo@shop.com",
                subject="Sale",
                date=datetime(2026, 1, 2, tzinfo=UTC),
                message_id="<1>",
                list_unsubscribe="<https://shop.com/u>",
            )
        ]
        conn = MagicMock()
        conn.fetch_marketing_emails.return_value = iter(emails)
        conn.__enter__ = lambda s: conn
        conn.__exit__ = lambda *a: None

        with patch("nothx.scanner.IMAPConnection", return_value=conn):
            result = scan_inbox(config, persist=False)

        # In-memory stats are still produced...
        assert "shop.com" in result.sender_stats
        # ...but nothing was written to the database.
        assert db.get_sender("shop.com") is None
        with db.get_db() as dbconn:
            count = dbconn.execute("SELECT COUNT(*) FROM senders").fetchone()[0]
        assert count == 0
