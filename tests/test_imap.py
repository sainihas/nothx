"""Tests for IMAP header parsing and date handling."""

import email
from datetime import datetime, timezone
from unittest.mock import MagicMock

from nothx.config import AccountConfig
from nothx.imap import IMAPConnection, _imap_date


def make_connection() -> IMAPConnection:
    account = AccountConfig(provider="gmail", email="me@example.com", password="secret")
    conn = IMAPConnection(account)
    conn.conn = MagicMock()
    return conn


def parse_message(raw: str):
    return email.message_from_string(raw)


class TestImapDate:
    def test_format(self):
        assert _imap_date(datetime(2026, 7, 2)) == "02-Jul-2026"

    def test_all_months_english(self):
        months = []
        for month in range(1, 13):
            months.append(_imap_date(datetime(2026, month, 15)).split("-")[1])
        assert months == [
            "Jan", "Feb", "Mar", "Apr", "May", "Jun",
            "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
        ]


class TestParseHeader:
    def test_basic_header(self):
        msg = parse_message(
            "From: Store <deals@store.com>\r\n"
            "Subject: Big Sale\r\n"
            "Date: Tue, 30 Jun 2026 10:00:00 +0200\r\n"
            "Message-ID: <abc@store.com>\r\n"
            "List-Unsubscribe: <https://store.com/unsub>\r\n"
            "\r\n"
        )
        header = make_connection()._parse_header(msg, is_seen=True)
        assert header is not None
        assert header.domain == "store.com"
        assert header.subject == "Big Sale"
        assert header.is_seen is True
        # Dates are normalized to aware UTC
        assert header.date.tzinfo is not None
        assert header.date == datetime(2026, 6, 30, 8, 0, 0, tzinfo=timezone.utc)

    def test_encoded_word_subject(self):
        msg = parse_message(
            "From: x@y.com\r\n"
            "Subject: =?utf-8?B?U2FsZSDwn5iA?=\r\n"
            "Date: Tue, 30 Jun 2026 10:00:00 +0000\r\n"
            "\r\n"
        )
        header = make_connection()._parse_header(msg, is_seen=False)
        assert header is not None
        assert header.subject == "Sale 😀"

    def test_missing_date_falls_back_to_aware_now(self):
        msg = parse_message("From: x@y.com\r\nSubject: hi\r\n\r\n")
        header = make_connection()._parse_header(msg, is_seen=False)
        assert header is not None
        assert header.date.tzinfo is not None

    def test_unparseable_date_falls_back_to_aware_now(self):
        msg = parse_message(
            "From: x@y.com\r\nSubject: hi\r\nDate: not a date\r\n\r\n"
        )
        header = make_connection()._parse_header(msg, is_seen=False)
        assert header is not None
        assert header.date.tzinfo is not None

    def test_naive_date_normalized_to_utc(self):
        """Dates with -0000 (unknown tz) parse as naive; must be normalized."""
        msg = parse_message(
            "From: x@y.com\r\nSubject: hi\r\nDate: Tue, 30 Jun 2026 10:00:00 -0000\r\n\r\n"
        )
        header = make_connection()._parse_header(msg, is_seen=False)
        assert header is not None
        assert header.date.tzinfo is not None

    def test_dates_always_comparable(self):
        """Mixed parseable/unparseable dates must still sort (no naive/aware mix)."""
        conn = make_connection()
        raw_ok = "From: a@b.com\r\nSubject: s\r\nDate: Tue, 30 Jun 2026 10:00:00 +0200\r\n\r\n"
        raw_bad = "From: a@b.com\r\nSubject: s\r\nDate: garbage\r\n\r\n"
        h1 = conn._parse_header(parse_message(raw_ok), is_seen=False)
        h2 = conn._parse_header(parse_message(raw_bad), is_seen=False)
        assert h1 is not None and h2 is not None
        assert sorted([h1.date, h2.date])  # raises TypeError if naive/aware mixed
