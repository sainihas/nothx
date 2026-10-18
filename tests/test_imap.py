"""Tests for IMAP header parsing and date handling."""

import email
from datetime import UTC, datetime
from unittest.mock import MagicMock, patch

from nothx.config import AccountConfig
from nothx.imap import IMAPConnection, _imap_date
from nothx.models import MailboxActionOutcome, MailboxInfo, MessageRef


def make_connection() -> IMAPConnection:
    account = AccountConfig(provider="gmail", email="me@example.com", password="secret")
    conn = IMAPConnection(account)
    conn.conn = MagicMock()
    return conn


def parse_message(raw: str):
    return email.message_from_string(raw)


def test_non_ascii_junk_mailbox_encoding_failure_is_reported() -> None:
    connection = make_connection()
    locator = MessageRef("me@example.com", "INBOX", 44, 9)
    junk = MailboxInfo("Courrier indésirable", "Courrier indésirable")
    encoding_error = UnicodeEncodeError("ascii", "é", 0, 1, "ordinal not in range")

    with patch("nothx.imap.move_uid_to_junk", side_effect=encoding_error):
        result = connection.move_message_to_junk(locator, junk)

    assert result.outcome is MailboxActionOutcome.FAILED
    assert result.destination == "Courrier indésirable"
    assert result.error == "IMAP mailbox action failed (UnicodeEncodeError)"


class TestImapDate:
    def test_format(self):
        assert _imap_date(datetime(2026, 7, 2)) == "02-Jul-2026"

    def test_all_months_english(self):
        months = []
        for month in range(1, 13):
            months.append(_imap_date(datetime(2026, month, 15)).split("-")[1])
        assert months == [
            "Jan",
            "Feb",
            "Mar",
            "Apr",
            "May",
            "Jun",
            "Jul",
            "Aug",
            "Sep",
            "Oct",
            "Nov",
            "Dec",
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
        assert header.date == datetime(2026, 6, 30, 8, 0, 0, tzinfo=UTC)

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
        msg = parse_message("From: x@y.com\r\nSubject: hi\r\nDate: not a date\r\n\r\n")
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


class TestHeaderDecoding:
    def test_raw_utf8_headers_remain_text_and_keep_sender_identity(self):
        msg = email.message_from_bytes(
            "From: Caf\u00e9 <news@example.com>\r\nSubject: D\u00e9j\u00e0 vu\r\n\r\n".encode()
        )
        header = make_connection()._parse_header(msg, is_seen=False)
        assert header is not None
        assert isinstance(header.sender, str)
        assert header.sender_address == "news@example.com"
        assert header.subject == "D\u00e9j\u00e0 vu"

    def test_unknown_encoded_word_charset_uses_text_fallback(self):
        msg = parse_message(
            "From: =?not-a-real-charset?Q?Caf=C3=A9?= <news@example.com>\r\n"
            "Subject: =?not-a-real-charset?Q?D=C3=A9j=C3=A0_vu?=\r\n\r\n"
        )
        header = make_connection()._parse_header(msg, is_seen=False)
        assert header is not None
        assert header.sender == "Caf\u00e9 <news@example.com>"
        assert header.sender_address == "news@example.com"
        assert header.subject == "D\u00e9j\u00e0 vu"


class TestAuthenticatedCapabilities:
    def test_refreshes_greeting_cache_before_discovery_and_move(self):
        client = MagicMock()
        client.capabilities = ("IMAP4REV1", "AUTH=PLAIN")
        client.capability.return_value = ("OK", [b"IMAP4rev1 MOVE UIDPLUS SPECIAL-USE X-GM-EXT-1"])
        connection = IMAPConnection(AccountConfig("gmail", "me@example.com", "secret"))
        with patch("nothx.imap.imaplib.IMAP4_SSL", return_value=client):
            assert connection.connect()
        assert "MOVE" in client.capabilities
        assert "UIDPLUS" in client.capabilities
        assert "SPECIAL-USE" in client.capabilities
        assert connection._has_capability("X-GM-EXT-1")
        assert client.method_calls[0][0] == "login"
        assert client.method_calls[1][0] == "capability"
        connection.disconnect()
