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
    def test_outlook_import_on_gmail_uses_exchange_authentication(self):
        base = (
            "From: Store <deals@store.example>\r\n"
            "Subject: Big Sale\r\n"
            "Date: Tue, 30 Jun 2026 10:00:00 +0200\r\n"
            "Authentication-Results: spf=pass smtp.mailfrom=store.example; "
            "dkim=pass header.d=store.example;dmarc=pass header.from=store.example\r\n"
        )
        stamped = base + "X-MS-Exchange-Organization-AuthSource: relay.example.outlook.com\r\n\r\n"
        imported = make_connection()._parse_header(parse_message(stamped), is_seen=False)
        forged = make_connection()._parse_header(parse_message(base + "\r\n"), is_seen=False)
        assert imported is not None and imported.authentication.trusted is True
        assert forged is not None and forged.authentication.trusted is False

    def test_outlook_import_needs_a_microsoft_exchange_stamp(self):
        msg = parse_message(
            "From: Store <deals@store.example>\r\n"
            "Subject: Big Sale\r\n"
            "Date: Tue, 30 Jun 2026 10:00:00 +0200\r\n"
            "Authentication-Results: mx.microsoft.com 1; spf=pass smtp.mailfrom=store.example; "
            "dkim=pass header.d=store.example;dmarc=pass header.from=store.example\r\n"
            "X-MS-Exchange-Organization-AuthSource: relay.store.example\r\n\r\n"
        )
        header = make_connection()._parse_header(msg, is_seen=False)
        assert header is not None and header.authentication.trusted is False

    def test_outlook_import_keeps_microsoft_phishing_verdict(self):
        msg = parse_message(
            "From: Bank <alerts@bank.example>\r\n"
            "Subject: Verify your account\r\n"
            "Date: Tue, 30 Jun 2026 10:00:00 +0200\r\n"
            "Authentication-Results: mx.microsoft.com 1; spf=pass smtp.mailfrom=bank.example; "
            "dkim=pass header.d=bank.example;dmarc=pass header.from=bank.example\r\n"
            "X-Forefront-Antispam-Report: CIP:192.0.2.1;CTRY:;SFV:NSPM;CAT:HPHSH;SCL:9\r\n"
            "X-MS-Exchange-Organization-AuthSource: relay.example.outlook.com\r\n\r\n"
        )
        gmail_native = parse_message(
            msg.as_string().replace("X-MS-Exchange-Organization-AuthSource", "X-Other")
        )
        gmail_stamped = parse_message(
            "Authentication-Results: mx.google.com; dkim=pass header.d=bank.example; "
            "dmarc=pass header.from=bank.example\r\n" + msg.as_string()
        )
        imported = make_connection()._parse_header(msg, is_seen=False)
        native = make_connection()._parse_header(gmail_native, is_seen=False)
        stamped = make_connection()._parse_header(gmail_stamped, is_seen=False)
        assert imported is not None and imported.provider_threat == "HPHSH"
        assert native is not None and native.provider_threat is None
        assert stamped is not None and stamped.provider_threat is None

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


def test_raw_folded_display_name_does_not_hide_a_valid_sender():
    message = email.message_from_bytes(
        b'From: "First, Second & Third\r\n Team" <bulletin@example.com>\r\n'
        b"Subject: Weekly digest\r\n\r\n"
    )
    header = make_connection()._parse_header(message, is_seen=False)
    assert header is not None
    assert header.sender_address == "bulletin@example.com"


def test_refresh_header_checks_uidvalidity_and_only_peeks_headers():
    import pytest

    connection = make_connection()
    locator = MessageRef("me@example.com", "INBOX", 44, 9)
    connection.conn.select.return_value = ("OK", [b"10"])
    connection.conn.uid.return_value = (
        "OK",
        [
            (
                b'1 (UID 9 FLAGS (\\Seen) INTERNALDATE "01-Jul-2026 10:00:00 +0000")',
                b"From: news@example.com\r\nMessage-ID: <old@example.com>\r\nSubject: Offers\r\n\r\n",
            )
        ],
    )
    with patch.object(connection, "_selected_uidvalidity", return_value=44):
        header = connection.fetch_header(locator)
    assert header is not None
    assert header.uid == 9 and header.uidvalidity == 44
    assert header.is_seen
    command = connection.conn.uid.call_args.args
    assert command[0:2] == ("FETCH", "9")
    assert "BODY.PEEK[HEADER.FIELDS" in command[2]
    assert "BODY[]" not in command[2]
    connection.conn.uid.reset_mock()
    with patch.object(connection, "_selected_uidvalidity", return_value=45):
        with pytest.raises(ValueError, match="UIDVALIDITY"):
            connection.fetch_header(locator)
    connection.conn.uid.assert_not_called()


def test_refresh_header_rejects_other_uid():
    import pytest

    connection = make_connection()
    connection.conn.select.return_value = ("OK", [b"10"])
    connection.conn.uid.return_value = (
        "OK",
        [(b"1 (UID 10 FLAGS ())", b"From: news@example.com\r\n")],
    )
    with patch.object(connection, "_selected_uidvalidity", return_value=44):
        with pytest.raises(ValueError, match="different source UID"):
            connection.fetch_header(MessageRef("me@example.com", "INBOX", 44, 9))
