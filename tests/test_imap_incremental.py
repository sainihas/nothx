"""Focused protocol tests for UID cursors and bounded footer fetching."""

from datetime import UTC, datetime
from typing import Any
from unittest.mock import patch

from nothx.config import AccountConfig
from nothx.footer import FooterExtraction
from nothx.imap import IMAPConnection
from nothx.models import EmailHeader, FooterUnsubscribeCandidate

RAW_HEADER = (
    b"From: News <news@example.com>\r\n"
    b"Subject: Update\r\n"
    b"Date: Thu, 09 Jul 2026 12:00:00 +0000\r\n"
    b"Message-ID: <one@example.com>\r\n\r\n"
)


class HeaderClient:
    capabilities: tuple[str, ...] = ()

    def __init__(self, *, uidvalidity: int = 7, fetch_ok: bool = True) -> None:
        self.uidvalidity = uidvalidity
        self.fetch_ok = fetch_ok
        self.calls: list[tuple[str, tuple[Any, ...]]] = []
        self.headers_by_uid: dict[str, bytes] = {}
        self.internaldates_by_uid: dict[str, str] = {}

    def select(self, _folder: str, readonly: bool = True) -> tuple[str, list[bytes]]:
        assert readonly is True
        return "OK", [b"2"]

    def response(self, code: str) -> tuple[str, list[bytes]]:
        if code == "UIDVALIDITY":
            return "OK", [str(self.uidvalidity).encode()]
        if code == "UIDNEXT":
            return "OK", [b"13"]
        return "OK", []

    def uid(self, command: str, *args: Any) -> tuple[str, list[Any]]:
        self.calls.append((command, args))
        if command == "SEARCH":
            return "OK", [b"10 11 12"]
        if command == "FETCH":
            if not self.fetch_ok:
                return "NO", []
            uids = str(args[0]).split(",")
            return "OK", [
                (
                    (
                        f'1 (UID {uid} INTERNALDATE "'
                        f"{self.internaldates_by_uid.get(uid, '09-Jul-2026 13:00:00 +0000')}"
                        f'" FLAGS (\\Seen))'
                    ).encode(),
                    self.headers_by_uid.get(uid, RAW_HEADER),
                )
                for uid in uids
            ]
        raise AssertionError(command)


def connection(client: Any) -> IMAPConnection:
    result = IMAPConnection(AccountConfig("gmail", "me@example.com", "secret"))
    result.conn = client
    return result


def test_incremental_uid_cursor_is_exclusive_and_filters_server_range() -> None:
    client = HeaderClient()
    imap = connection(client)

    headers = list(imap.fetch_marketing_emails(since_uid=10, expected_uidvalidity=7))

    assert [header.uid for header in headers] == [11, 12]
    search = next(args for command, args in client.calls if command == "SEARCH")
    assert search[-1] == "11:*"
    assert imap.last_fetch_uidvalidity == 7
    assert imap.last_fetch_highest_uid == 12
    assert imap.last_fetch_complete is True
    assert {header.received_at for header in headers} == {datetime(2026, 7, 9, 13, 0, tzinfo=UTC)}


def test_uidvalidity_change_discards_old_cursor_before_search() -> None:
    client = HeaderClient(uidvalidity=8)
    imap = connection(client)

    list(imap.fetch_marketing_emails(since_uid=500, expected_uidvalidity=7))

    search = next(args for command, args in client.calls if command == "SEARCH")
    assert search[-2] == "SINCE"
    assert imap.last_fetch_uidvalidity == 8


def test_failed_fetch_batch_is_never_checkpointable() -> None:
    imap = connection(HeaderClient(fetch_ok=False))

    assert list(imap.fetch_marketing_emails()) == []
    assert imap.last_fetch_complete is False


def test_requested_uid_without_valid_parsed_header_is_never_checkpointable() -> None:
    imap = connection(HeaderClient())
    imap._parse_header = lambda _message, _seen: None  # type: ignore[method-assign]

    assert list(imap.fetch_marketing_emails()) == []
    assert imap.last_fetch_complete is False


def test_internaldate_not_sender_date_controls_delivery_time() -> None:
    client = HeaderClient()
    client.headers_by_uid = {
        "11": RAW_HEADER.replace(
            b"Thu, 09 Jul 2026 12:00:00 +0000", b"Thu, 09 Jul 1970 12:00:00 +0000"
        ),
        "12": RAW_HEADER.replace(
            b"Thu, 09 Jul 2026 12:00:00 +0000", b"Thu, 09 Jul 2099 12:00:00 +0000"
        ),
    }
    client.internaldates_by_uid = {
        "11": "08-Jul-2026 23:30:00 -0400",
        "12": "09-Jul-2026 04:30:00 +0100",
    }
    imap = connection(client)

    headers = list(imap.fetch_marketing_emails(since_uid=10, expected_uidvalidity=7))

    assert [item.date.year for item in headers] == [1970, 2099]
    assert [item.received_at for item in headers] == [
        datetime(2026, 7, 9, 3, 30, tzinfo=UTC),
        datetime(2026, 7, 9, 3, 30, tzinfo=UTC),
    ]
    assert imap.last_fetch_complete is True


def test_missing_internaldate_prevents_yield_and_checkpoint() -> None:
    client = HeaderClient()
    client.internaldates_by_uid = {"10": "invalid", "11": "invalid", "12": "invalid"}
    imap = connection(client)

    assert list(imap.fetch_marketing_emails()) == []
    assert imap.last_fetch_complete is False


class FooterClient:
    capabilities: tuple[str, ...] = ()

    def select(self, _folder: str, readonly: bool = True) -> tuple[str, list[bytes]]:
        assert readonly
        return "OK", [b"1"]

    def response(self, code: str) -> tuple[str, list[bytes]]:
        assert code == "UIDVALIDITY"
        return "OK", [b"44"]

    def uid(self, command: str, *args: Any) -> tuple[str, list[Any]]:
        if command == "SEARCH":
            return "OK", [b"9"]
        request = str(args[-1])
        if "BODYSTRUCTURE" in request:
            structure = (
                b'1 (UID 9 BODYSTRUCTURE ("TEXT" "PLAIN" ("CHARSET" "UTF-8") '
                b'NIL NIL "7BIT" 80 2 NIL ("INLINE" NIL) NIL NIL))'
            )
            return "OK", [structure]
        assert "BODY.PEEK[1]" in request
        body = b"To unsubscribe: https://letters.example/unsubscribe?token=opaque"
        return "OK", [(b"1 (UID 9 BODY[1]<0>)", body)]


def test_footer_fetch_revalidates_locator_and_returns_ephemeral_candidate() -> None:
    imap = connection(FooterClient())
    header = EmailHeader(
        sender="news@example.com",
        subject="Update",
        date=datetime(2026, 7, 9, tzinfo=UTC),
        message_id="<one@example.com>",
        account_key="me@example.com",
        mailbox_name="INBOX",
        uidvalidity=44,
        uid=9,
    )

    candidates = imap.fetch_footer_candidates(header)

    assert [item.uri for item in candidates] == ["https://letters.example/unsubscribe?token=opaque"]
    assert candidates[0].source == "footer_plain"


def test_footer_form_signal_is_preserved_even_when_candidates_exist() -> None:
    imap = connection(FooterClient())
    header = EmailHeader(
        sender="news@example.com",
        subject="Update",
        date=datetime(2026, 7, 9, tzinfo=UTC),
        message_id="<one@example.com>",
        account_key="me@example.com",
        mailbox_name="INBOX",
        uidvalidity=44,
        uid=9,
    )
    candidate = FooterUnsubscribeCandidate(
        "https://letters.example/unsubscribe?token=opaque",
        "footer_html",
        "unsubscribe",
    )

    with patch(
        "nothx.imap.extract_footer_candidates",
        return_value=FooterExtraction((candidate,), 1, 20, forms_seen=True),
    ):
        assert imap.fetch_footer_candidates(header) == (candidate,)

    assert header.footer_requires_user is True
