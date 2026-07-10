"""Tests for portable SPECIAL-USE discovery and UID-safe Junk movement."""

from __future__ import annotations

from typing import Any

import pytest

from nothx.mailbox import (
    MailboxParseError,
    discover_from_list,
    discover_mailboxes,
    move_uid_to_junk,
    parse_flags,
    parse_list_response,
    validate_uid_locator,
)
from nothx.models import MailboxActionOutcome, MailboxInfo, MessageRef


class FakeIMAP:
    def __init__(
        self,
        *,
        capabilities: tuple[bytes, ...] = (b"IMAP4rev1",),
        uidvalidity: bytes = b"77",
        permanent_flags: bytes = b"(\\Seen \\Deleted \\*)",
        existing_uids: bytes = b"42",
    ) -> None:
        self.capabilities = capabilities
        self.uidvalidity = uidvalidity
        self.permanent_flags = permanent_flags
        self.existing_uids = existing_uids
        self.list_status = "OK"
        self.list_data: list[Any] = []
        self.special_use_status = "OK"
        self.special_use_data: list[Any] = []
        self.list_calls: list[tuple[str, str]] = []
        self.select_status = "OK"
        self.command_status: dict[str, str] = {}
        self.selected: list[tuple[str, bool]] = []
        self.commands: list[tuple[str, tuple[Any, ...]]] = []

    def list(self, directory: str = '""', pattern: str = "*") -> tuple[str, list[Any]]:
        assert directory == '""'
        self.list_calls.append((directory, pattern))
        if pattern == "* RETURN (SPECIAL-USE)":
            return self.special_use_status, self.special_use_data
        assert pattern == "*"
        return self.list_status, self.list_data

    def select(self, mailbox: str = "INBOX", readonly: bool = False) -> tuple[str, list[bytes]]:
        self.selected.append((mailbox, readonly))
        return self.select_status, [b"1"]

    def response(self, code: str) -> tuple[str, list[bytes]]:
        if code == "UIDVALIDITY":
            return code, [self.uidvalidity]
        if code == "PERMANENTFLAGS":
            return code, [self.permanent_flags]
        return code, []

    def uid(self, command: str, *args: Any) -> tuple[str, list[bytes]]:
        normalized = command.upper()
        self.commands.append((normalized, args))
        status = self.command_status.get(normalized, "OK")
        if normalized == "SEARCH":
            return status, [self.existing_uids]
        return status, [b""]

    def capability(self) -> tuple[str, list[bytes]]:
        return "OK", [b"IMAP4rev1"]


def locator(*, uidvalidity: int = 77, mailbox: str = "INBOX") -> MessageRef:
    return MessageRef("me@example.com", mailbox, uidvalidity, 42)


def junk(name: str = "Junk E-mail") -> MailboxInfo:
    return MailboxInfo(name, name, "/", (r"\junk",), True)


class TestListParsing:
    def test_quoted_special_use_and_escaped_name(self) -> None:
        result = parse_list_response(b'(\\HasNoChildren \\Junk) "/" "Junk \\"mail\\""')
        assert result.name == 'Junk "mail"'
        assert result.delimiter == "/"
        assert result.is_junk is True
        assert result.selectable is True

    def test_nil_delimiter_and_literal_mailbox(self) -> None:
        result = parse_list_response((b"(\\Junk) NIL {4}", b"Spam"))
        assert result.name == "Spam"
        assert result.delimiter is None

    def test_modified_utf7_wire_name_is_preserved(self) -> None:
        result = parse_list_response(b'(\\Junk) "/" "&AMk-l&AO8-ments supprim&AOk-s"')
        assert result.wire_name == "&AMk-l&AO8-ments supprim&AOk-s"

    @pytest.mark.parametrize(
        "response",
        [b"not a list", b'(\\Junk "/" "Spam"', b'(\\Junk) "/"', (b"(\\Junk) NIL {5}", b"Spam")],
    )
    def test_malformed_response_is_rejected(self, response: Any) -> None:
        with pytest.raises(MailboxParseError):
            parse_list_response(response)


class TestDiscovery:
    def test_unique_special_use_junk_is_selected(self) -> None:
        result = discover_from_list(
            [b'(\\HasNoChildren) "/" INBOX', b'(\\HasNoChildren \\Junk) "/" "Spam"']
        )
        assert result.inbox is not None and result.inbox.name == "INBOX"
        assert result.junk is not None and result.junk.name == "Spam"
        assert result.junk_is_ambiguous is False

    def test_multiple_junk_mailboxes_require_override(self) -> None:
        rows = [b'(\\Junk) "/" "Spam"', b'(\\Junk) "/" "Quarantine"']
        ambiguous = discover_from_list(rows)
        selected = discover_from_list(rows, junk_override="Quarantine")
        assert ambiguous.junk is None
        assert ambiguous.junk_is_ambiguous is True
        assert selected.junk is not None and selected.junk.name == "Quarantine"
        assert selected.override_used is True

    def test_override_can_select_non_special_use_mailbox(self) -> None:
        result = discover_from_list(
            ['(\\HasNoChildren) "/" "Courrier indésirable"'],
            junk_override="Courrier indésirable",
        )
        assert result.junk is not None
        assert result.junk.name == "Courrier indésirable"

    def test_does_not_guess_common_or_noselect_names(self) -> None:
        result = discover_from_list(
            [b'(\\HasNoChildren) "/" Spam', b'(\\NoSelect \\Junk) "/" Junk']
        )
        assert result.junk is None
        assert result.junk_candidates == ()

    def test_network_wrapper_reports_list_failure(self) -> None:
        client = FakeIMAP()
        client.list_status = "NO"
        result = discover_mailboxes(client)
        assert result.mailboxes == ()
        assert result.errors == ("IMAP LIST failed",)

    def test_malformed_rows_and_missing_override_are_reported(self) -> None:
        result = discover_from_list(
            [b"malformed", b'(\\HasNoChildren) "/" INBOX'],
            junk_override="Missing",
        )
        assert result.inbox is not None
        assert len(result.errors) == 2
        assert result.junk is None

    def test_network_wrapper_parses_successful_list(self) -> None:
        client = FakeIMAP()
        client.list_data = [b'(\\Junk) "/" Spam']
        result = discover_mailboxes(client)
        assert result.junk is not None and result.junk.name == "Spam"

    def test_special_use_return_option_is_requested_when_advertised(self) -> None:
        client = FakeIMAP(capabilities=(b"IMAP4rev1 SPECIAL-USE",))
        client.list_data = [b'(\\HasNoChildren) "/" Spam']
        client.special_use_data = [b'(\\HasNoChildren \\Junk) "/" Spam']

        result = discover_mailboxes(client)

        assert result.junk is not None and result.junk.name == "Spam"
        assert client.list_calls == [('""', "* RETURN (SPECIAL-USE)")]

    def test_rejected_special_use_return_option_falls_back_safely(self) -> None:
        client = FakeIMAP(capabilities=(b"IMAP4rev1 SPECIAL-USE",))
        client.special_use_status = "BAD"
        client.list_data = [b'(\\HasNoChildren \\Junk) "/" Spam']

        result = discover_mailboxes(client)

        assert result.junk is not None and result.junk.name == "Spam"
        assert client.list_calls == [
            ('""', "* RETURN (SPECIAL-USE)"),
            ('""', "*"),
        ]


class TestFlagParsing:
    def test_splits_and_normalizes_flags_and_keywords(self) -> None:
        flags = parse_flags(b"FLAGS (\\Seen $Junk $NotJunk $Phishing $canunsubscribe custom)")
        assert flags.system == frozenset({r"\seen"})
        assert flags.keywords == frozenset(
            {"$junk", "$notjunk", "$phishing", "$canunsubscribe", "custom"}
        )
        assert flags.is_junk
        assert flags.is_not_junk
        assert flags.is_phishing
        assert flags.can_unsubscribe

    def test_invalid_or_missing_flags_are_empty(self) -> None:
        assert parse_flags(None).all == frozenset()
        assert parse_flags(b"not flags").all == frozenset()

    def test_fetch_wrapper_does_not_leak_uid_tokens_into_flags(self) -> None:
        flags = parse_flags(b"42 (UID 900 FLAGS (\\Seen $Junk))")
        assert flags.system == frozenset({r"\seen"})
        assert flags.keywords == frozenset({"$junk"})


class TestUIDValidation:
    def test_reselects_writable_and_validates_exact_uid(self) -> None:
        client = FakeIMAP(existing_uids=b"4 42 420")
        result = validate_uid_locator(client, locator())
        assert result.valid is True
        assert result.selected_uidvalidity == 77
        assert client.selected == [('"INBOX"', False)]
        assert client.commands == [("SEARCH", (None, "UID", "42"))]

    def test_changed_uidvalidity_fails_before_any_uid_command(self) -> None:
        client = FakeIMAP(uidvalidity=b"78")
        result = validate_uid_locator(client, locator())
        assert result.valid is False
        assert "UIDVALIDITY changed" in (result.error or "")
        assert client.commands == []

    def test_missing_uid_fails_closed(self) -> None:
        client = FakeIMAP(existing_uids=b"41 43")
        result = validate_uid_locator(client, locator())
        assert result.valid is False
        assert result.uid_exists is False
        assert result.exact_search_completed is True

    def test_readonly_or_missing_uidvalidity_fails_closed(self) -> None:
        readonly = FakeIMAP()
        readonly.select_status = "NO"
        assert validate_uid_locator(readonly, locator()).valid is False

        missing = FakeIMAP(uidvalidity=b"")
        result = validate_uid_locator(missing, locator())
        assert result.valid is False
        assert "did not provide" in (result.error or "")

    def test_uid_search_failure_is_not_treated_as_absence(self) -> None:
        client = FakeIMAP()
        client.command_status["SEARCH"] = "NO"
        result = validate_uid_locator(client, locator())
        assert result.valid is False
        assert result.error == "UID search failed"
        assert result.exact_search_completed is False

    def test_malformed_uid_search_data_is_not_treated_as_absence(self) -> None:
        client = FakeIMAP(existing_uids=b"not-a-uid")
        result = validate_uid_locator(client, locator())
        assert result.valid is False
        assert result.error == "UID search returned malformed data"
        assert result.exact_search_completed is False

    def test_invalid_numeric_locator_is_rejected_before_select(self) -> None:
        client = FakeIMAP()
        result = validate_uid_locator(
            client, MessageRef("me@example.com", "INBOX", uidvalidity=0, uid=42)
        )
        assert result.valid is False
        assert client.selected == []


class TestMoveToJunk:
    def test_uid_move_is_preferred_and_keywords_are_updated(self) -> None:
        client = FakeIMAP(capabilities=(b"IMAP4rev1", b"MOVE", b"UIDPLUS"))
        result = move_uid_to_junk(client, locator(), junk('Junk "E-mail"'))
        assert result.outcome is MailboxActionOutcome.MOVED
        assert result.method == "uid-move"
        assert result.source_removed is True
        assert result.junk_keyword_set is True
        assert result.not_junk_keyword_removed is True
        assert ("MOVE", ("42", '"Junk \\"E-mail\\""')) in client.commands
        assert all(command != "EXPUNGE" for command, _ in client.commands)

    def test_copy_delete_uses_uid_expunge_only_with_uidplus(self) -> None:
        client = FakeIMAP(capabilities=(b"IMAP4rev1 UIDPLUS",))
        result = move_uid_to_junk(client, locator(), junk())
        assert result.outcome is MailboxActionOutcome.MOVED
        assert result.method == "uid-copy-delete-expunge"
        assert ("COPY", ("42", '"Junk E-mail"')) in client.commands
        assert ("STORE", ("42", "+FLAGS.SILENT", r"(\Deleted)")) in client.commands
        assert ("EXPUNGE", ("42",)) in client.commands
        # The helper exposes no call to client.expunge(), so mailbox-wide
        # EXPUNGE is impossible on this path.

    def test_without_uidplus_copy_is_reported_partial_and_never_expunged(self) -> None:
        client = FakeIMAP()
        result = move_uid_to_junk(client, locator(), junk())
        assert result.outcome is MailboxActionOutcome.PARTIAL
        assert result.destination_created is True
        assert result.source_marked_deleted is True
        assert result.source_removed is False
        assert all(command != "EXPUNGE" for command, _ in client.commands)

    def test_failed_move_does_not_risk_duplicate_copy(self) -> None:
        client = FakeIMAP(capabilities=(b"MOVE",))
        client.command_status["MOVE"] = "NO"
        result = move_uid_to_junk(client, locator(), junk())
        assert result.outcome is MailboxActionOutcome.FAILED
        assert all(command != "COPY" for command, _ in client.commands)

    def test_failed_copy_is_reported_without_delete_or_expunge(self) -> None:
        client = FakeIMAP()
        client.command_status["COPY"] = "NO"
        result = move_uid_to_junk(client, locator(), junk())
        assert result.outcome is MailboxActionOutcome.FAILED
        commands = [command for command, _ in client.commands]
        assert "COPY" in commands
        assert "EXPUNGE" not in commands

    def test_failed_uid_expunge_is_partial(self) -> None:
        client = FakeIMAP(capabilities=(b"UIDPLUS",))
        client.command_status["EXPUNGE"] = "NO"
        result = move_uid_to_junk(client, locator(), junk())
        assert result.outcome is MailboxActionOutcome.PARTIAL
        assert result.source_marked_deleted is True
        assert result.source_removed is False

    def test_stale_locator_causes_no_store_copy_move_or_expunge(self) -> None:
        client = FakeIMAP(uidvalidity=b"999", capabilities=(b"MOVE UIDPLUS",))
        result = move_uid_to_junk(client, locator(), junk())
        assert result.outcome is MailboxActionOutcome.FAILED
        assert client.commands == []

    def test_exact_uid_absence_with_matching_uidvalidity_is_terminal(self) -> None:
        client = FakeIMAP(existing_uids=b"", capabilities=(b"MOVE UIDPLUS",))
        result = move_uid_to_junk(client, locator(), junk())
        assert result.outcome is MailboxActionOutcome.NOT_FOUND
        assert result.source_removed is True
        assert result.method == "uid-search"
        assert client.commands == [("SEARCH", (None, "UID", "42"))]

    def test_uid_search_failure_remains_a_mailbox_failure(self) -> None:
        client = FakeIMAP(capabilities=(b"MOVE UIDPLUS",))
        client.command_status["SEARCH"] = "NO"
        result = move_uid_to_junk(client, locator(), junk())
        assert result.outcome is MailboxActionOutcome.FAILED
        assert result.source_removed is False

    def test_malformed_uid_search_remains_a_mailbox_failure(self) -> None:
        client = FakeIMAP(existing_uids=b"garbage", capabilities=(b"MOVE UIDPLUS",))
        result = move_uid_to_junk(client, locator(), junk())
        assert result.outcome is MailboxActionOutcome.FAILED
        assert result.source_removed is False

    def test_already_in_junk_is_a_noop(self) -> None:
        client = FakeIMAP(capabilities=(b"MOVE",))
        result = move_uid_to_junk(client, locator(mailbox="Spam"), junk("Spam"))
        assert result.outcome is MailboxActionOutcome.ALREADY_JUNK
        assert client.selected == []
        assert client.commands == []

    def test_non_inbox_mailbox_names_are_not_assumed_case_insensitive(self) -> None:
        client = FakeIMAP(capabilities=(b"MOVE",))
        result = move_uid_to_junk(client, locator(mailbox="Spam"), junk("spam"))
        assert result.outcome is MailboxActionOutcome.MOVED
        assert any(command == "MOVE" for command, _ in client.commands)

    def test_inbox_name_is_case_insensitive(self) -> None:
        client = FakeIMAP()
        result = move_uid_to_junk(client, locator(mailbox="inbox"), "INBOX")
        assert result.outcome is MailboxActionOutcome.ALREADY_JUNK

    def test_command_injection_in_destination_name_is_rejected(self) -> None:
        client = FakeIMAP(capabilities=(b"MOVE",))
        result = move_uid_to_junk(client, locator(), "Junk\r\nEXPUNGE")
        assert result.outcome is MailboxActionOutcome.FAILED
        assert client.commands == []
