"""Account/list identity, mailbox discovery, and cursor persistence tests."""

import tempfile
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from nothx import db
from nothx.config import AccountConfig, Config
from nothx.mailbox import MailboxDiscovery
from nothx.models import (
    AuthenticationEvidence,
    AuthResult,
    EmailHeader,
    FooterUnsubscribeCandidate,
    MailboxInfo,
)
from nothx.scanner import scan_inbox


@pytest.fixture
def database() -> Path:
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "scanner.db"
        with patch("nothx.db.get_db_path", return_value=path):
            db.init_db()
            yield path


def header(
    uid: int,
    *,
    sender: str = "news@letters.example",
    list_id: str | None = "<weekly.letters.example>",
    mailbox: str = "INBOX",
    role: str = "inbox",
) -> EmailHeader:
    return EmailHeader(
        sender=sender,
        subject=f"Issue {uid}",
        date=datetime(2026, 7, min(uid, 28), tzinfo=UTC),
        message_id=f"<{uid}@letters.example>",
        list_id=list_id,
        mailbox_name=mailbox,
        mailbox_role=role,
        uidvalidity=70,
        uid=uid,
    )


def fake_connection(
    by_mailbox: dict[str, list[EmailHeader]],
    *,
    discovery: MailboxDiscovery | None = None,
    complete: bool = True,
) -> MagicMock:
    conn = MagicMock()
    conn.__enter__.return_value = conn
    conn.__exit__.return_value = None
    conn.discover_mailboxes.return_value = discovery or MailboxDiscovery((), None, None, ())

    def fetch(**kwargs):
        messages = by_mailbox.get(kwargs["folder"], [])
        conn.last_fetch_complete = complete
        conn.last_fetch_uidvalidity = 70
        conn.last_fetch_highest_uid = max((item.uid or 0 for item in messages), default=0)
        return iter(messages)

    conn.fetch_marketing_emails.side_effect = fetch
    return conn


def test_scans_only_unambiguous_special_use_junk_and_explicit_custom_folder(
    database: Path,
) -> None:
    del database
    junk = MailboxInfo("Correo no deseado", "Correo no deseado", "/", (r"\junk",))
    discovery = MailboxDiscovery((junk,), None, junk, (junk,))
    conn = fake_connection(
        {
            "INBOX": [header(1)],
            "Correo no deseado": [header(2, mailbox="Correo no deseado", role="junk")],
            "Receipts": [header(3, mailbox="Receipts", role="custom")],
        },
        discovery=discovery,
    )
    config = Config(
        accounts={
            "main": AccountConfig(
                "gmail", "me@example.com", "pw", extra_scan_mailboxes=["Receipts"]
            )
        }
    )

    with patch("nothx.scanner.IMAPConnection", return_value=conn):
        result = scan_inbox(config, persist=False)

    folders = [call.kwargs["folder"] for call in conn.fetch_marketing_emails.call_args_list]
    assert folders == ["INBOX", "Correo no deseado", "Receipts"]
    assert sum(item.total_emails for item in result.subscription_stats.values()) == 3


def test_ambiguous_junk_is_not_guessed(database: Path) -> None:
    del database
    first = MailboxInfo("Spam A", "Spam A", "/", (r"\junk",))
    second = MailboxInfo("Spam B", "Spam B", "/", (r"\junk",))
    discovery = MailboxDiscovery((first, second), None, None, (first, second))
    conn = fake_connection({"INBOX": []}, discovery=discovery)
    config = Config(accounts={"main": AccountConfig("gmail", "me@example.com", "pw")})

    with patch("nothx.scanner.IMAPConnection", return_value=conn):
        scan_inbox(config, persist=False)

    assert [call.kwargs["folder"] for call in conn.fetch_marketing_emails.call_args_list] == [
        "INBOX"
    ]


def test_cursor_advances_only_after_message_persistence(database: Path) -> None:
    del database
    db.upsert_mailbox_state(
        "me@example.com",
        "INBOX",
        "inbox",
        uidvalidity=70,
        last_uid=4,
        scan_complete=True,
    )
    conn = fake_connection({"INBOX": [header(5)]})
    config = Config(
        scan_junk=False,
        accounts={"main": AccountConfig("gmail", "me@example.com", "pw")},
    )

    with patch("nothx.scanner.IMAPConnection", return_value=conn):
        scan_inbox(config)

    call = conn.fetch_marketing_emails.call_args
    assert call.kwargs["since_uid"] == 4
    assert call.kwargs["expected_uidvalidity"] == 70
    assert db.get_mailbox_state("me@example.com", "INBOX")["last_uid"] == 5
    assert len(db.list_message_refs(account="me@example.com")) == 1


def test_server_received_time_controls_subscription_lifecycle(database: Path) -> None:
    del database
    forged_old = header(1)
    forged_old.date = datetime(1970, 1, 1, tzinfo=UTC)
    forged_old.received_at = datetime(2026, 7, 8, 12, 0, tzinfo=UTC)
    forged_future = header(2)
    forged_future.date = datetime(2099, 1, 1, tzinfo=UTC)
    forged_future.received_at = datetime(2026, 7, 9, 12, 0, tzinfo=UTC)
    conn = fake_connection({"INBOX": [forged_old, forged_future]})
    config = Config(
        scan_junk=False,
        accounts={"main": AccountConfig("gmail", "me@example.com", "pw")},
    )

    with patch("nothx.scanner.IMAPConnection", return_value=conn):
        result = scan_inbox(config)

    subscription = db.list_subscriptions(account="me@example.com")[0]
    assert subscription["first_seen"].startswith("2026-07-08T12:00:00")
    assert subscription["last_seen"].startswith("2026-07-09T12:00:00")
    assert subscription["last_delivery_at"].startswith("2026-07-09T12:00:00")
    stats = next(iter(result.subscription_stats.values()))
    assert stats.first_seen == forged_old.received_at
    assert stats.last_seen == forged_future.received_at
    assert {row["received_at"] for row in db.list_message_refs(account="me@example.com")} == {
        "2026-07-08T12:00:00+00:00",
        "2026-07-09T12:00:00+00:00",
    }


def test_incomplete_fetch_does_not_persist_or_advance(database: Path) -> None:
    del database
    db.upsert_mailbox_state(
        "me@example.com",
        "INBOX",
        "inbox",
        uidvalidity=70,
        last_uid=4,
        scan_complete=True,
    )
    conn = fake_connection({"INBOX": [header(5)]}, complete=False)
    config = Config(
        scan_junk=False,
        accounts={"main": AccountConfig("gmail", "me@example.com", "pw")},
    )

    with patch("nothx.scanner.IMAPConnection", return_value=conn):
        scan_inbox(config)

    assert db.get_mailbox_state("me@example.com", "INBOX")["last_uid"] == 4
    assert db.list_subscriptions(account="me@example.com") == []
    assert db.list_message_refs(account="me@example.com") == []


def test_full_history_and_rescan_explicitly_bypass_incremental_cursor(database: Path) -> None:
    del database
    db.upsert_mailbox_state(
        "me@example.com",
        "INBOX",
        "inbox",
        uidvalidity=70,
        last_uid=50,
        scan_complete=True,
    )
    config = Config(
        scan_junk=False,
        accounts={"main": AccountConfig("gmail", "me@example.com", "pw")},
    )
    history = fake_connection({"INBOX": []})
    with patch("nothx.scanner.IMAPConnection", return_value=history):
        scan_inbox(config, persist=False, full_history=True)
    assert history.fetch_marketing_emails.call_args.kwargs["since_uid"] is None
    assert history.fetch_marketing_emails.call_args.kwargs["full_history"] is True

    recent = fake_connection({"INBOX": []})
    with patch("nothx.scanner.IMAPConnection", return_value=recent):
        scan_inbox(config, persist=False, rescan=True)
    assert recent.fetch_marketing_emails.call_args.kwargs["since_uid"] is None
    assert recent.fetch_marketing_emails.call_args.kwargs["full_history"] is False

    with pytest.raises(ValueError, match="mutually exclusive"):
        scan_inbox(config, persist=False, full_history=True, rescan=True)


def test_unambiguous_fallback_identity_is_promoted_and_grouped(database: Path) -> None:
    del database
    messages = [
        header(1, list_id=None),
        header(2, list_id="<weekly.letters.example>"),
    ]
    conn = fake_connection({"INBOX": messages})
    config = Config(
        scan_junk=False,
        accounts={"main": AccountConfig("gmail", "me@example.com", "pw")},
    )

    with patch("nothx.scanner.IMAPConnection", return_value=conn):
        result = scan_inbox(config)

    assert len(result.subscription_stats) == 1
    subscriptions = db.list_subscriptions(account="me@example.com")
    assert [(row["identity_kind"], row["identity_value"]) for row in subscriptions] == [
        ("list_id", "weekly.letters.example")
    ]
    assert subscriptions[0]["promoted_from_value"] == "news@letters.example"
    refs = db.list_message_refs(subscription_id=int(subscriptions[0]["id"]))
    assert {row["uid"] for row in refs} == {1, 2}

    # A later delivery can omit List-Id again; the recorded exact promotion
    # keeps it attached to the same account/list identity.
    followup = fake_connection({"INBOX": [header(3, list_id=None)]})
    with patch("nothx.scanner.IMAPConnection", return_value=followup):
        second = scan_inbox(config)
    assert len(second.subscription_stats) == 1
    assert len(db.list_subscriptions(account="me@example.com")) == 1
    assert len(db.list_message_refs(subscription_id=int(subscriptions[0]["id"]))) == 3


def test_multiple_list_ids_from_one_address_are_never_merged(database: Path) -> None:
    del database
    messages = [
        header(1, list_id=None),
        header(2, list_id="<weekly.letters.example>"),
        header(3, list_id="<daily.letters.example>"),
    ]
    conn = fake_connection({"INBOX": messages})
    config = Config(
        scan_junk=False,
        accounts={"main": AccountConfig("gmail", "me@example.com", "pw")},
    )

    with patch("nothx.scanner.IMAPConnection", return_value=conn):
        result = scan_inbox(config)

    assert len(result.subscription_stats) == 3
    identities = {
        (row["identity_kind"], row["identity_value"])
        for row in db.list_subscriptions(account="me@example.com")
    }
    assert identities == {
        ("from", "news@letters.example"),
        ("list_id", "weekly.letters.example"),
        ("list_id", "daily.letters.example"),
    }


def test_same_domain_and_uid_in_two_accounts_remain_independent(database: Path) -> None:
    del database
    first_message = header(1, list_id="<first.letters.example>")
    second_message = header(1, list_id="<second.letters.example>")
    connections = {
        "one@example.com": fake_connection({"INBOX": [first_message]}),
        "two@example.com": fake_connection({"INBOX": [second_message]}),
    }
    config = Config(
        scan_junk=False,
        accounts={
            "one": AccountConfig("gmail", "one@example.com", "pw"),
            "two": AccountConfig("gmail", "two@example.com", "pw"),
        },
    )

    with patch(
        "nothx.scanner.IMAPConnection",
        side_effect=lambda account: connections[account.email],
    ):
        result = scan_inbox(config)

    assert len(result.subscription_stats) == 2
    subscriptions = db.list_subscriptions()
    assert {(row["account"], row["identity_value"]) for row in subscriptions} == {
        ("one@example.com", "first.letters.example"),
        ("two@example.com", "second.letters.example"),
    }
    assert len(db.list_message_refs()) == 2


def test_footer_scan_is_default_off_and_strictly_eligible(database: Path) -> None:
    del database
    message = header(1)
    message.authentication = AuthenticationEvidence(
        dkim=AuthResult.PASS,
        dkim_domains=("letters.example",),
        trusted=True,
    )
    conn = fake_connection({"INBOX": [message]})
    conn.fetch_footer_candidates.return_value = (
        FooterUnsubscribeCandidate(
            "https://letters.example/unsubscribe?token=secret",
            "footer_plain",
            "unsubscribe",
        ),
    )
    config = Config(
        scan_junk=False,
        accounts={"main": AccountConfig("gmail", "me@example.com", "pw")},
    )

    with patch("nothx.scanner.IMAPConnection", return_value=conn):
        scan_inbox(config, persist=False)
    conn.fetch_footer_candidates.assert_not_called()

    config.footer_scan_enabled = True
    with patch("nothx.scanner.IMAPConnection", return_value=conn):
        result = scan_inbox(config, persist=False, rescan=True)

    conn.fetch_footer_candidates.assert_called_once_with(message)
    scanned = next(iter(result.subscription_emails.values()))[0]
    assert scanned.footer_unsubscribe_candidates[0].source == "footer_plain"


def test_esp_candidate_with_http_only_header_can_use_safe_footer_fallback(
    database: Path,
) -> None:
    del database
    message = header(1, list_id=None)
    message.esp = "sendgrid"
    message.list_unsubscribe = "<http://letters.example/insecure>"
    message.authentication = AuthenticationEvidence(
        dkim=AuthResult.PASS,
        dkim_domains=("letters.example",),
        trusted=True,
    )
    conn = fake_connection({"INBOX": [message]})
    conn.fetch_footer_candidates.return_value = ()
    config = Config(
        scan_junk=False,
        footer_scan_enabled=True,
        accounts={"main": AccountConfig("gmail", "me@example.com", "pw")},
    )

    with patch("nothx.scanner.IMAPConnection", return_value=conn):
        scan_inbox(config, persist=False)

    conn.fetch_footer_candidates.assert_called_once_with(message)


def test_unaligned_dkim_cannot_authorize_footer_body_fetch(database: Path) -> None:
    del database
    message = header(1)
    message.authentication = AuthenticationEvidence(
        dkim=AuthResult.PASS,
        dkim_domains=("attacker.example",),
        trusted=True,
    )
    conn = fake_connection({"INBOX": [message]})
    config = Config(
        scan_junk=False,
        footer_scan_enabled=True,
        accounts={"main": AccountConfig("gmail", "me@example.com", "pw")},
    )

    with patch("nothx.scanner.IMAPConnection", return_value=conn):
        scan_inbox(config, persist=False)

    conn.fetch_footer_candidates.assert_not_called()


@pytest.mark.parametrize("persist", [False, True])
@pytest.mark.parametrize(
    "bad_sender", ["", "not an address", "@example.com", '"space here"@example.com']
)
@pytest.mark.parametrize("bad_list_id", [None, "<valid.list.example>"])
def test_invalid_sender_cannot_abort_or_poison_other_messages(
    database: Path, persist: bool, bad_sender: str, bad_list_id: str | None
) -> None:
    del database
    valid = header(1)
    invalid = header(2, sender=bad_sender, list_id=bad_list_id)
    conn = fake_connection({"INBOX": [valid, invalid]})
    config = Config(accounts={"main": AccountConfig("gmail", "me@example.com", "pw")})

    with patch("nothx.scanner.IMAPConnection", return_value=conn):
        result = scan_inbox(config, persist=persist)

    assert result.skipped_invalid_senders == 1
    assert list(result.domain_emails) == ["letters.example"]
    assert sum(s.total_emails for s in result.subscription_stats.values()) == 1
    if persist:
        assert len(db.list_subscriptions()) == 1
        state = db.get_mailbox_state("me@example.com", "INBOX")
        assert state["last_uid"] == 2
    else:
        assert db.list_subscriptions() == []
        assert db.get_mailbox_state("me@example.com", "INBOX") is None


def test_full_inbox_scan_excludes_junk_and_custom_and_reports_coverage(database: Path) -> None:
    del database
    junk = MailboxInfo("Spam", "Spam", "/", (r"\junk",))
    conn = fake_connection(
        {"INBOX": [header(1)]}, discovery=MailboxDiscovery((junk,), None, junk, (junk,))
    )
    conn.last_fetch_mailbox_total = 100
    conn.last_fetch_selected = 1
    conn.last_fetch_scope = "full history"
    config = Config(
        accounts={
            "main": AccountConfig("gmail", "me@example.com", "pw", extra_scan_mailboxes=["Archive"])
        }
    )
    with patch("nothx.scanner.IMAPConnection", return_value=conn):
        result = scan_inbox(config, persist=False, full_history=True, inbox_only=True)
    assert [call.kwargs["folder"] for call in conn.fetch_marketing_emails.call_args_list] == [
        "INBOX"
    ]
    conn.discover_mailboxes.assert_not_called()
    assert result.coverage[0].total == 100
    assert result.coverage[0].selected == result.coverage[0].fetched == 1
    assert result.coverage[0].scope == "full history"
    assert db.list_subscriptions() == []


def test_partial_fetch_is_visible_in_coverage(database: Path) -> None:
    del database
    conn = fake_connection({"INBOX": [header(1)]}, complete=False)
    with patch("nothx.scanner.IMAPConnection", return_value=conn):
        result = scan_inbox(
            Config(accounts={"main": AccountConfig("gmail", "me@example.com", "pw")}), persist=False
        )
    assert result.coverage[0].complete is False


def test_folded_from_headers_are_processed_instead_of_counted_as_invalid(database):
    messages = [
        header(
            index, sender='"First, Second & Third\r\n Team" <bulletin@example.com>', list_id=None
        )
        for index in (1, 2)
    ]
    conn = fake_connection({"INBOX": messages})
    config = Config(accounts={"main": AccountConfig("gmail", "owner@example.com", "pw")})
    with patch("nothx.scanner.IMAPConnection", return_value=conn):
        result = scan_inbox(config, persist=True)
    assert result.skipped_invalid_senders == 0
    assert len(result.subscription_stats) == 1
    sender = next(iter(result.subscription_stats.values()))
    assert sender.total_emails == 2
    assert sender.identity_value == "bulletin@example.com"
    assert len(db.list_message_refs()) == 2


def test_metadata_batches_bound_connections_and_rollback_failed_batch(database: Path) -> None:
    from nothx.scanner import _persist_headers

    headers = [header(index) for index in range(1, 1002)]
    for item in headers:
        item.account_key = "me@example.com"
    with patch("nothx.db.get_connection", wraps=db.get_connection) as connections:
        _persist_headers("me@example.com", headers, {})
    assert connections.call_count == 4
    assert len(db.list_message_refs(account="me@example.com", limit=2000)) == 1001
    before = db.get_mailbox_state("me@example.com", "INBOX")
    fresh = header(1002, sender="failed@example.com", list_id=None)
    fresh.account_key = "me@example.com"
    with patch("nothx.db.upsert_message_ref", side_effect=RuntimeError("write failed")):
        with pytest.raises(RuntimeError):
            _persist_headers("me@example.com", [fresh], {})
    assert len(db.list_message_refs(account="me@example.com", limit=2000)) == 1001
    assert db.get_mailbox_state("me@example.com", "INBOX") == before
    assert (
        db.get_subscription(
            account="me@example.com", identity_kind="from", identity_value="failed@example.com"
        )
        is None
    )
    db.upsert_subscription("me@example.com", "from", "new@example.com")
    assert db.get_subscription(
        account="me@example.com", identity_kind="from", identity_value="new@example.com"
    )


def test_stored_promotion_conflicts_are_checked_past_first_500(database: Path) -> None:
    from nothx.scanner import _aliases_with_stored_promotions

    db.upsert_subscription("me@example.com", "from", "shared@example.com")
    db.promote_subscription_identity("me@example.com", "shared@example.com", "original.example")
    with db.metadata_batch():
        for index in range(505):
            db.upsert_subscription(
                "me@example.com",
                "list_id",
                f"list-{index}.example",
                from_address=f"news-{index}@example.com",
            )
    item = header(1, sender="shared@example.com", list_id="<different.example>")
    item.account_key = "me@example.com"
    assert ("me@example.com", "shared@example.com") not in _aliases_with_stored_promotions([item])


def test_footer_budget_prioritizes_newest_distinct_subscriptions(database: Path) -> None:
    del database
    old, middle, newest = header(1), header(2), header(3)
    other = header(4, list_id="<other.letters.example>")
    for message in (old, middle, newest, other):
        message.authentication = AuthenticationEvidence(trusted=True, dmarc=AuthResult.PASS)
    conn = fake_connection({"INBOX": [old, middle, newest, other]})
    conn.fetch_footer_candidates.return_value = ()
    config = Config(
        scan_junk=False,
        footer_scan_enabled=True,
        accounts={"main": AccountConfig("gmail", "me@example.com", "pw")},
    )
    with (
        patch("nothx.scanner.IMAPConnection", return_value=conn),
        patch("nothx.scanner.MAX_MESSAGES_PER_ACCOUNT", 2),
    ):
        scan_inbox(config, full_history=True, persist=False)
    assert [call.args[0].uid for call in conn.fetch_footer_candidates.call_args_list] == [4, 3]
