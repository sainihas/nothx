"""Focused CLI acceptance tests for account-scoped safe automation."""

from __future__ import annotations

import hashlib
import imaplib
import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

from nothx import db
from nothx.cli import (
    _attempt_unsubscribe_for_domain,
    _block_subscription,
    _operation_key,
    _persist_subscription_records,
    _reconcile_due_operations,
    _redact_failure_detail,
    _unsubscribe_operation_plan,
    account_add,
    account_remove,
    cleanup,
    config_cmd,
    consent,
    export,
    history,
    open_unsubscribe,
    review,
    run,
    schedule,
    undo,
)
from nothx.config import (
    CONSENT_REVOKED,
    CURRENT_MAILBOX_MUTATION_CONSENT_VERSION,
    CURRENT_UNSUBSCRIBE_CONSENT_VERSION,
    AccountConfig,
    Config,
)
from nothx.mailbox import MailboxActionResult, MailboxDiscovery, UIDValidation
from nothx.models import (
    Action,
    Classification,
    EmailHeader,
    EmailType,
    MailboxActionOutcome,
    MailboxInfo,
    SenderStats,
    UnsubMethod,
    UnsubResult,
    UnsubscribeOutcome,
)
from nothx.safefetch import redacted_url
from nothx.scanner import ScanResult, _stats_for_emails


@pytest.fixture
def configured_cli():
    with tempfile.TemporaryDirectory() as directory:
        config_dir = Path(directory) / ".nothx"
        config_dir.mkdir()
        config_path = config_dir / "config.json"
        db_path = config_dir / "nothx.db"
        with (
            patch("nothx.config.get_config_dir", return_value=config_dir),
            patch("nothx.config.get_config_path", return_value=config_path),
            patch("nothx.db.get_db_path", return_value=db_path),
        ):
            db.init_db()
            config = Config()
            config.accounts["default"] = AccountConfig(
                provider="gmail",
                email="user@example.com",
                password="secret",
            )
            config.default_account = "default"
            config.ai.provider = "none"
            config.save()
            yield CliRunner(), config


def _subscription_scan(action: Action) -> tuple[ScanResult, dict[str, Classification]]:
    header = EmailHeader(
        sender="Deals <deals@shop.example>",
        subject="Sale",
        date=datetime(2026, 7, 1, tzinfo=UTC),
        message_id="<sale-1@example>",
        list_id="Shop deals <deals.shop.example>",
        account_name="default",
        account_key="user@example.com",
        mailbox_name="INBOX",
        mailbox_role="inbox",
        uidvalidity=44,
        uid=101,
    )
    key = header.subscription_identity.key
    stats = _stats_for_emails(header.domain, [header])
    stats.total_emails = 4
    result = ScanResult(
        {header.domain: stats},
        {header.domain: [header]},
        {key: stats},
        {key: [header]},
    )
    classifications = {
        key: Classification(
            email_type=EmailType.MARKETING,
            action=action,
            confidence=0.99,
            reasoning="fixture",
            source="user_rule",
        )
    }
    return result, classifications


def test_run_full_history_and_rescan_bypass_incremental_cursor(configured_cli):
    runner, _config = configured_cli
    empty = ScanResult({}, {}, {}, {})
    with patch("nothx.cli.scan_inbox", return_value=empty) as scan:
        result = runner.invoke(run, ["--dry-run", "--full-history"])
        assert result.exit_code == 0
        assert scan.call_args.kwargs["full_history"] is True
        assert scan.call_args.kwargs["rescan"] is False

        result = runner.invoke(run, ["--dry-run", "--rescan"])
        assert result.exit_code == 0
        assert scan.call_args.kwargs["full_history"] is False
        assert scan.call_args.kwargs["rescan"] is True


def test_schedule_daily(configured_cli):
    runner, _config = configured_cli
    with patch("nothx.cli.install_schedule", return_value=(True, "Scheduled daily")) as install:
        result = runner.invoke(schedule, ["--daily"])
    assert result.exit_code == 0
    install.assert_called_once_with("daily")


def test_explicit_consent_and_footer_configuration(configured_cli):
    runner, _config = configured_cli
    result = runner.invoke(consent, ["--all", "--yes"])
    assert result.exit_code == 0
    loaded = Config.load()
    assert loaded.unsubscribe_consent_version == CURRENT_UNSUBSCRIBE_CONSENT_VERSION
    assert loaded.mailbox_mutation_consent_version == CURRENT_MAILBOX_MUTATION_CONSENT_VERSION

    result = runner.invoke(config_cmd, ["--footer-scan", "on"])
    assert result.exit_code == 0
    assert Config.load().footer_scan_enabled is True


def test_outlook_device_flow_browser_failure_is_nonfatal(configured_cli):
    runner, _config = configured_cli
    with (
        patch("nothx.cli.questionary.select") as select,
        patch("nothx.cli.questionary.text") as text_prompt,
        patch("nothx.cli.msauth.start_device_flow") as start,
        patch("nothx.cli.msauth.poll_for_token") as poll,
        patch("nothx.cli.msauth.save_token") as save,
        patch("nothx.cli.webbrowser.open", side_effect=RuntimeError("no browser")),
        patch("nothx.cli.test_account", return_value=(True, "Connected")),
    ):
        select.return_value.ask.side_effect = ["outlook", "oauth"]
        text_prompt.return_value.ask.side_effect = ["person@outlook.com", "client-id"]
        start.return_value = {
            "device_code": "device-code",
            "user_code": "ABCD-EFGH",
            "verification_uri": "https://microsoft.com/devicelogin",
            "expires_in": 900,
            "interval": 5,
        }
        poll.return_value = {
            "access_token": "access-token",
            "refresh_token": "refresh-token",
            "scope": "scopes",
        }
        result = runner.invoke(account_add, [])
    assert result.exit_code == 0
    account = next(
        account
        for account in Config.load().accounts.values()
        if account.email == "person@outlook.com"
    )
    assert account.uses_oauth
    assert account.client_id == "client-id"
    save.assert_called_once()


def test_account_remove_deletes_oauth_cache_entry(configured_cli):
    runner, config = configured_cli
    config.accounts["oauth"] = AccountConfig(
        provider="outlook",
        email="person@outlook.com",
        auth="oauth",
        client_id="client-id",
    )
    config.save()
    with (
        patch("nothx.cli.questionary.select") as select,
        patch("nothx.cli.msauth.delete_token") as delete,
    ):
        select.return_value.ask.side_effect = ["oauth", "yes"]
        result = runner.invoke(account_remove, [])
    assert result.exit_code == 0
    delete.assert_called_once_with("person@outlook.com")


def test_dry_run_performs_neither_block_nor_unsubscribe(configured_cli):
    runner, config = configured_cli
    config.unsubscribe_consent_version = CURRENT_UNSUBSCRIBE_CONSENT_VERSION
    config.mailbox_mutation_consent_version = CURRENT_MAILBOX_MUTATION_CONSENT_VERSION
    config.save()
    scan_result, classifications = _subscription_scan(Action.BLOCK)
    engine = MagicMock()
    engine.classify_batch.return_value = classifications
    with (
        patch("nothx.cli.scan_inbox", return_value=scan_result),
        patch("nothx.cli.ClassificationEngine", return_value=engine),
        patch("nothx.cli._block_subscription") as block,
        patch("nothx.cli.unsubscribe_subscription") as unsubscribe,
    ):
        result = runner.invoke(run, ["--dry-run", "--auto"])
    assert result.exit_code == 0
    block.assert_not_called()
    unsubscribe.assert_not_called()


def test_confirm_auto_performs_zero_mutations(configured_cli):
    runner, config = configured_cli
    config.operation_mode = "confirm"
    config.unsubscribe_consent_version = CURRENT_UNSUBSCRIBE_CONSENT_VERSION
    config.mailbox_mutation_consent_version = CURRENT_MAILBOX_MUTATION_CONSENT_VERSION
    config.save()
    scan_result, classifications = _subscription_scan(Action.BLOCK)
    engine = MagicMock()
    engine.classify_batch.return_value = classifications
    with (
        patch("nothx.cli.scan_inbox", return_value=scan_result),
        patch("nothx.cli.ClassificationEngine", return_value=engine),
        patch("nothx.cli._block_subscription") as block,
        patch("nothx.cli.unsubscribe_subscription") as unsubscribe,
    ):
        result = runner.invoke(run, ["--auto"])
    assert result.exit_code == 0
    assert "skipping network and mailbox actions" in result.output
    block.assert_not_called()
    unsubscribe.assert_not_called()


def test_block_path_never_calls_unsubscribe(configured_cli):
    runner, config = configured_cli
    config.mailbox_mutation_consent_version = CURRENT_MAILBOX_MUTATION_CONSENT_VERSION
    config.save()
    scan_result, classifications = _subscription_scan(Action.BLOCK)
    engine = MagicMock()
    engine.classify_batch.return_value = classifications
    with (
        patch("nothx.cli.scan_inbox", return_value=scan_result),
        patch("nothx.cli.ClassificationEngine", return_value=engine),
        patch("nothx.cli._block_subscription", return_value=(1, 0)) as block,
        patch("nothx.cli.unsubscribe_subscription") as unsubscribe,
    ):
        result = runner.invoke(run, ["--auto"])
    assert result.exit_code == 0
    block.assert_called_once()
    unsubscribe.assert_not_called()


def test_mixed_authentication_cli_policy_does_not_poison_subscription(configured_cli):
    runner, config = configured_cli
    config.mailbox_mutation_consent_version = CURRENT_MAILBOX_MUTATION_CONSENT_VERSION
    config.save()
    scan_result, classifications = _subscription_scan(Action.BLOCK)
    key = next(iter(scan_result.subscription_stats))
    sender = scan_result.subscription_stats[key]
    sender.authenticated_emails = 3
    sender.authentication_failed_emails = 1
    classifications[key] = Classification(
        email_type=EmailType.MARKETING,
        action=Action.BLOCK,
        confidence=0.99,
        reasoning="AI treated fail-dominant aggregate booleans as spam",
        source="ai",
    )
    engine = MagicMock()
    engine.classify_batch.return_value = classifications

    with (
        patch("nothx.cli.scan_inbox", return_value=scan_result),
        patch("nothx.cli.ClassificationEngine", return_value=engine),
        patch("nothx.cli._block_subscription") as block,
        patch("nothx.cli.unsubscribe_subscription") as unsubscribe,
    ):
        result = runner.invoke(run, ["--auto"])

    assert result.exit_code == 0
    block.assert_not_called()
    unsubscribe.assert_not_called()


def test_preclaimed_operation_prevents_duplicate_network_execution(configured_cli):
    runner, config = configured_cli
    config.unsubscribe_consent_version = CURRENT_UNSUBSCRIBE_CONSENT_VERSION
    config.save()
    scan_result, classifications = _subscription_scan(Action.UNSUB)
    key = next(iter(scan_result.subscription_emails))
    sender = scan_result.subscription_stats[key]
    headers = scan_result.subscription_emails[key]
    classification = classifications[key]
    subscription, messages = _persist_subscription_records(sender, headers, classification)
    operation, acquired = db.claim_unsubscribe_operation(
        subscription["id"],
        _operation_key("unsubscribe", sender, headers),
        "other-live-process",
        trigger_message_ref_id=messages[0][1]["id"],
    )
    assert acquired is True

    engine = MagicMock()
    engine.classify_batch.return_value = classifications
    with (
        patch("nothx.cli.scan_inbox", return_value=scan_result),
        patch("nothx.cli.ClassificationEngine", return_value=engine),
        patch("nothx.cli.unsubscribe_subscription") as unsubscribe,
    ):
        result = runner.invoke(run, ["--auto"])

    assert result.exit_code == 0
    unsubscribe.assert_not_called()
    assert db.get_unsubscribe_operation(operation["id"])["outcome"] is None


def test_preclaimed_block_operation_prevents_duplicate_mailbox_execution(configured_cli):
    _runner, config = configured_cli
    scan_result, classifications = _subscription_scan(Action.BLOCK)
    key = next(iter(scan_result.subscription_emails))
    sender = scan_result.subscription_stats[key]
    headers = scan_result.subscription_emails[key]
    classification = classifications[key]
    subscription, messages = _persist_subscription_records(
        sender,
        headers,
        classification,
        policy_action="block",
    )
    operation, acquired = db.claim_unsubscribe_operation(
        subscription["id"],
        _operation_key("block", sender, headers),
        "other-live-process",
        kind="block",
        trigger_message_ref_id=messages[0][1]["id"],
    )
    assert acquired is True

    with patch("nothx.cli.IMAPConnection") as connection:
        result = _block_subscription(config, sender, headers, classification)

    assert result == (0, 0)
    connection.assert_not_called()
    assert db.get_unsubscribe_operation(operation["id"])["outcome"] is None


def test_nonretryable_partial_mailbox_action_is_not_copied_again(configured_cli):
    _runner, config = configured_cli
    scan_result, classifications = _subscription_scan(Action.BLOCK)
    key = next(iter(scan_result.subscription_emails))
    headers = scan_result.subscription_emails[key]
    sender = scan_result.subscription_stats[key]
    classification = classifications[key]
    locator = headers[0].message_ref
    assert locator is not None

    junk = MailboxInfo("Junk", "Junk", attributes=(r"\Junk",))
    connection = MagicMock()
    connection.__enter__.return_value = connection
    connection.__exit__.return_value = False
    connection.conn = MagicMock()
    connection.discover_mailboxes.return_value = MailboxDiscovery(
        mailboxes=(junk,),
        inbox=None,
        junk=junk,
        junk_candidates=(junk,),
    )
    connection.move_message_to_junk.return_value = MailboxActionResult(
        MailboxActionOutcome.PARTIAL,
        locator,
        junk.wire_name,
        retryable=False,
        error="copied but source remains",
    )

    with (
        patch("nothx.cli.IMAPConnection", return_value=connection),
        patch("nothx.cli.validate_uid_locator", return_value=UIDValidation(True, 44, True)),
    ):
        assert _block_subscription(config, sender, headers, classification) == (0, 1)
        assert _block_subscription(config, sender, headers, classification) == (0, 1)

    assert connection.move_message_to_junk.call_count == 1
    actions = db.list_mailbox_actions()
    assert len(actions) == 1
    assert actions[0]["outcome"] == "partial"
    assert actions[0]["retryable"] == 0

    with (
        patch("nothx.cli.IMAPConnection", return_value=connection),
        patch("nothx.cli.validate_uid_locator", return_value=UIDValidation(False, 99, False)),
    ):
        assert _block_subscription(config, sender, headers, classification) == (0, 1)
    assert db.list_mailbox_actions()[0]["outcome"] == "partial"

    with (
        patch("nothx.cli.IMAPConnection", return_value=connection),
        patch("nothx.cli.validate_uid_locator", side_effect=imaplib.IMAP4.abort("disconnected")),
    ):
        assert _block_subscription(config, sender, headers, classification) == (0, 1)
    assert db.list_mailbox_actions()[0]["outcome"] == "partial"

    with (
        patch("nothx.cli.IMAPConnection", return_value=connection),
        patch(
            "nothx.cli.validate_uid_locator",
            return_value=UIDValidation(False, 44, False, exact_search_completed=True),
        ) as validate,
    ):
        assert _block_subscription(config, sender, headers, classification) == (1, 0)
    assert validate.call_args.kwargs["readonly"] is True
    assert connection.move_message_to_junk.call_count == 1
    assert db.list_mailbox_actions()[0]["outcome"] == "not_found"


def test_block_moves_only_inbox_refs_in_the_approved_scan(configured_cli):
    _runner, config = configured_cli
    scan_result, classifications = _subscription_scan(Action.BLOCK)
    key = next(iter(scan_result.subscription_emails))
    headers = scan_result.subscription_emails[key]
    sender = scan_result.subscription_stats[key]
    classification = classifications[key]
    subscription, _messages = _persist_subscription_records(sender, headers, classification)
    db.upsert_message_ref(
        subscription["id"],
        "user@example.com",
        "INBOX",
        "inbox",
        44,
        100,
        message_id="<older@example>",
        received_at=datetime(2026, 6, 30, tzinfo=UTC),
    )

    junk = MailboxInfo("Junk", "Junk", attributes=(r"\Junk",))
    connection = MagicMock()
    connection.__enter__.return_value = connection
    connection.__exit__.return_value = False
    connection.conn = MagicMock()
    connection.discover_mailboxes.return_value = MailboxDiscovery(
        mailboxes=(junk,),
        inbox=None,
        junk=junk,
        junk_candidates=(junk,),
    )
    connection.move_message_to_junk.side_effect = lambda locator, target: MailboxActionResult(
        MailboxActionOutcome.MOVED,
        locator,
        target.wire_name,
        source_removed=True,
    )

    with patch("nothx.cli.IMAPConnection", return_value=connection):
        moved, failed = _block_subscription(config, sender, headers, classification)

    assert (moved, failed) == (1, 0)
    moved_uids = {call.args[0].uid for call in connection.move_message_to_junk.call_args_list}
    assert moved_uids == {101}
    assert {row["outcome"] for row in db.list_mailbox_actions()} == {"moved"}


def test_missing_unsubscribe_consent_makes_no_network_call(configured_cli):
    runner, config = configured_cli
    config.unsubscribe_consent_version = CONSENT_REVOKED
    config.save()
    scan_result, classifications = _subscription_scan(Action.UNSUB)
    engine = MagicMock()
    engine.classify_batch.return_value = classifications
    with (
        patch("nothx.cli.scan_inbox", return_value=scan_result),
        patch("nothx.cli.ClassificationEngine", return_value=engine),
        patch("nothx.cli.unsubscribe_subscription") as unsubscribe,
    ):
        result = runner.invoke(run, ["--auto"])
    assert result.exit_code == 0
    assert "consent is missing" in result.output
    unsubscribe.assert_not_called()
    sender = next(iter(scan_result.subscription_stats.values()))
    subscription = db.get_subscription(
        account=sender.account_key,
        identity_kind=sender.identity_kind,
        identity_value=sender.identity_value,
    )
    assert subscription is not None
    assert subscription["policy_action"] == "review"
    assert subscription["last_outcome"] == "needs_user"
    operations = db.list_unsubscribe_operations(subscription_id=subscription["id"])
    assert operations[0]["error_code"] == "unsubscribe_consent_required"


def test_granting_consent_resumes_only_consent_blocked_unsubscribe(configured_cli):
    runner, config = configured_cli
    config.unsubscribe_consent_version = CONSENT_REVOKED
    config.save()
    scan_result, classifications = _subscription_scan(Action.UNSUB)
    engine = MagicMock()
    engine.classify_batch.return_value = classifications
    with (
        patch("nothx.cli.scan_inbox", return_value=scan_result),
        patch("nothx.cli.ClassificationEngine", return_value=engine),
        patch("nothx.cli.unsubscribe_subscription") as unsubscribe,
    ):
        first = runner.invoke(run, ["--auto"])
        assert first.exit_code == 0
        unsubscribe.assert_not_called()

        config.unsubscribe_consent_version = CURRENT_UNSUBSCRIBE_CONSENT_VERSION
        config.save()
        unsubscribe.return_value = UnsubResult(
            success=True,
            method=UnsubMethod.GET,
            outcome=UnsubscribeOutcome.REQUESTED,
        )
        second = runner.invoke(run, ["--auto"])

    assert second.exit_code == 0
    unsubscribe.assert_called_once()
    sender = next(iter(scan_result.subscription_stats.values()))
    subscription = db.get_subscription(
        account=sender.account_key,
        identity_kind=sender.identity_kind,
        identity_value=sender.identity_value,
    )
    assert subscription is not None
    assert subscription["policy_action"] == "unsub"
    assert subscription["last_outcome"] == "requested"


def test_ordinary_review_is_persisted_by_account_and_list(configured_cli):
    runner, _config = configured_cli
    scan_result, classifications = _subscription_scan(Action.REVIEW)
    engine = MagicMock()
    engine.classify_batch.return_value = classifications
    with (
        patch("nothx.cli.scan_inbox", return_value=scan_result),
        patch("nothx.cli.ClassificationEngine", return_value=engine),
    ):
        result = runner.invoke(run, ["--auto"])

    assert result.exit_code == 0
    sender = next(iter(scan_result.subscription_stats.values()))
    subscription = db.get_subscription(
        account=sender.account_key,
        identity_kind=sender.identity_kind,
        identity_value=sender.identity_value,
    )
    assert subscription is not None
    assert subscription["policy_action"] == "review"
    assert db.list_subscriptions(policy_action="review") == [subscription]


def test_missing_mailbox_consent_still_persists_future_block_policy(configured_cli):
    runner, config = configured_cli
    config.mailbox_mutation_consent_version = CONSENT_REVOKED
    config.save()
    scan_result, classifications = _subscription_scan(Action.BLOCK)
    engine = MagicMock()
    engine.classify_batch.return_value = classifications
    with (
        patch("nothx.cli.scan_inbox", return_value=scan_result),
        patch("nothx.cli.ClassificationEngine", return_value=engine),
        patch("nothx.cli._block_subscription") as block,
        patch("nothx.cli.unsubscribe_subscription") as unsubscribe,
    ):
        result = runner.invoke(run, ["--auto"])
    assert result.exit_code == 0
    block.assert_not_called()
    unsubscribe.assert_not_called()
    sender = next(iter(scan_result.subscription_stats.values()))
    subscription = db.get_subscription(
        account=sender.account_key,
        identity_kind=sender.identity_kind,
        identity_value=sender.identity_value,
    )
    assert subscription["policy_action"] == "block"
    assert subscription["last_outcome"] == "needs_user"


def test_provider_junk_overrides_explicit_unsubscribe_rule(configured_cli):
    runner, config = configured_cli
    config.unsubscribe_consent_version = CURRENT_UNSUBSCRIBE_CONSENT_VERSION
    config.mailbox_mutation_consent_version = CURRENT_MAILBOX_MUTATION_CONSENT_VERSION
    config.save()
    scan_result, classifications = _subscription_scan(Action.UNSUB)
    sender = next(iter(scan_result.subscription_stats.values()))
    sender.junk_keyword_emails = 1
    sender.clean_inbox_emails = 0
    engine = MagicMock()
    engine.classify_batch.return_value = classifications
    with (
        patch("nothx.cli.scan_inbox", return_value=scan_result),
        patch("nothx.cli.ClassificationEngine", return_value=engine),
        patch("nothx.cli._block_subscription", return_value=(1, 0)) as block,
        patch("nothx.cli.unsubscribe_subscription") as unsubscribe,
    ):
        result = runner.invoke(run, ["--auto"])
    assert result.exit_code == 0
    block.assert_called_once()
    unsubscribe.assert_not_called()


def test_provider_policy_block_is_not_deferred_for_one_message(configured_cli):
    runner, config = configured_cli
    config.mailbox_mutation_consent_version = CURRENT_MAILBOX_MUTATION_CONSENT_VERSION
    config.save()
    scan_result, classifications = _subscription_scan(Action.BLOCK)
    sender = next(iter(scan_result.subscription_stats.values()))
    sender.total_emails = 1
    classification = next(iter(classifications.values()))
    classification.source = "provider_policy"
    engine = MagicMock()
    engine.classify_batch.return_value = classifications
    with (
        patch("nothx.cli.scan_inbox", return_value=scan_result),
        patch("nothx.cli.ClassificationEngine", return_value=engine),
        patch("nothx.cli._block_subscription", return_value=(1, 0)) as block,
        patch("nothx.cli.unsubscribe_subscription") as unsubscribe,
    ):
        result = runner.invoke(run, ["--auto"])
    assert result.exit_code == 0
    block.assert_called_once()
    unsubscribe.assert_not_called()


def test_active_unsubscribe_policy_cannot_be_reclassified_to_keep(configured_cli):
    runner, config = configured_cli
    config.unsubscribe_consent_version = CURRENT_UNSUBSCRIBE_CONSENT_VERSION
    config.save()
    scan_result, classifications = _subscription_scan(Action.KEEP)
    for classification in classifications.values():
        classification.source = "heuristics"
    sender = next(iter(scan_result.subscription_stats.values()))
    db.upsert_subscription(
        sender.account_key,
        sender.identity_kind,
        sender.identity_value,
        list_id=sender.identity_value,
        sender_domain=sender.domain,
        policy_action="unsub",
    )
    engine = MagicMock()
    engine.classify_batch.return_value = classifications
    accepted = UnsubResult(
        success=True,
        method=UnsubMethod.GET,
        outcome=UnsubscribeOutcome.REQUESTED,
    )
    with (
        patch("nothx.cli.scan_inbox", return_value=scan_result),
        patch("nothx.cli.ClassificationEngine", return_value=engine),
        patch("nothx.cli.unsubscribe_subscription", return_value=accepted) as unsubscribe,
        patch("nothx.cli._record_unsubscribe_result") as record,
    ):
        result = runner.invoke(run, ["--auto"])

    assert result.exit_code == 0
    unsubscribe.assert_called_once()
    record.assert_called_once()


def test_persisted_junk_and_fresh_inbox_evidence_require_review(configured_cli):
    runner, config = configured_cli
    config.unsubscribe_consent_version = CURRENT_UNSUBSCRIBE_CONSENT_VERSION
    config.mailbox_mutation_consent_version = CURRENT_MAILBOX_MUTATION_CONSENT_VERSION
    config.save()
    scan_result, classifications = _subscription_scan(Action.UNSUB)
    sender = next(iter(scan_result.subscription_stats.values()))
    subscription = db.upsert_subscription(
        sender.account_key,
        sender.identity_kind,
        sender.identity_value,
        list_id=sender.identity_value,
        sender_domain=sender.domain,
        policy_action="unsub",
    )
    db.upsert_message_ref(
        subscription["id"],
        sender.account_key,
        "[Gmail]/Spam",
        "junk",
        77,
        88,
        flags=["$Junk"],
    )
    engine = MagicMock()
    engine.classify_batch.return_value = classifications

    with (
        patch("nothx.cli.scan_inbox", return_value=scan_result),
        patch("nothx.cli.ClassificationEngine", return_value=engine),
        patch("nothx.cli._block_subscription", return_value=(1, 0)) as block,
        patch("nothx.cli.unsubscribe_subscription") as unsubscribe,
    ):
        result = runner.invoke(run, ["--auto"])

    assert result.exit_code == 0
    block.assert_not_called()
    unsubscribe.assert_not_called()
    assert db.get_subscription(subscription["id"])["policy_action"] == "review"


def test_persistence_uses_promoted_scanner_identity(configured_cli):
    _runner, _config = configured_cli
    header = EmailHeader(
        sender="news@sender.example",
        subject="News",
        date=datetime(2026, 7, 1, tzinfo=UTC),
        message_id="<promoted@example>",
        account_key="user@example.com",
        mailbox_name="INBOX",
        mailbox_role="inbox",
        uidvalidity=9,
        uid=10,
    )
    sender = SenderStats(
        domain="sender.example",
        total_emails=1,
        account_key="user@example.com",
        identity_kind="list_id",
        identity_value="promoted.sender.example",
    )
    classification = Classification(
        email_type=EmailType.NEWSLETTER,
        action=Action.KEEP,
        confidence=0.9,
        reasoning="fixture",
        source="user_rule",
    )
    subscription, _messages = _persist_subscription_records(sender, [header], classification)
    assert subscription["identity_kind"] == "list_id"
    assert subscription["identity_value"] == "promoted.sender.example"
    assert subscription["ai_email_type"] is None
    assert subscription["ai_recommended_action"] is None


def test_persistence_uses_server_received_time_not_forged_date(configured_cli):
    _runner, _config = configured_cli
    received_at = datetime(2026, 6, 30, 12, tzinfo=UTC)
    forged_date = datetime(2099, 1, 1, tzinfo=UTC)
    header = EmailHeader(
        sender="news@sender.example",
        subject="News",
        date=forged_date,
        received_at=received_at,
        message_id="<received-at@example>",
        account_key="user@example.com",
        mailbox_name="INBOX",
        mailbox_role="inbox",
        uidvalidity=9,
        uid=11,
    )
    sender = SenderStats(
        domain="sender.example",
        total_emails=1,
        account_key="user@example.com",
        identity_kind="from",
        identity_value="news@sender.example",
    )
    classification = Classification(
        email_type=EmailType.NEWSLETTER,
        action=Action.KEEP,
        confidence=0.9,
        reasoning="fixture",
        source="user_rule",
    )

    subscription, messages = _persist_subscription_records(sender, [header], classification)

    assert datetime.fromisoformat(subscription["last_delivery_at"]) == received_at
    assert datetime.fromisoformat(messages[0][1]["received_at"]) == received_at


def _lifecycle_subscription(
    *, outcome: str, retry_generation: int, delivery_offset_hours: int
) -> dict:
    now = datetime.now(UTC)
    subscription = db.upsert_subscription(
        "user@example.com",
        "list_id",
        f"lifecycle-{outcome}-{retry_generation}.example",
        last_delivery_at=now + timedelta(hours=delivery_offset_hours),
    )
    initial_outcome = "requested" if outcome == "verified_quiet" else outcome
    operation = db.get_or_create_unsubscribe_operation(
        subscription["id"],
        f"fixture-{outcome}-{retry_generation}",
        outcome=initial_outcome,
        retry_generation=retry_generation,
        requested_at=now - timedelta(hours=72),
        grace_until=now - timedelta(hours=24),
        started_at=now,
    )
    db.record_unsubscribe_attempt(
        operation["id"],
        "fixture-endpoint",
        method="get",
        outcome="accepted" if initial_outcome == "requested" else "permanent_failure",
        endpoint_fingerprint="a" * 64,
        destination_redacted="https://sender.example/unsubscribe",
        attempted_at=now,
    )
    if outcome == "verified_quiet":
        db.update_unsubscribe_operation_outcome(operation["id"], "verified_quiet", verified_at=now)
        db.upsert_subscription(
            "user@example.com",
            "list_id",
            f"lifecycle-{outcome}-{retry_generation}.example",
            last_delivery_at=now + timedelta(hours=delivery_offset_hours),
        )
    return db.get_subscription(subscription["id"])


def test_verified_quiet_reopens_once_for_truly_new_delivery(configured_cli):
    _runner, _config = configured_cli
    subscription = _lifecycle_subscription(
        outcome="verified_quiet", retry_generation=0, delivery_offset_hours=2
    )
    execute, exclusions, generation, escalate = _unsubscribe_operation_plan(subscription)
    assert execute is True
    assert generation == 1
    assert "a" * 64 in exclusions
    assert escalate is False


def test_failed_endpoint_is_not_replayed_for_same_source(configured_cli):
    _runner, _config = configured_cli
    subscription = _lifecycle_subscription(
        outcome="failed", retry_generation=0, delivery_offset_hours=-2
    )
    execute, exclusions, _generation, escalate = _unsubscribe_operation_plan(subscription)
    assert execute is False
    assert "a" * 64 in exclusions
    assert escalate is False


def test_generation_one_failure_escalates_instead_of_looping(configured_cli):
    _runner, _config = configured_cli
    subscription = _lifecycle_subscription(
        outcome="failed", retry_generation=1, delivery_offset_hours=2
    )
    execute, _exclusions, generation, escalate = _unsubscribe_operation_plan(subscription)
    assert execute is False
    assert generation == 1
    assert escalate is True


def test_generation_one_with_only_old_endpoint_blocks_without_network(configured_cli):
    runner, config = configured_cli
    config.unsubscribe_consent_version = CURRENT_UNSUBSCRIBE_CONSENT_VERSION
    config.save()
    scan_result, classifications = _subscription_scan(Action.UNSUB)
    key = next(iter(scan_result.subscription_emails))
    header = scan_result.subscription_emails[key][0]
    target = "https://sender.example/unsubscribe?token=already-tried"
    header.list_unsubscribe = f"<{target}>"
    header.keywords = ("$canunsubscribe",)
    sender = scan_result.subscription_stats[key]
    classification = classifications[key]
    subscription, messages = _persist_subscription_records(sender, [header], classification)
    initial = db.get_or_create_unsubscribe_operation(
        subscription["id"],
        "accepted-generation-zero",
        kind="unsubscribe",
        trigger_message_ref_id=messages[0][1]["id"],
        retry_generation=0,
    )
    fingerprint = hashlib.sha256(target.encode()).hexdigest()
    db.record_unsubscribe_attempt(
        initial["id"],
        "accepted-endpoint",
        method="get",
        outcome="accepted",
        endpoint_fingerprint=fingerprint,
    )
    db.update_unsubscribe_operation_outcome(initial["id"], "requested")
    db.update_unsubscribe_operation_outcome(initial["id"], "ineffective")

    engine = MagicMock()
    engine.classify_batch.return_value = classifications
    with (
        patch("nothx.cli.scan_inbox", return_value=scan_result),
        patch("nothx.cli.ClassificationEngine", return_value=engine),
        patch("nothx.unsubscriber._execute_get") as execute_get,
    ):
        result = runner.invoke(run, ["--auto"])

    assert result.exit_code == 0
    execute_get.assert_not_called()
    refreshed = db.get_subscription(subscription["id"])
    assert refreshed["policy_action"] == "block"
    operations = db.list_unsubscribe_operations(subscription_id=subscription["id"])
    assert any(
        operation["kind"] == "unsubscribe"
        and operation["retry_generation"] == 1
        and operation["outcome"] == "failed"
        for operation in operations
    )
    assert any(operation["kind"] == "block" for operation in operations)


def test_needs_user_remains_manual_even_after_new_delivery(configured_cli):
    _runner, _config = configured_cli
    subscription = _lifecycle_subscription(
        outcome="needs_user", retry_generation=0, delivery_offset_hours=2
    )
    execute, _exclusions, _generation, escalate = _unsubscribe_operation_plan(subscription)
    assert execute is False
    assert escalate is False


def test_requested_is_never_replayed_before_complete_scan_reconciliation(configured_cli):
    _runner, _config = configured_cli
    subscription = _lifecycle_subscription(
        outcome="requested", retry_generation=0, delivery_offset_hours=2
    )
    execute, _exclusions, _generation, escalate = _unsubscribe_operation_plan(subscription)
    assert execute is False
    assert escalate is False


def test_reconciliation_respects_selected_account_scope(configured_cli):
    _runner, config = configured_cli
    with patch("nothx.cli.db.list_operations_due_for_verification", return_value=[]) as due:
        _reconcile_due_operations(config, accounts={"B@example.com", "a@example.com"})

    assert [call.kwargs for call in due.call_args_list] == [
        {"account": "a@example.com"},
        {"account": "b@example.com"},
    ]


def test_second_post_grace_delivery_waits_for_classification_and_approval(
    configured_cli,
):
    _runner, config = configured_cli
    config.mailbox_mutation_consent_version = CURRENT_MAILBOX_MUTATION_CONSENT_VERSION
    config.save()
    now = datetime.now(UTC)
    grace = now - timedelta(hours=24)
    subscription = db.upsert_subscription(
        "user@example.com",
        "list_id",
        "repeat-offender.sender.example",
        sender_domain="sender.example",
        last_delivery_at=now - timedelta(hours=1),
    )
    db.upsert_message_ref(
        subscription["id"],
        "user@example.com",
        "INBOX",
        "inbox",
        44,
        80,
        received_at=now - timedelta(hours=1),
    )
    operation = db.get_or_create_unsubscribe_operation(
        subscription["id"],
        "second-request",
        outcome="requested",
        retry_generation=1,
        requested_at=now - timedelta(hours=72),
        grace_until=grace,
    )
    db.advance_mailbox_cursor(
        "user@example.com",
        "INBOX",
        "inbox",
        44,
        80,
        scan_complete=True,
        scanned_at=now,
    )

    with patch(
        "nothx.cli._move_persisted_subscription_to_junk",
        return_value=(1, 0),
    ) as move:
        _reconcile_due_operations(config)

    assert db.get_unsubscribe_operation(operation["id"])["outcome"] == "ineffective"
    assert db.get_subscription(subscription["id"])["policy_action"] != "block"
    move.assert_not_called()


def test_failure_detail_redaction_removes_query_and_mailto_tokens():
    detail = "failed https://sender.example/u?token=secret and mailto:user@example.com?body=opaque"
    redacted = _redact_failure_detail(detail)
    assert redacted is not None
    assert "secret" not in redacted
    assert "opaque" not in redacted
    assert "user@example.com" not in redacted


def test_manual_page_open_rescans_and_never_prints_token(configured_cli):
    runner, config = configured_cli
    config.unsubscribe_consent_version = CURRENT_UNSUBSCRIBE_CONSENT_VERSION
    config.save()
    scan_result, _classifications = _subscription_scan(Action.REVIEW)
    key = next(iter(scan_result.subscription_emails))
    header = scan_result.subscription_emails[key][0]
    header.list_unsubscribe = (
        "<https://sender.example/unsubscribe?recipient=user%40example.com&token=secret>"
    )
    sender = scan_result.subscription_stats[key]
    subscription = db.upsert_subscription(
        sender.account_key,
        sender.identity_kind,
        sender.identity_value,
        list_id=sender.identity_value,
        last_delivery_at=header.date,
    )
    with (
        patch(
            "nothx.resolution.refresh_sources",
            return_value=(sender, scan_result.subscription_emails[key]),
        ) as scan,
        patch("nothx.cli.webbrowser.open", return_value=True) as browser,
    ):
        result = runner.invoke(
            open_unsubscribe,
            [str(subscription["id"]), "--yes"],
        )
    assert result.exit_code == 0
    assert "secret" not in result.output
    assert "recipient=" not in result.output
    assert redacted_url(header.list_unsubscribe_targets[0]) in result.output
    assert "sender.example" not in result.output
    scan.assert_called_once()
    browser.assert_called_once_with(header.list_unsubscribe_targets[0])


def test_manual_domain_unsubscribe_without_consent_makes_no_contact(configured_cli):
    _runner, config = configured_cli
    config.unsubscribe_consent_version = CONSENT_REVOKED
    sender = {"domain": "sender.example"}
    with (
        patch("nothx.scanner.get_emails_for_domain") as fetch_headers,
        patch("nothx.cli.unsubscribe_subscription") as unsubscribe_call,
    ):
        result = _attempt_unsubscribe_for_domain(config, "sender.example", sender)

    assert result.outcome is UnsubscribeOutcome.NEEDS_USER
    assert result.needs_confirmation
    fetch_headers.assert_not_called()
    unsubscribe_call.assert_not_called()


def test_manual_domain_unsubscribe_refuses_junk_before_executor(configured_cli):
    _runner, config = configured_cli
    config.unsubscribe_consent_version = CURRENT_UNSUBSCRIBE_CONSENT_VERSION
    scan_result, _classifications = _subscription_scan(Action.REVIEW)
    item = next(iter(scan_result.subscription_emails.values()))[0]
    item.keywords = ("$Junk",)
    with (
        patch("nothx.scanner.get_emails_for_domain", return_value=[item]),
        patch("nothx.cli.unsubscribe_subscription") as unsubscribe_call,
    ):
        result = _attempt_unsubscribe_for_domain(
            config,
            "sender.example",
            {"domain": "sender.example"},
        )

    assert result.outcome is UnsubscribeOutcome.BLOCKED
    unsubscribe_call.assert_not_called()


def test_manual_domain_unsubscribe_refuses_persisted_block_before_rescan(configured_cli):
    _runner, config = configured_cli
    config.unsubscribe_consent_version = CURRENT_UNSUBSCRIBE_CONSENT_VERSION
    subscription = db.upsert_subscription(
        "user@example.com",
        "list_id",
        "blocked.sender.example",
        sender_domain="sender.example",
        policy_action="block",
    )
    db.upsert_message_ref(
        subscription["id"],
        "user@example.com",
        "Junk",
        "junk",
        44,
        92,
        provider_verdict="phishing",
    )

    with (
        patch("nothx.scanner.get_emails_for_domain") as fetch_headers,
        patch("nothx.cli.unsubscribe_subscription") as unsubscribe_call,
    ):
        result = _attempt_unsubscribe_for_domain(
            config,
            "sender.example",
            {"domain": "sender.example"},
        )

    assert result.outcome is UnsubscribeOutcome.BLOCKED
    fetch_headers.assert_not_called()
    unsubscribe_call.assert_not_called()


def test_manual_domain_request_is_authoritative_and_not_replayed(configured_cli):
    _runner, config = configured_cli
    config.unsubscribe_consent_version = CURRENT_UNSUBSCRIBE_CONSENT_VERSION
    scan_result, _classifications = _subscription_scan(Action.REVIEW)
    item = next(iter(scan_result.subscription_emails.values()))[0]
    accepted = UnsubResult(
        True,
        UnsubMethod.GET,
        outcome=UnsubscribeOutcome.REQUESTED,
    )

    with (
        patch("nothx.scanner.get_emails_for_domain", return_value=[item]),
        patch(
            "nothx.cli.unsubscribe_subscription",
            return_value=accepted,
        ) as unsubscribe_call,
    ):
        first = _attempt_unsubscribe_for_domain(
            config,
            item.domain,
            {"domain": item.domain},
        )
        second = _attempt_unsubscribe_for_domain(
            config,
            item.domain,
            {"domain": item.domain},
        )

    assert first.outcome is UnsubscribeOutcome.REQUESTED
    assert second.outcome is UnsubscribeOutcome.NEEDS_USER
    unsubscribe_call.assert_called_once()
    subscriptions = db.list_subscriptions(account="user@example.com")
    assert len(subscriptions) == 1
    assert subscriptions[0]["last_outcome"] == "requested"
    assert subscriptions[0]["policy_action"] == "unsub"
    operations = db.list_unsubscribe_operations(subscription_id=subscriptions[0]["id"])
    assert len(operations) == 1
    assert operations[0]["outcome"] == "requested"


def test_manual_domain_rescan_resolves_account_alias_without_duplicate_identity(configured_cli):
    _runner, config = configured_cli
    config.unsubscribe_consent_version = CURRENT_UNSUBSCRIBE_CONSENT_VERSION
    config.accounts["work"] = AccountConfig(
        provider="gmail",
        email="work@example.com",
        password="secret",
    )
    scan_result, _classifications = _subscription_scan(Action.REVIEW)
    item = next(iter(scan_result.subscription_emails.values()))[0]
    item.account_key = ""
    item.account_name = "default"
    subscription = db.upsert_subscription(
        "user@example.com",
        "list_id",
        item.normalized_list_id,
        list_id=item.normalized_list_id,
        sender_domain=item.domain,
        policy_action="unsub",
    )
    operation = db.get_or_create_unsubscribe_operation(
        subscription["id"],
        "accepted-before-compatibility-rescan",
        kind="unsubscribe",
    )
    db.update_unsubscribe_operation_outcome(operation["id"], "requested")

    with (
        patch("nothx.scanner.get_emails_for_domain", return_value=[item]),
        patch("nothx.cli.unsubscribe_subscription") as unsubscribe_call,
    ):
        result = _attempt_unsubscribe_for_domain(
            config,
            item.domain,
            {"domain": item.domain},
        )

    assert result.outcome is UnsubscribeOutcome.NEEDS_USER
    unsubscribe_call.assert_not_called()
    subscriptions = db.list_subscriptions()
    assert len(subscriptions) == 1
    assert subscriptions[0]["account"] == "user@example.com"


def test_open_unsubscribe_requires_current_contact_consent(configured_cli):
    runner, config = configured_cli
    config.unsubscribe_consent_version = CONSENT_REVOKED
    config.save()
    subscription = db.upsert_subscription(
        "user@example.com",
        "list_id",
        "consent-open.sender.example",
        policy_action="review",
    )
    with (
        patch("nothx.cli.scan_inbox") as scan,
        patch("nothx.cli.webbrowser.open") as browser,
    ):
        result = runner.invoke(open_unsubscribe, [str(subscription["id"]), "--yes"])

    assert result.exit_code == 0
    assert "consent is required" in " ".join(result.output.split())
    scan.assert_not_called()
    browser.assert_not_called()


def test_open_unsubscribe_refuses_auth_failed_rescan(configured_cli):
    runner, config = configured_cli
    config.unsubscribe_consent_version = CURRENT_UNSUBSCRIBE_CONSENT_VERSION
    config.save()
    scan_result, _classifications = _subscription_scan(Action.REVIEW)
    key = next(iter(scan_result.subscription_emails))
    item = scan_result.subscription_emails[key][0]
    item.dkim_pass = False
    sender = scan_result.subscription_stats[key]
    subscription = db.upsert_subscription(
        sender.account_key,
        sender.identity_kind,
        sender.identity_value,
        list_id=sender.identity_value,
        last_delivery_at=item.date,
    )
    with (
        patch(
            "nothx.resolution.refresh_sources",
            return_value=(sender, scan_result.subscription_emails[key]),
        ) as scan,
        patch("nothx.cli.webbrowser.open") as browser,
    ):
        result = runner.invoke(open_unsubscribe, [str(subscription["id"]), "--yes"])

    assert result.exit_code == 0
    assert "does not permit contacting" in " ".join(result.output.split())
    scan.assert_called_once()
    browser.assert_not_called()


def test_legacy_history_and_export_redact_old_raw_urls(configured_cli):
    runner, _config = configured_cli
    db.log_unsub_attempt(
        "sender.example",
        False,
        UnsubMethod.GET,
        error="failed https://sender.example/u?token=old-secret",
    )
    result = runner.invoke(history, ["--json"])
    assert result.exit_code == 0
    assert "old-secret" not in result.output
    assert "sender.example/u" not in result.output

    with tempfile.NamedTemporaryFile(suffix=".csv") as destination:
        result = runner.invoke(export, ["history", "--output", destination.name])
        assert result.exit_code == 0
        exported = Path(destination.name).read_text()
    assert "old-secret" not in exported
    assert "sender.example/u" not in exported


def test_review_lists_account_scoped_manual_subscription(configured_cli):
    runner, _config = configured_cli
    subscription = db.upsert_subscription(
        "user@example.com",
        "list_id",
        "manual.sender.example",
        policy_action="review",
    )
    with patch("nothx.cli.questionary.select") as select:
        select.return_value.ask.side_effect = [f"row:{subscription['id']}", "skip"]
        result = runner.invoke(review, [])
    assert result.exit_code == 0
    assert "user@example.com" in result.output
    assert "list_id:manual.sender.example" in result.output
    assert str(subscription["id"]) in result.output


def test_manual_review_block_applies_to_persisted_subscription(configured_cli):
    runner, config = configured_cli
    config.mailbox_mutation_consent_version = CURRENT_MAILBOX_MUTATION_CONSENT_VERSION
    config.save()
    subscription = db.upsert_subscription(
        "user@example.com",
        "list_id",
        "manual-block.sender.example",
        sender_domain="sender.example",
        policy_action="review",
    )
    db.upsert_message_ref(
        subscription["id"],
        "user@example.com",
        "INBOX",
        "inbox",
        44,
        90,
    )
    with (
        patch("nothx.cli.questionary.select") as select,
        patch(
            "nothx.cli._move_persisted_subscription_to_junk",
            return_value=(1, 0),
        ) as move,
    ):
        select.return_value.ask.side_effect = [f"row:{subscription['id']}", "block"]
        result = runner.invoke(review, [])

    assert result.exit_code == 0
    move.assert_called_once()
    assert db.get_subscription(subscription["id"])["policy_action"] == "block"


def test_open_unsubscribe_refuses_blocked_or_junk_subscription(configured_cli):
    runner, _config = configured_cli
    blocked = db.upsert_subscription(
        "user@example.com",
        "list_id",
        "blocked-open.sender.example",
        policy_action="block",
    )
    junk = db.upsert_subscription(
        "user@example.com",
        "list_id",
        "junk-open.sender.example",
        policy_action="review",
    )
    db.upsert_message_ref(
        junk["id"],
        "user@example.com",
        "Junk",
        "junk",
        44,
        91,
        flags=["$Phishing"],
    )

    with (
        patch("nothx.cli.scan_inbox") as scan,
        patch("nothx.cli.webbrowser.open") as browser,
    ):
        blocked_result = runner.invoke(open_unsubscribe, [str(blocked["id"]), "--yes"])
        junk_result = runner.invoke(open_unsubscribe, [str(junk["id"]), "--yes"])

    assert blocked_result.exit_code == 0
    assert junk_result.exit_code == 0
    assert "will not contact" in " ".join(blocked_result.output.split())
    assert "will not contact" in " ".join(junk_result.output.split())
    scan.assert_not_called()
    browser.assert_not_called()


def test_undo_updates_authoritative_future_policy(configured_cli):
    runner, _config = configured_cli
    subscription = db.upsert_subscription(
        "user@example.com",
        "list_id",
        "blocked.sender.example",
        sender_domain="sender.example",
        policy_action="block",
    )
    result = runner.invoke(undo, ["sender.example"])
    assert result.exit_code == 0
    assert db.get_subscription(subscription["id"])["policy_action"] == "keep"


class TestConsentParkedBlockDrain:
    """Blocks parked behind a missing consent must be drainable, not re-asked."""

    def _park_block(self, identity: str = "spam.example.com") -> dict:
        subscription = db.upsert_subscription(
            "user@example.com",
            "list_id",
            identity,
            from_address=f"noreply@{identity}",
            sender_domain=identity,
        )
        db.set_subscription_policy(subscription["id"], "block")
        operation = db.get_or_create_unsubscribe_operation(
            subscription["id"], f"block-consent-v1-{identity}", kind="block"
        )
        db.update_unsubscribe_operation_outcome(
            operation["id"],
            "needs_user",
            error_code="mailbox_consent_required",
        )
        return subscription

    def test_apply_pending_drains_rows_with_no_messages(self, configured_cli):
        """The common case: mail is long gone, so no IMAP traffic is needed."""
        runner, config = configured_cli
        for index in range(3):
            self._park_block(f"spam{index}.example.com")
        config.mailbox_mutation_consent_version = CURRENT_MAILBOX_MUTATION_CONSENT_VERSION
        config.save()

        result = runner.invoke(review, ["--apply-pending"])

        assert result.exit_code == 0, result.output
        assert "Applied 3 queued block(s)" in result.output
        assert db.count_consent_parked_blocks() == 0

    def test_apply_pending_refuses_without_consent(self, configured_cli):
        runner, config = configured_cli
        self._park_block()
        config.mailbox_mutation_consent_version = CONSENT_REVOKED
        config.save()

        result = runner.invoke(review, ["--apply-pending"])

        assert result.exit_code == 0, result.output
        assert "mailbox-action consent is missing" in result.output
        assert db.count_consent_parked_blocks() == 1

    def test_apply_pending_with_empty_queue(self, configured_cli):
        runner, _config = configured_cli

        result = runner.invoke(review, ["--apply-pending"])

        assert result.exit_code == 0, result.output
        assert "No queued block decisions" in result.output

    def test_granting_consent_drains_the_queue(self, configured_cli):
        runner, config = configured_cli
        self._park_block()
        config.mailbox_mutation_consent_version = CONSENT_REVOKED
        config.save()

        result = runner.invoke(consent, ["--mailbox-actions", "--yes"])

        assert result.exit_code == 0, result.output
        assert "Applied 1 queued block(s)" in result.output
        assert db.count_consent_parked_blocks() == 0

    def test_review_does_not_prompt_for_parked_blocks(self, configured_cli):
        """Parked rows are reported as queued work, never as a question."""
        runner, config = configured_cli
        self._park_block()
        config.mailbox_mutation_consent_version = CURRENT_MAILBOX_MUTATION_CONSENT_VERSION
        config.save()

        result = runner.invoke(review, [])

        assert result.exit_code == 0, result.output
        assert "need manual action" not in result.output
        assert "nothx review --apply-pending" in result.output


def test_invalid_sender_warning_is_visible_without_false_success(configured_cli):
    runner, _config = configured_cli
    empty = ScanResult({}, {}, {}, {}, skipped_invalid_senders=2)
    with patch("nothx.cli.scan_inbox", return_value=empty):
        result = runner.invoke(run, ["--dry-run", "--auto"])
    assert result.exit_code == 0
    assert "Left 2 messages" in result.output
    assert "inspect them in your mail app" in " ".join(result.output.split())
    assert "No marketing emails found" not in result.output


def test_persisted_folder_conflict_is_reviewed_and_never_contacted(configured_cli):
    from nothx.cli import _persisted_threat_action, _subscription_has_persisted_threat

    runner, _config = configured_cli
    scan, classifications = _subscription_scan(Action.UNSUB)
    key, stats = next(iter(scan.subscription_stats.items()))
    headers = scan.get_emails_for_subscription(key)
    subscription, _ = _persist_subscription_records(stats, headers, classifications[key])
    junk_header = EmailHeader(
        sender=headers[0].sender,
        subject="Offer",
        date=headers[0].date,
        message_id="<junk@example>",
        list_id=headers[0].list_id,
        account_key=headers[0].account_key,
        mailbox_name="Junk",
        mailbox_role="junk",
        uidvalidity=45,
        uid=2,
    )
    _persist_subscription_records(stats, [junk_header], classifications[key])
    assert _subscription_has_persisted_threat(subscription["id"])
    assert _persisted_threat_action(subscription["id"]) is Action.REVIEW
    with (
        patch("nothx.cli.scan_inbox", return_value=scan),
        patch("nothx.cli.ClassificationEngine.classify_batch", return_value=classifications),
        patch("nothx.cli.unsubscribe_subscription") as unsub,
        patch("nothx.cli._block_subscription") as block,
    ):
        result = runner.invoke(run, ["--auto"])
    assert result.exit_code == 0, result.output
    assert "1 marketing/spam groups need review" in result.output
    unsub.assert_not_called()
    block.assert_not_called()


def test_ai_diagnostics_explain_disabled_provider_and_pipx_recovery(configured_cli):
    from nothx.cli import test_connection

    runner, config = configured_cli
    config.ai.enabled = False
    config.ai.provider = "anthropic"
    config.save()
    with (
        patch("nothx.cli.test_account", return_value=(True, "ok")),
        patch("nothx.cli.test_ai_connection", return_value=(False, "Anthropic SDK not installed")),
    ):
        result = runner.invoke(test_connection, ["--ai"])
    assert result.exit_code == 0
    output = " ".join(result.output.split())
    assert "AI is disabled" in output
    assert "pipx inject nothx anthropic" in output
    assert "nothx test --ai" in output


@pytest.mark.parametrize("choice", [None, "skip"])
def test_manual_review_cancel_or_skip_never_falls_into_same_domain_legacy_prompt(
    configured_cli, choice
):
    runner, _config = configured_cli
    subscription = db.upsert_subscription(
        "user@example.com",
        "from",
        "notice@sender.example",
        sender_domain="sender.example",
        policy_action="review",
    )
    db.upsert_sender("sender.example", 4, 0, ["Notification"], True)
    with patch("nothx.cli.questionary.select") as select:
        select.return_value.ask.side_effect = [f"row:{subscription['id']}", choice]
        result = runner.invoke(review, [])
    assert result.exit_code == 0, result.output
    assert select.call_count == 2
    assert select.call_args.kwargs["default"] == "skip"


def test_status_uses_current_subscription_outcomes_instead_of_legacy_success(configured_cli):
    from nothx.cli import status

    runner, _config = configured_cli
    sub = db.upsert_subscription(
        "user@example.com", "from", "offers@sender.example", policy_action="unsub"
    )
    operation = db.get_or_create_unsubscribe_operation(sub["id"], "accepted-test")
    db.update_unsubscribe_operation_outcome(operation["id"], "requested")
    db.upsert_subscription(
        "user@example.com", "from", "alerts@sender.example", policy_action="review"
    )
    result = runner.invoke(status, [])
    assert result.exit_code == 0, result.output
    assert "Subscriptions" in result.output
    assert "Requested" in result.output
    assert "Pending review: 1" in result.output
    assert "Unsubbed" not in result.output
    assert db.get_subscription_stats() == {
        "total": 2,
        "kept": 0,
        "requested": 1,
        "verified_quiet": 0,
        "pending_review": 1,
    }


@pytest.mark.parametrize("policy", ["keep", "block"])
def test_explicit_policy_survives_moved_junk_and_new_inbox_delivery(configured_cli, policy):
    runner, config = configured_cli
    first_scan, initial = _subscription_scan(Action.REVIEW)
    key, stats = next(iter(first_scan.subscription_stats.items()))
    original = first_scan.get_emails_for_subscription(key)[0]
    subscription, _ = _persist_subscription_records(stats, [original], initial[key])
    db.set_subscription_policy(subscription["id"], policy)
    junk_header = EmailHeader(
        original.sender,
        "Offer",
        original.date,
        "<moved>",
        list_id=original.list_id,
        account_key=original.account_key,
        mailbox_name="Junk",
        mailbox_role="junk",
        uidvalidity=45,
        uid=2,
    )
    _persist_subscription_records(stats, [junk_header], initial[key])
    later = EmailHeader(
        original.sender,
        "Offer",
        original.date,
        "<later>",
        list_id=original.list_id,
        account_key=original.account_key,
        account_name="default",
        uidvalidity=44,
        uid=102,
    )
    new_stats = _stats_for_emails(later.domain, [later])
    scan = ScanResult(
        {later.domain: new_stats},
        {later.domain: [later]},
        {key: new_stats},
        {key: [later]},
    )
    with (
        patch("nothx.cli.scan_inbox", return_value=scan),
        patch("nothx.cli.ClassificationEngine.classify_batch", return_value=initial),
        patch("nothx.cli._block_subscription", return_value=(1, 0)) as block,
        patch("nothx.cli.unsubscribe_subscription") as unsub,
    ):
        result = runner.invoke(run, ["--auto"])
    assert result.exit_code == 0, result.output
    assert block.call_count == (1 if policy == "block" else 0)
    unsub.assert_not_called()
    stored = db.get_subscription(subscription["id"])
    assert stored["policy_action"] == policy
    assert stored["policy_source"] == "manual"


@pytest.mark.parametrize("origin", ["saved", "rule"])
def test_all_failed_deliveries_do_not_condemn_saved_clean_history(configured_cli, origin):
    runner, _config = configured_cli
    scan, classes = _subscription_scan(Action.KEEP)
    key, stats = next(iter(scan.subscription_stats.items()))
    if origin == "saved":
        sub, _ = _persist_subscription_records(
            stats, scan.get_emails_for_subscription(key), classes[key]
        )
        db.set_subscription_policy(sub["id"], "keep")
        classes[key] = Classification(
            EmailType.UNKNOWN, Action.BLOCK, 1.0, "Failed auth", "auth_policy"
        )
    stats.authenticated_emails = 0
    stats.authentication_failed_emails = 4
    stats.clean_inbox_emails = 0
    with (
        patch("nothx.cli.scan_inbox", return_value=scan),
        patch("nothx.cli.ClassificationEngine.classify_batch", return_value=classes),
        patch("nothx.cli._block_subscription", return_value=(1, 0)) as block,
        patch("nothx.cli.unsubscribe_subscription") as unsub,
    ):
        result = runner.invoke(run, ["--auto"])
    assert result.exit_code == 0, result.output
    if origin == "saved":
        block.assert_not_called()
    else:
        block.assert_called_once()
    unsub.assert_not_called()


@pytest.mark.parametrize(
    "initial_action,choice", [(Action.UNSUB, "keep"), (Action.KEEP, "keep"), (Action.KEEP, "block")]
)
def test_interactive_scan_choices_remain_manual_after_new_junk_evidence(
    configured_cli, initial_action, choice
):
    runner, _config = configured_cli
    scan, classes = _subscription_scan(initial_action)
    key, stats = next(iter(scan.subscription_stats.items()))
    original = scan.get_emails_for_subscription(key)[0]
    classes[key].source = "ai"
    if choice == "block":
        stats.has_unsubscribe = False
    with (
        patch("nothx.cli.scan_inbox", return_value=scan),
        patch("nothx.cli.ClassificationEngine.classify_batch", return_value=classes),
        patch("nothx.cli._styled_confirm", return_value=True),
        patch("nothx.cli.questionary.select") as select,
        patch("nothx.cli._move_persisted_subscription_to_junk", return_value=(1, 0)),
    ):
        select.return_value.ask.side_effect = [
            "unsub" if initial_action is Action.UNSUB else "keep",
            f"sender:{key}",
            choice,
            "finish",
        ]
        first = runner.invoke(run, [])
    assert first.exit_code == 0, first.output
    assert select.call_count == 4
    sub = db.get_subscription(
        account=stats.account_key,
        identity_kind=stats.identity_kind,
        identity_value=stats.identity_value,
    )
    assert sub["policy_action"] == choice
    assert sub["policy_source"] == "manual"
    assert sub["ai_recommended_action"] == initial_action.value
    junk = EmailHeader(
        original.sender,
        "Offer",
        original.date,
        "<moved-junk>",
        list_id=original.list_id,
        account_key=original.account_key,
        mailbox_name="Junk",
        mailbox_role="junk",
        uidvalidity=45,
        uid=2,
    )
    _persist_subscription_records(stats, [junk], classes[key])
    with (
        patch("nothx.cli.scan_inbox", return_value=scan),
        patch("nothx.cli.ClassificationEngine.classify_batch", return_value=classes),
        patch("nothx.cli._block_subscription", return_value=(1, 0)) as block,
        patch("nothx.cli.unsubscribe_subscription") as unsub,
    ):
        second = runner.invoke(run, ["--auto"])
    assert second.exit_code == 0, second.output
    assert block.call_count == (1 if choice == "block" else 0)
    unsub.assert_not_called()
    assert db.get_subscription(sub["id"])["policy_action"] == choice
    assert db.get_subscription(sub["id"])["policy_source"] == "manual"


def test_interactive_unsubscribe_retry_escalation_is_automatic_not_manual_block(configured_cli):
    runner, _config = configured_cli
    scan, classes = _subscription_scan(Action.UNSUB)
    key, stats = next(iter(scan.subscription_stats.items()))
    original = scan.get_emails_for_subscription(key)[0]
    now = datetime.now(UTC)
    original.received_at = now
    classes[key].source = "ai"
    sub, _ = _persist_subscription_records(stats, [original], classes[key])
    op = db.get_or_create_unsubscribe_operation(sub["id"], "failed-final-retry", retry_generation=1)
    db.update_unsubscribe_operation_outcome(
        op["id"], "failed", completed_at=now - timedelta(hours=1)
    )
    with (
        patch("nothx.cli.scan_inbox", return_value=scan),
        patch("nothx.cli.ClassificationEngine.classify_batch", return_value=classes),
        patch("nothx.cli._styled_confirm", return_value=True),
        patch("nothx.cli.questionary.select") as select,
        patch("nothx.cli._move_persisted_subscription_to_junk", return_value=(1, 0)) as move,
        patch("nothx.cli.unsubscribe_subscription") as unsub,
    ):
        select.return_value.ask.return_value = "finish"
        result = runner.invoke(run, [])
    assert result.exit_code == 0, result.output
    move.assert_called_once()
    unsub.assert_not_called()
    stored = db.get_subscription(sub["id"])
    assert stored["policy_action"] == "block"
    assert stored["policy_source"] == "automatic"
    assert stored["classification_source"] == "retry_policy"
    assert stored["ai_recommended_action"] == "unsub"


def test_cleanup_preview_is_full_inbox_ai_without_actions_or_saved_decisions(configured_cli):
    runner, _config = configured_cli
    scan_result, classifications = _subscription_scan(Action.UNSUB)
    with (
        patch("nothx.cli.scan_inbox", return_value=scan_result) as scan,
        patch("nothx.cli.ClassificationEngine") as engine,
        patch("nothx.cli.unsubscribe_subscription") as unsub,
        patch("nothx.cli._block_subscription") as block,
        patch("nothx.cli._reconcile_due_operations") as reconcile,
        patch("nothx.cli._persist_subscription_records") as persist,
        patch("nothx.cli.db.log_run") as log,
    ):
        engine.return_value.classify_batch.return_value = classifications
        result = runner.invoke(cleanup, ["--preview", "--details"])
    assert result.exit_code == 0, result.output
    assert scan.call_args.kwargs["full_history"] is True
    assert scan.call_args.kwargs["inbox_only"] is True
    assert scan.call_args.kwargs["persist"] is False
    options = engine.return_value.classify_batch.call_args.kwargs
    assert options["persist"] is False
    assert options["allow_ai"] is True
    assert callable(options["on_ai_progress"])
    for mutation in (unsub, block, reconcile, persist, log):
        mutation.assert_not_called()
    assert "Sale" in result.output
    assert "Preview only" in result.output


def test_normal_run_rechecks_recent_headers_unless_new_only(configured_cli):
    runner, _config = configured_cli
    with patch("nothx.cli.scan_inbox", return_value=ScanResult({}, {})) as scan:
        result = runner.invoke(run, ["--dry-run"])
        assert result.exit_code == 0
        assert scan.call_args.kwargs["rescan"] is True
        result = runner.invoke(run, ["--dry-run", "--new-only"])
        assert result.exit_code == 0
        assert scan.call_args.kwargs["rescan"] is False
        assert "No marketing emails" not in result.output


def test_coverage_shows_backlog_and_no_new_does_not_mean_clean(configured_cli):
    from nothx.scanner import MailboxCoverage

    runner, _config = configured_cli
    empty = ScanResult(
        {},
        {},
        coverage=[MailboxCoverage("default", "INBOX", "inbox", "incremental", 100, 0, 0, True)],
    )
    with patch("nothx.cli.scan_inbox", return_value=empty):
        result = runner.invoke(run, ["--dry-run", "--new-only"])
    assert result.exit_code == 0
    assert "100 Inbox messages were outside" in result.output
    assert "No marketing emails" not in result.output
    assert "incremental" in result.output


def test_outlook_reuses_client_and_keeps_signin_when_imap_unavailable(configured_cli):
    from nothx.msauth import ConsentStatus

    runner, config = configured_cli
    config.microsoft_client_id = "public-app-id"
    config.save()
    with (
        patch("nothx.cli.questionary.select") as select,
        patch("nothx.cli.questionary.text") as text_prompt,
        patch("nothx.cli.msauth.get_consent_status", return_value=ConsentStatus(True)),
        patch("nothx.cli.msauth.get_access_token", return_value="access-token"),
        patch("nothx.cli.msauth.start_device_flow") as start,
        patch("nothx.cli.msauth.delete_token") as delete,
        patch("nothx.cli.test_account", return_value=(False, "IMAP unavailable")),
    ):
        select.return_value.ask.return_value = "outlook"
        text_prompt.return_value.ask.return_value = "person@example.com"
        result = runner.invoke(account_add, [])
    assert result.exit_code == 0, result.output
    start.assert_not_called()
    delete.assert_not_called()
    assert text_prompt.call_count == 1
    account = next(
        account for account in Config.load().accounts.values() if account.provider == "outlook"
    )
    assert account.uses_oauth
    assert account.client_id == "public-app-id"
    assert "Sign-in saved, but Inbox access failed" in result.output
    assert "Let devices and apps use IMAP" in result.output


@pytest.mark.parametrize(
    "source,expected", [("automatic", "1 to unsubscribe"), ("manual", "1 to keep")]
)
def test_fresh_ai_reconsiders_automatic_keep_but_honors_manual_keep(
    configured_cli, source, expected
):
    runner, _config = configured_cli
    scan_result, classifications = _subscription_scan(Action.UNSUB)
    sender = next(iter(scan_result.subscription_stats.values()))
    classifications[sender.classification_key].source = "ai"
    subscription = db.upsert_subscription(
        sender.account_key, sender.identity_kind, sender.identity_value
    )
    db.set_subscription_policy(subscription["id"], "keep", source=source)
    with (
        patch("nothx.cli.scan_inbox", return_value=scan_result),
        patch("nothx.cli.ClassificationEngine") as engine,
    ):
        engine.return_value.classify_batch.return_value = classifications
        result = runner.invoke(run, ["--preview"])
    assert result.exit_code == 0, result.output
    assert expected in result.output
    assert db.get_subscription(subscription["id"])["policy_action"] == "keep"


@pytest.mark.parametrize("action", [Action.UNSUB, Action.BLOCK])
def test_incomplete_scan_defers_actions_even_with_explicit_rules(configured_cli, action):
    from nothx.scanner import MailboxCoverage

    runner, _config = configured_cli
    scan_result, classifications = _subscription_scan(action)
    scan_result.coverage = [
        MailboxCoverage("default", "INBOX", "inbox", "full history", 20, 20, 1, False)
    ]
    with (
        patch("nothx.cli.scan_inbox", return_value=scan_result),
        patch("nothx.cli.ClassificationEngine") as engine,
        patch("nothx.cli._reconcile_due_operations"),
        patch("nothx.cli.unsubscribe_subscription") as unsub,
        patch("nothx.cli._block_subscription") as block,
    ):
        engine.return_value.classify_batch.return_value = classifications
        result = runner.invoke(run, ["--auto"])
    assert result.exit_code == 0, result.output
    unsub.assert_not_called()
    block.assert_not_called()
    assert "Incomplete scan" in result.output
    assert "1 marketing/spam groups need review" in result.output


def test_missing_unsubscribe_method_does_not_bypass_volume_safeguard(configured_cli):
    runner, _config = configured_cli
    scan_result, classifications = _subscription_scan(Action.BLOCK)
    sender = next(iter(scan_result.subscription_stats.values()))
    sender.total_emails = 1
    classification = classifications[sender.classification_key]
    classification.source = "method_policy"
    classification.original_source = "ai"
    classification.recommended_action = Action.UNSUB
    with (
        patch("nothx.cli.scan_inbox", return_value=scan_result),
        patch("nothx.cli.ClassificationEngine") as engine,
        patch("nothx.cli._reconcile_due_operations"),
        patch("nothx.cli._block_subscription") as block,
    ):
        engine.return_value.classify_batch.return_value = classifications
        result = runner.invoke(run, ["--auto"])
    assert result.exit_code == 0, result.output
    block.assert_not_called()
    subscription = db.get_subscription(
        account=sender.account_key,
        identity_kind=sender.identity_kind,
        identity_value=sender.identity_value,
    )
    assert subscription["policy_action"] == "review"
    assert subscription["classification_source"] == "volume_policy"


def test_incomplete_scan_cannot_verify_or_escalate_existing_operations(configured_cli):
    from nothx.scanner import MailboxCoverage

    runner, _config = configured_cli
    scan_result = ScanResult(
        {},
        {},
        coverage=[MailboxCoverage("default", "INBOX", "inbox", "full history", 100, 100, 0, False)],
    )
    with (
        patch("nothx.cli.scan_inbox", return_value=scan_result),
        patch("nothx.cli._reconcile_due_operations") as reconcile,
    ):
        result = runner.invoke(run, ["--auto"])
    assert result.exit_code == 0, result.output
    assert reconcile.call_args.kwargs["accounts"] == set()


def test_fresh_inbox_evidence_conflicts_with_stored_junk_in_preview(configured_cli):
    from nothx.cli import _persisted_threat_action

    runner, _config = configured_cli
    del runner
    scan_result, _ = _subscription_scan(Action.UNSUB)
    sender = next(iter(scan_result.subscription_stats.values()))
    subscription = db.upsert_subscription(
        sender.account_key, sender.identity_kind, sender.identity_value
    )
    db.upsert_message_ref(subscription["id"], sender.account_key, "Spam", "junk", 1, 1)
    assert _persisted_threat_action(subscription["id"]) is Action.BLOCK
    assert _persisted_threat_action(subscription["id"], sender=sender) is Action.REVIEW
    sender.provider_threat = True
    assert _persisted_threat_action(subscription["id"], sender=sender) is Action.REVIEW
    sender.clean_inbox_emails = 0
    assert _persisted_threat_action(subscription["id"], sender=sender) is Action.BLOCK


def test_old_automatic_block_cannot_override_a_service_notice_guard(configured_cli):
    runner, _config = configured_cli
    scan_result, classifications = _subscription_scan(Action.REVIEW)
    sender = next(iter(scan_result.subscription_stats.values()))
    classifications[sender.classification_key].source = "transactional_policy"
    subscription = db.upsert_subscription(
        sender.account_key, sender.identity_kind, sender.identity_value
    )
    db.set_subscription_policy(subscription["id"], "block", source="automatic")
    with (
        patch("nothx.cli.scan_inbox", return_value=scan_result),
        patch("nothx.cli.ClassificationEngine") as engine,
        patch("nothx.cli._block_subscription") as block,
    ):
        engine.return_value.classify_batch.return_value = classifications
        result = runner.invoke(run, ["--preview"])
    assert result.exit_code == 0, result.output
    assert "1 marketing/spam groups need review" in result.output
    block.assert_not_called()


def test_reconnecting_revoked_microsoft_account_preserves_name_and_preferences(configured_cli):
    from nothx.errors import ErrorCode, OAuthError
    from nothx.msauth import ConsentStatus

    runner, config = configured_cli
    config.accounts["personal"] = AccountConfig(
        "outlook",
        "person@example.com",
        auth="oauth",
        client_id="public-app",
        junk_mailbox="Junk",
        extra_scan_mailboxes=["Receipts"],
    )
    config.microsoft_client_id = "public-app"
    config.save()
    revoked = OAuthError(
        code=ErrorCode.OAUTH_TOKEN_REFRESH_FAILED,
        message="Authorization expired",
        details={"error": "invalid_grant"},
    )
    with (
        patch("nothx.cli.questionary.select") as select,
        patch("nothx.cli.questionary.text") as text_prompt,
        patch("nothx.cli.msauth.get_consent_status", return_value=ConsentStatus(True)),
        patch("nothx.cli.msauth.get_access_token", side_effect=revoked),
        patch(
            "nothx.cli.msauth.start_device_flow",
            return_value={
                "verification_uri": "https://microsoft.com/devicelogin",
                "user_code": "ABCD-EFGH",
                "device_code": "device",
                "expires_in": 900,
            },
        ) as start,
        patch("nothx.cli.msauth.poll_for_token", return_value={"access_token": "new"}),
        patch("nothx.cli.msauth.save_token") as save,
        patch("nothx.cli.webbrowser.open", return_value=True),
        patch("nothx.cli.test_account", return_value=(True, "Connected")),
    ):
        select.return_value.ask.return_value = "outlook"
        text_prompt.return_value.ask.return_value = "PERSON@example.com"
        result = runner.invoke(account_add, [])
    assert result.exit_code == 0, result.output
    start.assert_called_once_with("public-app")
    save.assert_called_once()
    loaded = Config.load()
    assert set(loaded.accounts) == {"default", "personal"}
    assert loaded.accounts["personal"].junk_mailbox == "Junk"
    assert loaded.accounts["personal"].extra_scan_mailboxes == ["Receipts"]
    assert "Updated account" in result.output


def test_engaged_marketing_preference_is_saved(configured_cli):
    runner, _config = configured_cli
    assert Config.load().review_engaged_marketing is True
    result = runner.invoke(config_cmd, ["--engaged-marketing", "allow"])
    assert result.exit_code == 0, result.output
    assert Config.load().review_engaged_marketing is False
    runner.invoke(config_cmd, ["--engaged-marketing", "review"])
    assert Config.load().review_engaged_marketing is True


@pytest.mark.parametrize("threat", ["phishing", "auth_failure"])
def test_automatic_block_executor_cannot_move_clean_mail_because_of_one_threat_flag(
    configured_cli, threat
):
    from dataclasses import replace

    runner, config = configured_cli
    del runner
    scan_result, classifications = _subscription_scan(Action.BLOCK)
    sender = next(iter(scan_result.subscription_stats.values()))
    clean = next(iter(scan_result.subscription_emails.values()))[0]
    flagged = replace(clean, uid=102, keywords=("$Phishing",))
    if threat == "auth_failure":
        from nothx.models import AuthenticationEvidence, AuthResult

        flagged = replace(
            clean,
            uid=102,
            authentication=AuthenticationEvidence(
                trusted=True, spf=AuthResult.FAIL, dkim=AuthResult.FAIL, dmarc=AuthResult.FAIL
            ),
        )
    classification = classifications[sender.classification_key]
    classification.source = "provider_policy"
    with patch("nothx.cli.IMAPConnection") as connection:
        moved, failed = _block_subscription(config, sender, [clean, flagged], classification)
    assert moved == 0
    assert failed == 2
    connection.assert_not_called()
    subscription = db.list_subscriptions()[0]
    assert subscription["policy_action"] == "review"
    assert subscription["last_outcome"] == "needs_user"


def test_existing_manual_boundary_is_not_counted_as_a_new_unsubscribe(configured_cli):
    runner, _config = configured_cli
    scan_result, classifications = _subscription_scan(Action.UNSUB)
    sender = next(iter(scan_result.subscription_stats.values()))
    subscription = db.upsert_subscription(
        sender.account_key, sender.identity_kind, sender.identity_value
    )
    operation = db.get_or_create_unsubscribe_operation(subscription["id"], "manual-boundary")
    db.update_unsubscribe_operation_outcome(operation["id"], "needs_user")
    with (
        patch("nothx.cli.scan_inbox", return_value=scan_result),
        patch("nothx.cli.ClassificationEngine") as engine,
    ):
        engine.return_value.classify_batch.return_value = classifications
        result = runner.invoke(run, ["--preview"])
    assert result.exit_code == 0, result.output
    assert "0 to unsubscribe now" in result.output
    assert "1 unsubscribe requests need manual action" in result.output


@pytest.mark.parametrize("manual_keep", [False, True])
@pytest.mark.parametrize("auto", [False, True])
def test_due_retry_cannot_move_fresh_service_notice_before_approval(
    configured_cli, manual_keep, auto
):
    from nothx.scanner import MailboxCoverage

    runner, _config = configured_cli
    scan, classes = _subscription_scan(Action.REVIEW)
    scan.coverage = [MailboxCoverage("default", "INBOX", "inbox", "recent", 1, 1, 1, True)]
    key, sender = next(iter(scan.subscription_stats.items()))
    header = scan.subscription_emails[key][0]
    header.subject = "Privacy policy update"
    header.received_at = datetime.now(UTC)
    classes[key].source = "transactional_policy"
    subscription, _ = _persist_subscription_records(sender, [header], classes[key])
    if manual_keep:
        db.set_subscription_policy(subscription["id"], "keep", source="manual")
    operation = db.get_or_create_unsubscribe_operation(
        subscription["id"], "second-request", retry_generation=1, outcome="requested"
    )
    due = {
        **operation,
        "last_delivery_at": header.received_at.isoformat(),
        "grace_until": (header.received_at - timedelta(hours=1)).isoformat(),
    }
    with (
        patch("nothx.cli.scan_inbox", return_value=scan),
        patch("nothx.cli.ClassificationEngine.classify_batch", return_value=classes),
        patch("nothx.cli.db.list_operations_due_for_verification", return_value=[due]),
        patch("nothx.cli.IMAPConnection") as connection,
        patch("nothx.cli.unsubscribe_subscription") as unsubscribe,
        patch("nothx.cli._styled_confirm", return_value=False),
        patch("nothx.cli.questionary.select") as select,
    ):
        select.return_value.ask.return_value = "skip"
        result = runner.invoke(run, ["--auto"] if auto else [])
    assert result.exit_code == 0, result.output
    connection.assert_not_called()
    unsubscribe.assert_not_called()
    assert db.get_unsubscribe_operation(operation["id"])["outcome"] == "ineffective"
    assert db.get_subscription(subscription["id"])["policy_action"] != "block"


def test_open_unsubscribe_refuses_failed_source_refresh(configured_cli):
    runner, config, subscription, stats, headers = _resolve_fixture(configured_cli)
    with (
        patch("nothx.resolution.refresh_sources", side_effect=ValueError("UIDVALIDITY changed")),
        patch("nothx.cli.scan_inbox") as scan,
        patch("nothx.cli.webbrowser.open") as browser,
    ):
        result = runner.invoke(open_unsubscribe, [str(subscription["id"]), "--yes"])
    assert result.exit_code == 0, result.output
    assert "Source refresh failed" in result.output
    browser.assert_not_called()
    scan.assert_not_called()


def test_domain_contact_scan_rejects_an_interrupted_prefix(configured_cli):
    from nothx.errors import IMAPError
    from nothx.scanner import get_emails_for_domain

    _runner, config = configured_cli
    scan, _classes = _subscription_scan(Action.UNSUB)
    header = next(iter(scan.subscription_emails.values()))[0]
    connection = MagicMock()
    connection.__enter__.return_value = connection
    connection.fetch_marketing_emails.return_value = [header]
    connection.last_fetch_complete = False
    with (
        patch("nothx.scanner.IMAPConnection", return_value=connection),
        pytest.raises(IMAPError, match="incomplete"),
    ):
        get_emails_for_domain(config, header.domain)


def test_all_failed_authentication_is_not_counted_as_clean_inbox(configured_cli):
    from nothx.models import AuthenticationEvidence, AuthResult

    runner, _config = configured_cli
    scan, _classes = _subscription_scan(Action.UNSUB)
    header = next(iter(scan.subscription_emails.values()))[0]
    header.authentication = AuthenticationEvidence(
        trusted=True, spf=AuthResult.FAIL, dkim=AuthResult.FAIL, dmarc=AuthResult.FAIL
    )
    sender = _stats_for_emails(header.domain, [header])
    assert sender.clean_inbox_emails == 0
    assert sender.authentication_failed_emails == 1
    key = sender.classification_key
    scan.subscription_stats[key] = sender
    scan.sender_stats[header.domain] = sender
    _persist_subscription_records(
        sender,
        [header],
        Classification(EmailType.UNKNOWN, Action.REVIEW, 0.5, "fixture", "auth_policy"),
    )
    with (
        patch("nothx.cli.scan_inbox", return_value=scan),
        patch("nothx.cli._block_subscription", return_value=(1, 0)) as block,
        patch("nothx.cli.unsubscribe_subscription") as unsubscribe,
    ):
        result = runner.invoke(run, ["--auto"])
    assert result.exit_code == 0, result.output
    block.assert_called_once()
    unsubscribe.assert_not_called()


@pytest.mark.parametrize("has_inbox", [False, True])
def test_consent_resume_preserves_automatic_provenance_and_requires_fresh_scope(
    configured_cli, has_inbox
):
    from nothx.cli import _record_block_needs_consent

    runner, config = configured_cli
    scan, classes = _subscription_scan(Action.BLOCK)
    key, sender = next(iter(scan.subscription_stats.items()))
    classes[key].source = "ai"
    _record_block_needs_consent(sender, scan.subscription_emails[key], classes[key])
    subscription = db.get_subscription(
        account=sender.account_key,
        identity_kind=sender.identity_kind,
        identity_value=sender.identity_value,
    )
    if not has_inbox:
        with db.get_db() as connection:
            connection.execute("DELETE FROM message_refs")
    else:
        db.upsert_message_ref(
            subscription["id"],
            sender.account_key,
            "INBOX",
            "inbox",
            44,
            100,
            message_id="<old-security@example.com>",
            flags=[r"\Seen"],
        )
    config.mailbox_mutation_consent_version = CONSENT_REVOKED
    config.save()
    with patch("nothx.cli.IMAPConnection") as imap:
        result = runner.invoke(consent, ["--mailbox-actions", "--yes"])
    assert result.exit_code == 0, result.output
    imap.assert_not_called()
    stored = db.get_subscription(subscription["id"])
    assert stored["policy_source"] == "automatic"
    assert stored["policy_action"] == ("review" if has_inbox else "block")
    assert db.count_consent_parked_blocks() == 0
    if has_inbox:
        assert "Fresh classification required" in " ".join(result.output.split())
        assert "Deferred automatic block" in result.output


def test_manual_mixed_evidence_block_uses_displayed_scope_snapshot(configured_cli):
    runner, config = configured_cli
    scan, classes = _subscription_scan(Action.REVIEW)
    key, sender = next(iter(scan.subscription_stats.items()))
    classes[key].source = "provider_policy"
    header = scan.subscription_emails[key][0]
    header.keywords = ("$Phishing",)
    subscription, _ = _persist_subscription_records(
        sender, [header], classes[key], policy_action="review"
    )
    db.upsert_message_ref(
        subscription["id"],
        sender.account_key,
        "INBOX",
        "inbox",
        44,
        100,
        message_id="<old-clean@example.com>",
        flags=[r"\Seen"],
    )
    connection = MagicMock()
    connection.__enter__.return_value = connection
    connection.conn = MagicMock()
    junk = MailboxInfo("Junk", "Junk", attributes=(r"\Junk",))
    connection.discover_mailboxes.return_value = MailboxDiscovery(
        mailboxes=(junk,),
        inbox=None,
        junk=junk,
        junk_candidates=(junk,),
    )
    connection.move_message_to_junk.side_effect = lambda locator, target: MailboxActionResult(
        MailboxActionOutcome.MOVED,
        locator,
        target.wire_name,
        source_removed=True,
    )

    def approve():
        db.upsert_message_ref(
            subscription["id"],
            sender.account_key,
            "INBOX",
            "inbox",
            44,
            102,
            message_id="<arrived-after-preview@example.com>",
        )
        return "block"

    with (
        patch("nothx.cli.questionary.select") as select,
        patch("nothx.cli.IMAPConnection", return_value=connection),
    ):
        answers = iter([f"row:{subscription['id']}", None])
        select.return_value.ask.side_effect = lambda: next(answers) or approve()
        result = runner.invoke(review, [])
    assert result.exit_code == 0, result.output
    assert "Stored Inbox refs" in result.output
    assert "recorded history" in result.output
    stored = db.get_subscription(subscription["id"])
    assert (stored["policy_action"], stored["policy_source"]) == ("block", "manual")
    assert {call.args[0].uid for call in connection.move_message_to_junk.call_args_list} == {
        100,
        101,
    }
    assert "Blocked: 2 moved, 0 partial/failed" in result.output


def test_full_history_old_service_notice_blocks_stored_automatic_suppression(configured_cli):
    runner, _config = configured_cli
    scan, classes = _subscription_scan(Action.BLOCK)
    key, sender = next(iter(scan.subscription_stats.items()))
    template = scan.subscription_emails[key][0]
    from dataclasses import replace

    from nothx.models import AuthenticationEvidence, AuthResult

    headers = [
        replace(
            template,
            subject="Privacy policy update" if index == 1 else "Quick question about your company",
            date=datetime(2026, 1, index, tzinfo=UTC),
            received_at=None,
            uid=index,
            authentication=AuthenticationEvidence(
                trusted=True,
                dkim=AuthResult.PASS,
                dmarc=AuthResult.PASS,
                dkim_domains=(template.domain,),
            ),
        )
        for index in range(1, 9)
    ]
    sender = _stats_for_emails(template.domain, headers)
    scan.subscription_stats = {key: sender}
    scan.subscription_emails = {key: headers}
    subscription, _ = _persist_subscription_records(
        sender, headers, replace(classes[key], source="heuristics"), policy_action="block"
    )
    with (
        patch("nothx.cli.scan_inbox", return_value=scan),
        patch("nothx.cli.IMAPConnection") as imap,
        patch("nothx.cli.unsubscribe_subscription") as unsubscribe,
    ):
        result = runner.invoke(cleanup, ["--apply", "--auto"])
    assert result.exit_code == 0, result.output
    imap.assert_not_called()
    unsubscribe.assert_not_called()
    assert db.get_subscription(subscription["id"])["policy_action"] == "keep"
    assert "outside cleanup review" in result.output


@pytest.mark.parametrize(
    "command,args,full_history",
    [(cleanup, [], True), (cleanup, ["--apply"], True), (run, [], False)],
)
@pytest.mark.parametrize("approve", [False, True])
def test_cleanup_and_recent_review_then_act_without_rescanning(
    configured_cli, command, args, full_history, approve
):
    runner, config = configured_cli
    config.unsubscribe_consent_version = CURRENT_UNSUBSCRIBE_CONSENT_VERSION
    config.mailbox_mutation_consent_version = CURRENT_MAILBOX_MUTATION_CONSENT_VERSION
    config.save()
    result, classes = _subscription_scan(Action.BLOCK)
    with (
        patch("nothx.cli.scan_inbox", return_value=result) as scan,
        patch("nothx.cli.ClassificationEngine.classify_batch", return_value=classes) as classify,
        patch("nothx.cli._styled_confirm", return_value=approve) as confirm,
        patch("nothx.cli._block_subscription", return_value=(1, 0)) as block,
        patch("nothx.cli._reconcile_due_operations"),
        patch("nothx.cli._review_scan_decisions"),
    ):
        outcome = runner.invoke(command, args)
    assert outcome.exit_code == 0, outcome.output
    scan.assert_called_once()
    classify.assert_called_once()
    assert scan.call_args.kwargs["full_history"] is full_history
    assert scan.call_args.kwargs["persist"] is True
    assert classify.call_args.kwargs["persist"] is True
    assert "Apply 0 unsubscribe requests and 1 block policies?" in confirm.call_args.args[0]
    assert block.call_count == int(approve)
    assert "run nothx cleanup --apply" not in outcome.output.lower()


@pytest.mark.parametrize("extra", ["--apply", "--auto"])
def test_cleanup_preview_rejects_action_flags(configured_cli, extra):
    runner, _ = configured_cli
    with patch("nothx.cli.scan_inbox") as scan:
        result = runner.invoke(cleanup, ["--preview", extra])
    assert result.exit_code == 2
    scan.assert_not_called()


@pytest.mark.parametrize("phishing", [False, True])
def test_protected_invoice_is_not_auto_blocked_for_auth_failure_alone(configured_cli, phishing):
    from nothx.models import AuthenticationEvidence, AuthResult

    runner, config = configured_cli
    config.mailbox_mutation_consent_version = CURRENT_MAILBOX_MUTATION_CONSENT_VERSION
    config.save()
    scan, classes = _subscription_scan(Action.BLOCK)
    key, old = next(iter(scan.subscription_stats.items()))
    header = scan.subscription_emails[key][0]
    header.subject = "Invoice for your recent order"
    header.authentication = AuthenticationEvidence(
        trusted=True, spf=AuthResult.FAIL, dkim=AuthResult.FAIL, dmarc=AuthResult.FAIL
    )
    header.provider_threat = "phishing" if phishing else None
    sender = _stats_for_emails(header.domain, [header])
    scan.subscription_stats = {key: sender}
    classes[key] = Classification(
        EmailType.UNKNOWN, Action.BLOCK, 0.99, "Auth failed", "auth_policy"
    )
    sub, _ = _persist_subscription_records(sender, [header], classes[key], policy_action="block")
    with (
        patch("nothx.cli.scan_inbox", return_value=scan),
        patch("nothx.cli.ClassificationEngine.classify_batch", return_value=classes),
        patch("nothx.cli._block_subscription", return_value=(1, 0)) as block,
        patch("nothx.cli.unsubscribe_subscription") as unsub,
    ):
        result = runner.invoke(cleanup, ["--auto"])
    assert result.exit_code == 0, result.output
    assert block.call_count == int(phishing)
    unsub.assert_not_called()
    if not phishing:
        assert db.get_subscription(sub["id"])["policy_action"] == "keep"
        assert "outside cleanup review" in result.output


def test_personal_uncertain_mail_is_outside_cleanup_review(configured_cli):
    runner, _ = configured_cli
    scan, classes = _subscription_scan(Action.REVIEW)
    key, sender = next(iter(scan.subscription_stats.items()))
    sender.sample_subjects = ["Dinner tomorrow"]
    sender.sample_senders = ["friend@example.com"]
    sender.promotional_subject_emails = 0
    sender.promotional_sample_subjects = []
    classes[key] = Classification(
        EmailType.UNKNOWN, Action.REVIEW, 0.5, "Personal thread", "uncertain"
    )
    with (
        patch("nothx.cli.scan_inbox", return_value=scan),
        patch("nothx.cli.ClassificationEngine.classify_batch", return_value=classes),
        patch("nothx.cli._styled_confirm") as confirm,
        patch("nothx.cli.unsubscribe_subscription") as unsub,
        patch("nothx.cli._block_subscription") as block,
    ):
        result = runner.invoke(cleanup, [])
    assert result.exit_code == 0, result.output
    confirm.assert_not_called()
    unsub.assert_not_called()
    block.assert_not_called()
    assert "0 marketing/spam groups need review" in result.output
    assert "outside cleanup review" in result.output


@pytest.mark.parametrize("initial_action", [Action.KEEP, Action.REVIEW, Action.UNSUB])
def test_post_review_rechecks_incomplete_account_even_after_manual_override(
    configured_cli, initial_action
):
    from nothx.scanner import MailboxCoverage

    runner, _ = configured_cli
    scan, classes = _subscription_scan(initial_action)
    scan.coverage = [MailboxCoverage("default", "INBOX", "inbox", "full history", 20, 20, 1, False)]

    def bypass(unsub, keep, review, block, **kwargs):
        assert kwargs["incomplete_accounts"] == frozenset({"user@example.com"})
        row = next(item for group in (unsub, keep, review, block) for item in group)
        for group in (unsub, keep, review, block):
            group.clear()
        key, sender, classification = row
        from nothx.cli import _manual_classification

        block.append((key, sender, _manual_classification(classification, Action.BLOCK)))

    with (
        patch("nothx.cli.scan_inbox", return_value=scan),
        patch("nothx.cli.ClassificationEngine.classify_batch", return_value=classes),
        patch("nothx.cli._styled_confirm", return_value=True),
        patch("nothx.cli._review_scan_decisions", side_effect=bypass),
        patch("nothx.cli._block_subscription") as block,
        patch("nothx.cli.unsubscribe_subscription") as unsub,
    ):
        result = runner.invoke(cleanup, [])
    assert result.exit_code == 0, result.output
    block.assert_not_called()
    unsub.assert_not_called()


@pytest.mark.parametrize("stored_action", [Action.UNSUB, Action.BLOCK])
def test_unknown_ai_review_cannot_revive_old_automatic_destructive_policy(
    configured_cli, stored_action
):
    runner, _ = configured_cli
    scan, classes = _subscription_scan(stored_action)
    key, sender = next(iter(scan.subscription_stats.items()))
    old = classes[key]
    old.source = "ai"
    sub, _ = _persist_subscription_records(
        sender, scan.subscription_emails[key], old, policy_action=stored_action.value
    )
    classes[key] = Classification(
        EmailType.UNKNOWN,
        Action.REVIEW,
        0.99,
        "Unrecognized cached content type",
        "ai",
        recommended_action=stored_action,
        original_source="ai",
    )
    with (
        patch("nothx.cli.scan_inbox", return_value=scan),
        patch("nothx.cli.ClassificationEngine.classify_batch", return_value=classes),
        patch("nothx.cli._block_subscription") as block,
        patch("nothx.cli.unsubscribe_subscription") as unsub,
    ):
        result = runner.invoke(cleanup, ["--auto"])
    assert result.exit_code == 0, result.output
    block.assert_not_called()
    unsub.assert_not_called()
    assert db.get_subscription(sub["id"])["policy_action"] == "review"


def test_saved_review_finish_leaves_every_policy_and_mailbox_untouched(configured_cli):
    runner, _ = configured_cli
    subscriptions = [
        db.upsert_subscription(
            f"owner-{i}@example.com", "from", "offers@mail.example", policy_action="review"
        )
        for i in range(2)
    ]
    with (
        patch("nothx.cli.questionary.select") as select,
        patch("nothx.cli._apply_manual_subscription_block") as block,
        patch("nothx.cli.open_unsubscribe") as open_page,
    ):
        select.return_value.ask.return_value = "finish"
        result = runner.invoke(review, [])
    assert result.exit_code == 0, result.output
    assert select.call_count == 1
    assert all(db.get_subscription(s["id"])["policy_action"] == "review" for s in subscriptions)
    block.assert_not_called()
    open_page.assert_not_called()


@pytest.mark.parametrize("flag,policy", [("--keep", "keep"), ("--unsub", "unsub")])
def test_saved_review_filters_preserve_full_identity(configured_cli, flag, policy):
    runner, _ = configured_cli
    selected = db.upsert_subscription(
        "owner@example.com", "from", "one@mail.example", policy_action=policy
    )
    other = db.upsert_subscription(
        "other@example.com", "from", "one@mail.example", policy_action=policy
    )
    with patch("nothx.cli.questionary.select") as select:
        select.return_value.ask.side_effect = [f"row:{selected['id']}", "keep", "finish"]
        result = runner.invoke(review, [flag])
    assert result.exit_code == 0, result.output
    labels = [c.title for c in select.call_args_list[0].kwargs["choices"]]
    assert any("owner@example.com" in label and "one@mail.example" in label for label in labels)
    assert any("other@example.com" in label and "one@mail.example" in label for label in labels)
    assert db.get_subscription(selected["id"])["policy_action"] == "keep"
    assert db.get_subscription(other["id"])["policy_action"] == policy


def test_authoritative_kept_personal_domain_never_reappears_as_legacy_review(configured_cli):
    runner, _ = configured_cli
    db.upsert_subscription(
        "owner@example.com",
        "from",
        "friend@mail.example",
        sender_domain="mail.example",
        policy_action="keep",
    )
    db.upsert_sender("mail.example", 4, 0, ["Dinner tomorrow"], False)
    with patch("nothx.cli.questionary.select") as select:
        result = runner.invoke(review, [])
    assert result.exit_code == 0, result.output
    select.assert_not_called()


def test_saved_review_can_search_beyond_former_queue_cap(configured_cli):
    runner, _ = configured_cli
    rows = [
        {
            "id": i,
            "account": "owner@example.com",
            "identity_kind": "from",
            "identity_value": f"sender-{i}@mail.example",
            "policy_action": "review",
        }
        for i in reversed(range(10_001))
    ]

    def subscriptions(*, policy_action=None, limit=500, **kwargs):
        if policy_action != "review":
            return []
        return rows if limit is None else rows[:limit]

    with (
        patch("nothx.cli.db.list_subscriptions", side_effect=subscriptions),
        patch("nothx.cli.questionary.select") as select,
        patch("nothx.cli.questionary.text") as search,
    ):
        select.return_value.ask.side_effect = ["search", "row:0", "skip", "finish"]
        search.return_value.ask.return_value = "sender-0@"
        result = runner.invoke(review, [])
    assert result.exit_code == 0, result.output
    assert "10,001" in result.output
    assert "sender-0@mail.example" in result.output
    assert select.call_count == 4


def test_mixed_saved_and_legacy_store_exposes_both_without_domain_fallthrough(configured_cli):
    runner, _ = configured_cli
    modern = db.upsert_subscription(
        "owner@example.com",
        "from",
        "offer@modern.example",
        sender_domain="modern.example",
        policy_action="review",
    )
    db.upsert_sender("modern.example", 4, 0, ["Offer"], True)
    db.upsert_sender("legacy.example", 4, 0, ["Sale"], True)
    with patch("nothx.cli.questionary.select") as select:
        select.return_value.ask.side_effect = ["legacy", "row:legacy.example", "keep"]
        result = runner.invoke(review, [])
    assert result.exit_code == 0, result.output
    groups = {c.value for c in select.call_args_list[0].kwargs["choices"]}
    assert groups == {"subscriptions", "legacy", "finish"}
    legacy_values = {c.value for c in select.call_args_list[1].kwargs["choices"]}
    assert "row:legacy.example" in legacy_values
    assert "row:modern.example" not in legacy_values
    assert db.get_subscription(modern["id"])["policy_action"] == "review"
    assert db.get_sender("legacy.example")["status"] == "keep"
    with patch("nothx.cli.questionary.select") as select:
        select.return_value.ask.return_value = "finish"
        result = runner.invoke(review, ["--all"])
    assert result.exit_code == 0, result.output
    assert select.call_count == 1
    assert db.get_subscription(modern["id"])["policy_action"] == "review"


def test_mixed_service_promotions_reach_cleanup_review_without_actions(configured_cli):
    runner, _ = configured_cli
    scan, classes = _subscription_scan(Action.REVIEW)
    key, sender = next(iter(scan.subscription_stats.items()))
    sender.sample_subjects = ["Your order confirmation"] * 5
    sender.protected_subject_emails = 5
    sender.promotional_subject_emails = 1
    sender.promotional_sample_subjects = ["Use promo code Q7M4"]
    classes[key] = Classification(
        EmailType.TRANSACTIONAL, Action.REVIEW, 0.9, "Mixed service mail", "transactional_policy"
    )
    with (
        patch("nothx.cli.scan_inbox", return_value=scan),
        patch("nothx.cli.ClassificationEngine.classify_batch", return_value=classes),
        patch("nothx.cli._styled_confirm", return_value=False),
        patch("nothx.cli.unsubscribe_subscription") as unsub,
        patch("nothx.cli._block_subscription") as block,
    ):
        result = runner.invoke(cleanup, [])
    assert result.exit_code == 0, result.output
    assert "1 marketing/spam groups need review" in result.output
    assert (
        db.get_subscription(
            account=sender.account_key,
            identity_kind=sender.identity_kind,
            identity_value=sender.identity_value,
        )["policy_action"]
        == "review"
    )
    unsub.assert_not_called()
    block.assert_not_called()


def _resolve_fixture(configured_cli):
    runner, config = configured_cli
    config.unsubscribe_consent_version = CURRENT_UNSUBSCRIBE_CONSENT_VERSION
    config.save()
    scan, classes = _subscription_scan(Action.REVIEW)
    key, stats = next(iter(scan.subscription_stats.items()))
    headers = scan.subscription_emails[key]
    headers[0].list_unsubscribe = "<https://shop.example/unsubscribe?token=secret>"
    subscription, _ = _persist_subscription_records(stats, headers, classes[key])
    return runner, config, subscription, stats, headers


def test_resolve_dry_run_does_not_mutate_or_contact(configured_cli):
    from nothx.cli import resolve_subscription

    runner, config, subscription, stats, headers = _resolve_fixture(configured_cli)
    with (
        patch("nothx.resolution.refresh_sources", return_value=(stats, headers)),
        patch("nothx.cli.unsubscribe_subscription") as send,
    ):
        result = runner.invoke(resolve_subscription, [str(subscription["id"]), "--dry-run"])
    assert result.exit_code == 0, result.output
    assert "no request sent" in result.output
    assert "secret" not in result.output
    assert db.list_unsubscribe_operations(subscription_id=subscription["id"]) == []
    send.assert_not_called()


def test_resolve_acceptance_prevents_second_request(configured_cli):
    from nothx.cli import resolve_subscription

    runner, config, subscription, stats, headers = _resolve_fixture(configured_cli)
    with (
        patch("nothx.resolution.refresh_sources", return_value=(stats, headers)) as refresh,
        patch(
            "nothx.cli.unsubscribe_subscription",
            return_value=UnsubResult(success=True, method=UnsubMethod.GET),
        ) as send,
    ):
        first = runner.invoke(resolve_subscription, [str(subscription["id"]), "--yes"])
        second = runner.invoke(resolve_subscription, [str(subscription["id"]), "--retry", "--yes"])
    assert first.exit_code == second.exit_code == 0, first.output + second.output
    assert "Request accepted" in first.output
    assert "no duplicate" in second.output
    assert send.call_count == refresh.call_count == 1
    assert db.get_subscription(subscription["id"])["last_outcome"] == "requested"


def test_resolve_retry_is_explicit_and_bounded(configured_cli):
    from nothx.cli import resolve_subscription

    runner, config, subscription, stats, headers = _resolve_fixture(configured_cli)
    with (
        patch("nothx.resolution.refresh_sources", return_value=(stats, headers)),
        patch(
            "nothx.cli.unsubscribe_subscription",
            return_value=UnsubResult(
                success=False, method=UnsubMethod.GET, needs_confirmation=True
            ),
        ) as send,
    ):
        first = runner.invoke(resolve_subscription, [str(subscription["id"]), "--yes"])
        refused = runner.invoke(resolve_subscription, [str(subscription["id"]), "--yes"])
        retry = runner.invoke(resolve_subscription, [str(subscription["id"]), "--retry", "--yes"])
        exhausted = runner.invoke(
            resolve_subscription, [str(subscription["id"]), "--retry", "--yes"]
        )
    assert first.exit_code == retry.exit_code == 0, first.output + retry.output
    assert refused.exit_code == exhausted.exit_code == 1
    assert "exhausted" in exhausted.output
    assert send.call_count == 2


def test_resolve_records_user_confirmation_without_network(configured_cli):
    from nothx.cli import resolve_subscription

    runner, config, subscription, stats, headers = _resolve_fixture(configured_cli)
    operation = db.get_or_create_unsubscribe_operation(
        subscription["id"], "browser-case", outcome="needs_user"
    )
    with (
        patch("nothx.resolution.refresh_sources") as refresh,
        patch("nothx.cli.unsubscribe_subscription") as send,
    ):
        result = runner.invoke(
            resolve_subscription, [str(subscription["id"]), "--completed", "--yes"]
        )
    assert result.exit_code == 0, result.output
    assert db.get_subscription(subscription["id"])["last_outcome"] == "requested"
    assert db.get_unsubscribe_operation(operation["id"])["error_code"] == "user_confirmed_browser"
    send.assert_not_called()
    refresh.assert_not_called()


def test_resolve_never_retries_ambiguous_send(configured_cli):
    from nothx.cli import resolve_subscription

    runner, config, subscription, stats, headers = _resolve_fixture(configured_cli)
    operation = db.get_or_create_unsubscribe_operation(
        subscription["id"], "uncertain", outcome="needs_user"
    )
    db.record_unsubscribe_attempt(
        operation["id"],
        "smtp",
        method="mailto",
        outcome="needs_user",
        endpoint_fingerprint="a" * 64,
        ambiguous_send=True,
    )
    with (
        patch("nothx.resolution.refresh_sources") as refresh,
        patch("nothx.cli.unsubscribe_subscription") as send,
    ):
        result = runner.invoke(resolve_subscription, [str(subscription["id"]), "--retry", "--yes"])
    assert result.exit_code == 1
    assert "may have succeeded" in result.output
    refresh.assert_not_called()
    send.assert_not_called()


def test_refresh_sources_revalidates_identity_and_obeys_footer_consent(configured_cli):
    from nothx.resolution import refresh_sources

    runner, config, subscription, stats, headers = _resolve_fixture(configured_cli)
    config.footer_scan_enabled = False
    with patch("nothx.resolution.IMAPConnection") as connection:
        conn = connection.return_value.__enter__.return_value
        conn.fetch_header.return_value = headers[0]
        refreshed_stats, refreshed = refresh_sources(config, subscription)
        assert refreshed[0].uid == 101
        conn.fetch_footer_candidates.assert_not_called()
        headers[0].message_id = "<different@example>"
        with pytest.raises(ValueError, match="identity changed"):
            refresh_sources(config, subscription)


def test_resolve_mixed_sender_requires_source_and_preserves_policy(configured_cli):
    from dataclasses import replace

    from nothx.cli import resolve_subscription

    runner, config = configured_cli
    config.unsubscribe_consent_version = CURRENT_UNSUBSCRIBE_CONSENT_VERSION
    config.save()
    scan, classes = _subscription_scan(Action.REVIEW)
    key = next(iter(scan.subscription_emails))
    first = replace(
        scan.subscription_emails[key][0],
        list_id=None,
        list_unsubscribe="<https://shop.example/unsubscribe/news>",
    )
    second = replace(
        first,
        uid=102,
        message_id="<service@example>",
        subject="Service update",
        list_unsubscribe="<https://shop.example/unsubscribe/service>",
    )
    stats = _stats_for_emails(first.domain, [first, second])
    subscription, _ = _persist_subscription_records(
        stats, [first, second], classes[key], policy_action="review"
    )
    with (
        patch("nothx.resolution.refresh_sources", return_value=(stats, [first, second])),
        patch(
            "nothx.cli.unsubscribe_subscription",
            return_value=UnsubResult(success=True, method=UnsubMethod.GET),
        ) as send,
    ):
        refused = runner.invoke(resolve_subscription, [str(subscription["id"]), "--yes"])
        assert refused.exit_code == 1
        send.assert_not_called()
        selected = runner.invoke(
            resolve_subscription, [str(subscription["id"]), "--source-uid", "101", "--yes"]
        )
    assert selected.exit_code == 0, selected.output
    assert send.call_args.args[0] == [first]
    assert db.get_subscription(subscription["id"])["policy_action"] == "review"


def test_resolve_threat_and_revoked_consent_stop_before_refresh(configured_cli):
    from nothx.cli import resolve_subscription

    runner, config, subscription, stats, headers = _resolve_fixture(configured_cli)
    config.unsubscribe_consent_version = CONSENT_REVOKED
    config.save()
    with patch("nothx.resolution.refresh_sources") as refresh:
        refused = runner.invoke(resolve_subscription, [str(subscription["id"]), "--yes"])
        assert refused.exit_code == 1
        config.unsubscribe_consent_version = CURRENT_UNSUBSCRIBE_CONSENT_VERSION
        config.save()
        db.set_subscription_policy(subscription["id"], "block")
        blocked = runner.invoke(resolve_subscription, [str(subscription["id"]), "--yes"])
        assert blocked.exit_code == 1
        refresh.assert_not_called()


def test_refresh_footer_alternative_with_header_requires_trusted_bulk_and_opt_in(configured_cli):
    from nothx.models import AuthenticationEvidence, AuthResult
    from nothx.resolution import refresh_sources

    runner, config, subscription, stats, headers = _resolve_fixture(configured_cli)
    config.footer_scan_enabled = True
    headers[0].authentication = AuthenticationEvidence(trusted=True, dmarc=AuthResult.PASS)
    with patch("nothx.resolution.IMAPConnection") as connection:
        conn = connection.return_value.__enter__.return_value
        conn.fetch_header.return_value = headers[0]
        conn.fetch_footer_candidates.return_value = ()
        refresh_sources(config, subscription)
        conn.fetch_footer_candidates.assert_called_once_with(headers[0])
        conn.fetch_footer_candidates.reset_mock()
        headers[0].authentication = AuthenticationEvidence()
        refresh_sources(config, subscription)
        conn.fetch_footer_candidates.assert_not_called()


def test_review_includes_failed_unsub_decisions(configured_cli):
    runner, config, subscription, stats, headers = _resolve_fixture(configured_cli)
    db.set_subscription_policy(subscription["id"], "unsub")
    db.get_or_create_unsubscribe_operation(subscription["id"], "failed-review", outcome="failed")
    with patch("nothx.cli._pick_saved_reviews", return_value=[]) as picker:
        result = runner.invoke(review, [])
    assert result.exit_code == 0, result.output
    assert str(subscription["id"]) in [value for value, label in picker.call_args.args[0]]


def test_browser_never_downgrades_one_click_post_to_get(configured_cli):
    runner, config, subscription, stats, headers = _resolve_fixture(configured_cli)
    headers[0].list_unsubscribe_post = "List-Unsubscribe=One-Click"
    headers[0].list_unsubscribe_count = 1
    headers[0].list_unsubscribe_post_count = 1
    with (
        patch("nothx.resolution.refresh_sources", return_value=(stats, headers)) as scan_call,
        patch("nothx.cli.webbrowser.open") as browser,
    ):
        result = runner.invoke(open_unsubscribe, [str(subscription["id"]), "--yes"])
    assert result.exit_code == 0, result.output
    browser.assert_not_called()
    scan_call.assert_called_once_with(config, subscription)


@pytest.mark.parametrize("already_attempted", [False, True])
def test_resolve_no_eligible_method_does_not_consume_retry(configured_cli, already_attempted):
    from nothx.cli import resolve_subscription

    runner, config, subscription, stats, headers = _resolve_fixture(configured_cli)
    operation = db.get_or_create_unsubscribe_operation(
        subscription["id"], "old-failure", outcome="failed"
    )
    if already_attempted:
        target = headers[0].list_unsubscribe_targets[0]
        db.record_unsubscribe_attempt(
            operation["id"],
            "old-target",
            method="get",
            outcome="permanent_failure",
            endpoint_fingerprint=hashlib.sha256(target.encode()).hexdigest(),
        )
    else:
        headers[0].list_unsubscribe = "<http://shop.example/insecure>"
    with (
        patch("nothx.resolution.refresh_sources", return_value=(stats, headers)),
        patch("nothx.cli.unsubscribe_subscription") as send,
    ):
        result = runner.invoke(resolve_subscription, [str(subscription["id"]), "--retry", "--yes"])
    assert result.exit_code == 0, result.output
    assert "No eligible untried method" in result.output
    send.assert_not_called()
    assert len(db.list_unsubscribe_operations(subscription_id=subscription["id"])) == 1
    assert db.get_subscription(subscription["id"])["retry_count"] == 0


def test_mixed_sender_requires_choice_even_with_only_one_candidate(configured_cli):
    from dataclasses import replace

    from nothx.cli import resolve_subscription

    runner, config, subscription, old_stats, headers = _resolve_fixture(configured_cli)
    first = replace(
        headers[0], list_id=None, list_unsubscribe=None, uid=201, message_id="<newsletter@example>"
    )
    service = replace(
        first,
        uid=102,
        message_id="<service@example>",
        subject="Service notice",
        list_unsubscribe="<https://shop.example/service-settings>",
    )
    stats = _stats_for_emails(first.domain, [first, service])
    classification = Classification(EmailType.MARKETING, Action.REVIEW, 1.0, "Mixed", "heuristic")
    mixed, _ = _persist_subscription_records(stats, [first, service], classification)
    with (
        patch("nothx.resolution.refresh_sources", return_value=(stats, [first, service])),
        patch("nothx.cli.unsubscribe_subscription") as send,
    ):
        result = runner.invoke(resolve_subscription, [str(mixed["id"]), "--yes"])
    assert result.exit_code == 1
    assert "--source-uid" in result.output
    send.assert_not_called()


@pytest.mark.parametrize("duplicate", [True, False])
def test_browser_excludes_malformed_declared_post_targets(configured_cli, duplicate):
    runner, config, subscription, stats, headers = _resolve_fixture(configured_cli)
    headers[0].list_unsubscribe_post = "List-Unsubscribe=One-Click"
    headers[0].list_unsubscribe_post_count = 1
    if duplicate:
        headers[0].list_unsubscribe_count = 2
    else:
        headers[0].list_unsubscribe = "<https://shop.example/a>, <https://shop.example/b>"
        headers[0].list_unsubscribe_count = 1
    with (
        patch("nothx.resolution.refresh_sources", return_value=(stats, headers)),
        patch("nothx.cli.webbrowser.open") as browser,
    ):
        result = runner.invoke(open_unsubscribe, [str(subscription["id"]), "--yes"])
    assert result.exit_code == 0, result.output
    browser.assert_not_called()


@pytest.mark.parametrize("error_code", ["unsubscribe_consent_required", "authentication_unknown"])
def test_resolve_no_contact_boundary_preserves_retry_budget(configured_cli, error_code):
    from nothx.cli import resolve_subscription

    runner, config, subscription, stats, headers = _resolve_fixture(configured_cli)
    op = db.get_or_create_unsubscribe_operation(subscription["id"], "parked")
    db.update_unsubscribe_operation_outcome(op["id"], "needs_user", error_code=error_code)
    db.record_unsubscribe_attempt(
        op["id"], "policy", method="none", outcome="needs_user", endpoint_fingerprint="a" * 64
    )
    with (
        patch("nothx.resolution.refresh_sources", return_value=(stats, headers)),
        patch(
            "nothx.cli.unsubscribe_subscription",
            return_value=UnsubResult(success=True, method=UnsubMethod.GET),
        ),
    ):
        result = runner.invoke(resolve_subscription, [str(subscription["id"]), "--yes"])
    assert result.exit_code == 0, result.output
    assert "Request accepted" in result.output
    saved = db.get_subscription(subscription["id"])
    assert saved["retry_count"] == 0
    latest = db.list_unsubscribe_operations(subscription_id=subscription["id"])[0]
    assert latest["retry_generation"] == 0
    db.update_unsubscribe_operation_outcome(latest["id"], "ineffective")
    execute, _, generation, escalate = _unsubscribe_operation_plan(
        db.get_subscription(subscription["id"])
    )
    assert execute and generation == 1 and not escalate


def test_browser_confirmation_serializes_with_live_claim(configured_cli):
    runner, config, subscription, stats, headers = _resolve_fixture(configured_cli)
    db.get_or_create_unsubscribe_operation(subscription["id"], "manual", outcome="needs_user")
    pending, acquired = db.claim_unsubscribe_operation(
        subscription["id"], "retry", "worker", retry_generation=1
    )
    assert acquired
    with pytest.raises(ValueError, match="unresolved"):
        db.acknowledge_browser_confirmation(subscription["id"])
    assert db.get_unsubscribe_operation(pending["id"])["outcome"] is None
    assert not db.list_unsubscribe_attempts(pending["id"])


def test_browser_first_confirmation_creates_scoped_audit(configured_cli):
    runner, config, subscription, stats, headers = _resolve_fixture(configured_cli)
    operation = db.acknowledge_browser_confirmation(subscription["id"])
    assert operation["outcome"] == "requested"
    assert operation["verification_scope"] == "source"
    assert (
        db.list_unsubscribe_attempts(operation["id"])[0]["error_code"] == "user_confirmed_browser"
    )
    assert db.acknowledge_browser_confirmation(subscription["id"])["id"] == operation["id"]
    assert len(db.list_unsubscribe_attempts(operation["id"])) == 1


def test_acknowledged_ambiguity_allows_an_alternate_endpoint(configured_cli):
    from nothx.cli import resolve_subscription

    runner, config, subscription, stats, headers = _resolve_fixture(configured_cli)
    op = db.get_or_create_unsubscribe_operation(
        subscription["id"], "ambiguous", outcome="needs_user"
    )
    db.record_unsubscribe_attempt(
        op["id"],
        "ambiguous",
        method="get",
        outcome="needs_user",
        endpoint_fingerprint="b" * 64,
        ambiguous_send=True,
    )
    db.acknowledge_browser_confirmation(subscription["id"])
    db.update_unsubscribe_operation_outcome(op["id"], "ineffective")
    with (
        patch("nothx.resolution.refresh_sources", return_value=(stats, headers)),
        patch(
            "nothx.cli.unsubscribe_subscription",
            return_value=UnsubResult(success=True, method=UnsubMethod.GET),
        ) as send,
    ):
        result = runner.invoke(resolve_subscription, [str(subscription["id"]), "--retry", "--yes"])
    assert result.exit_code == 0, result.output
    assert "Request accepted" in result.output
    assert "b" * 64 in send.call_args.kwargs["exclude_fingerprints"]


def test_source_request_is_not_verified_against_service_delivery(configured_cli):
    from dataclasses import replace

    from nothx.cli import resolve_subscription

    runner, config, old, stats, headers = _resolve_fixture(configured_cli)
    header = replace(headers[0], list_id=None, uid=202)
    identity = header.subscription_identity
    stats = _stats_for_emails(header.domain, [header], identity)
    subscription, _ = _persist_subscription_records(
        stats,
        [header],
        Classification(EmailType.MARKETING, Action.REVIEW, 0.9, "review", "heuristics"),
    )
    with (
        patch("nothx.resolution.refresh_sources", return_value=(stats, [header])),
        patch(
            "nothx.cli.unsubscribe_subscription",
            return_value=UnsubResult(success=True, method=UnsubMethod.GET),
        ),
    ):
        result = runner.invoke(
            resolve_subscription, [str(subscription["id"]), "--source-uid", "202", "--yes"]
        )
    assert result.exit_code == 0, result.output
    op = db.list_unsubscribe_operations(subscription_id=subscription["id"])[0]
    assert op["verification_scope"] == "source"
    assert not db.list_operations_due_for_verification(
        as_of=datetime.now(UTC) + timedelta(days=5), require_complete_scan=False
    )
    assert db.get_subscription(subscription["id"])["policy_action"] != "unsub"


def test_resolve_list_excludes_aliased_service_source(configured_cli):
    from dataclasses import replace

    from nothx.cli import resolve_subscription

    runner, config, subscription, stats, headers = _resolve_fixture(configured_cli)
    service = replace(headers[0], uid=202, list_id=None, subject="Account notice")
    with (
        patch("nothx.resolution.refresh_sources", return_value=(stats, [service, *headers])),
        patch(
            "nothx.cli.unsubscribe_subscription",
            return_value=UnsubResult(success=True, method=UnsubMethod.GET),
        ) as send,
    ):
        result = runner.invoke(resolve_subscription, [str(subscription["id"]), "--yes"])
    assert result.exit_code == 0, result.output
    assert [h.uid for h in send.call_args.args[0]] == [101]


def test_refresh_alias_without_promotion_and_missing_message_id(configured_cli):
    from dataclasses import replace

    from nothx.resolution import refresh_sources

    runner, config, subscription, stats, headers = _resolve_fixture(configured_cli)
    alias = replace(headers[0], uid=202, list_id=None, message_id="")
    db.upsert_message_ref(
        subscription["id"],
        alias.account_key,
        alias.mailbox_name,
        "inbox",
        alias.uidvalidity,
        alias.uid,
        from_address=alias.sender_address,
        message_id=None,
    )
    assert subscription["promoted_from_kind"] is None
    with patch("nothx.resolution.IMAPConnection") as connection:
        conn = connection.return_value.__enter__.return_value
        conn.fetch_header.side_effect = lambda locator: alias if locator.uid == 202 else headers[0]
        _, found = refresh_sources(config, subscription)
    assert {h.uid for h in found} == {101, 202}


def test_refresh_prioritizes_old_promotion_and_can_target_an_older_uid(configured_cli):
    from dataclasses import replace

    from nothx.resolution import refresh_sources

    runner, config, subscription, stats, headers = _resolve_fixture(configured_cli)
    original = headers[0]
    for uid in range(1, 61):
        db.upsert_message_ref(
            subscription["id"],
            original.account_key,
            original.mailbox_name,
            "inbox",
            original.uidvalidity,
            uid,
            message_id=original.message_id,
            from_address=original.sender_address,
            list_id=original.normalized_list_id,
            received_at=datetime.now(UTC) - timedelta(days=61 - uid),
            promotional=uid == 1,
        )
    with patch("nothx.resolution.IMAPConnection") as connection:
        conn = connection.return_value.__enter__.return_value
        conn.fetch_header.side_effect = lambda locator: replace(original, uid=locator.uid)
        _, found = refresh_sources(config, subscription)
        assert 1 in {h.uid for h in found}
        assert len(found) == 50
        _, found = refresh_sources(config, subscription, source_uid=2)
        assert [h.uid for h in found] == [2]


def test_review_continues_after_resolve_refusal(configured_cli):
    import click

    runner, config, subscription, stats, headers = _resolve_fixture(configured_cli)
    db.set_subscription_policy(subscription["id"], "review")
    other = db.upsert_subscription(
        "user@example.com", "from", "other@example.com", policy_action="review"
    )
    with (
        patch(
            "nothx.cli._pick_saved_reviews",
            return_value=[str(subscription["id"]), str(other["id"])],
        ),
        patch("nothx.cli.questionary.select") as select,
        patch(
            "nothx.cli.resolve_subscription.callback",
            side_effect=click.ClickException("Retry exhausted"),
        ),
    ):
        select.return_value.ask.side_effect = ["resolve", "keep"]
        result = runner.invoke(review, [])
    assert result.exit_code == 0, result.output
    assert "Retry exhausted" in result.output
    assert db.get_subscription(other["id"])["policy_action"] == "keep"


def test_resolve_exhausted_dry_run_reports_real_execution_limit(configured_cli):
    from nothx.cli import resolve_subscription

    runner, config, subscription, stats, headers = _resolve_fixture(configured_cli)
    op = db.get_or_create_unsubscribe_operation(
        subscription["id"], "spent", outcome="failed", retry_generation=1
    )
    db.record_unsubscribe_attempt(
        op["id"], "get", method="get", outcome="permanent_failure", endpoint_fingerprint="c" * 64
    )
    with patch("nothx.resolution.refresh_sources", return_value=(stats, headers)):
        result = runner.invoke(resolve_subscription, [str(subscription["id"]), "--dry-run"])
    assert result.exit_code == 0, result.output
    assert "Retry exhausted" in result.output
    assert len(db.list_unsubscribe_operations(subscription_id=subscription["id"])) == 1


def test_browser_confirmation_can_renew_an_ineffective_request(configured_cli):
    runner, config, subscription, stats, headers = _resolve_fixture(configured_cli)
    old = datetime.now(UTC) - timedelta(days=5)
    op = db.get_or_create_unsubscribe_operation(
        subscription["id"], "old", outcome="requested", requested_at=old
    )
    db.update_unsubscribe_operation_outcome(op["id"], "ineffective")
    acknowledged = db.acknowledge_browser_confirmation(subscription["id"])
    assert acknowledged["outcome"] == "requested"
    assert datetime.fromisoformat(acknowledged["grace_until"]) > datetime.now(UTC)


def test_parked_generation_one_can_resume_its_unspent_retry(configured_cli):
    from nothx.cli import resolve_subscription

    runner, config, subscription, stats, headers = _resolve_fixture(configured_cli)
    first = db.get_or_create_unsubscribe_operation(subscription["id"], "first", outcome="failed")
    db.record_unsubscribe_attempt(
        first["id"], "get", method="get", outcome="permanent_failure", endpoint_fingerprint="a" * 64
    )
    parked = db.get_or_create_unsubscribe_operation(
        subscription["id"], "parked", retry_generation=1
    )
    db.update_unsubscribe_operation_outcome(
        parked["id"], "needs_user", error_code="unsubscribe_consent_required"
    )
    with (
        patch("nothx.resolution.refresh_sources", return_value=(stats, headers)),
        patch(
            "nothx.cli.unsubscribe_subscription",
            return_value=UnsubResult(success=True, method=UnsubMethod.GET),
        ) as send,
    ):
        result = runner.invoke(resolve_subscription, [str(subscription["id"]), "--retry", "--yes"])
    assert result.exit_code == 0, result.output
    assert "Request accepted" in result.output
    send.assert_called_once()
    assert (
        db.list_unsubscribe_operations(subscription_id=subscription["id"])[0]["retry_generation"]
        == 1
    )


def test_browser_ack_keeps_existing_whole_sender_verification_scope(configured_cli):
    runner, config = configured_cli
    sub = db.upsert_subscription(
        "user@example.com", "from", "offers@example.com", policy_action="unsub"
    )
    op = db.get_or_create_unsubscribe_operation(sub["id"], "automatic", outcome="needs_user")
    acknowledged = db.acknowledge_browser_confirmation(sub["id"])
    assert acknowledged["verification_scope"] == "subscription"
    due = db.list_operations_due_for_verification(
        as_of=datetime.now(UTC) + timedelta(days=3), require_complete_scan=False
    )
    assert [item["id"] for item in due] == [op["id"]]


def test_refresh_keeps_newest_token_despite_many_old_promotions(configured_cli):
    from dataclasses import replace

    from nothx.resolution import refresh_sources

    runner, config, subscription, stats, headers = _resolve_fixture(configured_cli)
    original = headers[0]
    now = datetime.now(UTC)
    for uid in range(1, 61):
        db.upsert_message_ref(
            subscription["id"],
            original.account_key,
            original.mailbox_name,
            "inbox",
            original.uidvalidity,
            uid,
            message_id=original.message_id,
            from_address=original.sender_address,
            list_id=original.normalized_list_id,
            received_at=now - timedelta(days=61 - uid),
            promotional=uid != 60,
        )
    with patch("nothx.resolution.IMAPConnection") as connection:
        conn = connection.return_value.__enter__.return_value
        conn.fetch_header.side_effect = lambda locator: replace(
            original, uid=locator.uid, received_at=now - timedelta(days=61 - locator.uid)
        )
        _, found = refresh_sources(config, subscription)
    assert 60 in [h.uid for h in found[:3]]
    assert len(found) == 50


def test_resolve_preview_shows_older_sources_beyond_twelve_rows(configured_cli):
    from dataclasses import replace

    from nothx.cli import resolve_subscription

    runner, config, subscription, stats, headers = _resolve_fixture(configured_cli)
    sources = [replace(headers[0], uid=uid) for uid in range(1, 21)]
    with patch("nothx.resolution.refresh_sources", return_value=(stats, sources)):
        result = runner.invoke(resolve_subscription, [str(subscription["id"]), "--dry-run"])
    assert result.exit_code == 0, result.output
    assert "UID 20" in result.output


def test_accepted_request_cleans_only_approved_unprotected_locators(configured_cli):
    from dataclasses import replace

    from nothx.cli import _clean_unwanted_inbox

    _, config = configured_cli
    config.move_unwanted_to_junk = True
    scan, classes = _subscription_scan(Action.UNSUB)
    key = next(iter(classes))
    header = scan.subscription_emails[key][0]
    protected = replace(header, uid=102, subject="Your order receipt")
    subscription, messages = _persist_subscription_records(
        scan.subscription_stats[key], [header, protected], classes[key], policy_action="unsub"
    )
    request, _ = db.claim_unsubscribe_operation(subscription["id"], "request", "request-owner")
    db.update_unsubscribe_operation_outcome(request["id"], "requested", claim_owner="request-owner")
    before = db.get_subscription(subscription["id"])
    junk = MailboxInfo("Junk", "Junk", attributes=(r"\Junk",))
    connection = MagicMock()
    connection.__enter__.return_value = connection
    connection.discover_mailboxes.return_value = MailboxDiscovery(
        mailboxes=(junk,), inbox=None, junk=junk, junk_candidates=(junk,)
    )
    connection.move_message_to_junk.return_value = MailboxActionResult(
        MailboxActionOutcome.MOVED, header.message_ref, junk.wire_name
    )
    with patch("nothx.cli.IMAPConnection", return_value=connection):
        assert _clean_unwanted_inbox(config, subscription, messages) == (1, 0)
        assert _clean_unwanted_inbox(config, subscription, messages) == (0, 0)
    connection.move_message_to_junk.assert_called_once_with(header.message_ref, junk)
    assert db.get_subscription(subscription["id"]) == before
    assert db.list_mailbox_actions()[0]["message_ref_id"] == messages[0][1]["id"]
    assert _unsubscribe_operation_plan(before)[0] is False


@pytest.mark.parametrize("state", ["needs_user", "failed", "no_consent", "disabled"])
def test_cleanup_keeps_unresolved_sources_and_respects_consent(configured_cli, state):
    from nothx.cli import _clean_unwanted_inbox

    _, config = configured_cli
    config.move_unwanted_to_junk = state != "disabled"
    if state == "no_consent":
        config.mailbox_mutation_consent_version = CONSENT_REVOKED
    scan, classes = _subscription_scan(Action.UNSUB)
    key = next(iter(classes))
    subscription, messages = _persist_subscription_records(
        scan.subscription_stats[key], scan.subscription_emails[key], classes[key]
    )
    operation, _ = db.claim_unsubscribe_operation(subscription["id"], "request", "owner")
    db.update_unsubscribe_operation_outcome(
        operation["id"],
        state if state in {"needs_user", "failed"} else "requested",
        claim_owner="owner",
    )
    with patch("nothx.cli.IMAPConnection") as connection:
        assert _clean_unwanted_inbox(config, subscription, messages) == (0, 0)
    connection.assert_not_called()


def test_unwanted_mail_preference_round_trips(configured_cli):
    runner, _ = configured_cli
    assert runner.invoke(config_cmd, ["--unwanted-mail", "junk"]).exit_code == 0
    assert Config.load().move_unwanted_to_junk
    assert runner.invoke(config_cmd, ["--unwanted-mail", "keep"]).exit_code == 0
    assert not Config.load().move_unwanted_to_junk


def test_scan_clears_new_delivery_without_repeating_accepted_request(configured_cli):
    from dataclasses import replace

    runner, config = configured_cli
    config.move_unwanted_to_junk = True
    config.save()
    scan, classes = _subscription_scan(Action.UNSUB)
    key = next(iter(classes))
    original = scan.subscription_emails[key][0]
    junk = MailboxInfo("Junk", "Junk", attributes=(r"\Junk",))
    connection = MagicMock()
    connection.__enter__.return_value = connection
    connection.discover_mailboxes.return_value = MailboxDiscovery(
        mailboxes=(junk,), inbox=None, junk=junk, junk_candidates=(junk,)
    )
    connection.move_message_to_junk.side_effect = lambda locator, target: MailboxActionResult(
        MailboxActionOutcome.MOVED, locator, target.wire_name
    )
    with (
        patch("nothx.cli.scan_inbox", return_value=scan),
        patch("nothx.cli.ClassificationEngine.classify_batch", return_value=classes),
        patch("nothx.cli.IMAPConnection", return_value=connection),
        patch(
            "nothx.cli.unsubscribe_subscription",
            return_value=UnsubResult(
                success=True, method=UnsubMethod.GET, outcome=UnsubscribeOutcome.REQUESTED
            ),
        ) as unsubscribe,
    ):
        first = runner.invoke(run, ["--auto"])
        assert first.exit_code == 0, first.output
        newer = replace(original, uid=103, message_id="<sale-2@example>")
        scan.subscription_emails[key] = [newer]
        second = runner.invoke(run, ["--auto"])
        assert second.exit_code == 0, second.output
    unsubscribe.assert_called_once()
    assert connection.move_message_to_junk.call_count == 2
    assert {r["outcome"] for r in db.list_mailbox_actions()} == {"moved"}
    assert len(db.list_unsubscribe_operations()) == 1
    assert db.list_subscriptions()[0]["last_outcome"] == "requested"


def test_source_acceptance_does_not_clean_other_messages(configured_cli):
    from dataclasses import replace

    from nothx.cli import _clean_unwanted_inbox

    _, config = configured_cli
    config.move_unwanted_to_junk = True
    scan, classes = _subscription_scan(Action.UNSUB)
    key = next(iter(classes))
    header = scan.subscription_emails[key][0]
    subscription, messages = _persist_subscription_records(
        scan.subscription_stats[key], [header, replace(header, uid=102)], classes[key]
    )
    operation, _ = db.claim_unsubscribe_operation(
        subscription["id"],
        "source-request",
        "owner",
        verification_scope="source",
        trigger_message_ref_id=messages[0][1]["id"],
    )
    db.update_unsubscribe_operation_outcome(operation["id"], "requested", claim_owner="owner")
    with patch("nothx.cli._move_persisted_subscription_to_junk", return_value=(1, 0)) as move:
        assert _clean_unwanted_inbox(config, subscription, messages) == (1, 0)
    assert move.call_args.kwargs["message_ids"] == {messages[0][1]["id"]}


def test_own_junk_move_is_not_provider_threat_and_does_not_hide_delivery(configured_cli):
    from dataclasses import replace

    from nothx.cli import _clean_unwanted_inbox, _persisted_threat_action

    _, config = configured_cli
    config.move_unwanted_to_junk = True
    scan, classes = _subscription_scan(Action.UNSUB)
    key = next(iter(classes))
    now = datetime.now(UTC)
    header = replace(scan.subscription_emails[key][0], date=now, received_at=now)
    sender = scan.subscription_stats[key]
    subscription, messages = _persist_subscription_records(sender, [header], classes[key])
    request, _ = db.claim_unsubscribe_operation(subscription["id"], "request", "owner")
    db.update_unsubscribe_operation_outcome(
        request["id"],
        "requested",
        requested_at=now - timedelta(days=4),
        grace_until=now - timedelta(days=2),
        claim_owner="owner",
    )
    junk = MailboxInfo("Junk", "Junk", attributes=(r"\Junk",))
    connection = MagicMock()
    connection.__enter__.return_value = connection
    connection.discover_mailboxes.return_value = MailboxDiscovery(
        mailboxes=(junk,), inbox=None, junk=junk, junk_candidates=(junk,)
    )
    connection.move_message_to_junk.return_value = MailboxActionResult(
        MailboxActionOutcome.MOVED, header.message_ref, junk.wire_name
    )
    with patch("nothx.cli.IMAPConnection", return_value=connection):
        assert _clean_unwanted_inbox(config, subscription, messages) == (1, 0)
    copied = replace(header, mailbox_name="Junk", mailbox_role="junk", uid=901, keywords=("$Junk",))
    copied.locally_cleaned = (
        db.message_cleanup_key(
            copied.account_key, copied.message_id, copied.sender_address, copied.received_at
        )
        in db.get_locally_cleaned_message_keys()
    )
    assert copied.locally_cleaned
    _persist_subscription_records(sender, [copied], classes[key])
    stats = _stats_for_emails(header.domain, [header, copied])
    assert stats.junk_emails == stats.junk_keyword_emails == 0
    assert _persisted_threat_action(subscription["id"], sender=stats) is None
    db.upsert_mailbox_state(
        header.account_key, "INBOX", "inbox", uidvalidity=44, last_uid=101, scan_complete=True
    )
    _reconcile_due_operations(config)
    assert db.get_unsubscribe_operation(request["id"])["outcome"] == "ineffective"
    copied.provider_threat = "phishing"
    _persist_subscription_records(sender, [copied], classes[key])
    assert _persisted_threat_action(subscription["id"]) is Action.REVIEW
