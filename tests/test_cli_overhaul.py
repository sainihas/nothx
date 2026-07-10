"""Focused CLI acceptance tests for account-scoped safe automation."""

from __future__ import annotations

import hashlib
import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

from nothx import db
from nothx.cli import (
    _block_subscription,
    _operation_key,
    _persist_subscription_records,
    _reconcile_due_operations,
    _redact_failure_detail,
    _unsubscribe_operation_plan,
    account_add,
    account_remove,
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
    CURRENT_MAILBOX_MUTATION_CONSENT_VERSION,
    CURRENT_UNSUBSCRIBE_CONSENT_VERSION,
    AccountConfig,
    Config,
)
from nothx.mailbox import MailboxActionResult, MailboxDiscovery
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


def test_partial_mailbox_action_is_retried_until_source_is_removed(configured_cli):
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
    connection.move_message_to_junk.side_effect = [
        MailboxActionResult(
            MailboxActionOutcome.PARTIAL,
            locator,
            junk.wire_name,
            error="copied but source remains",
        ),
        MailboxActionResult(
            MailboxActionOutcome.MOVED,
            locator,
            junk.wire_name,
            source_removed=True,
        ),
    ]

    with patch("nothx.cli.IMAPConnection", return_value=connection):
        assert _block_subscription(config, sender, headers, classification) == (0, 1)
        assert _block_subscription(config, sender, headers, classification) == (1, 0)

    assert connection.move_message_to_junk.call_count == 2
    actions = db.list_mailbox_actions()
    assert len(actions) == 1
    assert actions[0]["outcome"] == "moved"


def test_block_moves_all_persisted_inbox_refs_not_only_current_scan(configured_cli):
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

    assert (moved, failed) == (2, 0)
    moved_uids = {call.args[0].uid for call in connection.move_message_to_junk.call_args_list}
    assert moved_uids == {100, 101}
    assert {row["outcome"] for row in db.list_mailbox_actions()} == {"moved"}


def test_missing_unsubscribe_consent_makes_no_network_call(configured_cli):
    runner, _config = configured_cli
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
    runner, _config = configured_cli
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


def test_second_post_grace_delivery_blocks_persisted_refs_without_current_scan(
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
    assert db.get_subscription(subscription["id"])["policy_action"] == "block"
    move.assert_called_once()
    moved_subscription = move.call_args.args[1]
    assert moved_subscription["id"] == subscription["id"]


def test_failure_detail_redaction_removes_query_and_mailto_tokens():
    detail = "failed https://sender.example/u?token=secret and mailto:user@example.com?body=opaque"
    redacted = _redact_failure_detail(detail)
    assert redacted is not None
    assert "secret" not in redacted
    assert "opaque" not in redacted
    assert "user@example.com" not in redacted


def test_manual_page_open_rescans_and_never_prints_token(configured_cli):
    runner, _config = configured_cli
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
        patch("nothx.cli.scan_inbox", return_value=scan_result) as scan,
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
        select.return_value.ask.return_value = "skip"
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
        select.return_value.ask.return_value = "block"
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
