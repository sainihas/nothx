"""Focused tests for account/list-scoped persistence and migration."""

import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import patch

import pytest

from nothx import db


@pytest.fixture
def state_db(tmp_path: Path):
    db_path = tmp_path / "state.db"
    with patch("nothx.db.get_db_path", return_value=db_path):
        db.init_db()
        yield db_path


def _subscription(account: str = "me@example.com", identity: str = "news.example.com"):
    return db.upsert_subscription(
        account,
        "list_id",
        identity,
        from_address="news@example.com",
        sender_domain="example.com",
    )


def _message(subscription_id: int, *, account: str = "me@example.com", uid: int = 1):
    return db.upsert_message_ref(
        subscription_id,
        account,
        "INBOX",
        "inbox",
        42,
        uid,
        from_address="news@example.com",
        list_id="news.example.com",
        flags=["$canunsubscribe", "\\Seen"],
        auth_evidence={"dkim": "pass"},
        endpoint_fingerprints=["sha256:abc"],
        has_header_method=True,
        can_unsubscribe=True,
    )


class TestAuthoritativeSchema:
    def test_schema_pragmas_tables_and_sensitive_columns(self, state_db):
        with db.get_db() as conn:
            assert conn.execute("PRAGMA foreign_keys").fetchone()[0] == 1
            assert conn.execute("PRAGMA busy_timeout").fetchone()[0] == db.BUSY_TIMEOUT_MS
            assert conn.execute("PRAGMA journal_mode").fetchone()[0].lower() == "wal"
            tables = {
                row[0]
                for row in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type = 'table'"
                ).fetchall()
            }
            assert {
                "mailbox_state",
                "subscriptions",
                "message_refs",
                "unsubscribe_operations",
                "unsubscribe_attempts",
                "mailbox_actions",
            } <= tables
            columns = {
                row["name"]
                for table in (
                    "message_refs",
                    "unsubscribe_operations",
                    "unsubscribe_attempts",
                )
                for row in conn.execute(f"PRAGMA table_info({table})").fetchall()
            }
            assert "url" not in columns
            assert "body" not in columns
            mailbox_action_columns = {
                row["name"] for row in conn.execute("PRAGMA table_info(mailbox_actions)").fetchall()
            }
            assert "retryable" in mailbox_action_columns

    def test_account_and_list_identity_are_independent(self, state_db):
        first = _subscription()
        second = _subscription(identity="offers.example.com")
        third = _subscription(account="other@example.com")

        assert len({first["id"], second["id"], third["id"]}) == 3
        assert len(db.list_subscriptions(account="me@example.com")) == 2

    def test_fallback_promotion_preserves_row_and_rejects_ambiguous_target(self, state_db):
        fallback = db.upsert_subscription("me@example.com", "from", "Sender <news@example.com>")
        promoted = db.promote_subscription_identity(
            "me@example.com", "news@example.com", "news.example.com"
        )

        assert promoted is not None
        assert promoted["id"] == fallback["id"]
        assert promoted["identity_kind"] == "list_id"
        assert promoted["promoted_from_value"] == "news@example.com"

        db.upsert_subscription("me@example.com", "from", "other@example.com")
        db.upsert_subscription("me@example.com", "list_id", "other.example.com")
        with pytest.raises(ValueError, match="refusing to guess"):
            db.promote_subscription_identity(
                "me@example.com", "other@example.com", "other.example.com"
            )


class TestMailboxAndMessages:
    def test_cursor_is_monotonic_and_resets_on_uidvalidity_change(self, state_db):
        db.advance_mailbox_cursor("me@example.com", "INBOX", "inbox", 10, 100)
        state = db.advance_mailbox_cursor("me@example.com", "INBOX", "inbox", 10, 90)
        assert state["last_uid"] == 100

        state = db.advance_mailbox_cursor("me@example.com", "INBOX", "inbox", 11, 3)
        assert state["uidvalidity"] == 11
        assert state["last_uid"] == 3

    def test_message_ref_is_uid_idempotent_and_account_checked(self, state_db):
        subscription = _subscription()
        first = _message(subscription["id"])
        second = _message(subscription["id"])

        assert first["id"] == second["id"]
        assert second["flags"] == ["$canunsubscribe", "\\Seen"]
        assert second["auth_evidence"] == {"dkim": "pass"}
        with pytest.raises(ValueError, match="does not match"):
            db.upsert_message_ref(subscription["id"], "other@example.com", "INBOX", "inbox", 42, 2)

    def test_mailbox_action_retry_updates_nonterminal_but_not_terminal_result(self, state_db):
        subscription = _subscription()
        message = _message(subscription["id"])

        partial = db.record_mailbox_action(
            subscription["id"],
            message["id"],
            "move-to-junk-v1",
            action="move_to_junk",
            outcome="partial",
            source_mailbox="INBOX",
            target_mailbox="Junk",
            error_code="source_remains",
        )
        assert partial["outcome"] == "partial"

        moved = db.record_mailbox_action(
            subscription["id"],
            message["id"],
            "move-to-junk-v1",
            action="move_to_junk",
            outcome="moved",
            source_mailbox="INBOX",
            target_mailbox="Junk",
        )
        assert moved["outcome"] == "moved"
        assert moved["error_code"] is None

        preserved = db.record_mailbox_action(
            subscription["id"],
            message["id"],
            "move-to-junk-v1",
            action="move_to_junk",
            outcome="failed",
            source_mailbox="INBOX",
            target_mailbox="Junk",
            error_code="late_racing_failure",
        )
        assert preserved["outcome"] == "moved"
        assert preserved["error_code"] is None

        absent_message = _message(subscription["id"], uid=2)
        absent = db.record_mailbox_action(
            subscription["id"],
            absent_message["id"],
            "move-to-junk-v1",
            action="move_to_junk",
            outcome="not_found",
            source_mailbox="INBOX",
            target_mailbox="Junk",
        )
        assert absent["outcome"] == "not_found"
        preserved_absent = db.record_mailbox_action(
            subscription["id"],
            absent_message["id"],
            "move-to-junk-v1",
            action="move_to_junk",
            outcome="failed",
            source_mailbox="INBOX",
            target_mailbox="Junk",
            error_code="late_racing_failure",
        )
        assert preserved_absent["outcome"] == "not_found"
        assert preserved_absent["error_code"] is None

        copied_message = _message(subscription["id"], uid=3)
        copied = db.record_mailbox_action(
            subscription["id"],
            copied_message["id"],
            "move-to-junk-v1",
            action="move_to_junk",
            outcome="partial",
            source_mailbox="INBOX",
            target_mailbox="Junk",
            retryable=False,
            error_code="source_marked_deleted",
        )
        assert copied["outcome"] == "partial"
        assert copied["retryable"] == 0

        preserved_copied = db.record_mailbox_action(
            subscription["id"],
            copied_message["id"],
            "move-to-junk-v1",
            action="move_to_junk",
            outcome="moved",
            source_mailbox="INBOX",
            target_mailbox="Junk",
        )
        assert preserved_copied["outcome"] == "partial"
        assert preserved_copied["retryable"] == 0
        assert preserved_copied["error_code"] == "source_marked_deleted"
        assert db.get_grouped_metrics()["mailbox_actions"]["partial"] == 1

        claimed_message = _message(subscription["id"], uid=4)
        owner_operation, owner_acquired = db.claim_unsubscribe_operation(
            subscription["id"],
            "block-owner",
            "owner-worker",
            kind="block",
        )
        assert owner_acquired is True
        other_operation = db.get_or_create_unsubscribe_operation(
            subscription["id"],
            "block-other",
            kind="block",
        )
        claimed = db.record_mailbox_action(
            subscription["id"],
            claimed_message["id"],
            "move-to-junk-v1",
            action="move_to_junk",
            outcome="claimed",
            source_mailbox="INBOX",
            target_mailbox="Junk",
            operation_id=owner_operation["id"],
            claim_owner="owner-worker",
            retryable=False,
        )
        assert claimed["outcome"] == "claimed"

        with pytest.raises(ValueError, match="not owned"):
            db.record_mailbox_action(
                subscription["id"],
                claimed_message["id"],
                "move-to-junk-v1",
                action="move_to_junk",
                outcome="moved",
                source_mailbox="INBOX",
                target_mailbox="Junk",
                operation_id=other_operation["id"],
            )

        completed_claim = db.record_mailbox_action(
            subscription["id"],
            claimed_message["id"],
            "move-to-junk-v1",
            action="move_to_junk",
            outcome="moved",
            source_mailbox="INBOX",
            target_mailbox="Junk",
            operation_id=owner_operation["id"],
            claim_owner="owner-worker",
            retryable=True,
        )
        assert completed_claim["outcome"] == "moved"
        assert completed_claim["retryable"] == 1

    def test_expired_operation_cannot_complete_stale_mailbox_action(self, state_db):
        subscription = _subscription()
        message = _message(subscription["id"])
        old = datetime.now(UTC) - timedelta(hours=2)
        operation, acquired = db.claim_unsubscribe_operation(
            subscription["id"],
            "stale-block",
            "stale-worker",
            kind="block",
            lease_seconds=1,
            claimed_at=old,
        )
        assert acquired is True
        db.record_mailbox_action(
            subscription["id"],
            message["id"],
            "move-to-junk-v1",
            action="move_to_junk",
            outcome="claimed",
            source_mailbox="INBOX",
            target_mailbox="Junk",
            operation_id=operation["id"],
            claim_owner="stale-worker",
            retryable=False,
        )
        expired, replacement_acquired = db.claim_unsubscribe_operation(
            subscription["id"],
            "stale-block",
            "replacement-worker",
            kind="block",
            claimed_at=datetime.now(UTC),
        )
        assert replacement_acquired is False
        assert expired["outcome"] == "needs_user"
        assert expired["claim_owner"] is None

        with pytest.raises(ValueError, match="not owned"):
            db.record_mailbox_action(
                subscription["id"],
                message["id"],
                "move-to-junk-v1",
                action="move_to_junk",
                outcome="moved",
                source_mailbox="INBOX",
                target_mailbox="Junk",
                operation_id=operation["id"],
                claim_owner="stale-worker",
            )
        action = db.list_mailbox_actions(subscription_id=subscription["id"])[0]
        assert action["outcome"] == "claimed"
        assert action["retryable"] == 0


class TestGroupedOperations:
    def test_execution_claim_is_atomic_and_owner_checked(self, state_db):
        subscription = _subscription()
        message = _message(subscription["id"])
        first, acquired = db.claim_unsubscribe_operation(
            subscription["id"],
            "source:42:1:generation:0",
            "worker-one",
            trigger_message_ref_id=message["id"],
        )
        assert acquired is True
        assert first["outcome"] is None

        duplicate, duplicate_acquired = db.claim_unsubscribe_operation(
            subscription["id"],
            "source:42:1:generation:0",
            "worker-two",
            trigger_message_ref_id=message["id"],
        )
        assert duplicate_acquired is False
        assert duplicate["id"] == first["id"]
        assert duplicate["outcome"] is None

        with pytest.raises(ValueError, match="not owned"):
            db.update_unsubscribe_operation_outcome(first["id"], "failed", claim_owner="worker-two")
        with pytest.raises(ValueError, match="not owned"):
            db.update_unsubscribe_operation_outcome(first["id"], "failed")
        completed = db.update_unsubscribe_operation_outcome(
            first["id"], "requested", claim_owner="worker-one"
        )
        assert completed["outcome"] == "requested"
        assert completed["claim_owner"] is None

    def test_different_source_cannot_race_active_or_requested_subscription(self, state_db):
        subscription = _subscription()
        first, acquired = db.claim_unsubscribe_operation(
            subscription["id"],
            "source:42:10:generation:0",
            "worker-one",
        )
        assert acquired is True

        active_conflict, active_acquired = db.claim_unsubscribe_operation(
            subscription["id"],
            "source:42:11:generation:0",
            "worker-two",
        )
        assert active_acquired is False
        assert active_conflict["id"] == first["id"]
        assert active_conflict["outcome"] is None

        db.update_unsubscribe_operation_outcome(
            first["id"],
            "requested",
            claim_owner="worker-one",
        )
        requested_conflict, requested_acquired = db.claim_unsubscribe_operation(
            subscription["id"],
            "source:42:12:generation:0",
            "worker-three",
        )
        assert requested_acquired is False
        assert requested_conflict["id"] == first["id"]
        assert requested_conflict["outcome"] == "requested"

    @pytest.mark.parametrize("outcome", ["needs_user", "failed"])
    def test_same_generation_completed_source_blocks_stale_claim(self, state_db, outcome: str):
        subscription = _subscription()
        first, acquired = db.claim_unsubscribe_operation(
            subscription["id"],
            "source-a",
            "worker-one",
            retry_generation=0,
        )
        assert acquired is True
        db.update_unsubscribe_operation_outcome(
            first["id"],
            outcome,
            claim_owner="worker-one",
        )

        conflict, stale_acquired = db.claim_unsubscribe_operation(
            subscription["id"],
            "source-b",
            "worker-two",
            retry_generation=0,
        )
        assert stale_acquired is False
        assert conflict["id"] == first["id"]

        fresh, fresh_acquired = db.claim_unsubscribe_operation(
            subscription["id"],
            "source-b",
            "worker-two",
            retry_generation=1,
        )
        assert fresh_acquired is True
        assert fresh["id"] != first["id"]

    def test_current_consent_can_resume_only_consent_blocked_source(self, state_db):
        subscription = _subscription()
        consent_wait, acquired = db.claim_unsubscribe_operation(
            subscription["id"],
            "consent-wait",
            "worker-one",
        )
        assert acquired is True
        db.update_unsubscribe_operation_outcome(
            consent_wait["id"],
            "needs_user",
            claim_owner="worker-one",
            error_code="unsubscribe_consent_required",
        )

        resumed, resumed_acquired = db.claim_unsubscribe_operation(
            subscription["id"],
            "real-source",
            "worker-two",
            allow_consent_resume=True,
        )

        assert resumed_acquired is True
        assert resumed["id"] != consent_wait["id"]

    def test_block_claim_serializes_sources_but_allows_later_delivery(self, state_db):
        subscription = _subscription()
        first, acquired = db.claim_unsubscribe_operation(
            subscription["id"],
            "block-source-1",
            "worker-one",
            kind="block",
        )
        assert acquired is True

        conflict, conflict_acquired = db.claim_unsubscribe_operation(
            subscription["id"],
            "block-source-2",
            "worker-two",
            kind="block",
        )
        assert conflict_acquired is False
        assert conflict["id"] == first["id"]

        db.update_unsubscribe_operation_outcome(
            first["id"],
            "blocked",
            claim_owner="worker-one",
        )
        later, later_acquired = db.claim_unsubscribe_operation(
            subscription["id"],
            "block-source-2",
            "worker-two",
            kind="block",
        )
        assert later_acquired is True
        assert later["id"] != first["id"]

    def test_active_claims_fence_unsubscribe_and_block_paths(self, state_db):
        subscription = _subscription()
        unsubscribe, unsubscribe_acquired = db.claim_unsubscribe_operation(
            subscription["id"],
            "unsubscribe-source",
            "unsubscribe-worker",
        )
        assert unsubscribe_acquired is True

        conflict, block_acquired = db.claim_unsubscribe_operation(
            subscription["id"],
            "block-source",
            "block-worker",
            kind="block",
        )
        assert block_acquired is False
        assert conflict["id"] == unsubscribe["id"]

        db.update_unsubscribe_operation_outcome(
            unsubscribe["id"],
            "requested",
            claim_owner="unsubscribe-worker",
        )
        block, block_acquired = db.claim_unsubscribe_operation(
            subscription["id"],
            "block-source",
            "block-worker",
            kind="block",
        )
        assert block_acquired is True

        reverse_conflict, unsubscribe_again = db.claim_unsubscribe_operation(
            subscription["id"],
            "another-unsubscribe-source",
            "another-unsubscribe-worker",
        )
        assert unsubscribe_again is False
        assert reverse_conflict["id"] == block["id"]

    def test_failed_block_operation_can_be_safely_reclaimed(self, state_db):
        subscription = _subscription()
        operation, acquired = db.claim_unsubscribe_operation(
            subscription["id"],
            "retryable-block-source",
            "worker-one",
            kind="block",
        )
        assert acquired is True
        db.update_unsubscribe_operation_outcome(
            operation["id"],
            "failed",
            claim_owner="worker-one",
        )

        reclaimed, reclaimed_acquired = db.claim_unsubscribe_operation(
            subscription["id"],
            "retryable-block-source",
            "worker-two",
            kind="block",
        )

        assert reclaimed_acquired is True
        assert reclaimed["id"] == operation["id"]
        assert reclaimed["outcome"] is None
        assert reclaimed["claim_owner"] == "worker-two"

    def test_failed_block_cannot_reopen_beside_another_live_claim(self, state_db):
        subscription = _subscription()
        failed, acquired = db.claim_unsubscribe_operation(
            subscription["id"],
            "failed-block",
            "worker-one",
            kind="block",
        )
        assert acquired is True
        db.update_unsubscribe_operation_outcome(
            failed["id"],
            "failed",
            claim_owner="worker-one",
        )
        live, live_acquired = db.claim_unsubscribe_operation(
            subscription["id"],
            "live-block",
            "worker-two",
            kind="block",
        )
        assert live_acquired is True

        conflict, reopened = db.claim_unsubscribe_operation(
            subscription["id"],
            "failed-block",
            "worker-three",
            kind="block",
        )

        assert reopened is False
        assert conflict["id"] == live["id"]

    def test_failed_block_does_not_reopen_while_expiring_another_claim(self, state_db):
        subscription = _subscription()
        failed, acquired = db.claim_unsubscribe_operation(
            subscription["id"],
            "failed-block",
            "worker-one",
            kind="block",
        )
        assert acquired is True
        db.update_unsubscribe_operation_outcome(
            failed["id"],
            "failed",
            claim_owner="worker-one",
        )
        old = datetime.now(UTC) - timedelta(hours=2)
        stale, stale_acquired = db.claim_unsubscribe_operation(
            subscription["id"],
            "stale-unsubscribe",
            "stale-worker",
            lease_seconds=1,
            claimed_at=old,
        )
        assert stale_acquired is True

        conflict, reopened = db.claim_unsubscribe_operation(
            subscription["id"],
            "failed-block",
            "worker-two",
            kind="block",
            claimed_at=datetime.now(UTC),
        )

        assert reopened is False
        assert conflict["id"] == stale["id"]
        assert conflict["outcome"] == "needs_user"
        assert conflict["claim_owner"] is None
        assert db.get_unsubscribe_operation(failed["id"])["outcome"] == "failed"

    def test_expired_claim_becomes_manual_and_is_never_reclaimed(self, state_db):
        subscription = _subscription()
        old = datetime.now(UTC) - timedelta(hours=2)
        claimed, acquired = db.claim_unsubscribe_operation(
            subscription["id"],
            "possibly-contacted-source",
            "crashed-worker",
            lease_seconds=1,
            claimed_at=old,
        )
        assert acquired is True

        inspected, replay_acquired = db.claim_unsubscribe_operation(
            subscription["id"],
            "possibly-contacted-source",
            "replacement-worker",
            claimed_at=datetime.now(UTC),
        )
        assert replay_acquired is False
        assert inspected["id"] == claimed["id"]
        assert inspected["outcome"] == "needs_user"
        assert inspected["error_code"] == "execution_claim_expired"
        assert db.get_subscription(subscription["id"])["last_outcome"] == "needs_user"

    def test_terminal_quiet_operation_can_be_created_atomically(self, state_db):
        subscription = _subscription()

        operation = db.get_or_create_unsubscribe_operation(
            subscription["id"],
            "historical-verification",
            kind="verification",
            outcome="verified_quiet",
        )

        assert operation["outcome"] == "verified_quiet"
        assert operation["verified_at"] is not None

    def test_operations_and_attempts_are_idempotent_and_redacted(self, state_db):
        subscription = _subscription()
        message = _message(subscription["id"])
        requested = datetime.now(UTC) - timedelta(days=3)
        grace = requested + timedelta(hours=48)
        first = db.get_or_create_unsubscribe_operation(
            subscription["id"],
            "message:42:1:generation:0",
            outcome="requested",
            trigger_message_ref_id=message["id"],
            endpoint_fingerprint="sha256:abc",
            destination_redacted="example.com/unsubscribe",
            requested_at=requested,
            grace_until=grace,
        )
        second = db.get_or_create_unsubscribe_operation(
            subscription["id"], "message:42:1:generation:0"
        )
        assert first["id"] == second["id"]

        attempt = db.record_unsubscribe_attempt(
            first["id"],
            "endpoint:sha256:abc",
            method="one-click",
            outcome="accepted",
            endpoint_fingerprint="sha256:abc",
            message_ref_id=message["id"],
            http_status=200,
        )
        duplicate = db.record_unsubscribe_attempt(
            first["id"],
            "endpoint:sha256:abc",
            method="one-click",
            outcome="accepted",
            endpoint_fingerprint="sha256:abc",
            message_ref_id=message["id"],
            http_status=200,
        )
        assert duplicate["id"] == attempt["id"]
        assert db.get_unsubscribe_operation(first["id"])["attempt_count"] == 1

        with pytest.raises(ValueError, match="raw unsubscribe"):
            db.record_unsubscribe_attempt(
                first["id"],
                "unsafe",
                method="get",
                outcome="accepted",
                endpoint_fingerprint="https://example.com/?token=secret",
            )
        with pytest.raises(ValueError, match="cannot contain a query"):
            db.get_or_create_unsubscribe_operation(
                subscription["id"],
                "unsafe-destination",
                destination_redacted="example.com/unsubscribe?token=secret",
            )

    def test_due_verification_requires_complete_post_grace_scan(self, state_db):
        subscription = _subscription()
        requested = datetime.now(UTC) - timedelta(days=3)
        grace = requested + timedelta(hours=48)
        operation = db.get_or_create_unsubscribe_operation(
            subscription["id"],
            "verify-me",
            outcome="requested",
            requested_at=requested,
            grace_until=grace,
        )
        assert db.list_operations_due_for_verification() == []

        db.advance_mailbox_cursor(
            "me@example.com",
            "INBOX",
            "inbox",
            42,
            100,
            scan_complete=True,
            scanned_at=grace + timedelta(minutes=1),
        )
        due = db.list_operations_due_for_verification()
        assert [item["id"] for item in due] == [operation["id"]]

        db.update_unsubscribe_operation_outcome(operation["id"], "verified_quiet")
        with pytest.raises(ValueError, match="Cannot regress"):
            db.update_unsubscribe_operation_outcome(operation["id"], "failed")

    def test_mailbox_actions_and_grouped_metrics(self, state_db):
        subscription = _subscription()
        message = _message(subscription["id"])
        operation = db.get_or_create_unsubscribe_operation(
            subscription["id"], "block:42:1", kind="block", outcome="blocked"
        )
        first = db.record_mailbox_action(
            subscription["id"],
            message["id"],
            "move:42:1",
            action="move_to_junk",
            outcome="moved",
            source_mailbox="INBOX",
            target_mailbox="Junk",
            operation_id=operation["id"],
        )
        duplicate = db.record_mailbox_action(
            subscription["id"],
            message["id"],
            "move:42:1",
            action="move_to_junk",
            outcome="moved",
            source_mailbox="INBOX",
            target_mailbox="Junk",
            operation_id=operation["id"],
        )
        assert duplicate["id"] == first["id"]
        metrics = db.get_grouped_metrics(account="me@example.com")
        assert metrics["operations"]["blocked"] == 1
        assert metrics["mailbox_actions"] == {"moved": 1}


def test_v1_migration_backup_and_only_explicit_rules(tmp_path: Path):
    db_path = tmp_path / "legacy.db"
    conn = sqlite3.connect(db_path)
    conn.executescript(
        """
        CREATE TABLE senders (
            domain TEXT PRIMARY KEY, first_seen TEXT, last_seen TEXT,
            total_emails INTEGER DEFAULT 0, seen_emails INTEGER DEFAULT 0,
            status TEXT DEFAULT 'unknown', ai_classification TEXT,
            ai_confidence REAL, user_override TEXT, sample_subjects TEXT,
            has_unsubscribe INTEGER DEFAULT 0
        );
        CREATE TABLE unsub_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT, domain TEXT, attempted_at TEXT,
            success INTEGER, method TEXT, http_status INTEGER, error TEXT,
            response_snippet TEXT, needs_confirmation INTEGER DEFAULT 0
        );
        PRAGMA user_version = 1;
        """
    )
    conn.executemany(
        "INSERT INTO senders (domain, status, user_override) VALUES (?, ?, ?)",
        [
            ("keep.example", "keep", "keep"),
            ("block.example", "blocked", "block"),
            ("old-success.example", "unsubscribed", None),
            ("unsub-override.example", "unknown", "unsub"),
        ],
    )
    conn.execute(
        "INSERT INTO unsub_log (domain, success, method) VALUES (?, 1, 'get')",
        ("old-success.example",),
    )
    conn.commit()
    conn.close()

    with patch("nothx.db.get_db_path", return_value=db_path):
        db.init_db()
        assert db.list_subscriptions() == []
        rules = {rule["pattern"]: rule for rule in db.get_rules()}
        assert set(rules) == {"keep.example", "block.example"}
        assert all(rule["priority"] == 1000 for rule in rules.values())
        assert all(rule["match_type"] == "exact" for rule in rules.values())
        with db.get_db() as migrated:
            assert migrated.execute("SELECT COUNT(*) FROM unsub_log").fetchone()[0] == 1

    backups = list(tmp_path.glob("legacy.db.backup-v1-to-v2-*"))
    assert len(backups) == 1
    assert backups[0].stat().st_mode & 0o777 == 0o600
    snapshot = sqlite3.connect(backups[0])
    try:
        assert snapshot.execute("PRAGMA user_version").fetchone()[0] == 1
        assert snapshot.execute("SELECT COUNT(*) FROM senders").fetchone()[0] == 4
        assert (
            snapshot.execute("SELECT 1 FROM sqlite_master WHERE name = 'subscriptions'").fetchone()
            is None
        )
    finally:
        snapshot.close()


def test_v2_retryability_repair_is_backed_up_and_partial_rows_are_terminal(
    tmp_path: Path,
):
    db_path = tmp_path / "pre-release-v2.db"
    with patch("nothx.db.get_db_path", return_value=db_path):
        db.init_db()
        subscription = _subscription()
        message = _message(subscription["id"])
        db.record_mailbox_action(
            subscription["id"],
            message["id"],
            "move-to-junk-v1",
            action="move_to_junk",
            outcome="partial",
            source_mailbox="INBOX",
            target_mailbox="Junk",
            retryable=True,
        )
        failed_message = _message(subscription["id"], uid=2)
        db.record_mailbox_action(
            subscription["id"],
            failed_message["id"],
            "move-to-junk-v1",
            action="move_to_junk",
            outcome="failed",
            source_mailbox="INBOX",
            target_mailbox="Junk",
            retryable=True,
        )
        with db.get_db() as conn:
            conn.execute("ALTER TABLE mailbox_actions DROP COLUMN retryable")
            conn.execute("PRAGMA user_version = 2")

        db.init_db()

        repaired = db.list_mailbox_actions(subscription_id=subscription["id"])
        assert {row["outcome"] for row in repaired} == {"partial", "failed"}
        assert all(row["retryable"] == 0 for row in repaired)

    backups = list(tmp_path.glob("pre-release-v2.db.backup-v2-to-v2-*"))
    assert len(backups) == 1
    assert backups[0].stat().st_mode & 0o777 == 0o600
    snapshot = sqlite3.connect(backups[0])
    try:
        columns = {
            row[1] for row in snapshot.execute("PRAGMA table_info(mailbox_actions)").fetchall()
        }
        assert "retryable" not in columns
    finally:
        snapshot.close()


def test_v2_claim_column_repair_is_backed_up(tmp_path: Path):
    db_path = tmp_path / "pre-claim-v2.db"
    with patch("nothx.db.get_db_path", return_value=db_path):
        db.init_db()
        with db.get_db() as conn:
            conn.execute("DROP INDEX idx_operations_claim")
            conn.execute("ALTER TABLE unsubscribe_operations DROP COLUMN claim_owner")
            conn.execute("ALTER TABLE unsubscribe_operations DROP COLUMN claimed_at")
            conn.execute("ALTER TABLE unsubscribe_operations DROP COLUMN claim_expires_at")
            conn.execute("PRAGMA user_version = 2")

        db.init_db()

        with db.get_db() as repaired:
            columns = {
                row["name"]
                for row in repaired.execute("PRAGMA table_info(unsubscribe_operations)").fetchall()
            }
        assert {"claim_owner", "claimed_at", "claim_expires_at"} <= columns

    backups = list(tmp_path.glob("pre-claim-v2.db.backup-v2-to-v2-*"))
    assert len(backups) == 1
    snapshot = sqlite3.connect(backups[0])
    try:
        columns = {
            row[1]
            for row in snapshot.execute("PRAGMA table_info(unsubscribe_operations)").fetchall()
        }
        assert "claim_owner" not in columns
    finally:
        snapshot.close()


def test_migration_backup_failure_propagates_without_schema_changes(tmp_path: Path):
    db_path = tmp_path / "legacy-failure.db"
    conn = sqlite3.connect(db_path)
    conn.executescript(
        """
        CREATE TABLE senders (
            domain TEXT PRIMARY KEY,
            user_override TEXT
        );
        INSERT INTO senders (domain, user_override) VALUES ('keep.example', 'keep');
        PRAGMA user_version = 1;
        """
    )
    before = conn.execute(
        "SELECT type, name, sql FROM sqlite_master ORDER BY type, name"
    ).fetchall()
    conn.commit()
    conn.close()

    class FailingBackupConnection(sqlite3.Connection):
        def backup(self, target: sqlite3.Connection, **kwargs: object) -> None:
            del target, kwargs
            raise OSError("disk full")

    failing_connection = sqlite3.connect(db_path, factory=FailingBackupConnection)
    with (
        patch("nothx.db.get_db_path", return_value=db_path),
        patch("nothx.db.get_connection", return_value=failing_connection),
        pytest.raises(OSError, match="disk full"),
    ):
        db.init_db()

    unchanged = sqlite3.connect(db_path)
    try:
        after = unchanged.execute(
            "SELECT type, name, sql FROM sqlite_master ORDER BY type, name"
        ).fetchall()
        assert after == before
        assert unchanged.execute("PRAGMA user_version").fetchone()[0] == 1
        assert (
            unchanged.execute("SELECT 1 FROM sqlite_master WHERE name = 'subscriptions'").fetchone()
            is None
        )
    finally:
        unchanged.close()
    assert not list(tmp_path.glob("legacy-failure.db.backup-v1-to-v2-*"))


def test_schema_ddl_rolls_back_when_migration_fails(tmp_path: Path):
    db_path = tmp_path / "atomic-migration.db"

    def fail_after_ddl(conn: sqlite3.Connection, _version: int) -> None:
        conn.execute("CREATE TABLE migration_probe (id INTEGER PRIMARY KEY)")
        raise RuntimeError("migration failed")

    with (
        patch("nothx.db.get_db_path", return_value=db_path),
        patch("nothx.db._migrate", side_effect=fail_after_ddl),
        pytest.raises(RuntimeError, match="migration failed"),
    ):
        db.init_db()

    conn = sqlite3.connect(db_path)
    try:
        user_tables = conn.execute(
            """
            SELECT name FROM sqlite_master
            WHERE type = 'table' AND name NOT LIKE 'sqlite_%'
            """
        ).fetchall()
        assert user_tables == []
        assert conn.execute("PRAGMA user_version").fetchone()[0] == 0
    finally:
        conn.close()


def test_legacy_override_never_clobbers_existing_user_rule(tmp_path: Path):
    db_path = tmp_path / "collision.db"
    conn = sqlite3.connect(db_path)
    conn.executescript(
        """
        CREATE TABLE senders (
            domain TEXT PRIMARY KEY, first_seen TEXT, last_seen TEXT,
            total_emails INTEGER DEFAULT 0, seen_emails INTEGER DEFAULT 0,
            status TEXT DEFAULT 'unknown', ai_classification TEXT,
            ai_confidence REAL, user_override TEXT, sample_subjects TEXT,
            has_unsubscribe INTEGER DEFAULT 0
        );
        CREATE TABLE rules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            pattern TEXT UNIQUE, action TEXT, created_at TEXT
        );
        INSERT INTO senders (domain, user_override)
            VALUES ('same.example', 'block'), ('new.example', 'block');
        INSERT INTO rules (pattern, action, created_at)
            VALUES ('Same.Example', 'keep', 'old'), ('unrelated.example', 'keep', 'old');
        PRAGMA user_version = 1;
        """
    )
    conn.commit()
    conn.close()

    with patch("nothx.db.get_db_path", return_value=db_path):
        db.init_db()
        rules = {row["pattern"]: row for row in db.get_rules()}
        assert rules["Same.Example"]["action"] == "keep"
        assert rules["Same.Example"]["priority"] == 100
        assert rules["Same.Example"]["match_type"] == "pattern"
        assert rules["Same.Example"]["source"] == "user"
        assert "same.example" not in rules
        assert rules["unrelated.example"]["action"] == "keep"
        assert rules["new.example"]["action"] == "block"
        assert rules["new.example"]["priority"] == 1000
        assert rules["new.example"]["match_type"] == "exact"
        assert rules["new.example"]["source"] == "legacy_override"
