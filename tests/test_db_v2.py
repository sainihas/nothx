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


def test_legacy_override_wins_same_pattern_collision_and_keeps_other_rules(tmp_path: Path):
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
        INSERT INTO senders (domain, user_override) VALUES ('same.example', 'block');
        INSERT INTO rules (pattern, action, created_at)
            VALUES ('same.example', 'keep', 'old'), ('unrelated.example', 'keep', 'old');
        PRAGMA user_version = 1;
        """
    )
    conn.commit()
    conn.close()

    with patch("nothx.db.get_db_path", return_value=db_path):
        db.init_db()
        rules = {row["pattern"]: row for row in db.get_rules()}
        assert rules["same.example"]["action"] == "block"
        assert rules["same.example"]["priority"] == 1000
        assert rules["same.example"]["match_type"] == "exact"
        assert rules["same.example"]["source"] == "legacy_override"
        assert rules["unrelated.example"]["action"] == "keep"
