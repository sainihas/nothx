"""SQLite database management for nothx.

The original database is intentionally kept intact for backwards compatibility,
but new scanning and unsubscribe code should use the account-scoped tables in
this module.  In particular, raw unsubscribe URLs and message bodies must never
be written to this database.
"""

import email.utils
import json
import os
import re
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from .config import get_db_path
from .models import Action, RunStats, SenderStatus, UnsubMethod, UserAction, UserPreference

BUSY_TIMEOUT_MS = 5_000
DEFAULT_OPERATION_LEASE_SECONDS = 30 * 60
_LIST_ID_VALUE_RE = re.compile(r"^[A-Za-z0-9!#$%&'*+\-/=?^_`{|}~.]{1,255}$")


def get_connection() -> sqlite3.Connection:
    """Get a configured database connection.

    Foreign keys are connection-local in SQLite, so they must be enabled for
    every caller.  WAL and a finite busy timeout let independently scheduled
    account scans coexist without silently losing writes.
    """
    db_path = get_db_path()
    conn = sqlite3.connect(db_path, timeout=BUSY_TIMEOUT_MS / 1_000)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute(f"PRAGMA busy_timeout = {BUSY_TIMEOUT_MS}")
    conn.execute("PRAGMA journal_mode = WAL")
    return conn


@contextmanager
def get_db() -> Iterator[sqlite3.Connection]:
    """Context manager for database connections."""
    conn = get_connection()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db() -> None:
    """Initialize or transactionally migrate the database schema.

    Existing databases are backed up using SQLite's online-backup API before
    any schema DDL is applied.  A brand-new, empty database does not need a
    backup.
    """
    db_path = Path(get_db_path())
    conn = get_connection()
    try:
        old_version = int(conn.execute("PRAGMA user_version").fetchone()[0])
        has_user_tables = _has_user_tables(conn)
        needs_current_schema_repair = (
            old_version == SCHEMA_VERSION
            and has_user_tables
            and (
                not _column_exists(conn, "mailbox_actions", "retryable")
                or any(
                    not _column_exists(conn, "unsubscribe_operations", column)
                    for column in ("claim_owner", "claimed_at", "claim_expires_at")
                )
            )
        )
        if has_user_tables and (old_version < SCHEMA_VERSION or needs_current_schema_repair):
            _create_migration_backup(conn, db_path, old_version)

        # Use explicit transaction control for schema changes. This keeps the
        # migration atomic regardless of sqlite3's legacy transaction mode.
        conn.isolation_level = None
        conn.execute("BEGIN IMMEDIATE")
        _create_legacy_tables(conn)
        _migrate(conn, old_version)
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def _create_legacy_tables(conn: sqlite3.Connection) -> None:
    """Create the compatibility tables without relying on ``executescript``.

    ``executescript`` implicitly commits pending transactions.  Executing each
    statement individually keeps initial creation and migration atomic.
    """
    statements = (
        """
            CREATE TABLE IF NOT EXISTS senders (
                domain TEXT PRIMARY KEY,
                first_seen TEXT,
                last_seen TEXT,
                total_emails INTEGER DEFAULT 0,
                seen_emails INTEGER DEFAULT 0,
                status TEXT DEFAULT 'unknown',
                ai_classification TEXT,
                ai_confidence REAL,
                user_override TEXT,
                sample_subjects TEXT,
                has_unsubscribe INTEGER DEFAULT 0
            )
        """,
        """
            CREATE TABLE IF NOT EXISTS unsub_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain TEXT,
                attempted_at TEXT,
                success INTEGER,
                method TEXT,
                http_status INTEGER,
                error TEXT,
                response_snippet TEXT,
                needs_confirmation INTEGER DEFAULT 0,
                FOREIGN KEY (domain) REFERENCES senders(domain)
            )
        """,
        """
            CREATE TABLE IF NOT EXISTS corrections (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain TEXT,
                ai_decision TEXT,
                user_decision TEXT,
                timestamp TEXT,
                FOREIGN KEY (domain) REFERENCES senders(domain)
            )
        """,
        """
            CREATE TABLE IF NOT EXISTS runs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ran_at TEXT,
                mode TEXT,
                emails_scanned INTEGER DEFAULT 0,
                unique_senders INTEGER DEFAULT 0,
                auto_unsubbed INTEGER DEFAULT 0,
                kept INTEGER DEFAULT 0,
                review_queued INTEGER DEFAULT 0,
                failed INTEGER DEFAULT 0
            )
        """,
        """
            CREATE TABLE IF NOT EXISTS rules (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                pattern TEXT UNIQUE,
                action TEXT,
                created_at TEXT,
                priority INTEGER NOT NULL DEFAULT 100,
                source TEXT NOT NULL DEFAULT 'user',
                match_type TEXT NOT NULL DEFAULT 'pattern'
            )
        """,
        """
            CREATE TABLE IF NOT EXISTS user_actions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain TEXT,
                action TEXT,
                ai_recommendation TEXT,
                heuristic_score INTEGER,
                open_rate REAL,
                email_count INTEGER,
                timestamp TEXT,
                FOREIGN KEY (domain) REFERENCES senders(domain)
            )
        """,
        """
            CREATE TABLE IF NOT EXISTS user_preferences (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                feature TEXT UNIQUE,
                value REAL,
                confidence REAL,
                sample_count INTEGER,
                source TEXT DEFAULT 'learned',
                last_updated TEXT
            )
        """,
    )
    for statement in statements:
        conn.execute(statement)


# Bump this when adding a migration step below.
SCHEMA_VERSION = 2

_OPERATION_OUTCOMES = (
    "requested",
    "needs_user",
    "verified_quiet",
    "ineffective",
    "failed",
    "blocked",
)


def _has_user_tables(conn: sqlite3.Connection) -> bool:
    row = conn.execute(
        """
        SELECT 1 FROM sqlite_master
        WHERE type = 'table' AND name NOT LIKE 'sqlite_%'
        LIMIT 1
        """
    ).fetchone()
    return row is not None


def _create_migration_backup(conn: sqlite3.Connection, db_path: Path, old_version: int) -> Path:
    """Create a consistent, owner-readable snapshot before migration."""
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%S%fZ")
    backup_path = db_path.with_name(
        f"{db_path.name}.backup-v{old_version}-to-v{SCHEMA_VERSION}-{stamp}"
    )
    flags = os.O_RDWR | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(backup_path, flags, 0o600)
        try:
            os.fchmod(fd, 0o600)
        finally:
            os.close(fd)

        backup_conn = sqlite3.connect(backup_path)
        try:
            conn.backup(backup_conn)
        finally:
            backup_conn.close()
        # Fail the migration if owner-only permissions cannot be guaranteed.
        # The snapshot contains sender metadata and must not be left readable
        # according to the process umask or inherited filesystem defaults.
        backup_path.chmod(0o600)
    except Exception:
        try:
            backup_path.unlink()
        except OSError:
            pass
        raise
    return backup_path


def _column_exists(conn: sqlite3.Connection, table: str, column: str) -> bool:
    """Check whether a column exists on a table."""
    rows = conn.execute(f"PRAGMA table_info({table})").fetchall()
    return any(row["name"] == column for row in rows)


def _add_column_if_missing(conn: sqlite3.Connection, table: str, column: str, ddl: str) -> None:
    """Add a column unless it already exists (idempotent)."""
    if not _column_exists(conn, table, column):
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {ddl}")


def _migrate(conn: sqlite3.Connection, version: int | None = None) -> None:
    """Upgrade existing databases to the current schema."""
    if version is None:
        version = int(conn.execute("PRAGMA user_version").fetchone()[0])
    if version > SCHEMA_VERSION:
        raise RuntimeError(f"Database schema v{version} is newer than supported v{SCHEMA_VERSION}")

    # These checks also repair an interrupted/manual legacy schema while all
    # changes are still protected by init_db's transaction.
    _add_column_if_missing(conn, "unsub_log", "needs_confirmation", "INTEGER DEFAULT 0")
    _add_column_if_missing(conn, "rules", "priority", "INTEGER NOT NULL DEFAULT 100")
    _add_column_if_missing(conn, "rules", "source", "TEXT NOT NULL DEFAULT 'user'")
    _add_column_if_missing(conn, "rules", "match_type", "TEXT NOT NULL DEFAULT 'pattern'")
    _create_authoritative_tables(conn)
    # Repair pre-release v2 databases created before durable execution claims
    # were added. These columns contain no endpoint or credential material.
    _add_column_if_missing(conn, "unsubscribe_operations", "claim_owner", "TEXT")
    _add_column_if_missing(conn, "unsubscribe_operations", "claimed_at", "TEXT")
    _add_column_if_missing(conn, "unsubscribe_operations", "claim_expires_at", "TEXT")
    had_mailbox_retryability = _column_exists(conn, "mailbox_actions", "retryable")
    _add_column_if_missing(
        conn,
        "mailbox_actions",
        "retryable",
        "INTEGER NOT NULL DEFAULT 1 CHECK (retryable IN (0, 1))",
    )
    if not had_mailbox_retryability:
        # Every pre-fix PARTIAL result followed COPY, and a legacy FAILED row
        # cannot distinguish a pre-COPY rejection from an ambiguous transport
        # loss after COPY. Fail closed for both so upgrading cannot create a
        # second destination copy.
        conn.execute(
            "UPDATE mailbox_actions SET retryable = 0 WHERE outcome IN ('partial', 'failed')"
        )
    _create_authoritative_indexes(conn)

    if version < 2:
        _migrate_explicit_legacy_overrides(conn)

    conn.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")


def _create_authoritative_tables(conn: sqlite3.Connection) -> None:
    """Create the account/list-scoped schema used by new code."""
    statements = (
        """
        CREATE TABLE IF NOT EXISTS mailbox_state (
            account TEXT NOT NULL CHECK (length(trim(account)) > 0),
            mailbox TEXT NOT NULL CHECK (length(mailbox) > 0),
            mailbox_role TEXT NOT NULL
                CHECK (mailbox_role IN ('inbox', 'junk', 'custom')),
            uidvalidity INTEGER CHECK (uidvalidity IS NULL OR uidvalidity > 0),
            last_uid INTEGER NOT NULL DEFAULT 0 CHECK (last_uid >= 0),
            scan_complete INTEGER NOT NULL DEFAULT 0 CHECK (scan_complete IN (0, 1)),
            last_scanned_at TEXT,
            last_complete_scan_at TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            PRIMARY KEY (account, mailbox)
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS subscriptions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            account TEXT NOT NULL CHECK (length(trim(account)) > 0),
            identity_kind TEXT NOT NULL CHECK (identity_kind IN ('list_id', 'from')),
            identity_value TEXT NOT NULL
                CHECK (length(identity_value) > 0 AND identity_value = lower(identity_value)),
            list_id TEXT CHECK (list_id IS NULL OR list_id = lower(list_id)),
            from_address TEXT CHECK (from_address IS NULL OR from_address = lower(from_address)),
            sender_domain TEXT CHECK (sender_domain IS NULL OR sender_domain = lower(sender_domain)),
            policy_action TEXT
                CHECK (policy_action IS NULL OR policy_action IN
                    ('keep', 'unsub', 'block', 'review')),
            ai_email_type TEXT,
            ai_recommended_action TEXT
                CHECK (ai_recommended_action IS NULL OR ai_recommended_action IN
                    ('keep', 'unsub', 'block', 'review')),
            classification_source TEXT,
            unwanted_confidence REAL
                CHECK (unwanted_confidence IS NULL OR
                    (unwanted_confidence >= 0.0 AND unwanted_confidence <= 1.0)),
            last_outcome TEXT
                CHECK (last_outcome IS NULL OR last_outcome IN
                    ('requested', 'needs_user', 'verified_quiet', 'ineffective',
                     'failed', 'blocked')),
            requested_at TEXT,
            grace_until TEXT,
            last_outcome_at TEXT,
            last_delivery_at TEXT,
            retry_count INTEGER NOT NULL DEFAULT 0 CHECK (retry_count >= 0),
            promoted_from_kind TEXT
                CHECK (promoted_from_kind IS NULL OR promoted_from_kind = 'from'),
            promoted_from_value TEXT,
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            UNIQUE (account, identity_kind, identity_value),
            CHECK (identity_kind != 'list_id' OR list_id = identity_value),
            CHECK (identity_kind != 'from' OR from_address = identity_value),
            CHECK ((promoted_from_kind IS NULL) = (promoted_from_value IS NULL))
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS message_refs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            subscription_id INTEGER NOT NULL,
            account TEXT NOT NULL CHECK (length(trim(account)) > 0),
            mailbox TEXT NOT NULL CHECK (length(mailbox) > 0),
            mailbox_role TEXT NOT NULL
                CHECK (mailbox_role IN ('inbox', 'junk', 'custom')),
            uidvalidity INTEGER NOT NULL CHECK (uidvalidity > 0),
            uid INTEGER NOT NULL CHECK (uid > 0),
            message_id TEXT,
            from_address TEXT,
            list_id TEXT,
            received_at TEXT,
            flags_json TEXT NOT NULL DEFAULT '[]',
            auth_evidence_json TEXT,
            bulk_evidence_json TEXT,
            provider_verdict TEXT,
            endpoint_fingerprints_json TEXT NOT NULL DEFAULT '[]',
            has_header_method INTEGER NOT NULL DEFAULT 0
                CHECK (has_header_method IN (0, 1)),
            can_unsubscribe INTEGER NOT NULL DEFAULT 0
                CHECK (can_unsubscribe IN (0, 1)),
            scanned_at TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (subscription_id) REFERENCES subscriptions(id) ON DELETE CASCADE,
            UNIQUE (account, mailbox, uidvalidity, uid)
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS unsubscribe_operations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            subscription_id INTEGER NOT NULL,
            operation_key TEXT NOT NULL CHECK (length(operation_key) > 0),
            kind TEXT NOT NULL DEFAULT 'unsubscribe'
                CHECK (kind IN ('unsubscribe', 'block', 'verification')),
            outcome TEXT CHECK (outcome IS NULL OR outcome IN
                ('requested', 'needs_user', 'verified_quiet', 'ineffective',
                 'failed', 'blocked')),
            trigger_message_ref_id INTEGER,
            endpoint_fingerprint TEXT
                CHECK (endpoint_fingerprint IS NULL OR
                    (length(endpoint_fingerprint) <= 255 AND
                     instr(endpoint_fingerprint, '://') = 0 AND
                     instr(endpoint_fingerprint, '?') = 0)),
            destination_redacted TEXT
                CHECK (destination_redacted IS NULL OR
                    (length(destination_redacted) <= 512 AND
                     instr(destination_redacted, '?') = 0 AND
                     instr(destination_redacted, '#') = 0)),
            retry_generation INTEGER NOT NULL DEFAULT 0 CHECK (retry_generation >= 0),
            attempt_count INTEGER NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
            requested_at TEXT,
            grace_until TEXT,
            verified_at TEXT,
            started_at TEXT NOT NULL,
            completed_at TEXT,
            error_code TEXT,
            detail_redacted TEXT,
            claim_owner TEXT,
            claimed_at TEXT,
            claim_expires_at TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (subscription_id) REFERENCES subscriptions(id) ON DELETE CASCADE,
            FOREIGN KEY (trigger_message_ref_id) REFERENCES message_refs(id) ON DELETE SET NULL,
            UNIQUE (subscription_id, operation_key),
            CHECK (outcome != 'requested' OR
                (requested_at IS NOT NULL AND grace_until IS NOT NULL)),
            CHECK (outcome != 'verified_quiet' OR verified_at IS NOT NULL)
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS unsubscribe_attempts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            operation_id INTEGER NOT NULL,
            attempt_key TEXT NOT NULL CHECK (length(attempt_key) > 0),
            attempt_number INTEGER NOT NULL CHECK (attempt_number > 0),
            message_ref_id INTEGER,
            method TEXT NOT NULL CHECK (length(method) > 0),
            outcome TEXT NOT NULL CHECK (outcome IN
                ('accepted', 'retryable_failure', 'permanent_failure',
                 'needs_user', 'ambiguous', 'skipped')),
            endpoint_fingerprint TEXT NOT NULL
                CHECK (length(endpoint_fingerprint) <= 255 AND
                    instr(endpoint_fingerprint, '://') = 0 AND
                    instr(endpoint_fingerprint, '?') = 0),
            destination_redacted TEXT
                CHECK (destination_redacted IS NULL OR
                    (length(destination_redacted) <= 512 AND
                     instr(destination_redacted, '?') = 0 AND
                     instr(destination_redacted, '#') = 0)),
            http_status INTEGER
                CHECK (http_status IS NULL OR (http_status >= 100 AND http_status <= 599)),
            error_code TEXT,
            detail_redacted TEXT,
            ambiguous_send INTEGER NOT NULL DEFAULT 0 CHECK (ambiguous_send IN (0, 1)),
            attempted_at TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY (operation_id) REFERENCES unsubscribe_operations(id) ON DELETE CASCADE,
            FOREIGN KEY (message_ref_id) REFERENCES message_refs(id) ON DELETE SET NULL,
            UNIQUE (operation_id, attempt_key),
            UNIQUE (operation_id, attempt_number)
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS mailbox_actions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            subscription_id INTEGER NOT NULL,
            message_ref_id INTEGER NOT NULL,
            operation_id INTEGER,
            action_key TEXT NOT NULL CHECK (length(action_key) > 0),
            action TEXT NOT NULL CHECK (length(action) > 0),
            outcome TEXT NOT NULL CHECK (length(outcome) > 0),
            source_mailbox TEXT NOT NULL CHECK (length(source_mailbox) > 0),
            target_mailbox TEXT,
            dry_run INTEGER NOT NULL DEFAULT 0 CHECK (dry_run IN (0, 1)),
            retryable INTEGER NOT NULL DEFAULT 1 CHECK (retryable IN (0, 1)),
            error_code TEXT,
            detail_redacted TEXT,
            started_at TEXT NOT NULL,
            completed_at TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY (subscription_id) REFERENCES subscriptions(id) ON DELETE CASCADE,
            FOREIGN KEY (message_ref_id) REFERENCES message_refs(id) ON DELETE CASCADE,
            FOREIGN KEY (operation_id) REFERENCES unsubscribe_operations(id) ON DELETE SET NULL,
            UNIQUE (message_ref_id, action_key)
        )
        """,
    )
    for statement in statements:
        conn.execute(statement)


def _create_authoritative_indexes(conn: sqlite3.Connection) -> None:
    statements = (
        "CREATE INDEX IF NOT EXISTS idx_rules_priority ON rules(priority DESC, created_at)",
        "CREATE INDEX IF NOT EXISTS idx_mailbox_state_role ON mailbox_state(account, mailbox_role)",
        "CREATE INDEX IF NOT EXISTS idx_subscriptions_policy ON subscriptions(account, policy_action)",
        "CREATE INDEX IF NOT EXISTS idx_subscriptions_outcome ON subscriptions(account, last_outcome, grace_until)",
        "CREATE INDEX IF NOT EXISTS idx_subscriptions_seen ON subscriptions(account, last_seen DESC)",
        "CREATE INDEX IF NOT EXISTS idx_message_refs_subscription ON message_refs(subscription_id, received_at DESC, id DESC)",
        "CREATE INDEX IF NOT EXISTS idx_message_refs_cursor ON message_refs(account, mailbox, uidvalidity, uid)",
        "CREATE INDEX IF NOT EXISTS idx_operations_subscription ON unsubscribe_operations(subscription_id, created_at DESC)",
        "CREATE INDEX IF NOT EXISTS idx_operations_due ON unsubscribe_operations(outcome, grace_until)",
        "CREATE INDEX IF NOT EXISTS idx_operations_claim ON unsubscribe_operations(outcome, claim_expires_at)",
        "CREATE INDEX IF NOT EXISTS idx_attempts_operation ON unsubscribe_attempts(operation_id, attempt_number)",
        "CREATE INDEX IF NOT EXISTS idx_attempts_fingerprint ON unsubscribe_attempts(endpoint_fingerprint)",
        "CREATE INDEX IF NOT EXISTS idx_mailbox_actions_subscription ON mailbox_actions(subscription_id, created_at DESC)",
        "CREATE INDEX IF NOT EXISTS idx_mailbox_actions_outcome ON mailbox_actions(outcome, created_at DESC)",
    )
    for statement in statements:
        conn.execute(statement)


def _migrate_explicit_legacy_overrides(conn: sqlite3.Connection) -> None:
    """Promote only explicit keep/block overrides to exact, durable rules.

    Legacy aggregate statuses and successful logs lack account/list identity and
    therefore must not produce subscriptions or future unsubscribe decisions.
    """
    now = datetime.now(UTC).isoformat()
    conn.execute(
        """
        INSERT INTO rules (pattern, action, created_at, priority, source, match_type)
        SELECT lower(trim(s.domain)), s.user_override, ?, 1000, 'legacy_override', 'exact'
        FROM senders AS s
        WHERE s.user_override IN ('keep', 'block')
          AND length(trim(s.domain)) > 0
          AND NOT EXISTS (
              SELECT 1 FROM rules AS r
              WHERE lower(trim(r.pattern)) = lower(trim(s.domain))
          )
        ON CONFLICT(pattern) DO NOTHING
        """,
        (now,),
    )


# ============================================================================
# Authoritative account/list state
# ============================================================================


def _iso_timestamp(value: datetime | str | None = None) -> str:
    """Return a normalized UTC ISO-8601 timestamp."""
    if value is None:
        parsed = datetime.now(UTC)
    elif isinstance(value, datetime):
        parsed = value
    else:
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValueError(f"Invalid ISO-8601 timestamp: {value!r}") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC).isoformat()


def _normalize_identity(identity_kind: str, identity_value: str) -> str:
    kind = identity_kind.strip().lower()
    if kind not in ("list_id", "from"):
        raise ValueError("identity_kind must be 'list_id' or 'from'")
    raw = identity_value.strip()
    if kind == "list_id":
        if "<" in raw or ">" in raw:
            start, end = raw.rfind("<"), raw.rfind(">")
            if start < 0 or end <= start or raw[end + 1 :].strip():
                raise ValueError("Invalid List-Id identity")
            raw = raw[start + 1 : end].strip()
        value = raw.lower()
        if "." not in value or "@" in value or _LIST_ID_VALUE_RE.fullmatch(value) is None:
            raise ValueError("Invalid List-Id identity")
        return value

    _, address = email.utils.parseaddr(raw)
    address = address.strip().lower()
    if (
        not address
        or len(address) > 320
        or address.count("@") != 1
        or any(ch.isspace() or ord(ch) < 33 for ch in address)
    ):
        raise ValueError("Invalid From identity")
    local, domain = address.rsplit("@", 1)
    if (
        not local
        or not domain
        or "." not in domain
        or domain.startswith(".")
        or domain.endswith(".")
    ):
        raise ValueError("Invalid From identity")
    return address


def _normalize_optional_address(value: str | None) -> str | None:
    return _normalize_identity("from", value) if value else None


def _normalize_optional_list_id(value: str | None) -> str | None:
    return _normalize_identity("list_id", value) if value else None


def _normalize_domain(value: str | None) -> str | None:
    if value is None:
        return None
    domain = value.strip().lower().rstrip(".")
    if not domain or "." not in domain or any(ch.isspace() or ord(ch) < 33 for ch in domain):
        raise ValueError("Invalid sender domain")
    return domain


def _validate_nonempty(value: str, field: str, max_length: int = 512) -> str:
    normalized = value.strip()
    if not normalized or len(normalized) > max_length or any(ord(ch) < 32 for ch in normalized):
        raise ValueError(f"Invalid {field}")
    return normalized


def _validate_fingerprint(value: str | None) -> str | None:
    if value is None:
        return None
    fingerprint = _validate_nonempty(value, "endpoint fingerprint", 255)
    if "://" in fingerprint or "?" in fingerprint or fingerprint.lower().startswith("mailto:"):
        raise ValueError("Endpoint fingerprints must not contain raw unsubscribe targets")
    return fingerprint


def _validate_redacted(value: str | None, field: str = "redacted detail") -> str | None:
    if value is None:
        return None
    if len(value) > 2_000 or any(ord(ch) < 9 for ch in value):
        raise ValueError(f"Invalid {field}")
    if field == "destination" and ("?" in value or "#" in value):
        raise ValueError("Redacted destinations cannot contain a query or fragment")
    return value


def _json_value(value: Any, *, list_default: bool = False) -> str:
    if value is None:
        value = [] if list_default else None
    try:
        return json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
    except (TypeError, ValueError) as exc:
        raise ValueError("Evidence must be JSON serializable") from exc


def _dict_row(row: sqlite3.Row | None) -> dict[str, Any] | None:
    return dict(row) if row is not None else None


def upsert_subscription(
    account: str,
    identity_kind: str,
    identity_value: str,
    *,
    list_id: str | None = None,
    from_address: str | None = None,
    sender_domain: str | None = None,
    policy_action: str | None = None,
    ai_email_type: str | None = None,
    ai_recommended_action: str | None = None,
    classification_source: str | None = None,
    unwanted_confidence: float | None = None,
    first_seen: datetime | str | None = None,
    last_seen: datetime | str | None = None,
    last_delivery_at: datetime | str | None = None,
) -> dict[str, Any]:
    """Insert or update one real, account-scoped subscription identity."""
    account = _validate_nonempty(account, "account", 320)
    identity_kind = identity_kind.strip().lower()
    identity_value = _normalize_identity(identity_kind, identity_value)
    list_id = _normalize_optional_list_id(list_id)
    from_address = _normalize_optional_address(from_address)
    if identity_kind == "list_id":
        if list_id is not None and list_id != identity_value:
            raise ValueError("list_id must match the subscription identity")
        list_id = identity_value
    else:
        if from_address is not None and from_address != identity_value:
            raise ValueError("from_address must match the subscription identity")
        from_address = identity_value
    if policy_action not in (None, "keep", "unsub", "block", "review"):
        raise ValueError("Invalid subscription policy action")
    if ai_recommended_action not in (None, "keep", "unsub", "block", "review"):
        raise ValueError("Invalid AI recommended action")
    if unwanted_confidence is not None and not 0.0 <= unwanted_confidence <= 1.0:
        raise ValueError("unwanted_confidence must be between 0 and 1")

    now = _iso_timestamp()
    first = _iso_timestamp(first_seen) if first_seen is not None else now
    last = _iso_timestamp(last_seen) if last_seen is not None else first
    delivery = _iso_timestamp(last_delivery_at) if last_delivery_at is not None else last
    sender_domain = _normalize_domain(sender_domain)
    if sender_domain is None and from_address:
        sender_domain = from_address.rsplit("@", 1)[1]

    with get_db() as conn:
        conn.execute(
            """
            INSERT INTO subscriptions (
                account, identity_kind, identity_value, list_id, from_address,
                sender_domain, policy_action, ai_email_type, ai_recommended_action,
                classification_source, unwanted_confidence, last_delivery_at,
                first_seen, last_seen, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(account, identity_kind, identity_value) DO UPDATE SET
                list_id = COALESCE(excluded.list_id, subscriptions.list_id),
                from_address = COALESCE(excluded.from_address, subscriptions.from_address),
                sender_domain = COALESCE(excluded.sender_domain, subscriptions.sender_domain),
                policy_action = COALESCE(excluded.policy_action, subscriptions.policy_action),
                ai_email_type = COALESCE(excluded.ai_email_type, subscriptions.ai_email_type),
                ai_recommended_action = COALESCE(
                    excluded.ai_recommended_action, subscriptions.ai_recommended_action
                ),
                classification_source = COALESCE(
                    excluded.classification_source, subscriptions.classification_source
                ),
                unwanted_confidence = COALESCE(
                    excluded.unwanted_confidence, subscriptions.unwanted_confidence
                ),
                last_delivery_at = CASE
                    WHEN subscriptions.last_delivery_at IS NULL OR
                         excluded.last_delivery_at > subscriptions.last_delivery_at
                    THEN excluded.last_delivery_at ELSE subscriptions.last_delivery_at END,
                first_seen = CASE WHEN excluded.first_seen < subscriptions.first_seen
                    THEN excluded.first_seen ELSE subscriptions.first_seen END,
                last_seen = CASE WHEN excluded.last_seen > subscriptions.last_seen
                    THEN excluded.last_seen ELSE subscriptions.last_seen END,
                updated_at = excluded.updated_at
            """,
            (
                account,
                identity_kind,
                identity_value,
                list_id,
                from_address,
                sender_domain,
                policy_action,
                ai_email_type,
                ai_recommended_action,
                classification_source,
                unwanted_confidence,
                delivery,
                first,
                last,
                now,
                now,
            ),
        )
        row = conn.execute(
            """
            SELECT * FROM subscriptions
            WHERE account = ? AND identity_kind = ? AND identity_value = ?
            """,
            (account, identity_kind, identity_value),
        ).fetchone()
        assert row is not None
        return dict(row)


def get_subscription(
    subscription_id: int | None = None,
    *,
    account: str | None = None,
    identity_kind: str | None = None,
    identity_value: str | None = None,
) -> dict[str, Any] | None:
    """Get a subscription by ID or by its complete natural identity."""
    with get_db() as conn:
        if subscription_id is not None:
            if account is not None or identity_kind is not None or identity_value is not None:
                raise ValueError("Use either subscription_id or account/identity fields")
            return _dict_row(
                conn.execute(
                    "SELECT * FROM subscriptions WHERE id = ?", (subscription_id,)
                ).fetchone()
            )
        if account is None or identity_kind is None or identity_value is None:
            raise ValueError("account, identity_kind, and identity_value are required")
        normalized = _normalize_identity(identity_kind, identity_value)
        return _dict_row(
            conn.execute(
                """
                SELECT * FROM subscriptions
                WHERE account = ? AND identity_kind = ? AND identity_value = ?
                """,
                (account.strip(), identity_kind.strip().lower(), normalized),
            ).fetchone()
        )


def list_subscriptions(
    *,
    account: str | None = None,
    policy_action: str | None = None,
    outcome: str | None = None,
    limit: int = 500,
) -> list[dict[str, Any]]:
    """List account-scoped subscriptions with stable newest-first ordering."""
    if limit < 1:
        return []
    if policy_action not in (None, "keep", "unsub", "block", "review"):
        raise ValueError("Invalid subscription policy action")
    if outcome is not None and outcome not in _OPERATION_OUTCOMES:
        raise ValueError("Invalid grouped outcome")
    clauses: list[str] = []
    params: list[Any] = []
    if account is not None:
        clauses.append("account = ?")
        params.append(account.strip())
    if policy_action is not None:
        clauses.append("policy_action = ?")
        params.append(policy_action)
    if outcome is not None:
        clauses.append("last_outcome = ?")
        params.append(outcome)
    where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
    params.append(limit)
    with get_db() as conn:
        rows = conn.execute(
            f"SELECT * FROM subscriptions{where} ORDER BY last_seen DESC, id DESC LIMIT ?",
            params,
        ).fetchall()
        return [dict(row) for row in rows]


def promote_subscription_identity(
    account: str,
    from_address: str,
    list_id: str,
) -> dict[str, Any] | None:
    """Promote one exact fallback identity to a List-Id without guessing.

    If the List-Id already belongs to a different row, no merge is attempted:
    combining its operations and policies would be ambiguous and unsafe.
    """
    account = _validate_nonempty(account, "account", 320)
    from_value = _normalize_identity("from", from_address)
    list_value = _normalize_identity("list_id", list_id)
    with get_db() as conn:
        conn.execute("BEGIN IMMEDIATE")
        fallback = conn.execute(
            """
            SELECT * FROM subscriptions
            WHERE account = ? AND identity_kind = 'from' AND identity_value = ?
            """,
            (account, from_value),
        ).fetchone()
        target = conn.execute(
            """
            SELECT * FROM subscriptions
            WHERE account = ? AND identity_kind = 'list_id' AND identity_value = ?
            """,
            (account, list_value),
        ).fetchone()
        if fallback is None:
            return dict(target) if target is not None else None
        if target is not None and target["id"] != fallback["id"]:
            raise ValueError("List-Id already belongs to another subscription; refusing to guess")
        now = _iso_timestamp()
        conn.execute(
            """
            UPDATE subscriptions
            SET identity_kind = 'list_id', identity_value = ?, list_id = ?,
                promoted_from_kind = 'from', promoted_from_value = ?, updated_at = ?
            WHERE id = ?
            """,
            (list_value, list_value, from_value, now, fallback["id"]),
        )
        row = conn.execute("SELECT * FROM subscriptions WHERE id = ?", (fallback["id"],)).fetchone()
        assert row is not None
        return dict(row)


def set_subscription_policy(subscription_id: int, action: str | None) -> bool:
    """Set or clear the durable future policy for a subscription."""
    if action not in (None, "keep", "unsub", "block", "review"):
        raise ValueError("Invalid subscription policy action")
    with get_db() as conn:
        cursor = conn.execute(
            "UPDATE subscriptions SET policy_action = ?, updated_at = ? WHERE id = ?",
            (action, _iso_timestamp(), subscription_id),
        )
        return cursor.rowcount > 0


def update_subscription_classification(
    subscription_id: int,
    *,
    ai_email_type: str | None,
    ai_recommended_action: str | None,
    classification_source: str | None = "ai",
    unwanted_confidence: float | None = None,
) -> bool:
    """Persist AI type and recommendation as separate facts."""
    if ai_recommended_action not in (None, "keep", "unsub", "block", "review"):
        raise ValueError("Invalid AI recommended action")
    if unwanted_confidence is not None and not 0.0 <= unwanted_confidence <= 1.0:
        raise ValueError("unwanted_confidence must be between 0 and 1")
    with get_db() as conn:
        cursor = conn.execute(
            """
            UPDATE subscriptions
            SET ai_email_type = ?, ai_recommended_action = ?,
                classification_source = ?, unwanted_confidence = ?, updated_at = ?
            WHERE id = ?
            """,
            (
                ai_email_type,
                ai_recommended_action,
                classification_source,
                unwanted_confidence,
                _iso_timestamp(),
                subscription_id,
            ),
        )
        return cursor.rowcount > 0


def upsert_mailbox_state(
    account: str,
    mailbox: str,
    mailbox_role: str,
    *,
    uidvalidity: int | None,
    last_uid: int = 0,
    scan_complete: bool = False,
    scanned_at: datetime | str | None = None,
    allow_uid_regression: bool = False,
) -> dict[str, Any]:
    """Advance an incremental mailbox cursor.

    Cursors are monotonic while UIDVALIDITY is unchanged.  A changed
    UIDVALIDITY starts a new UID namespace and safely resets the cursor to the
    supplied value.  Explicit full rescans can opt into UID regression.
    """
    account = _validate_nonempty(account, "account", 320)
    mailbox = _validate_nonempty(mailbox, "mailbox", 1_024)
    mailbox_role = mailbox_role.strip().lower()
    if mailbox_role not in ("inbox", "junk", "custom"):
        raise ValueError("mailbox_role must be inbox, junk, or custom")
    if uidvalidity is not None and uidvalidity <= 0:
        raise ValueError("uidvalidity must be positive")
    if last_uid < 0:
        raise ValueError("last_uid cannot be negative")
    scanned = _iso_timestamp(scanned_at)
    complete_at = scanned if scan_complete else None

    with get_db() as conn:
        conn.execute(
            """
            INSERT INTO mailbox_state (
                account, mailbox, mailbox_role, uidvalidity, last_uid,
                scan_complete, last_scanned_at, last_complete_scan_at,
                created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(account, mailbox) DO UPDATE SET
                mailbox_role = excluded.mailbox_role,
                last_uid = CASE
                    WHEN mailbox_state.uidvalidity IS NOT excluded.uidvalidity
                        THEN excluded.last_uid
                    WHEN ? = 1 THEN excluded.last_uid
                    WHEN excluded.last_uid > mailbox_state.last_uid THEN excluded.last_uid
                    ELSE mailbox_state.last_uid
                END,
                uidvalidity = COALESCE(excluded.uidvalidity, mailbox_state.uidvalidity),
                scan_complete = excluded.scan_complete,
                last_scanned_at = excluded.last_scanned_at,
                last_complete_scan_at = CASE WHEN excluded.scan_complete = 1
                    THEN excluded.last_complete_scan_at
                    ELSE mailbox_state.last_complete_scan_at END,
                updated_at = excluded.updated_at
            """,
            (
                account,
                mailbox,
                mailbox_role,
                uidvalidity,
                last_uid,
                int(scan_complete),
                scanned,
                complete_at,
                scanned,
                scanned,
                int(allow_uid_regression),
            ),
        )
        row = conn.execute(
            "SELECT * FROM mailbox_state WHERE account = ? AND mailbox = ?",
            (account, mailbox),
        ).fetchone()
        assert row is not None
        return dict(row)


def advance_mailbox_cursor(
    account: str,
    mailbox: str,
    mailbox_role: str,
    uidvalidity: int,
    last_uid: int,
    *,
    scan_complete: bool = False,
    scanned_at: datetime | str | None = None,
) -> dict[str, Any]:
    """Convenience wrapper for monotonic cursor advancement."""
    return upsert_mailbox_state(
        account,
        mailbox,
        mailbox_role,
        uidvalidity=uidvalidity,
        last_uid=last_uid,
        scan_complete=scan_complete,
        scanned_at=scanned_at,
    )


def get_mailbox_state(account: str, mailbox: str) -> dict[str, Any] | None:
    with get_db() as conn:
        return _dict_row(
            conn.execute(
                "SELECT * FROM mailbox_state WHERE account = ? AND mailbox = ?",
                (account.strip(), mailbox),
            ).fetchone()
        )


def list_mailbox_states(
    *, account: str | None = None, mailbox_role: str | None = None
) -> list[dict[str, Any]]:
    if mailbox_role not in (None, "inbox", "junk", "custom"):
        raise ValueError("Invalid mailbox role")
    clauses: list[str] = []
    params: list[Any] = []
    if account is not None:
        clauses.append("account = ?")
        params.append(account.strip())
    if mailbox_role is not None:
        clauses.append("mailbox_role = ?")
        params.append(mailbox_role)
    where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
    with get_db() as conn:
        rows = conn.execute(
            f"SELECT * FROM mailbox_state{where} ORDER BY account, mailbox_role, mailbox",
            params,
        ).fetchall()
        return [dict(row) for row in rows]


def upsert_message_ref(
    subscription_id: int,
    account: str,
    mailbox: str,
    mailbox_role: str,
    uidvalidity: int,
    uid: int,
    *,
    message_id: str | None = None,
    from_address: str | None = None,
    list_id: str | None = None,
    received_at: datetime | str | None = None,
    flags: list[str] | tuple[str, ...] | set[str] | None = None,
    auth_evidence: Any = None,
    bulk_evidence: Any = None,
    provider_verdict: str | None = None,
    endpoint_fingerprints: list[str] | tuple[str, ...] | None = None,
    has_header_method: bool = False,
    can_unsubscribe: bool = False,
    scanned_at: datetime | str | None = None,
) -> dict[str, Any]:
    """Persist a UID-stable message reference and non-sensitive evidence."""
    account = _validate_nonempty(account, "account", 320)
    mailbox = _validate_nonempty(mailbox, "mailbox", 1_024)
    mailbox_role = mailbox_role.strip().lower()
    if mailbox_role not in ("inbox", "junk", "custom"):
        raise ValueError("Invalid mailbox role")
    if uidvalidity <= 0 or uid <= 0:
        raise ValueError("UIDVALIDITY and UID must be positive")
    normalized_flags = sorted({_validate_nonempty(flag, "flag", 255) for flag in (flags or [])})
    normalized_fingerprints: list[str] = []
    for value in endpoint_fingerprints or []:
        fingerprint = _validate_fingerprint(value)
        assert fingerprint is not None
        if fingerprint not in normalized_fingerprints:
            normalized_fingerprints.append(fingerprint)
    now = _iso_timestamp(scanned_at)
    received = _iso_timestamp(received_at) if received_at is not None else None
    from_address = _normalize_optional_address(from_address)
    list_id = _normalize_optional_list_id(list_id)

    with get_db() as conn:
        subscription = conn.execute(
            "SELECT account FROM subscriptions WHERE id = ?", (subscription_id,)
        ).fetchone()
        if subscription is None:
            raise ValueError("Unknown subscription_id")
        if subscription["account"] != account:
            raise ValueError("Message account does not match subscription account")
        conn.execute(
            """
            INSERT INTO message_refs (
                subscription_id, account, mailbox, mailbox_role, uidvalidity, uid,
                message_id, from_address, list_id, received_at, flags_json,
                auth_evidence_json, bulk_evidence_json, provider_verdict,
                endpoint_fingerprints_json, has_header_method, can_unsubscribe,
                scanned_at, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(account, mailbox, uidvalidity, uid) DO UPDATE SET
                subscription_id = excluded.subscription_id,
                mailbox_role = excluded.mailbox_role,
                message_id = COALESCE(excluded.message_id, message_refs.message_id),
                from_address = COALESCE(excluded.from_address, message_refs.from_address),
                list_id = COALESCE(excluded.list_id, message_refs.list_id),
                received_at = COALESCE(excluded.received_at, message_refs.received_at),
                flags_json = excluded.flags_json,
                auth_evidence_json = COALESCE(
                    excluded.auth_evidence_json, message_refs.auth_evidence_json
                ),
                bulk_evidence_json = COALESCE(
                    excluded.bulk_evidence_json, message_refs.bulk_evidence_json
                ),
                provider_verdict = COALESCE(
                    excluded.provider_verdict, message_refs.provider_verdict
                ),
                endpoint_fingerprints_json = excluded.endpoint_fingerprints_json,
                has_header_method = excluded.has_header_method,
                can_unsubscribe = excluded.can_unsubscribe,
                scanned_at = excluded.scanned_at,
                updated_at = excluded.updated_at
            """,
            (
                subscription_id,
                account,
                mailbox,
                mailbox_role,
                uidvalidity,
                uid,
                message_id,
                from_address,
                list_id,
                received,
                _json_value(normalized_flags),
                _json_value(auth_evidence) if auth_evidence is not None else None,
                _json_value(bulk_evidence) if bulk_evidence is not None else None,
                provider_verdict,
                _json_value(normalized_fingerprints),
                int(has_header_method),
                int(can_unsubscribe),
                now,
                now,
                now,
            ),
        )
        row = conn.execute(
            """
            SELECT * FROM message_refs
            WHERE account = ? AND mailbox = ? AND uidvalidity = ? AND uid = ?
            """,
            (account, mailbox, uidvalidity, uid),
        ).fetchone()
        assert row is not None
        result = dict(row)
        for key in (
            "flags_json",
            "auth_evidence_json",
            "bulk_evidence_json",
            "endpoint_fingerprints_json",
        ):
            result[key.removesuffix("_json")] = json.loads(result[key]) if result[key] else None
        return result


def get_message_ref(
    message_ref_id: int | None = None,
    *,
    account: str | None = None,
    mailbox: str | None = None,
    uidvalidity: int | None = None,
    uid: int | None = None,
) -> dict[str, Any] | None:
    """Get a message reference by ID or complete IMAP UID identity."""
    with get_db() as conn:
        if message_ref_id is not None:
            if any(value is not None for value in (account, mailbox, uidvalidity, uid)):
                raise ValueError("Use either message_ref_id or the complete UID identity")
            return _dict_row(
                conn.execute(
                    "SELECT * FROM message_refs WHERE id = ?", (message_ref_id,)
                ).fetchone()
            )
        if None in (account, mailbox, uidvalidity, uid):
            raise ValueError("account, mailbox, uidvalidity, and uid are required")
        return _dict_row(
            conn.execute(
                """
                SELECT * FROM message_refs
                WHERE account = ? AND mailbox = ? AND uidvalidity = ? AND uid = ?
                """,
                (account, mailbox, uidvalidity, uid),
            ).fetchone()
        )


def list_message_refs(
    *,
    subscription_id: int | None = None,
    account: str | None = None,
    mailbox_role: str | None = None,
    limit: int = 500,
) -> list[dict[str, Any]]:
    if limit < 1:
        return []
    if mailbox_role not in (None, "inbox", "junk", "custom"):
        raise ValueError("Invalid mailbox role")
    clauses: list[str] = []
    params: list[Any] = []
    if subscription_id is not None:
        clauses.append("subscription_id = ?")
        params.append(subscription_id)
    if account is not None:
        clauses.append("account = ?")
        params.append(account.strip())
    if mailbox_role is not None:
        clauses.append("mailbox_role = ?")
        params.append(mailbox_role)
    where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
    params.append(limit)
    with get_db() as conn:
        rows = conn.execute(
            f"""
            SELECT * FROM message_refs{where}
            ORDER BY COALESCE(received_at, scanned_at) DESC, id DESC LIMIT ?
            """,
            params,
        ).fetchall()
        return [dict(row) for row in rows]


def get_or_create_unsubscribe_operation(
    subscription_id: int,
    operation_key: str,
    *,
    kind: str = "unsubscribe",
    outcome: str | None = None,
    trigger_message_ref_id: int | None = None,
    endpoint_fingerprint: str | None = None,
    destination_redacted: str | None = None,
    retry_generation: int = 0,
    requested_at: datetime | str | None = None,
    grace_until: datetime | str | None = None,
    started_at: datetime | str | None = None,
) -> dict[str, Any]:
    """Idempotently create one grouped unsubscribe/block operation."""
    operation_key = _validate_nonempty(operation_key, "operation key", 255)
    if "://" in operation_key or "?" in operation_key:
        raise ValueError("operation_key must not contain a raw URL")
    if kind not in ("unsubscribe", "block", "verification"):
        raise ValueError("Invalid operation kind")
    if outcome is not None and outcome not in _OPERATION_OUTCOMES:
        raise ValueError("Invalid grouped outcome")
    if retry_generation < 0:
        raise ValueError("retry_generation cannot be negative")
    endpoint_fingerprint = _validate_fingerprint(endpoint_fingerprint)
    destination_redacted = _validate_redacted(destination_redacted, "destination")
    started = _iso_timestamp(started_at)
    requested = _iso_timestamp(requested_at) if requested_at is not None else None
    grace = _iso_timestamp(grace_until) if grace_until is not None else None
    if outcome == "requested":
        requested = requested or started
        grace = grace or _iso_timestamp(datetime.fromisoformat(requested) + timedelta(hours=48))
    verified = started if outcome == "verified_quiet" else None

    with get_db() as conn:
        subscription = conn.execute(
            "SELECT id FROM subscriptions WHERE id = ?", (subscription_id,)
        ).fetchone()
        if subscription is None:
            raise ValueError("Unknown subscription_id")
        if trigger_message_ref_id is not None:
            trigger = conn.execute(
                "SELECT subscription_id FROM message_refs WHERE id = ?",
                (trigger_message_ref_id,),
            ).fetchone()
            if trigger is None or trigger["subscription_id"] != subscription_id:
                raise ValueError("Trigger message does not belong to the subscription")
        cursor = conn.execute(
            """
            INSERT INTO unsubscribe_operations (
                subscription_id, operation_key, kind, outcome,
                trigger_message_ref_id, endpoint_fingerprint, destination_redacted,
                retry_generation, requested_at, grace_until, started_at,
                verified_at, completed_at, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(subscription_id, operation_key) DO NOTHING
            """,
            (
                subscription_id,
                operation_key,
                kind,
                outcome,
                trigger_message_ref_id,
                endpoint_fingerprint,
                destination_redacted,
                retry_generation,
                requested,
                grace,
                started,
                verified,
                started if outcome is not None else None,
                started,
                started,
            ),
        )
        row = conn.execute(
            """
            SELECT * FROM unsubscribe_operations
            WHERE subscription_id = ? AND operation_key = ?
            """,
            (subscription_id, operation_key),
        ).fetchone()
        assert row is not None
        if cursor.rowcount > 0 and outcome is not None and row["outcome"] == outcome:
            _sync_subscription_outcome(conn, dict(row), started)
        return dict(row)


def get_unsubscribe_operation(operation_id: int) -> dict[str, Any] | None:
    with get_db() as conn:
        return _dict_row(
            conn.execute(
                "SELECT * FROM unsubscribe_operations WHERE id = ?", (operation_id,)
            ).fetchone()
        )


def claim_unsubscribe_operation(
    subscription_id: int,
    operation_key: str,
    claim_owner: str,
    *,
    kind: str = "unsubscribe",
    allow_consent_resume: bool = False,
    trigger_message_ref_id: int | None = None,
    retry_generation: int = 0,
    lease_seconds: int = DEFAULT_OPERATION_LEASE_SECONDS,
    claimed_at: datetime | str | None = None,
) -> tuple[dict[str, Any], bool]:
    """Atomically reserve one unsubscribe or mailbox operation.

    A second process never owns an existing claim. If a different owner finds
    an expired claim, the operation becomes ``needs_user`` instead of being
    replayed: the previous process may have contacted an endpoint or mutated a
    mailbox before it crashed. Returning ``acquired=False`` is therefore a
    hard no-side-effect decision for the caller.
    """
    operation_key = _validate_nonempty(operation_key, "operation key", 255)
    if "://" in operation_key or "?" in operation_key:
        raise ValueError("operation_key must not contain a raw URL")
    owner = _validate_nonempty(claim_owner, "claim owner", 255)
    if kind not in {"unsubscribe", "block"}:
        raise ValueError("Claim kind must be 'unsubscribe' or 'block'")
    if retry_generation < 0:
        raise ValueError("retry_generation cannot be negative")
    if not 1 <= lease_seconds <= 24 * 60 * 60:
        raise ValueError("lease_seconds must be between 1 and 86400")
    claimed = _iso_timestamp(claimed_at)
    claimed_datetime = datetime.fromisoformat(claimed)
    expires = _iso_timestamp(claimed_datetime + timedelta(seconds=lease_seconds))

    with get_db() as conn:
        conn.execute("BEGIN IMMEDIATE")
        subscription = conn.execute(
            "SELECT id FROM subscriptions WHERE id = ?", (subscription_id,)
        ).fetchone()
        if subscription is None:
            raise ValueError("Unknown subscription_id")
        if trigger_message_ref_id is not None:
            trigger = conn.execute(
                "SELECT subscription_id FROM message_refs WHERE id = ?",
                (trigger_message_ref_id,),
            ).fetchone()
            if trigger is None or trigger["subscription_id"] != subscription_id:
                raise ValueError("Trigger message does not belong to the subscription")

        existing = conn.execute(
            """
            SELECT * FROM unsubscribe_operations
            WHERE subscription_id = ? AND operation_key = ?
            """,
            (subscription_id, operation_key),
        ).fetchone()
        if existing is not None:
            current = dict(existing)
            if current["outcome"] is not None:
                if kind == "block" and current["outcome"] == "failed":
                    live_conflict = conn.execute(
                        """
                        SELECT * FROM unsubscribe_operations
                        WHERE subscription_id = ? AND id != ?
                          AND outcome IS NULL AND claim_owner IS NOT NULL
                        ORDER BY id DESC LIMIT 1
                        """,
                        (subscription_id, current["id"]),
                    ).fetchone()
                    if live_conflict is not None:
                        conflicting = dict(live_conflict)
                        conflict_expiry = conflicting.get("claim_expires_at")
                        conflict_expired = True
                        if conflict_expiry:
                            try:
                                conflict_expired = (
                                    datetime.fromisoformat(conflict_expiry) <= claimed_datetime
                                )
                            except ValueError:
                                conflict_expired = True
                        if conflict_expired:
                            conn.execute(
                                """
                                UPDATE unsubscribe_operations
                                SET outcome = 'needs_user', completed_at = ?,
                                    error_code = 'execution_claim_expired',
                                    detail_redacted = ?, claim_owner = NULL,
                                    claimed_at = NULL, claim_expires_at = NULL,
                                    updated_at = ?
                                WHERE id = ? AND outcome IS NULL
                                """,
                                (
                                    claimed,
                                    (
                                        "A prior execution may have contacted the endpoint; automatic replay is suppressed"
                                        if conflicting["kind"] == "unsubscribe"
                                        else "A prior execution may have mutated the mailbox; automatic replay is suppressed"
                                    ),
                                    claimed,
                                    conflicting["id"],
                                ),
                            )
                            row = conn.execute(
                                "SELECT * FROM unsubscribe_operations WHERE id = ?",
                                (conflicting["id"],),
                            ).fetchone()
                            assert row is not None
                            conflicting = dict(row)
                            _sync_subscription_outcome(conn, conflicting, claimed)
                        return conflicting, False
                    conn.execute(
                        """
                        UPDATE unsubscribe_operations
                        SET outcome = NULL, completed_at = NULL,
                            error_code = NULL, detail_redacted = NULL,
                            claim_owner = ?, claimed_at = ?, claim_expires_at = ?,
                            updated_at = ?
                        WHERE id = ? AND outcome = 'failed'
                        """,
                        (owner, claimed, expires, claimed, current["id"]),
                    )
                    row = conn.execute(
                        "SELECT * FROM unsubscribe_operations WHERE id = ?",
                        (current["id"],),
                    ).fetchone()
                    assert row is not None
                    return dict(row), True
                return current, False
            if current.get("claim_owner") == owner:
                return current, True
            claim_expiry = current.get("claim_expires_at")
            expired = True
            if claim_expiry:
                try:
                    expiry_datetime = datetime.fromisoformat(claim_expiry)
                    expired = expiry_datetime <= claimed_datetime
                except ValueError:
                    expired = True
            if expired:
                conn.execute(
                    """
                    UPDATE unsubscribe_operations
                    SET outcome = 'needs_user', completed_at = ?,
                        error_code = 'execution_claim_expired',
                        detail_redacted = ?, claim_owner = NULL,
                        claimed_at = NULL, claim_expires_at = NULL,
                        updated_at = ?
                    WHERE id = ? AND outcome IS NULL
                    """,
                    (
                        claimed,
                        (
                            "A prior execution may have contacted the endpoint; automatic replay is suppressed"
                            if kind == "unsubscribe"
                            else "A prior execution may have mutated the mailbox; automatic replay is suppressed"
                        ),
                        claimed,
                        current["id"],
                    ),
                )
                row = conn.execute(
                    "SELECT * FROM unsubscribe_operations WHERE id = ?", (current["id"],)
                ).fetchone()
                assert row is not None
                current = dict(row)
                _sync_subscription_outcome(conn, current, claimed)
            return current, False

        # Planning happens before this reservation transaction. A concurrent
        # scan may therefore have reserved a different newest UID, or may
        # already have completed an accepted request, between planning and
        # claiming. Serialize at subscription scope as well as operation-key
        # scope so neither race can produce duplicate external traffic.
        conflict = conn.execute(
            """
            SELECT * FROM unsubscribe_operations
            WHERE subscription_id = ?
              AND (
                  (? = 'unsubscribe' AND kind = 'unsubscribe' AND (
                      outcome = 'requested'
                      OR (
                          retry_generation = ?
                          AND outcome IN ('needs_user', 'failed')
                          AND NOT (
                              ? = 1
                              AND outcome = 'needs_user'
                              AND error_code = 'unsubscribe_consent_required'
                          )
                      )
                  ))
                  OR (outcome IS NULL AND claim_owner IS NOT NULL)
              )
            ORDER BY CASE WHEN outcome IS NULL THEN 0 ELSE 1 END, id DESC
            LIMIT 1
            """,
            (
                subscription_id,
                kind,
                retry_generation,
                int(allow_consent_resume),
            ),
        ).fetchone()
        if conflict is not None:
            current = dict(conflict)
            if current["outcome"] is None:
                claim_expiry = current.get("claim_expires_at")
                expired = True
                if claim_expiry:
                    try:
                        expiry_datetime = datetime.fromisoformat(claim_expiry)
                        expired = expiry_datetime <= claimed_datetime
                    except ValueError:
                        expired = True
                if expired:
                    conn.execute(
                        """
                        UPDATE unsubscribe_operations
                        SET outcome = 'needs_user', completed_at = ?,
                            error_code = 'execution_claim_expired',
                            detail_redacted = ?, claim_owner = NULL,
                            claimed_at = NULL, claim_expires_at = NULL,
                            updated_at = ?
                        WHERE id = ? AND outcome IS NULL
                        """,
                        (
                            claimed,
                            (
                                "A prior execution may have contacted the endpoint; automatic replay is suppressed"
                                if current["kind"] == "unsubscribe"
                                else "A prior execution may have mutated the mailbox; automatic replay is suppressed"
                            ),
                            claimed,
                            current["id"],
                        ),
                    )
                    row = conn.execute(
                        "SELECT * FROM unsubscribe_operations WHERE id = ?", (current["id"],)
                    ).fetchone()
                    assert row is not None
                    current = dict(row)
                    _sync_subscription_outcome(conn, current, claimed)
            return current, False

        cursor = conn.execute(
            """
            INSERT INTO unsubscribe_operations (
                subscription_id, operation_key, kind, outcome,
                trigger_message_ref_id, retry_generation, attempt_count,
                started_at, claim_owner, claimed_at, claim_expires_at,
                created_at, updated_at
            ) VALUES (?, ?, ?, NULL, ?, ?, 0, ?, ?, ?, ?, ?, ?)
            """,
            (
                subscription_id,
                operation_key,
                kind,
                trigger_message_ref_id,
                retry_generation,
                claimed,
                owner,
                claimed,
                expires,
                claimed,
                claimed,
            ),
        )
        row = conn.execute(
            "SELECT * FROM unsubscribe_operations WHERE id = ?", (cursor.lastrowid,)
        ).fetchone()
        assert row is not None
        return dict(row), True


def list_unsubscribe_operations(
    *,
    subscription_id: int | None = None,
    account: str | None = None,
    outcome: str | None = None,
    limit: int = 500,
) -> list[dict[str, Any]]:
    if limit < 1:
        return []
    if outcome is not None and outcome not in _OPERATION_OUTCOMES:
        raise ValueError("Invalid grouped outcome")
    clauses: list[str] = []
    params: list[Any] = []
    if subscription_id is not None:
        clauses.append("o.subscription_id = ?")
        params.append(subscription_id)
    if account is not None:
        clauses.append("s.account = ?")
        params.append(account.strip())
    if outcome is not None:
        clauses.append("o.outcome = ?")
        params.append(outcome)
    where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
    params.append(limit)
    with get_db() as conn:
        rows = conn.execute(
            f"""
            SELECT o.*, s.account, s.identity_kind, s.identity_value
            FROM unsubscribe_operations o
            JOIN subscriptions s ON s.id = o.subscription_id
            {where}
            ORDER BY o.created_at DESC, o.id DESC LIMIT ?
            """,
            params,
        ).fetchall()
        return [dict(row) for row in rows]


def update_unsubscribe_operation_outcome(
    operation_id: int,
    outcome: str,
    *,
    requested_at: datetime | str | None = None,
    grace_until: datetime | str | None = None,
    verified_at: datetime | str | None = None,
    completed_at: datetime | str | None = None,
    error_code: str | None = None,
    detail_redacted: str | None = None,
    claim_owner: str | None = None,
) -> dict[str, Any]:
    """Record a grouped result without allowing accepted work to regress."""
    if outcome not in _OPERATION_OUTCOMES:
        raise ValueError("Invalid grouped outcome")
    detail_redacted = _validate_redacted(detail_redacted)
    completed = _iso_timestamp(completed_at)
    with get_db() as conn:
        conn.execute("BEGIN IMMEDIATE")
        current = conn.execute(
            "SELECT * FROM unsubscribe_operations WHERE id = ?", (operation_id,)
        ).fetchone()
        if current is None:
            raise ValueError("Unknown operation_id")
        if current["claim_owner"] is not None and current["claim_owner"] != claim_owner:
            raise ValueError("Unsubscribe operation claim is not owned by this executor")
        if claim_owner is not None and current["claim_owner"] != claim_owner:
            raise ValueError("Unsubscribe operation claim is not owned by this executor")
        current_outcome = current["outcome"]
        if current_outcome in ("verified_quiet", "blocked") and outcome != current_outcome:
            raise ValueError(f"Cannot regress terminal outcome {current_outcome}")
        if current_outcome == "requested" and outcome in ("needs_user", "failed"):
            raise ValueError("An accepted request cannot regress to an unaccepted outcome")

        requested = (
            _iso_timestamp(requested_at) if requested_at is not None else current["requested_at"]
        )
        grace = _iso_timestamp(grace_until) if grace_until is not None else current["grace_until"]
        verified = (
            _iso_timestamp(verified_at) if verified_at is not None else current["verified_at"]
        )
        if outcome == "requested":
            requested = requested or completed
            grace = grace or _iso_timestamp(datetime.fromisoformat(requested) + timedelta(hours=48))
        if outcome == "verified_quiet":
            verified = verified or completed

        conn.execute(
            """
            UPDATE unsubscribe_operations
            SET outcome = ?, requested_at = ?, grace_until = ?, verified_at = ?,
                completed_at = ?, error_code = ?, detail_redacted = ?,
                claim_owner = NULL, claimed_at = NULL, claim_expires_at = NULL,
                updated_at = ?
            WHERE id = ?
            """,
            (
                outcome,
                requested,
                grace,
                verified,
                completed,
                error_code,
                detail_redacted,
                completed,
                operation_id,
            ),
        )
        row = conn.execute(
            "SELECT * FROM unsubscribe_operations WHERE id = ?", (operation_id,)
        ).fetchone()
        assert row is not None
        _sync_subscription_outcome(conn, dict(row), completed)
        return dict(row)


# Concise alias used by scanner/executor integrations.
record_operation_outcome = update_unsubscribe_operation_outcome


def _sync_subscription_outcome(
    conn: sqlite3.Connection, operation: dict[str, Any], outcome_at: str
) -> None:
    outcome = operation.get("outcome")
    if outcome is None:
        return
    conn.execute(
        """
        UPDATE subscriptions
        SET last_outcome = CASE
                WHEN last_outcome_at IS NULL OR last_outcome_at <= ? THEN ?
                ELSE last_outcome END,
            last_outcome_at = CASE
                WHEN last_outcome_at IS NULL OR last_outcome_at <= ? THEN ?
                ELSE last_outcome_at END,
            requested_at = CASE WHEN ? = 'requested'
                THEN COALESCE(?, requested_at) ELSE requested_at END,
            grace_until = CASE WHEN ? = 'requested'
                THEN COALESCE(?, grace_until) ELSE grace_until END,
            retry_count = MAX(retry_count, ?),
            policy_action = CASE WHEN ? = 'blocked' THEN 'block' ELSE policy_action END,
            updated_at = ?
        WHERE id = ?
        """,
        (
            outcome_at,
            outcome,
            outcome_at,
            outcome_at,
            outcome,
            operation.get("requested_at"),
            outcome,
            operation.get("grace_until"),
            operation.get("retry_generation", 0),
            outcome,
            outcome_at,
            operation["subscription_id"],
        ),
    )


def list_operations_due_for_verification(
    *,
    as_of: datetime | str | None = None,
    account: str | None = None,
    require_complete_scan: bool = True,
) -> list[dict[str, Any]]:
    """List accepted requests whose 48-hour grace period has elapsed.

    By default, an operation is returned only after a complete Inbox scan for
    that account occurred at or after its grace deadline.
    """
    timestamp = _iso_timestamp(as_of)
    clauses = ["o.outcome = 'requested'", "o.grace_until <= ?"]
    params: list[Any] = [timestamp]
    if account is not None:
        clauses.append("s.account = ?")
        params.append(account.strip())
    if require_complete_scan:
        clauses.append(
            """
            EXISTS (
                SELECT 1 FROM mailbox_state ms
                WHERE ms.account = s.account AND ms.mailbox_role = 'inbox'
                  AND ms.scan_complete = 1
                  AND ms.last_complete_scan_at >= o.grace_until
            )
            """
        )
    with get_db() as conn:
        rows = conn.execute(
            f"""
            SELECT o.*, s.account, s.identity_kind, s.identity_value,
                   s.last_delivery_at
            FROM unsubscribe_operations o
            JOIN subscriptions s ON s.id = o.subscription_id
            WHERE {" AND ".join(clauses)}
            ORDER BY o.grace_until, o.id
            """,
            params,
        ).fetchall()
        return [dict(row) for row in rows]


def record_unsubscribe_attempt(
    operation_id: int,
    attempt_key: str,
    *,
    method: str,
    outcome: str,
    endpoint_fingerprint: str,
    message_ref_id: int | None = None,
    destination_redacted: str | None = None,
    http_status: int | None = None,
    error_code: str | None = None,
    detail_redacted: str | None = None,
    ambiguous_send: bool = False,
    attempted_at: datetime | str | None = None,
) -> dict[str, Any]:
    """Idempotently append one redacted endpoint attempt to an operation."""
    attempt_key = _validate_nonempty(attempt_key, "attempt key", 255)
    if "://" in attempt_key or "?" in attempt_key:
        raise ValueError("attempt_key must not contain a raw URL")
    method = _validate_nonempty(method, "unsubscribe method", 64)
    if outcome not in (
        "accepted",
        "retryable_failure",
        "permanent_failure",
        "needs_user",
        "ambiguous",
        "skipped",
    ):
        raise ValueError("Invalid attempt outcome")
    fingerprint = _validate_fingerprint(endpoint_fingerprint)
    assert fingerprint is not None
    destination_redacted = _validate_redacted(destination_redacted, "destination")
    detail_redacted = _validate_redacted(detail_redacted)
    if http_status is not None and not 100 <= http_status <= 599:
        raise ValueError("Invalid HTTP status")
    attempted = _iso_timestamp(attempted_at)

    with get_db() as conn:
        conn.execute("BEGIN IMMEDIATE")
        operation = conn.execute(
            "SELECT subscription_id FROM unsubscribe_operations WHERE id = ?",
            (operation_id,),
        ).fetchone()
        if operation is None:
            raise ValueError("Unknown operation_id")
        if message_ref_id is not None:
            message = conn.execute(
                "SELECT subscription_id FROM message_refs WHERE id = ?", (message_ref_id,)
            ).fetchone()
            if message is None or message["subscription_id"] != operation["subscription_id"]:
                raise ValueError("Attempt message does not belong to the operation subscription")
        existing = conn.execute(
            """
            SELECT * FROM unsubscribe_attempts
            WHERE operation_id = ? AND attempt_key = ?
            """,
            (operation_id, attempt_key),
        ).fetchone()
        if existing is not None:
            return dict(existing)
        next_number = int(
            conn.execute(
                """
                SELECT COALESCE(MAX(attempt_number), 0) + 1
                FROM unsubscribe_attempts WHERE operation_id = ?
                """,
                (operation_id,),
            ).fetchone()[0]
        )
        cursor = conn.execute(
            """
            INSERT INTO unsubscribe_attempts (
                operation_id, attempt_key, attempt_number, message_ref_id,
                method, outcome, endpoint_fingerprint, destination_redacted,
                http_status, error_code, detail_redacted, ambiguous_send,
                attempted_at, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                operation_id,
                attempt_key,
                next_number,
                message_ref_id,
                method,
                outcome,
                fingerprint,
                destination_redacted,
                http_status,
                error_code,
                detail_redacted,
                int(ambiguous_send),
                attempted,
                attempted,
            ),
        )
        conn.execute(
            """
            UPDATE unsubscribe_operations
            SET attempt_count = attempt_count + 1, updated_at = ? WHERE id = ?
            """,
            (attempted, operation_id),
        )
        row = conn.execute(
            "SELECT * FROM unsubscribe_attempts WHERE id = ?", (cursor.lastrowid,)
        ).fetchone()
        assert row is not None
        return dict(row)


def list_unsubscribe_attempts(operation_id: int, *, limit: int = 100) -> list[dict[str, Any]]:
    if limit < 1:
        return []
    with get_db() as conn:
        rows = conn.execute(
            """
            SELECT * FROM unsubscribe_attempts
            WHERE operation_id = ? ORDER BY attempt_number LIMIT ?
            """,
            (operation_id, limit),
        ).fetchall()
        return [dict(row) for row in rows]


def record_mailbox_action(
    subscription_id: int,
    message_ref_id: int,
    action_key: str,
    *,
    action: str,
    outcome: str,
    source_mailbox: str,
    target_mailbox: str | None = None,
    operation_id: int | None = None,
    claim_owner: str | None = None,
    dry_run: bool = False,
    retryable: bool = True,
    error_code: str | None = None,
    detail_redacted: str | None = None,
    started_at: datetime | str | None = None,
    completed_at: datetime | str | None = None,
) -> dict[str, Any]:
    """Idempotently record a grouped, message-specific mailbox mutation."""
    action_key = _validate_nonempty(action_key, "mailbox action key", 255)
    action = _validate_nonempty(action, "mailbox action", 64)
    outcome = _validate_nonempty(outcome, "mailbox action outcome", 64)
    source_mailbox = _validate_nonempty(source_mailbox, "source mailbox", 1_024)
    if target_mailbox is not None:
        target_mailbox = _validate_nonempty(target_mailbox, "target mailbox", 1_024)
    detail_redacted = _validate_redacted(detail_redacted)
    started = _iso_timestamp(started_at)
    completed = _iso_timestamp(completed_at) if completed_at is not None else started

    with get_db() as conn:
        conn.execute("BEGIN IMMEDIATE")
        message = conn.execute(
            "SELECT subscription_id, mailbox FROM message_refs WHERE id = ?",
            (message_ref_id,),
        ).fetchone()
        if message is None or message["subscription_id"] != subscription_id:
            raise ValueError("Mailbox-action message does not belong to subscription")
        if message["mailbox"] != source_mailbox:
            raise ValueError("Source mailbox does not match the persisted message reference")
        if outcome == "claimed" and (operation_id is None or claim_owner is None):
            raise ValueError("A mailbox action claim requires an owned operation")
        operation: sqlite3.Row | None = None
        if operation_id is not None:
            operation = conn.execute(
                """
                SELECT subscription_id, outcome, claim_owner
                FROM unsubscribe_operations WHERE id = ?
                """,
                (operation_id,),
            ).fetchone()
            if operation is None or operation["subscription_id"] != subscription_id:
                raise ValueError("Mailbox-action operation does not belong to subscription")
            if operation["claim_owner"] is not None and (
                claim_owner != operation["claim_owner"] or operation["outcome"] is not None
            ):
                raise ValueError("Mailbox-action operation claim is not owned by this executor")
            if claim_owner is not None and operation["claim_owner"] != claim_owner:
                raise ValueError("Mailbox-action operation claim is not owned by this executor")
        prior_action = conn.execute(
            """
            SELECT outcome, operation_id FROM mailbox_actions
            WHERE message_ref_id = ? AND action_key = ?
            """,
            (message_ref_id, action_key),
        ).fetchone()
        if prior_action is not None and prior_action["outcome"] == "claimed":
            if (
                operation_id != prior_action["operation_id"]
                or claim_owner is None
                or operation is None
                or operation["outcome"] is not None
                or operation["claim_owner"] != claim_owner
            ):
                raise ValueError("Mailbox-action claim completion is not owned by this executor")
        conn.execute(
            """
            INSERT INTO mailbox_actions (
                subscription_id, message_ref_id, operation_id, action_key,
                action, outcome, source_mailbox, target_mailbox, dry_run,
                retryable, error_code, detail_redacted, started_at, completed_at, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(message_ref_id, action_key) DO UPDATE SET
                operation_id = CASE
                    WHEN mailbox_actions.outcome IN ('moved', 'already_junk', 'not_found')
                         OR (mailbox_actions.retryable = 0 AND NOT (
                             mailbox_actions.outcome = 'claimed'
                             AND mailbox_actions.operation_id IS excluded.operation_id))
                        THEN mailbox_actions.operation_id
                    ELSE excluded.operation_id END,
                action = CASE
                    WHEN mailbox_actions.outcome IN ('moved', 'already_junk', 'not_found')
                         OR (mailbox_actions.retryable = 0 AND NOT (
                             mailbox_actions.outcome = 'claimed'
                             AND mailbox_actions.operation_id IS excluded.operation_id))
                        THEN mailbox_actions.action
                    ELSE excluded.action END,
                outcome = CASE
                    WHEN mailbox_actions.outcome IN ('moved', 'already_junk', 'not_found')
                         OR (mailbox_actions.retryable = 0 AND NOT (
                             mailbox_actions.outcome = 'claimed'
                             AND mailbox_actions.operation_id IS excluded.operation_id))
                        THEN mailbox_actions.outcome
                    ELSE excluded.outcome END,
                target_mailbox = CASE
                    WHEN mailbox_actions.outcome IN ('moved', 'already_junk', 'not_found')
                         OR (mailbox_actions.retryable = 0 AND NOT (
                             mailbox_actions.outcome = 'claimed'
                             AND mailbox_actions.operation_id IS excluded.operation_id))
                        THEN mailbox_actions.target_mailbox
                    ELSE excluded.target_mailbox END,
                dry_run = CASE
                    WHEN mailbox_actions.outcome IN ('moved', 'already_junk', 'not_found')
                         OR (mailbox_actions.retryable = 0 AND NOT (
                             mailbox_actions.outcome = 'claimed'
                             AND mailbox_actions.operation_id IS excluded.operation_id))
                        THEN mailbox_actions.dry_run
                    ELSE excluded.dry_run END,
                retryable = CASE
                    WHEN mailbox_actions.outcome IN ('moved', 'already_junk', 'not_found')
                         OR (mailbox_actions.retryable = 0 AND NOT (
                             mailbox_actions.outcome = 'claimed'
                             AND mailbox_actions.operation_id IS excluded.operation_id))
                        THEN mailbox_actions.retryable
                    ELSE excluded.retryable END,
                error_code = CASE
                    WHEN mailbox_actions.outcome IN ('moved', 'already_junk', 'not_found')
                         OR (mailbox_actions.retryable = 0 AND NOT (
                             mailbox_actions.outcome = 'claimed'
                             AND mailbox_actions.operation_id IS excluded.operation_id))
                        THEN mailbox_actions.error_code
                    ELSE excluded.error_code END,
                detail_redacted = CASE
                    WHEN mailbox_actions.outcome IN ('moved', 'already_junk', 'not_found')
                         OR (mailbox_actions.retryable = 0 AND NOT (
                             mailbox_actions.outcome = 'claimed'
                             AND mailbox_actions.operation_id IS excluded.operation_id))
                        THEN mailbox_actions.detail_redacted
                    ELSE excluded.detail_redacted END,
                started_at = CASE
                    WHEN mailbox_actions.outcome IN ('moved', 'already_junk', 'not_found')
                         OR (mailbox_actions.retryable = 0 AND NOT (
                             mailbox_actions.outcome = 'claimed'
                             AND mailbox_actions.operation_id IS excluded.operation_id))
                        THEN mailbox_actions.started_at
                    ELSE excluded.started_at END,
                completed_at = CASE
                    WHEN mailbox_actions.outcome IN ('moved', 'already_junk', 'not_found')
                         OR (mailbox_actions.retryable = 0 AND NOT (
                             mailbox_actions.outcome = 'claimed'
                             AND mailbox_actions.operation_id IS excluded.operation_id))
                        THEN mailbox_actions.completed_at
                    ELSE excluded.completed_at END
            """,
            (
                subscription_id,
                message_ref_id,
                operation_id,
                action_key,
                action,
                outcome,
                source_mailbox,
                target_mailbox,
                int(dry_run),
                int(retryable),
                error_code,
                detail_redacted,
                started,
                completed,
                completed,
            ),
        )
        row = conn.execute(
            """
            SELECT * FROM mailbox_actions
            WHERE message_ref_id = ? AND action_key = ?
            """,
            (message_ref_id, action_key),
        ).fetchone()
        assert row is not None
        return dict(row)


def list_mailbox_actions(
    *,
    subscription_id: int | None = None,
    outcome: str | None = None,
    limit: int = 500,
) -> list[dict[str, Any]]:
    if limit < 1:
        return []
    clauses: list[str] = []
    params: list[Any] = []
    if subscription_id is not None:
        clauses.append("subscription_id = ?")
        params.append(subscription_id)
    if outcome is not None:
        clauses.append("outcome = ?")
        params.append(outcome)
    where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
    params.append(limit)
    with get_db() as conn:
        rows = conn.execute(
            f"SELECT * FROM mailbox_actions{where} ORDER BY created_at DESC, id DESC LIMIT ?",
            params,
        ).fetchall()
        return [dict(row) for row in rows]


def get_operation_metrics(
    *, account: str | None = None, since: datetime | str | None = None
) -> dict[str, int]:
    """Return one count for every grouped outcome, including zeroes."""
    clauses = ["o.outcome IS NOT NULL"]
    params: list[Any] = []
    if account is not None:
        clauses.append("s.account = ?")
        params.append(account.strip())
    if since is not None:
        clauses.append("o.created_at >= ?")
        params.append(_iso_timestamp(since))
    metrics = {outcome: 0 for outcome in _OPERATION_OUTCOMES}
    with get_db() as conn:
        rows = conn.execute(
            f"""
            SELECT o.outcome, COUNT(*) AS count
            FROM unsubscribe_operations o
            JOIN subscriptions s ON s.id = o.subscription_id
            WHERE {" AND ".join(clauses)}
            GROUP BY o.outcome
            """,
            params,
        ).fetchall()
    for row in rows:
        metrics[row["outcome"]] = row["count"]
    return metrics


def get_grouped_metrics(
    *, account: str | None = None, since: datetime | str | None = None
) -> dict[str, Any]:
    """Return grouped operation, attempt, mailbox, and review metrics."""
    operation_metrics = get_operation_metrics(account=account, since=since)
    attempt_clauses: list[str] = []
    action_clauses: list[str] = []
    params: list[Any] = []
    action_params: list[Any] = []
    if account is not None:
        attempt_clauses.append("s.account = ?")
        action_clauses.append("s.account = ?")
        params.append(account.strip())
        action_params.append(account.strip())
    if since is not None:
        stamp = _iso_timestamp(since)
        attempt_clauses.append("a.attempted_at >= ?")
        action_clauses.append("ma.created_at >= ?")
        params.append(stamp)
        action_params.append(stamp)
    attempt_where = f"WHERE {' AND '.join(attempt_clauses)}" if attempt_clauses else ""
    action_where = f"WHERE {' AND '.join(action_clauses)}" if action_clauses else ""
    with get_db() as conn:
        attempt_rows = conn.execute(
            f"""
            SELECT a.outcome, COUNT(*) AS count
            FROM unsubscribe_attempts a
            JOIN unsubscribe_operations o ON o.id = a.operation_id
            JOIN subscriptions s ON s.id = o.subscription_id
            {attempt_where} GROUP BY a.outcome
            """,
            params,
        ).fetchall()
        action_rows = conn.execute(
            f"""
            SELECT ma.outcome, COUNT(*) AS count
            FROM mailbox_actions ma
            JOIN subscriptions s ON s.id = ma.subscription_id
            {action_where} GROUP BY ma.outcome
            """,
            action_params,
        ).fetchall()
        review_params: list[Any] = []
        review_where = "WHERE last_outcome = 'needs_user'"
        if account is not None:
            review_where += " AND account = ?"
            review_params.append(account.strip())
        manual = conn.execute(
            f"SELECT COUNT(*) AS count FROM subscriptions {review_where}",
            review_params,
        ).fetchone()["count"]
    return {
        "operations": operation_metrics,
        "attempts": {row["outcome"]: row["count"] for row in attempt_rows},
        "mailbox_actions": {row["outcome"]: row["count"] for row in action_rows},
        "manual_actions": manual,
    }


def _ensure_legacy_sender(conn: sqlite3.Connection, domain: str) -> None:
    """Keep permissive v1 logging APIs valid with foreign keys enabled."""
    now = _iso_timestamp()
    conn.execute(
        """
        INSERT INTO senders (domain, first_seen, last_seen)
        VALUES (?, ?, ?)
        ON CONFLICT(domain) DO NOTHING
        """,
        (domain, now, now),
    )


def upsert_sender(
    domain: str,
    total_emails: int,
    seen_emails: int,
    sample_subjects: list[str],
    has_unsubscribe: bool,
    first_seen: datetime | None = None,
    last_seen: datetime | None = None,
) -> None:
    """Insert or update a sender record."""
    with get_db() as conn:
        now = datetime.now(UTC).isoformat()
        first = first_seen.isoformat() if first_seen else now
        last = last_seen.isoformat() if last_seen else now
        subjects_json = "|".join(sample_subjects[:5])  # Store up to 5 samples

        conn.execute(
            """
            INSERT INTO senders (domain, first_seen, last_seen, total_emails, seen_emails, sample_subjects, has_unsubscribe)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(domain) DO UPDATE SET
                last_seen = excluded.last_seen,
                total_emails = excluded.total_emails,
                seen_emails = excluded.seen_emails,
                sample_subjects = excluded.sample_subjects,
                has_unsubscribe = excluded.has_unsubscribe
        """,
            (domain, first, last, total_emails, seen_emails, subjects_json, int(has_unsubscribe)),
        )


def update_sender_status(domain: str, status: SenderStatus) -> None:
    """Update the status of a sender."""
    with get_db() as conn:
        conn.execute("UPDATE senders SET status = ? WHERE domain = ?", (status.value, domain))


def update_sender_classification(domain: str, classification: str, confidence: float) -> None:
    """Update the AI classification of a sender."""
    with get_db() as conn:
        conn.execute(
            "UPDATE senders SET ai_classification = ?, ai_confidence = ? WHERE domain = ?",
            (classification, confidence, domain),
        )


def set_user_override(domain: str, action: str) -> None:
    """Set a user override for a sender."""
    with get_db() as conn:
        conn.execute("UPDATE senders SET user_override = ? WHERE domain = ?", (action, domain))


def get_sender(domain: str) -> dict | None:
    """Get a sender by domain."""
    with get_db() as conn:
        row = conn.execute("SELECT * FROM senders WHERE domain = ?", (domain,)).fetchone()
        return dict(row) if row else None


def get_senders_by_status(status: SenderStatus) -> list[dict]:
    """Get all senders with a specific status."""
    with get_db() as conn:
        rows = conn.execute(
            "SELECT * FROM senders WHERE status = ? ORDER BY total_emails DESC", (status.value,)
        ).fetchall()
        return [dict(row) for row in rows]


# Senders that still need a decision or retry. Unclassified senders count only
# while the user hasn't decided; failed unsubscribes always count (so a retry
# that fails again stays visible) until they succeed or are re-categorized.
_REVIEW_PREDICATE = "(status = 'unknown' AND user_override IS NULL) OR status = 'failed'"


def get_senders_for_review() -> list[dict]:
    """Get senders that need manual review, including failed unsubscribes."""
    with get_db() as conn:
        rows = conn.execute(f"""
            SELECT * FROM senders
            WHERE {_REVIEW_PREDICATE}
            ORDER BY total_emails DESC
        """).fetchall()
        return [dict(row) for row in rows]


def log_unsub_attempt(
    domain: str,
    success: bool,
    method: UnsubMethod | None,
    http_status: int | None = None,
    error: str | None = None,
    response_snippet: str | None = None,
    needs_confirmation: bool = False,
) -> None:
    """Log an unsubscribe attempt."""
    with get_db() as conn:
        _ensure_legacy_sender(conn, domain)
        conn.execute(
            """
            INSERT INTO unsub_log (domain, attempted_at, success, method, http_status, error, response_snippet, needs_confirmation)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
            (
                domain,
                datetime.now(UTC).isoformat(),
                int(success),
                method.value if method else None,
                http_status,
                error,
                response_snippet,
                int(needs_confirmation),
            ),
        )


def log_correction(domain: str, ai_decision: str, user_decision: str) -> None:
    """Log a user correction to an AI decision."""
    with get_db() as conn:
        _ensure_legacy_sender(conn, domain)
        conn.execute(
            """
            INSERT INTO corrections (domain, ai_decision, user_decision, timestamp)
            VALUES (?, ?, ?, ?)
        """,
            (domain, ai_decision, user_decision, datetime.now(UTC).isoformat()),
        )


def get_recent_corrections(limit: int = 20) -> list[dict]:
    """Get recent user corrections for AI learning."""
    with get_db() as conn:
        rows = conn.execute(
            """
            SELECT * FROM corrections
            ORDER BY timestamp DESC
            LIMIT ?
        """,
            (limit,),
        ).fetchall()
        return [dict(row) for row in rows]


def log_run(stats: RunStats) -> int | None:
    """Log a run and return its ID (or None if insert failed)."""
    with get_db() as conn:
        cursor = conn.execute(
            """
            INSERT INTO runs (ran_at, mode, emails_scanned, unique_senders, auto_unsubbed, kept, review_queued, failed)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
            (
                stats.ran_at.isoformat(),
                stats.mode,
                stats.emails_scanned,
                stats.unique_senders,
                stats.auto_unsubbed,
                stats.kept,
                stats.review_queued,
                stats.failed,
            ),
        )
        return cursor.lastrowid


def get_recent_runs(limit: int = 10) -> list[dict]:
    """Get recent runs."""
    with get_db() as conn:
        rows = conn.execute(
            """
            SELECT * FROM runs ORDER BY ran_at DESC LIMIT ?
        """,
            (limit,),
        ).fetchall()
        return [dict(row) for row in rows]


def get_recent_unsubscribes(days: int = 30) -> list[dict]:
    """Get recent successful unsubscribes."""
    with get_db() as conn:
        rows = conn.execute(
            """
            SELECT s.domain, s.total_emails, u.attempted_at, u.method
            FROM unsub_log u
            JOIN senders s ON u.domain = s.domain
            WHERE u.success = 1
            AND datetime(u.attempted_at) > datetime('now', ?)
            ORDER BY u.attempted_at DESC
        """,
            (f"-{days} days",),
        ).fetchall()
        return [dict(row) for row in rows]


def get_post_unsub_offenders(grace_days: int = 7) -> list[dict]:
    """Find senders still mailing after a successful unsubscribe.

    A sender counts as an offender if its most recent email (last_seen) arrived
    more than grace_days after our last successful unsubscribe attempt. Gmail
    and Yahoo allow senders up to ~48h to honor an unsubscribe, so a modest
    grace window avoids false positives; anything past it is a candidate to
    escalate to block/filter.
    """
    with get_db() as conn:
        rows = conn.execute(
            """
            SELECT s.domain, s.total_emails, s.last_seen,
                   MAX(u.attempted_at) AS unsubscribed_at
            FROM senders s
            JOIN unsub_log u ON u.domain = s.domain
            WHERE s.status = 'unsubscribed' AND u.success = 1
            GROUP BY s.domain
            HAVING datetime(s.last_seen) > datetime(MAX(u.attempted_at), ?)
            ORDER BY s.total_emails DESC
        """,
            (f"+{grace_days} days",),
        ).fetchall()
        return [dict(row) for row in rows]


def get_unsub_success_rate() -> tuple[int, int]:
    """Get unsubscribe success and failure counts.

    Returns:
        Tuple of (successful_count, failed_count)
    """
    with get_db() as conn:
        row = conn.execute(
            """
            SELECT
                COALESCE(SUM(CASE WHEN success = 1 THEN 1 ELSE 0 END), 0) as successful,
                COALESCE(SUM(CASE WHEN success = 0 THEN 1 ELSE 0 END), 0) as failed
            FROM unsub_log
        """
        ).fetchone()
        return (row["successful"], row["failed"]) if row else (0, 0)


def add_rule(
    pattern: str,
    action: str,
    *,
    priority: int = 100,
    source: str = "user",
    match_type: str = "pattern",
) -> None:
    """Add a user rule."""
    if match_type not in ("pattern", "exact"):
        raise ValueError("match_type must be pattern or exact")
    with get_db() as conn:
        conn.execute(
            """
            INSERT INTO rules (pattern, action, created_at, priority, source, match_type)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(pattern) DO UPDATE SET
                action = excluded.action,
                created_at = excluded.created_at,
                priority = excluded.priority,
                source = excluded.source,
                match_type = excluded.match_type
        """,
            (pattern, action, datetime.now(UTC).isoformat(), priority, source, match_type),
        )


def get_rules() -> list[dict]:
    """Get all user rules."""
    with get_db() as conn:
        rows = conn.execute("SELECT * FROM rules ORDER BY priority DESC, created_at, id").fetchall()
        return [dict(row) for row in rows]


def delete_rule(pattern: str) -> bool:
    """Delete a user rule."""
    with get_db() as conn:
        cursor = conn.execute("DELETE FROM rules WHERE pattern = ?", (pattern,))
        return cursor.rowcount > 0


def get_stats() -> dict:
    """Get overall statistics."""
    with get_db() as conn:
        senders = conn.execute("SELECT COUNT(*) as count FROM senders").fetchone()
        unsubbed = conn.execute(
            "SELECT COUNT(*) as count FROM senders WHERE status = 'unsubscribed'"
        ).fetchone()
        kept = conn.execute(
            "SELECT COUNT(*) as count FROM senders WHERE status = 'keep'"
        ).fetchone()
        review = conn.execute(
            f"SELECT COUNT(*) as count FROM senders WHERE {_REVIEW_PREDICATE}"
        ).fetchone()
        runs = conn.execute("SELECT COUNT(*) as count FROM runs").fetchone()
        last_run = conn.execute("SELECT ran_at FROM runs ORDER BY ran_at DESC LIMIT 1").fetchone()

        return {
            "total_senders": senders["count"],
            "unsubscribed": unsubbed["count"],
            "kept": kept["count"],
            "pending_review": review["count"],
            "total_runs": runs["count"],
            "last_run": last_run["ran_at"] if last_run else None,
        }


def get_all_senders(status_filter: str | None = None, sort_by: str = "last_seen") -> list[dict]:
    """Get all senders with optional filtering and sorting.

    Args:
        status_filter: Filter by status (keep, unsubscribed, blocked, unknown)
        sort_by: Sort by 'emails', 'domain', or 'last_seen' (default)
    """
    with get_db() as conn:
        query = "SELECT * FROM senders"
        params: list = []

        if status_filter:
            query += " WHERE status = ?"
            params.append(status_filter)

        sort_map = {
            "emails": "total_emails DESC",
            "domain": "domain ASC",
            "last_seen": "last_seen DESC",
        }
        order = sort_map.get(sort_by, "last_seen DESC")
        query += f" ORDER BY {order}"

        rows = conn.execute(query, params).fetchall()
        return [dict(row) for row in rows]


def search_senders(pattern: str) -> list[dict]:
    """Search senders by domain pattern."""
    with get_db() as conn:
        rows = conn.execute(
            """
            SELECT * FROM senders
            WHERE domain LIKE ?
            ORDER BY total_emails DESC
        """,
            (f"%{pattern}%",),
        ).fetchall()
        return [dict(row) for row in rows]


def get_activity_log(limit: int = 50, failures_only: bool = False) -> list[dict]:
    """Get recent activity log combining runs and unsubscribe attempts.

    Args:
        limit: Maximum number of entries to return
        failures_only: If True, only return failed unsubscribe attempts (skips runs)

    Returns a unified log of activity sorted by timestamp.
    """
    with get_db() as conn:
        all_activity: list[dict] = []

        # Get runs (skip when showing failures only, since runs aren't "failures")
        if not failures_only:
            runs = conn.execute(
                """
                SELECT
                    'run' as type,
                    ran_at as timestamp,
                    emails_scanned,
                    unique_senders,
                    auto_unsubbed,
                    failed,
                    mode
                FROM runs
                ORDER BY ran_at DESC
                LIMIT ?
            """,
                (limit,),
            ).fetchall()
            all_activity.extend(dict(row) for row in runs)

        # Get unsubscribe attempts
        unsub_query = """
            SELECT
                'unsub' as type,
                attempted_at as timestamp,
                domain,
                success,
                method,
                error
            FROM unsub_log
        """
        if failures_only:
            unsub_query += " WHERE success = 0"
        unsub_query += " ORDER BY attempted_at DESC LIMIT ?"

        unsubs = conn.execute(unsub_query, (limit,)).fetchall()
        all_activity.extend(dict(row) for row in unsubs)

        # Combine and sort
        all_activity.sort(key=lambda x: x["timestamp"], reverse=True)

        return all_activity[:limit]


def reset_database(keep_config: bool = False) -> tuple[int, int]:
    """Clear all data from the database.

    Args:
        keep_config: If True, keep rules table (not currently used as rules are in DB)

    Returns:
        Tuple of (senders_deleted, unsub_logs_deleted)
    """
    with get_db() as conn:
        senders = conn.execute("SELECT COUNT(*) as count FROM senders").fetchone()["count"]
        unsubs = conn.execute("SELECT COUNT(*) as count FROM unsub_log").fetchone()["count"]

        # Delete children before parents now that foreign-key enforcement is on.
        conn.execute("DELETE FROM mailbox_actions")
        conn.execute("DELETE FROM unsubscribe_attempts")
        conn.execute("DELETE FROM unsubscribe_operations")
        conn.execute("DELETE FROM message_refs")
        conn.execute("DELETE FROM subscriptions")
        conn.execute("DELETE FROM mailbox_state")
        conn.execute("DELETE FROM unsub_log")
        conn.execute("DELETE FROM corrections")
        conn.execute("DELETE FROM user_actions")
        conn.execute("DELETE FROM senders")
        conn.execute("DELETE FROM runs")
        conn.execute("DELETE FROM user_preferences")

        if not keep_config:
            conn.execute("DELETE FROM rules")

        return (senders, unsubs)


# ============================================================================
# User Learning System
# ============================================================================


def log_user_action(action: UserAction) -> None:
    """Log a user action for learning."""
    with get_db() as conn:
        _ensure_legacy_sender(conn, action.domain)
        conn.execute(
            """
            INSERT INTO user_actions (domain, action, ai_recommendation, heuristic_score, open_rate, email_count, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
            (
                action.domain,
                action.action.value,
                action.ai_recommendation.value if action.ai_recommendation else None,
                action.heuristic_score,
                action.open_rate,
                action.email_count,
                action.timestamp.isoformat(),
            ),
        )


def get_user_actions(
    days: int | None = None,
    limit: int = 100,
    action_filter: Action | None = None,
) -> list[UserAction]:
    """Get user actions for learning analysis.

    Args:
        days: Only return actions from the last N days
        limit: Maximum number of actions to return
        action_filter: Filter by specific action type
    """
    with get_db() as conn:
        query = "SELECT * FROM user_actions WHERE 1=1"
        params: list = []

        if days is not None:
            query += " AND datetime(timestamp) > datetime('now', ?)"
            params.append(f"-{days} days")

        if action_filter is not None:
            query += " AND action = ?"
            params.append(action_filter.value)

        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)

        rows = conn.execute(query, params).fetchall()

        return [
            UserAction(
                domain=row["domain"],
                action=Action(row["action"]),
                timestamp=datetime.fromisoformat(row["timestamp"]),
                ai_recommendation=Action(row["ai_recommendation"])
                if row["ai_recommendation"]
                else None,
                heuristic_score=row["heuristic_score"],
                open_rate=row["open_rate"],
                email_count=row["email_count"],
            )
            for row in rows
        ]


def get_user_actions_by_domain_pattern(pattern: str) -> list[UserAction]:
    """Get user actions for domains matching a pattern (for learning keyword associations)."""
    with get_db() as conn:
        rows = conn.execute(
            """
            SELECT * FROM user_actions
            WHERE domain LIKE ?
            ORDER BY timestamp DESC
        """,
            (f"%{pattern}%",),
        ).fetchall()

        return [
            UserAction(
                domain=row["domain"],
                action=Action(row["action"]),
                timestamp=datetime.fromisoformat(row["timestamp"]),
                ai_recommendation=Action(row["ai_recommendation"])
                if row["ai_recommendation"]
                else None,
                heuristic_score=row["heuristic_score"],
                open_rate=row["open_rate"],
                email_count=row["email_count"],
            )
            for row in rows
        ]


def get_action_count() -> int:
    """Get total number of logged user actions."""
    with get_db() as conn:
        row = conn.execute("SELECT COUNT(*) as count FROM user_actions").fetchone()
        return row["count"] if row else 0


def get_user_preference(feature: str) -> UserPreference | None:
    """Get a specific user preference."""
    with get_db() as conn:
        row = conn.execute(
            "SELECT * FROM user_preferences WHERE feature = ?", (feature,)
        ).fetchone()

        if not row:
            return None

        return UserPreference(
            feature=row["feature"],
            value=row["value"],
            confidence=row["confidence"],
            sample_count=row["sample_count"],
            source=row["source"] or "learned",
            last_updated=datetime.fromisoformat(row["last_updated"]),
        )


def set_user_preference(pref: UserPreference) -> None:
    """Set or update a user preference."""
    with get_db() as conn:
        conn.execute(
            """
            INSERT INTO user_preferences (feature, value, confidence, sample_count, source, last_updated)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(feature) DO UPDATE SET
                value = excluded.value,
                confidence = excluded.confidence,
                sample_count = excluded.sample_count,
                source = excluded.source,
                last_updated = excluded.last_updated
        """,
            (
                pref.feature,
                pref.value,
                pref.confidence,
                pref.sample_count,
                pref.source,
                pref.last_updated.isoformat(),
            ),
        )


def get_all_preferences() -> list[UserPreference]:
    """Get all user preferences."""
    with get_db() as conn:
        rows = conn.execute("SELECT * FROM user_preferences ORDER BY feature").fetchall()

        return [
            UserPreference(
                feature=row["feature"],
                value=row["value"],
                confidence=row["confidence"],
                sample_count=row["sample_count"],
                source=row["source"] or "learned",
                last_updated=datetime.fromisoformat(row["last_updated"]),
            )
            for row in rows
        ]


def get_preferences_by_prefix(prefix: str) -> list[UserPreference]:
    """Get preferences matching a prefix (e.g., 'keyword:' for all keyword preferences)."""
    with get_db() as conn:
        rows = conn.execute(
            "SELECT * FROM user_preferences WHERE feature LIKE ? ORDER BY feature",
            (f"{prefix}%",),
        ).fetchall()

        return [
            UserPreference(
                feature=row["feature"],
                value=row["value"],
                confidence=row["confidence"],
                sample_count=row["sample_count"],
                source=row["source"] or "learned",
                last_updated=datetime.fromisoformat(row["last_updated"]),
            )
            for row in rows
        ]


def delete_user_preference(feature: str) -> bool:
    """Delete a user preference."""
    with get_db() as conn:
        cursor = conn.execute("DELETE FROM user_preferences WHERE feature = ?", (feature,))
        return cursor.rowcount > 0


def get_learning_stats() -> dict:
    """Get statistics about the learning system."""
    with get_db() as conn:
        actions = conn.execute("SELECT COUNT(*) as count FROM user_actions").fetchone()
        preferences = conn.execute("SELECT COUNT(*) as count FROM user_preferences").fetchone()
        corrections = conn.execute(
            """
            SELECT COUNT(*) as count FROM user_actions
            WHERE ai_recommendation IS NOT NULL AND action != ai_recommendation
        """
        ).fetchone()

        # Action breakdown
        keep_count = conn.execute(
            "SELECT COUNT(*) as count FROM user_actions WHERE action = 'keep'"
        ).fetchone()
        unsub_count = conn.execute(
            "SELECT COUNT(*) as count FROM user_actions WHERE action = 'unsub'"
        ).fetchone()
        block_count = conn.execute(
            "SELECT COUNT(*) as count FROM user_actions WHERE action = 'block'"
        ).fetchone()

        return {
            "total_actions": actions["count"] if actions else 0,
            "total_preferences": preferences["count"] if preferences else 0,
            "total_corrections": corrections["count"] if corrections else 0,
            "keep_actions": keep_count["count"] if keep_count else 0,
            "unsub_actions": unsub_count["count"] if unsub_count else 0,
            "block_actions": block_count["count"] if block_count else 0,
        }
