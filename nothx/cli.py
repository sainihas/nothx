"""Command-line interface for nothx."""

import csv
import hashlib
import imaplib
import json
import logging
import re
import subprocess
import sys
import uuid
import webbrowser
from collections.abc import Iterator
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from typing import Any, cast

import click
import humanize
import questionary
from questionary import Style as QStyle
from rich.columns import Columns
from rich.markup import escape
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TaskProgressColumn,
    TextColumn,
    TimeElapsedColumn,
)
from rich.rule import Rule
from rich.table import Table
from rich.tree import Tree

from . import __version__, db, msauth
from .classifier import ClassificationEngine, get_learner
from .classifier.ai import test_ai_connection
from .classifier.heuristics import (
    has_explicit_offer_subject,
    has_promotional_subject,
    has_protected_subject,
)
from .config import (
    CLEANUP_LEVELS,
    CONSENT_REVOKED,
    CURRENT_MAILBOX_MUTATION_CONSENT_VERSION,
    CURRENT_UNSUBSCRIBE_CONSENT_VERSION,
    AccountConfig,
    Config,
    get_config_dir,
)
from .errors import ErrorCode, IMAPError, OAuthError
from .imap import IMAPConnection, test_account
from .mailbox import validate_uid_locator
from .models import (
    Action,
    Classification,
    EmailHeader,
    EmailType,
    MessageRef,
    RunStats,
    SenderStats,
    SenderStatus,
    UnsubResult,
    UnsubscribeOutcome,
    UserAction,
)
from .safefetch import redacted_url
from .scanner import MailboxCoverage, scan_inbox
from .scheduler import get_schedule_status, install_schedule, uninstall_schedule
from .theme import console, print_animated_welcome
from .timeutil import ensure_utc, utcnow
from .unsubscriber import (
    UnsafeUnsubscribeError,
    contact_suppression_reason,
    is_contact_permitted,
    unsubscribe_subscription,
)

logger = logging.getLogger(__name__)

DORMANT_SENDER_DAYS = 365


# Questionary style — orange1 highlight matching our logo color
Q_STYLE = QStyle(
    [
        ("highlighted", "fg:#ffaf00"),
        ("pointer", "fg:#ffaf00"),
        ("selected", "fg:#ffaf00"),
        ("qmark", "fg:#ffaf00"),
        ("answer", "fg:#ffaf00"),
    ]
)
Q_POINTER = "›"
Q_COMMON: dict[str, Any] = {
    "instruction": " ",
    "style": Q_STYLE,
    "pointer": Q_POINTER,
    "qmark": "",
}

# Style for text/password prompts — label goes in qmark for column-0 alignment
Q_INPUT_STYLE = QStyle(
    [
        ("qmark", "bold fg:#a0a0a0"),  # match header style
        ("answer", "fg:#ffaf00"),
        ("text", "fg:#ffaf00"),
    ]
)

# Vertical line prefix for indented content under section headers
_L = "[muted]│[/muted]"

# Upper bound on one manual-review page. High enough that a real queue fits in
# one pass; a queue that hits it is reported as truncated rather than as a total.


def _key(k: str) -> str:
    """Render a single keycap with rounded pill shape using half-block edges."""
    return f"[#505050]▐[/][#808080 on #505050] {k} [/][#505050]▌[/]"


_key_hints_shown = False


def _styled_select(choices: list, **kwargs) -> str | None:
    """Run a styled questionary.select, replacing answer line with ✓ confirmation."""
    result = questionary.select(
        "",
        choices=choices,
        instruction=" ",
        style=Q_STYLE,
        qmark="",
        pointer=Q_POINTER,
        **kwargs,
    ).ask()
    if result is not None:
        # Find display label from Choice objects or plain strings
        label = str(result)
        for c in choices:
            if isinstance(c, questionary.Choice) and c.value == result:
                label = str(c.title) if c.title is not None else label
                break
        # Overwrite questionary's answer line with styled ✓ version
        # The \n ensures 1 blank line between the preceding header and ✓,
        # matching the gap questionary's blank prompt provided during browsing.
        console.file.write("\033[1A\033[2K\r")
        console.file.flush()
        console.print(f"{_L}\n{_L} [green]✓ {label}[/green]")
    return result


def _select_header(label: str) -> None:
    """Print a section header with key hints on first call, plain header after."""
    global _key_hints_shown
    if not _key_hints_shown:
        _key_hints_shown = True
        console.print(
            f"\n\n[header]{label}[/header]    "
            f"{_key('↑')} {_key('↓')} [dim]navigate[/dim]  "
            f"{_key('⏎')} [dim]select[/dim]"
        )
    else:
        console.print(f"\n[header]{label}[/header]")


def _styled_confirm(message: str, default: bool = True) -> bool:
    """Styled yes/no selector matching the overall UI style."""
    console.print(f"\n[header]{message}[/header]")
    choices = [
        questionary.Choice("Yes", value="yes"),
        questionary.Choice("No", value="no"),
    ]
    result = _styled_select(choices)
    return result == "yes"


def _attempt_unsubscribe_for_domain(config: Config, domain: str, sender: dict) -> UnsubResult:
    """Safely resolve one domain-only choice to a real account/list operation."""
    from .scanner import _stats_for_emails, get_emails_for_domain

    del sender  # Compatibility argument; real identity comes from rescanned messages.

    if not config.permits_unsubscribe:
        result = UnsubResult(
            success=False,
            method=None,
            error="Current versioned unsubscribe-contact consent is required",
            needs_confirmation=True,
            outcome=UnsubscribeOutcome.NEEDS_USER,
        )
        console.print(f"{_L} [warning]{result.error}; no request was sent[/warning]")
        return result

    persisted = [
        subscription
        for subscription in db.list_subscriptions(limit=10_000)
        if (subscription.get("sender_domain") or "").casefold() == domain.casefold()
    ]
    if any(
        subscription.get("policy_action") == "block"
        or subscription.get("last_outcome") == "blocked"
        or _subscription_has_persisted_threat(subscription["id"])
        for subscription in persisted
    ):
        result = UnsubResult(
            success=False,
            method=None,
            error=(
                "A matching account/list identity is blocked or has persisted "
                "Junk/phishing evidence"
            ),
            outcome=UnsubscribeOutcome.BLOCKED,
        )
        console.print(f"{_L} [warning]{result.error}; no request was sent[/warning]")
        return result
    if len(persisted) > 1:
        result = UnsubResult(
            success=False,
            method=None,
            error=(
                "This domain contains multiple account/list identities; use `nothx review` "
                "to choose one without merging subscriptions"
            ),
            needs_confirmation=True,
            outcome=UnsubscribeOutcome.NEEDS_USER,
        )
        console.print(f"{_L} [warning]{result.error}; no request was sent[/warning]")
        return result

    console.print(f"{_L} [muted]Fetching recent email for {domain}...[/muted]")
    try:
        emails = get_emails_for_domain(config, domain)
    except (IMAPError, OSError) as error:
        console.print(f"{_L} [error]Could not reach mailbox for {domain}: {error}[/error]")
        db.update_sender_status(domain, SenderStatus.FAILED)
        return UnsubResult(
            success=False,
            method=None,
            error="Mailbox lookup failed",
            outcome=UnsubscribeOutcome.FAILED,
        )

    if not emails:
        console.print(
            f"{_L} [warning]No unsubscribe link found for {domain}; marked failed[/warning]"
        )
        db.update_sender_status(domain, SenderStatus.FAILED)
        return UnsubResult(
            success=False,
            method=None,
            error="No unsubscribe method available",
            outcome=UnsubscribeOutcome.FAILED,
        )

    # Test doubles and older adapters may omit the canonical account key while
    # retaining the configured alias. Resolve that alias first; only fall back
    # to the sole configured account when there is no alias at all.
    for header in emails:
        if not header.account_key and header.account_name:
            if resolved_account := config.get_account(header.account_name):
                header.account_key = resolved_account.email.casefold()
    if len(config.accounts) == 1:
        account_name, sole_account = next(iter(config.accounts.items()))
        for header in emails:
            header.account_name = header.account_name or account_name
            header.account_key = header.account_key or sole_account.email.casefold()

    grouped: dict[str, list[EmailHeader]] = {}
    for header in emails:
        grouped.setdefault(header.subscription_identity.key, []).append(header)

    manual_classification = Classification(
        email_type=EmailType.MARKETING,
        action=Action.UNSUB,
        confidence=1.0,
        reasoning="Explicit domain-level unsubscribe choice",
        source="user_rule",
    )
    if len(grouped) != 1:
        for headers in grouped.values():
            stats = _stats_for_emails(domain, headers)
            identity = headers[0].subscription_identity
            existing_group = db.get_subscription(
                account=identity.account_key,
                identity_kind=identity.kind,
                identity_value=identity.value,
            )
            subscription, _messages = _persist_subscription_records(
                stats,
                headers,
                manual_classification,
            )
            if existing_group is None:
                db.set_subscription_policy(subscription["id"], "review")
        result = UnsubResult(
            success=False,
            method=None,
            error=(
                "The rescan found multiple account/list identities; use `nothx review` "
                "to choose one without contacting every list at this domain"
            ),
            needs_confirmation=True,
            outcome=UnsubscribeOutcome.NEEDS_USER,
        )
        console.print(f"{_L} [warning]{result.error}; no request was sent[/warning]")
        return result

    headers = next(iter(grouped.values()))
    stats = _stats_for_emails(domain, headers)
    identity = headers[0].subscription_identity
    existing = db.get_subscription(
        account=identity.account_key,
        identity_kind=identity.kind,
        identity_value=identity.value,
    )
    if existing is not None and (
        existing.get("policy_action") == "block"
        or existing.get("last_outcome") == "blocked"
        or _subscription_has_persisted_threat(existing["id"])
    ):
        result = UnsubResult(
            success=False,
            method=None,
            error="This account/list identity is blocked or has persisted threat evidence",
            outcome=UnsubscribeOutcome.BLOCKED,
        )
        console.print(f"{_L} [warning]{result.error}; no request was sent[/warning]")
        return result

    subscription, messages = _persist_subscription_records(
        stats,
        headers,
        manual_classification,
    )
    execute, exclusions, retry_generation, escalate = _unsubscribe_operation_plan(subscription)
    consent_resume = _is_unsubscribe_consent_resume(subscription, config)
    if escalate:
        result = UnsubResult(
            success=False,
            method=None,
            error="This subscription exhausted its safe retry and must be blocked",
            outcome=UnsubscribeOutcome.BLOCKED,
        )
        db.set_subscription_policy(subscription["id"], "block", source="automatic")
        console.print(f"{_L} [warning]{result.error}; no request was sent[/warning]")
        return result
    if not execute:
        result = UnsubResult(
            success=False,
            method=None,
            error="A request is already accepted, in grace, or awaiting manual action",
            needs_confirmation=True,
            outcome=UnsubscribeOutcome.NEEDS_USER,
        )
        console.print(f"{_L} [warning]{result.error}; no duplicate request was sent[/warning]")
        return result

    claim_owner = uuid.uuid4().hex
    operation, acquired = db.claim_unsubscribe_operation(
        subscription["id"],
        _operation_key("unsubscribe", stats, headers),
        claim_owner,
        allow_consent_resume=consent_resume,
        trigger_message_ref_id=messages[0][1]["id"] if messages else None,
        retry_generation=retry_generation,
    )
    if not acquired:
        result = UnsubResult(
            success=False,
            method=None,
            error="Another process already claimed or completed this unsubscribe source",
            needs_confirmation=True,
            outcome=UnsubscribeOutcome.NEEDS_USER,
        )
        console.print(f"{_L} [warning]{result.error}; no duplicate request was sent[/warning]")
        return result

    denied_header = next(
        (header for header in headers if not is_contact_permitted(header, config)),
        None,
    )
    if denied_header is not None:
        reason = contact_suppression_reason(denied_header) or "Contact is not permitted"
        outcome = (
            UnsubscribeOutcome.BLOCKED
            if denied_header.server_junk or denied_header.server_phishing
            else UnsubscribeOutcome.NEEDS_USER
        )
        result = UnsubResult(
            success=False,
            method=None,
            error=reason,
            needs_confirmation=outcome is UnsubscribeOutcome.NEEDS_USER,
            outcome=outcome,
        )
    else:
        account = _matching_account(config, headers)
        result = unsubscribe_subscription(
            headers,
            config,
            account,
            automatic=False,
            exclude_fingerprints=exclusions,
        )
    _record_unsubscribe_result(
        stats,
        headers,
        manual_classification,
        result,
        retry_generation=retry_generation,
        operation_id=operation["id"],
        claim_owner=claim_owner,
    )
    if result.success:
        db.set_subscription_policy(subscription["id"], "unsub")

    if result.success:
        console.print(f"{_L} [unsubscribe]→ Unsubscribed[/unsubscribe]")
    elif result.needs_confirmation:
        detail = result.error or "Manual action is required"
        console.print(f"{_L} [warning]{detail}; no further request was sent[/warning]")
    else:
        console.print(f"{_L} [error]Unsubscribe failed: {result.error}[/error]")
    return result


def _redact_failure_detail(detail: str | None) -> str | None:
    """Keep useful failure text while removing destinations and opaque tokens."""
    if not detail:
        return None
    redacted = re.sub(r"(?i)https?://[^\s)>]+", "[redacted URL]", detail)
    redacted = re.sub(r"(?i)mailto:[^\s)>]+", "[redacted mailto]", redacted)
    return redacted[:500]


def _redacted_destination(target: str) -> str:
    """Use the centralized token-safe URL renderer."""
    return redacted_url(target)


def _safe_persisted_destination(target: str | None) -> str | None:
    """Mask token-bearing paths before destination metadata reaches SQLite."""
    if not target:
        return None
    if target.casefold().startswith("mailto:"):
        return "mailto:[redacted]"
    return _redacted_destination(target)


def _subscription_label(sender: SenderStats) -> str:
    """Return a human-readable, account-scoped subscription label."""
    account = sender.account_key or "unknown account"
    if sender.identity_kind == "list_id" and sender.identity_value:
        identity = f"List-Id {sender.identity_value}"
    elif sender.identity_value:
        identity = sender.identity_value
    else:
        identity = sender.domain
    return f"{account} · {identity}"


def _manual_classification(original: Classification, action: Action) -> Classification:
    """Keep model attribution separate from a confirmed local user choice."""
    return Classification(
        email_type=original.email_type,
        action=action,
        confidence=1.0,
        reasoning="Explicit choice during scan review",
        source="user_rule",
        recommended_action=original.recommended_action or original.action,
        original_source=original.original_source or original.source,
    )


def _learn_subscription_policy(subscription: dict[str, Any], action_value: str) -> None:
    """Teach from a manual account/list decision using the actual AI action."""
    domain = subscription.get("sender_domain")
    if not domain:
        return
    if db.get_sender(domain) is None:
        db.upsert_sender(domain, 0, 0, [], False)
    try:
        action = Action(action_value)
    except ValueError:
        return
    recommendation: Action | None = None
    if recommended := subscription.get("ai_recommended_action"):
        try:
            recommendation = Action(recommended)
        except ValueError:
            recommendation = None
    if recommendation is not None and recommendation is not action:
        db.log_correction(domain, recommendation.value, action.value)
    record = UserAction(
        domain=domain,
        action=action,
        timestamp=datetime.now(UTC),
        ai_recommendation=recommendation,
    )
    db.log_user_action(record)
    get_learner().update_from_action(record)


@dataclass(frozen=True)
class StoredEvidence:
    hard_threat: bool
    junk: bool
    inbox: bool
    not_junk: bool


def _stored_folder_evidence(subscription_id: int, *, include_auth: bool = True) -> StoredEvidence:
    """Summarize stored per-message folder and threat evidence for one identity."""
    hard_threat = junk = inbox = not_junk = False
    locally_cleaned = db.get_locally_cleaned_message_keys(subscription_id=subscription_id)
    for message in db.list_message_refs(subscription_id=subscription_id, limit=100_000):
        try:
            flags = json.loads(message.get("flags_json") or "[]")
        except (TypeError, json.JSONDecodeError):
            flags = []
        normalized = {str(flag).casefold() for flag in flags}
        verdict = str(message.get("provider_verdict") or "").casefold()
        # Folder-derived "junk" is soft evidence, not a phishing verdict.
        try:
            auth = json.loads(message.get("auth_evidence_json") or "{}")
        except (TypeError, json.JSONDecodeError):
            auth = {}
        failed_auth = (
            isinstance(auth, dict)
            and auth.get("trusted") is True
            and (
                all(auth.get(method) == "fail" for method in ("spf", "dkim", "dmarc"))
                and auth.get("arc") != "pass"
            )
        )
        is_hard_threat = bool(
            (verdict and verdict != "junk")
            or "$phishing" in normalized
            or (include_auth and failed_auth)
        )
        hard_threat |= is_hard_threat
        is_junk = (
            verdict == "junk"
            or message.get("mailbox_role") == "junk"
            or bool(normalized & {"$junk", r"\junk", "spam", r"\spam"})
        )
        cleanup_identity = message.get("message_id")
        if not cleanup_identity:
            try:
                bulk = json.loads(message.get("bulk_evidence_json") or "{}")
                cleanup_identity = bulk.get("cleanup_identity") if isinstance(bulk, dict) else None
            except (ValueError, TypeError):
                cleanup_identity = None
        if (
            db.message_cleanup_key(
                message["account"],
                cleanup_identity,
                message.get("from_address"),
                message.get("received_at"),
            )
            in locally_cleaned
        ):
            is_junk = False
        junk |= is_junk
        inbox |= message.get("mailbox_role") == "inbox" and not is_junk and not is_hard_threat
        not_junk |= bool(normalized & {"$notjunk", r"\notjunk", "notjunk", "$nonjunk"})
    return StoredEvidence(hard_threat=hard_threat, junk=junk, inbox=inbox, not_junk=not_junk)


def _persisted_threat_action(
    subscription_id: int,
    *,
    folder_evidence: bool = True,
    sender: SenderStats | None = None,
    include_auth: bool = True,
) -> Action | None:
    """Distinguish hard threats from conflicting Inbox/Junk folder evidence."""
    stored = _stored_folder_evidence(subscription_id, include_auth=include_auth)
    hard_threat = stored.hard_threat or bool(
        sender
        and (
            sender.provider_threat
            or sender.phishing_emails
            or (include_auth and sender.authentication_failed_emails)
        )
    )
    junk = stored.junk or bool(sender and (sender.junk_emails or sender.junk_keyword_emails))
    inbox = stored.inbox or bool(sender and sender.clean_inbox_emails)
    not_junk = stored.not_junk or bool(sender and sender.not_junk_emails)
    if hard_threat:
        return Action.REVIEW if folder_evidence and (inbox or not_junk) else Action.BLOCK
    if folder_evidence and junk and not (inbox or not_junk):
        return Action.BLOCK
    return None


def _subscription_has_persisted_threat(subscription_id: int) -> bool:
    """Return whether stored server evidence forbids contacting this sender."""
    return _persisted_threat_action(subscription_id) is not None


def _matching_account(config: Config, headers: list[EmailHeader]) -> AccountConfig | None:
    """Resolve a scanned subscription back to its configured mailbox."""
    if not headers:
        return None
    first = headers[0]
    if first.account_name and (account := config.get_account(first.account_name)):
        return account
    account_key = (first.account_key or "").casefold()
    return next(
        (
            account
            for account in config.accounts.values()
            if account.email.casefold() == account_key
        ),
        None,
    )


def _target_fingerprint(value: str) -> str:
    """Fingerprint an in-memory endpoint without persisting the raw target."""
    return hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()


def _persist_subscription_records(
    sender: SenderStats,
    headers: list[EmailHeader],
    classification: Classification,
    *,
    policy_action: str | None = None,
) -> tuple[dict[str, Any], list[tuple[EmailHeader, dict[str, Any]]]]:
    """Persist one real subscription and its stable message locators."""
    if not headers:
        raise ValueError("A subscription cannot be persisted without a real message")
    fallback_identity = headers[0].subscription_identity
    account_key = sender.account_key or fallback_identity.account_key
    identity_kind = sender.identity_kind or fallback_identity.kind
    identity_value = sender.identity_value or fallback_identity.value
    dates = [header.received_at or header.date for header in headers]
    has_ai_recommendation = classification.source == "ai" or classification.original_source == "ai"
    subscription = db.upsert_subscription(
        account_key,
        identity_kind,
        identity_value,
        list_id=identity_value if identity_kind == "list_id" else headers[0].normalized_list_id,
        from_address=identity_value
        if identity_kind == "from"
        else headers[0].sender_address or None,
        sender_domain=sender.domain,
        policy_action=policy_action,
        policy_source="manual" if classification.source == "user_rule" else "automatic",
        ai_email_type=classification.email_type.value if has_ai_recommendation else None,
        ai_recommended_action=(classification.recommended_action or classification.action).value
        if has_ai_recommendation
        else None,
        classification_source=classification.source,
        unwanted_confidence=classification.confidence,
        first_seen=min(dates),
        last_seen=max(dates),
        last_delivery_at=max(dates),
    )

    persisted: list[tuple[EmailHeader, dict[str, Any]]] = []
    for start in range(0, len(headers), 500):
        batch = headers[start : start + 500]
        with db.metadata_batch():
            for header in batch:
                locator = header.message_ref
                if locator is None:
                    continue
                fingerprints = [
                    _target_fingerprint(target)
                    for target in (
                        *header.list_unsubscribe_targets,
                        *(candidate.uri for candidate in header.footer_unsubscribe_candidates),
                    )
                ]
                auth = header.authentication
                message = db.upsert_message_ref(
                    subscription["id"],
                    locator.account_key,
                    locator.mailbox,
                    header.mailbox_role,
                    locator.uidvalidity,
                    locator.uid,
                    message_id=header.message_id,
                    from_address=header.sender_address or None,
                    list_id=header.normalized_list_id,
                    received_at=header.received_at or header.date,
                    flags=[*header.system_flags, *header.keywords, *header.gmail_labels],
                    auth_evidence={
                        "spf": auth.spf.value,
                        "dkim": auth.dkim.value,
                        "dmarc": auth.dmarc.value,
                        "arc": auth.arc.value,
                        "dkim_domains": list(auth.dkim_domains),
                        "dkim_selectors": list(auth.dkim_selectors),
                        "results": [
                            {
                                "method": evidence.method,
                                "result": evidence.result.value,
                                "identifier": evidence.identifier,
                                "domain": evidence.domain,
                                "selector": evidence.selector,
                            }
                            for evidence in auth.results
                        ],
                        "dkim_covers_unsubscribe": header.dkim_covers_unsubscribe,
                        "trusted": auth.trusted,
                    },
                    bulk_evidence={
                        "cleanup_identity": header.cleanup_identity,
                        "list_id": header.normalized_list_id,
                        "precedence": header.precedence,
                        "feedback_id": bool(header.feedback_id),
                        "esp": header.esp,
                        "provider_bulk": header.provider_bulk,
                    },
                    provider_verdict=header.provider_threat,
                    endpoint_fingerprints=fingerprints,
                    has_header_method=bool(header.list_unsubscribe_targets),
                    can_unsubscribe=header.server_can_unsubscribe,
                    promotional=has_promotional_subject(header.subject),
                )
                persisted.append((header, message))
    return subscription, persisted


def _operation_key(prefix: str, sender: SenderStats, headers: list[EmailHeader]) -> str:
    """Build an idempotency key from identity and the newest source message."""
    newest = max(headers, key=lambda header: header.received_at or header.date)
    locator = newest.message_ref
    source = (
        f"{locator.mailbox}:{locator.uidvalidity}:{locator.uid}" if locator else newest.message_id
    )
    material = f"{prefix}\0{sender.classification_key}\0{source}"
    return f"{prefix}-v1-{hashlib.sha256(material.encode()).hexdigest()}"


def _record_unsubscribe_result(
    sender: SenderStats,
    headers: list[EmailHeader],
    classification: Classification,
    result,
    *,
    retry_generation: int = 0,
    operation_id: int | None = None,
    claim_owner: str | None = None,
) -> None:
    """Persist one grouped operation and its redacted endpoint attempts."""
    subscription, messages = _persist_subscription_records(sender, headers, classification)
    if operation_id is None:
        operation = db.get_or_create_unsubscribe_operation(
            subscription["id"],
            _operation_key("unsubscribe", sender, headers),
            kind="unsubscribe",
            trigger_message_ref_id=messages[0][1]["id"] if messages else None,
            retry_generation=retry_generation,
        )
    else:
        claimed_operation = db.get_unsubscribe_operation(operation_id)
        if claimed_operation is None or claimed_operation["subscription_id"] != subscription["id"]:
            raise ValueError("Claimed operation does not belong to the subscription")
        operation = claimed_operation
    outcome = result.outcome or (
        UnsubscribeOutcome.REQUESTED
        if result.success
        else UnsubscribeOutcome.NEEDS_USER
        if result.needs_confirmation
        else UnsubscribeOutcome.FAILED
    )
    message_ids = {
        (
            header.message_ref.account_key,
            header.message_ref.mailbox,
            header.message_ref.uidvalidity,
            header.message_ref.uid,
        ): message["id"]
        for header, message in messages
        if header.message_ref is not None
    }
    attempt_results = list(getattr(result, "attempt_results", ()))
    if not attempt_results:
        # Policy-only/manual outcomes still get one grouped audit row without
        # inventing or storing a raw endpoint.
        fingerprint = _target_fingerprint(
            f"{result.method.value if result.method else 'none'}:{result.target_display or 'none'}"
        )
        db.record_unsubscribe_attempt(
            operation["id"],
            f"policy-v1-{fingerprint}",
            method=result.method.value if result.method else "none",
            outcome="needs_user"
            if outcome is UnsubscribeOutcome.NEEDS_USER
            else "accepted"
            if outcome is UnsubscribeOutcome.REQUESTED
            else "permanent_failure",
            endpoint_fingerprint=fingerprint,
            message_ref_id=messages[0][1]["id"] if messages else None,
            destination_redacted=_safe_persisted_destination(result.target_display),
            http_status=result.http_status,
            error_code="needs_user"
            if result.needs_confirmation
            else "request_failed"
            if result.error
            else None,
        )
    else:
        for index, attempt in enumerate(attempt_results, 1):
            locator = attempt.message_ref
            message_ref_id = None
            if locator is not None:
                message_ref_id = message_ids.get(
                    (
                        locator.account_key,
                        locator.mailbox,
                        locator.uidvalidity,
                        locator.uid,
                    )
                )
            db.record_unsubscribe_attempt(
                operation["id"],
                f"endpoint-v1-{attempt.endpoint_fingerprint}-{index}",
                method=attempt.method.value,
                outcome=attempt.outcome,
                endpoint_fingerprint=attempt.endpoint_fingerprint,
                message_ref_id=message_ref_id,
                destination_redacted=_safe_persisted_destination(attempt.target_display),
                http_status=attempt.http_status,
                error_code=attempt.error_code,
                ambiguous_send=attempt.ambiguous_send,
            )
    db.update_unsubscribe_operation_outcome(
        operation["id"],
        outcome.value,
        error_code="needs_user"
        if result.needs_confirmation
        else "request_failed"
        if result.error
        else None,
        detail_redacted=_redact_failure_detail(result.error),
        claim_owner=claim_owner,
    )


def _parse_timestamp(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def _unsubscribe_operation_plan(
    subscription: dict[str, Any],
) -> tuple[bool, set[str], int, bool]:
    """Return execute/exclusions/retry/escalate for the 48-hour lifecycle."""
    operations = db.list_unsubscribe_operations(subscription_id=subscription["id"])
    attempted_fingerprints: set[str] = set()
    for operation in operations:
        for attempt in db.list_unsubscribe_attempts(operation["id"]):
            attempted_fingerprints.add(attempt["endpoint_fingerprint"])

    outcome = subscription.get("last_outcome")
    retry_count = int(subscription.get("retry_count") or 0)
    if outcome == "blocked":
        return False, attempted_fingerprints, retry_count, False

    latest_operation = operations[0] if operations else {}
    delivered = _parse_timestamp(subscription.get("last_delivery_at"))
    last_operation_at = _parse_timestamp(
        latest_operation.get("verified_at")
        or latest_operation.get("completed_at")
        or latest_operation.get("created_at")
    )

    if outcome == "verified_quiet":
        if delivered is None or last_operation_at is None or delivered <= last_operation_at:
            return False, attempted_fingerprints, retry_count, False
        if retry_count >= 1:
            return False, attempted_fingerprints, retry_count, True
        return True, attempted_fingerprints, 1, False

    if outcome == "needs_user":
        # Manual boundaries (login, form, CAPTCHA, protected identity, unknown
        # authentication) are never crossed automatically on later scans.
        if latest_operation.get("error_code") == "unsubscribe_consent_required":
            # Granting the current versioned consent is an explicit resolution
            # of this one policy boundary; endpoint safety is still rechecked.
            return True, attempted_fingerprints, retry_count, False
        return False, attempted_fingerprints, retry_count, False

    if outcome == "failed":
        # A non-accepted endpoint is never replayed for the same source
        # message. One genuinely later delivery may supply a fresh endpoint;
        # mark it as the sole alternate generation so it cannot loop.
        if delivered is None or last_operation_at is None or delivered <= last_operation_at:
            return False, attempted_fingerprints, retry_count, False
        if retry_count >= 1:
            return False, attempted_fingerprints, retry_count, outcome == "failed"
        return True, attempted_fingerprints, 1, False

    if outcome not in {"requested", "ineffective"}:
        return True, attempted_fingerprints, retry_count, False

    if outcome == "requested":
        # Only `_reconcile_due_operations` may transition an accepted request,
        # and it is gated on a complete post-grace Inbox scan. Until then,
        # accepted work is never replayed, even if a partial scan saw mail.
        return False, attempted_fingerprints, retry_count, False

    if retry_count >= 1:
        return False, attempted_fingerprints, retry_count, True
    return True, attempted_fingerprints, 1, False


def _unsubscribe_execution_state(sender: SenderStats) -> str:
    if not (sender.account_key and sender.identity_kind and sender.identity_value):
        return "ready"
    subscription = db.get_subscription(
        account=sender.account_key,
        identity_kind=sender.identity_kind,
        identity_value=sender.identity_value,
    )
    if subscription is None:
        return "ready"
    execute, _exclusions, _generation, escalate = _unsubscribe_operation_plan(subscription)
    if execute:
        return "ready"
    if escalate:
        return "retry_block"
    return str(subscription.get("last_outcome") or "existing")


def _is_unsubscribe_consent_resume(subscription: dict[str, Any], config: Config) -> bool:
    """Return whether current consent resolves the latest no-contact boundary."""
    if not config.permits_unsubscribe or subscription.get("last_outcome") != "needs_user":
        return False
    operations = db.list_unsubscribe_operations(
        subscription_id=subscription["id"],
        limit=1,
    )
    return bool(operations and operations[0].get("error_code") == "unsubscribe_consent_required")


def _reconcile_due_operations(
    config: Config,
    *,
    accounts: set[str] | None = None,
) -> None:
    """Verify post-grace quietness without changing policies or moving mail."""
    operations = (
        db.list_operations_due_for_verification()
        if accounts is None
        else [
            operation
            for account in sorted({value.casefold() for value in accounts})
            for operation in db.list_operations_due_for_verification(account=account)
        ]
    )
    for operation in operations:
        delivered = _parse_timestamp(operation.get("last_delivery_at"))
        grace = _parse_timestamp(operation.get("grace_until"))
        if delivered is None or grace is None or delivered <= grace:
            db.update_unsubscribe_operation_outcome(
                operation["id"],
                "verified_quiet",
                verified_at=datetime.now(UTC),
            )
            continue

        db.update_unsubscribe_operation_outcome(operation["id"], "ineffective")


def _reconcile_mailbox_sources(config: Config, *, accounts: set[str]) -> None:
    resolved = 0
    for account in config.accounts.values():
        if account.email.casefold() not in accounts:
            continue
        pending = db.list_unresolved_mailbox_sources(account.email.casefold())
        if not pending:
            continue
        try:
            with IMAPConnection(account) as connection:
                if connection.conn is None:
                    continue
                for row in pending:
                    locator = MessageRef(
                        row["account"], row["mailbox"], row["uidvalidity"], row["uid"]
                    )
                    validation = validate_uid_locator(
                        cast(Any, connection.conn), locator, readonly=True
                    )
                    if (
                        validation.exact_search_completed
                        and validation.selected_uidvalidity == locator.uidvalidity
                        and not validation.uid_exists
                        and db.reconcile_missing_mailbox_source(row["id"])
                    ):
                        resolved += 1
        except (IMAPError, OSError, ValueError, imaplib.IMAP4.error):
            console.print("[warning]Some earlier Inbox moves remain unconfirmed.[/warning]")
    if resolved:
        console.print(
            f"[muted]Confirmed {resolved} earlier cleanup source(s) absent from Inbox; "
            "no moves replayed.[/muted]"
        )


def _block_subscription(
    config: Config,
    sender: SenderStats,
    headers: list[EmailHeader],
    classification: Classification,
) -> tuple[int, int]:
    """Move only Inbox messages included in the approved classification."""
    subscription, messages = _persist_subscription_records(
        sender,
        headers,
        classification,
        policy_action="block",
    )
    claim_owner = uuid.uuid4().hex
    operation, acquired = db.claim_unsubscribe_operation(
        subscription["id"],
        _operation_key("block", sender, headers),
        claim_owner,
        kind="block",
        trigger_message_ref_id=messages[0][1]["id"] if messages else None,
    )
    if not acquired:
        return 0, 0
    return _move_persisted_subscription_to_junk(
        config,
        subscription,
        operation["id"],
        claim_owner=claim_owner,
        message_ids={message["id"] for _header, message in messages},
    )


def _move_persisted_subscription_to_junk(
    config: Config,
    subscription: dict[str, Any],
    operation_id: int,
    *,
    claim_owner: str,
    message_ids: set[int] | None = None,
    preserve_policy: bool = False,
) -> tuple[int, int]:
    """Move approved Inbox locators, or the explicitly approved full identity."""
    inbox_messages = db.list_message_refs(
        subscription_id=subscription["id"],
        mailbox_role="inbox",
        limit=100_000,
    )
    if message_ids is not None:
        inbox_messages = [message for message in inbox_messages if message["id"] in message_ids]
    if not inbox_messages:
        db.update_unsubscribe_operation_outcome(
            operation_id,
            "blocked",
            claim_owner=claim_owner,
        )
        return 0, 0

    if not (
        subscription.get("policy_source") == "manual"
        and subscription.get("policy_action") == "block"
    ) and (_persisted_threat_action(subscription["id"]) is Action.REVIEW):
        if not preserve_policy:
            db.set_subscription_policy(subscription["id"], "review", source="automatic")
        db.update_unsubscribe_operation_outcome(
            operation_id,
            "needs_user",
            claim_owner=claim_owner,
            error_code="mixed_sender_evidence",
            detail_redacted="Clean and flagged messages share this identity; inspect individual messages",
        )
        return 0, len(inbox_messages)

    account = next(
        (
            candidate
            for candidate in config.accounts.values()
            if candidate.email.casefold() == subscription["account"].casefold()
        ),
        None,
    )
    if account is None:
        db.update_unsubscribe_operation_outcome(
            operation_id,
            "failed",
            error_code="account_missing",
            detail_redacted="The matching mailbox account is unavailable",
            claim_owner=claim_owner,
        )
        return 0, len(inbox_messages)

    moved = 0
    failed = 0
    try:
        with IMAPConnection(account) as connection:
            if connection.conn is None:
                raise OSError("IMAP connection was not established")
            discovery = connection.discover_mailboxes(
                junk_override=account.junk_mailbox,
            )
            if discovery.junk is None:
                detail = (
                    "Junk mailbox selection is ambiguous; configure account junk_mailbox"
                    if discovery.junk_is_ambiguous
                    else "The server did not advertise an unambiguous Junk mailbox"
                )
                db.update_unsubscribe_operation_outcome(
                    operation_id,
                    "failed",
                    error_code="junk_mailbox_unavailable",
                    detail_redacted=detail,
                    claim_owner=claim_owner,
                )
                return 0, len(inbox_messages)

            existing = {
                (row["message_ref_id"], row["action_key"]): row
                for row in db.list_mailbox_actions(
                    subscription_id=subscription["id"],
                    limit=100_000,
                )
            }
            for message in inbox_messages:
                action_key = "move-to-junk-v1"
                locator = MessageRef(
                    message["account"],
                    message["mailbox"],
                    int(message["uidvalidity"]),
                    int(message["uid"]),
                )
                previous = existing.get((message["id"], action_key))
                if previous and previous["outcome"] in {
                    "moved",
                    "already_junk",
                    "not_found",
                }:
                    moved += 1
                    continue
                if previous and not bool(previous.get("retryable", 1)):
                    # An uncertain MOVE or COPY must never create another
                    # destination copy; only source absence can resolve it.
                    if previous["outcome"] in {"partial", "failed"}:
                        validation = validate_uid_locator(
                            cast(Any, connection.conn), locator, readonly=True
                        )
                        if (
                            validation.exact_search_completed
                            and validation.selected_uidvalidity == locator.uidvalidity
                            and not validation.uid_exists
                            and db.reconcile_missing_mailbox_source(previous["id"])
                        ):
                            moved += 1
                            continue
                    failed += 1
                    continue
                action_claim = db.record_mailbox_action(
                    subscription["id"],
                    message["id"],
                    action_key,
                    action="move_to_junk",
                    outcome="claimed",
                    source_mailbox=locator.mailbox,
                    target_mailbox=discovery.junk.name,
                    operation_id=operation_id,
                    claim_owner=claim_owner,
                    retryable=False,
                    error_code="mailbox_action_claimed",
                    detail_redacted=(
                        "Mailbox action reserved before external mutation; stale claims "
                        "require manual review"
                    ),
                )
                if not (
                    action_claim["outcome"] == "claimed"
                    and action_claim.get("operation_id") == operation_id
                ):
                    if action_claim["outcome"] in {"moved", "already_junk", "not_found"}:
                        moved += 1
                    else:
                        failed += 1
                    continue
                action_result = connection.move_message_to_junk(locator, discovery.junk)
                outcome = action_result.outcome.value
                db.record_mailbox_action(
                    subscription["id"],
                    message["id"],
                    action_key,
                    action="move_to_junk",
                    outcome=outcome,
                    source_mailbox=locator.mailbox,
                    target_mailbox=discovery.junk.name,
                    operation_id=operation_id,
                    claim_owner=claim_owner,
                    retryable=action_result.retryable,
                    error_code="mailbox_action_failed" if action_result.error else None,
                    detail_redacted=_redact_failure_detail(action_result.error),
                )
                if outcome in {"moved", "already_junk", "not_found"}:
                    moved += 1
                else:
                    failed += 1
    except (IMAPError, OSError, imaplib.IMAP4.error) as error:
        failed = len(inbox_messages)
        db.update_unsubscribe_operation_outcome(
            operation_id,
            "failed",
            error_code="mailbox_transport_failed",
            detail_redacted=_redact_failure_detail(str(error)),
            claim_owner=claim_owner,
        )
        return moved, failed

    db.update_unsubscribe_operation_outcome(
        operation_id,
        "blocked" if failed == 0 else "failed",
        error_code="partial_mailbox_failure" if failed else None,
        detail_redacted=f"{failed} message action(s) failed" if failed else None,
        claim_owner=claim_owner,
    )
    return moved, failed


def _clean_unwanted_inbox(
    config: Config,
    subscription: dict[str, Any],
    messages: list[tuple[EmailHeader, dict[str, Any]]],
) -> tuple[int, int]:
    try:
        return _execute_inbox_cleanup(config, subscription, messages)
    except (ValueError, IMAPError, OSError, imaplib.IMAP4.error):
        console.print(
            "[warning]Inbox cleanup needs review; the unsubscribe result is preserved.[/warning]"
        )
        return 0, len(messages)


def _execute_inbox_cleanup(
    config: Config,
    subscription: dict[str, Any],
    messages: list[tuple[EmailHeader, dict[str, Any]]],
) -> tuple[int, int]:
    if not config.move_unwanted_to_junk or not config.permits_mailbox_mutation:
        return 0, 0
    operations = db.list_unsubscribe_operations(subscription_id=subscription["id"], limit=1)
    operation = operations[0] if operations else None
    if not operation or operation.get("outcome") not in {"requested", "verified_quiet"}:
        return 0, 0
    message_ids = {
        message["id"]
        for header, message in messages
        if header.mailbox_role == "inbox"
        and header.message_ref is not None
        and not has_protected_subject(header.subject)
        and not header.server_not_junk
        and not {flag.casefold() for flag in header.system_flags} & {r"\flagged", r"\answered"}
        and (
            operation.get("verification_scope") == "subscription"
            or message["id"] == operation.get("trigger_message_ref_id")
        )
    }
    if not message_ids:
        return 0, 0
    material = ",".join(str(value) for value in sorted(message_ids))
    owner = uuid.uuid4().hex
    operation, acquired = db.claim_unsubscribe_operation(
        subscription["id"],
        "inbox-cleanup-v1-" + hashlib.sha256(material.encode()).hexdigest(),
        owner,
        kind="block",
        affects_subscription=False,
    )
    if not acquired:
        return 0, 0
    moved, failed = _move_persisted_subscription_to_junk(
        config,
        subscription,
        operation["id"],
        claim_owner=owner,
        message_ids=message_ids,
        preserve_policy=True,
    )
    console.print(
        f"Inbox cleanup: {moved} message(s) no longer in Inbox; {failed} unresolved. "
        "Unsubscribe delivery verification remains separate."
    )
    return moved, failed


def _record_block_needs_consent(
    sender: SenderStats,
    headers: list[EmailHeader],
    classification: Classification,
) -> None:
    """Persist durable local BLOCK policy without performing an IMAP write."""
    subscription, _messages = _persist_subscription_records(
        sender,
        headers,
        classification,
        policy_action="block",
    )
    _record_persisted_block_needs_consent(subscription)


def _record_persisted_block_needs_consent(subscription: dict[str, Any]) -> None:
    """Queue the mailbox portion of an already-durable BLOCK policy."""
    operation = db.get_or_create_unsubscribe_operation(
        subscription["id"],
        "block-consent-v1",
        kind="block",
    )
    db.update_unsubscribe_operation_outcome(
        operation["id"],
        "needs_user",
        error_code="mailbox_consent_required",
        detail_redacted="IMAP Junk movement requires current mailbox-action consent",
    )


def _drain_consent_parked_blocks(config: Config) -> tuple[int, int, int]:
    """Resume manual blocks; reclassify automatic decisions with unproven scope."""
    if not config.permits_mailbox_mutation:
        return 0, 0, 0
    parked = db.list_consent_parked_blocks()
    if not parked:
        return 0, 0, 0

    scopes = {
        row["id"]: {
            int(message["id"])
            for message in db.list_message_refs(
                subscription_id=row["id"], mailbox_role="inbox", limit=100_000
            )
        }
        for row in parked
    }
    table = Table(title="Queued block scope")
    table.add_column("Account / identity")
    table.add_column("Inbox refs")
    table.add_column("Action")
    for row in parked:
        table.add_row(
            f"{row['account']} · {row['identity_kind']}:{row['identity_value']}",
            str(len(scopes[row["id"]])),
            "Move recorded history"
            if row.get("policy_source") == "manual"
            else "Fresh classification required"
            if scopes[row["id"]]
            else "No Inbox action",
        )
    console.print(table)
    console.print("[muted]Recorded locators may no longer be present in the mailbox.[/muted]")

    drained = 0
    moved_total = 0
    failed_total = 0
    with Progress(
        SpinnerColumn(style="#ffaf00"),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(complete_style="orange1", finished_style="orange1", pulse_style="orange1"),
        TaskProgressColumn(),
        console=console,
        transient=True,
    ) as progress:
        task = progress.add_task("Applying queued blocks...", total=len(parked))
        for subscription in parked:
            message_ids = scopes[subscription["id"]]
            if subscription.get("policy_source") != "manual":
                if message_ids:
                    db.set_subscription_policy(subscription["id"], "review", source="automatic")
                    for operation in db.list_unsubscribe_operations(
                        subscription_id=subscription["id"], outcome="needs_user"
                    ):
                        if operation.get("error_code") == "mailbox_consent_required":
                            db.update_unsubscribe_operation_outcome(
                                operation["id"],
                                "needs_user",
                                error_code="block_rescan_required",
                                detail_redacted="Automatic block requires fresh classification before mailbox actions",
                            )
                    console.print(
                        "[warning]Deferred automatic block to review. Run `nothx run` "
                        "to classify the current message scope before applying it.[/warning]"
                    )
                    progress.advance(task)
                    continue
                operation = db.get_or_create_unsubscribe_operation(
                    subscription["id"], "parked-empty-block-v1", kind="block"
                )
                db.update_unsubscribe_operation_outcome(operation["id"], "blocked")
                moved, failed = 0, 0
            else:
                moved, failed = _apply_manual_subscription_block(
                    config, subscription, message_ids=message_ids
                )
            moved_total += moved
            failed_total += failed
            if not failed:
                drained += 1
            progress.advance(task)
    return drained, moved_total, failed_total


def _report_consent_parked_blocks(config: Config) -> None:
    """Tell the user about queued BLOCK work without prompting for it."""
    parked = db.count_consent_parked_blocks()
    if not parked:
        return
    console.print(
        f"\n[warning]{parked} block decision(s) are queued from a run that predates "
        "your mailbox-action consent.[/warning]"
    )
    if config.permits_mailbox_mutation:
        console.print("[muted]Apply them with `nothx review --apply-pending`.[/muted]")
    else:
        console.print(
            "[muted]Grant consent with `nothx consent --mailbox-actions --yes` to apply them.[/muted]"
        )


def _apply_manual_subscription_block(
    config: Config,
    subscription: dict[str, Any],
    *,
    message_ids: set[int] | None = None,
) -> tuple[int, int]:
    """Apply an explicitly approved account/list BLOCK to persisted Inbox refs."""
    db.set_subscription_policy(subscription["id"], "block")
    subscription = db.get_subscription(subscription["id"]) or subscription
    if not config.permits_mailbox_mutation:
        _record_persisted_block_needs_consent(subscription)
        return 0, 0
    inbox_messages = db.list_message_refs(
        subscription_id=subscription["id"],
        mailbox_role="inbox",
        limit=100_000,
    )
    if message_ids is None:
        message_ids = {int(row["id"]) for row in inbox_messages}
    newest_message_id = max(message_ids, default=0)
    scope_key = hashlib.sha256(",".join(map(str, sorted(message_ids))).encode()).hexdigest()
    claim_owner = uuid.uuid4().hex
    operation, acquired = db.claim_unsubscribe_operation(
        subscription["id"],
        f"manual-block-v3-{scope_key}",
        claim_owner,
        kind="block",
        trigger_message_ref_id=newest_message_id or None,
    )
    if not acquired:
        return 0, 0
    return _move_persisted_subscription_to_junk(
        config,
        subscription,
        operation["id"],
        claim_owner=claim_owner,
        message_ids=message_ids,
    )


def _record_unsubscribe_needs_consent(
    sender: SenderStats,
    headers: list[EmailHeader],
    classification: Classification,
) -> None:
    """Queue an account/list review without issuing unsubscribe traffic."""
    subscription, messages = _persist_subscription_records(
        sender,
        headers,
        classification,
        policy_action="review",
    )
    operation = db.get_or_create_unsubscribe_operation(
        subscription["id"],
        f"unsubscribe-consent-v1-{sender.classification_key}",
        kind="unsubscribe",
        trigger_message_ref_id=messages[0][1]["id"] if messages else None,
    )
    db.update_unsubscribe_operation_outcome(
        operation["id"],
        "needs_user",
        error_code="unsubscribe_consent_required",
        detail_redacted="Automatic unsubscribe requires current versioned consent",
    )


def _change_sender_status(
    domain: str, new_status: str, sender: dict | None = None, config: Config | None = None
) -> bool:
    """Change a sender's status and log the action for learning.

    Args:
        domain: The sender domain to change.
        new_status: One of "keep", "unsub", "block".
        sender: Optional pre-fetched sender dict. If None, fetches from DB.
        config: Configuration used for network/mailbox consent. If omitted,
            the current configuration is loaded before any unsubscribe action.

    Returns:
        True if the status was changed, False if sender not found.
    """
    if sender is None:
        sender = db.get_sender(domain)
    if not sender:
        return False

    status_map = {
        "unsub": (SenderStatus.UNSUBSCRIBED, Action.UNSUB, "unsubscribe", "Unsubscribed"),
        "keep": (SenderStatus.KEEP, Action.KEEP, "keep", "Keep"),
        "block": (SenderStatus.BLOCKED, Action.BLOCK, "block", "Blocked"),
    }
    sender_status, action_enum, style, label = status_map[new_status]

    status_changed = True
    if new_status == "unsub":
        result = _attempt_unsubscribe_for_domain(config or Config.load(), domain, sender)
        if result.success:
            db.update_sender_status(domain, sender_status)
        else:
            status_changed = False
    elif new_status == "block":
        db.set_user_override(domain, new_status)
        block_config = config or Config.load()
        moved = 0
        failed = 0
        for subscription in db.list_subscriptions(limit=10_000):
            if (subscription.get("sender_domain") or "").casefold() != domain.casefold():
                continue
            subscription_moved, subscription_failed = _apply_manual_subscription_block(
                block_config,
                subscription,
            )
            moved += subscription_moved
            failed += subscription_failed
        db.update_sender_status(domain, sender_status)
        console.print(f"{_L} [block]→ Blocked[/block] ({moved} moved, {failed} partial/failed)")
    else:
        db.set_user_override(domain, new_status)
        db.update_sender_status(domain, sender_status)
        console.print(f"{_L} [{style}]→ {label}[/{style}]")

    # Build AI recommendation from sender data
    ai_rec = None
    if ai_class_str := sender.get("ai_classification"):
        if ai_class_str == "unsubscribe":
            ai_class_str = "unsub"
        try:
            ai_rec = Action(ai_class_str)
        except ValueError:
            pass

    if ai_rec and ai_rec.value != new_status:
        db.log_correction(domain, ai_rec.value, new_status)

    total = sender.get("total_emails", 0)
    seen = sender.get("seen_emails", 0)
    open_rate = (seen / total * 100) if total > 0 else 0

    action_record = UserAction(
        domain=domain,
        action=action_enum,
        timestamp=datetime.now(UTC),
        ai_recommendation=ai_rec,
        heuristic_score=None,
        open_rate=open_rate,
        email_count=total,
    )
    db.log_user_action(action_record)

    learner = get_learner()
    learner.update_from_action(action_record)

    return status_changed


# Simple email validation regex
EMAIL_REGEX = re.compile(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")


def _is_valid_email(email: str) -> bool:
    """Validate email address format."""
    if not email:
        return False
    return bool(EMAIL_REGEX.match(email.strip()))


# Provider-specific app password instructions
APP_PASSWORD_INSTRUCTIONS: dict[str, tuple[str, ...]] = {
    "gmail": (
        "[warning]For Gmail, you need an App Password:[/warning]",
        "  1. Go to [link=https://myaccount.google.com/apppasswords]myaccount.google.com/apppasswords[/link]",
        "  2. Generate a new password for 'nothx'",
        "  3. Copy the 16-character code\n",
    ),
    "outlook": (
        "[warning]Outlook/Live/Hotmail requires Microsoft sign-in (OAuth2).[/warning]",
        "  Run nothx account add and select Outlook / Live / Hotmail.\n",
    ),
    "yahoo": (
        "[warning]For Yahoo Mail, you need an App Password:[/warning]",
        "  1. Go to [link=https://login.yahoo.com/account/security]login.yahoo.com/account/security[/link]",
        "  2. Enable 2-Step Verification if not already enabled",
        "  3. Click 'Generate app password' and select 'Other App'",
        "  4. Copy the generated password\n",
    ),
    "icloud": (
        "[warning]For iCloud Mail, you need an App-Specific Password:[/warning]",
        "  1. Go to [link=https://appleid.apple.com/account/manage]appleid.apple.com[/link]",
        "  2. Sign in and go to 'Sign-In and Security' > 'App-Specific Passwords'",
        "  3. Click '+' to generate a new password for 'nothx'",
        "  4. Copy the generated password\n",
    ),
}

# Provider-specific API key setup instructions
API_KEY_INSTRUCTIONS: dict[str, tuple[str, ...]] = {
    "anthropic": (
        "[warning]To get your Anthropic API key:[/warning]",
        "  1. Go to [link=https://console.anthropic.com]console.anthropic.com[/link]",
        "  2. Sign in or create an account",
        "  3. Go to 'Settings' > 'API Keys'",
        "  4. Click 'Create Key' and copy it\n",
    ),
    "openai": (
        "[warning]To get your OpenAI API key:[/warning]",
        "  1. Go to [link=https://platform.openai.com/api-keys]platform.openai.com/api-keys[/link]",
        "  2. Sign in or create an account",
        "  3. Click 'Create new secret key'",
        "  4. Copy the key (it won't be shown again)\n",
    ),
    "gemini": (
        "[warning]To get your Google AI API key:[/warning]",
        "  1. Go to [link=https://aistudio.google.com/apikey]aistudio.google.com/apikey[/link]",
        "  2. Sign in with your Google account",
        "  3. Click 'Create API Key'",
        "  4. Copy the generated key\n",
    ),
}

# Provider-specific troubleshooting tips
TROUBLESHOOTING_TIPS: dict[str, tuple[str, ...]] = {
    "gmail": (
        "  • Verify your app password at [link=https://myaccount.google.com/apppasswords]myaccount.google.com/apppasswords[/link]",
    ),
    "outlook": (
        "  • Use Microsoft sign-in: run `nothx account add`",
        "  • Enable IMAP in Outlook web: Settings → Mail → Forwarding and IMAP",
        "  • Sign in with the same personal Microsoft email address used in nothx",
    ),
    "yahoo": (
        "  • Verify your app password at [link=https://login.yahoo.com/account/security]login.yahoo.com/account/security[/link]",
        "  • Make sure 2-Step Verification is enabled",
    ),
    "icloud": (
        "  • Verify your app password at [link=https://appleid.apple.com/account/manage]appleid.apple.com[/link]",
        "  • Go to 'Sign-In and Security' > 'App-Specific Passwords'",
    ),
}


def _get_greeting() -> str:
    """Get time-based greeting with user's first name if available."""
    import os as _os

    hour = datetime.now().hour
    if 5 <= hour < 12:
        emoji, greeting = "☀️", "Good morning"
    elif 12 <= hour < 17:
        emoji, greeting = "🌤️", "Good afternoon"
    elif 17 <= hour < 21:
        emoji, greeting = "🌆", "Good evening"
    else:
        emoji, greeting = "🌙", "Hey there"

    name = None
    for var in ("USER", "USERNAME", "LOGNAME"):
        if username := _os.environ.get(var):
            name = username.split(".")[0].capitalize()
            break

    if name:
        return f"{emoji} {greeting}, {name}!"
    return f"{emoji} {greeting}!"


def _build_version_line(config: Config) -> str:
    """Build the version + status string for display."""
    import sqlite3

    status_parts = [f"v{__version__}"]

    account_count = len(config.accounts)
    if account_count > 0:
        status_parts.append(f"{account_count} account{'s' if account_count != 1 else ''}")
    else:
        status_parts.append("not configured")

    try:
        db.init_db()
        stats = db.get_stats()
        if stats.get("last_run"):
            try:
                last_run = datetime.fromisoformat(stats["last_run"])
                status_parts.append(f"last scan {humanize.naturaltime(last_run)}")
            except (ValueError, TypeError):
                pass
        if stats.get("pending_review", 0) > 0:
            status_parts.append(f"{stats['pending_review']} pending")
    except (sqlite3.Error, OSError):
        pass

    return " · ".join(status_parts)


def _get_previous_run_summary_text() -> str | None:
    """Get brief summary text from the last run, or None."""
    import sqlite3

    try:
        activity = db.get_activity_log(limit=1)
        if activity and activity[0].get("type") == "run":
            r = activity[0]
            timestamp = r.get("timestamp", "")
            try:
                ts_dt = datetime.fromisoformat(timestamp)
                time_ago = humanize.naturaltime(ts_dt)
            except (ValueError, TypeError):
                time_ago = "recently"

            unsubbed = r.get("auto_unsubbed", 0)
            if unsubbed > 0:
                return f"Last run {time_ago} · unsubscribed from {unsubbed} sender{'s' if unsubbed != 1 else ''}"
    except (sqlite3.Error, OSError):
        pass
    return None


def _show_welcome_screen() -> None:
    """Show welcome screen with gradient panel and interactive command selector."""
    config = Config.load()
    greeting = _get_greeting()
    version_line = _build_version_line(config)

    # Animated gradient banner in a panel
    print_animated_welcome(greeting, version_line)

    _select_header("Get started")

    if not config.accounts:
        choices = [
            questionary.Choice("Set up email accounts and API key", value="init"),
            questionary.Choice("View all commands", value="help"),
            questionary.Choice("Exit", value="exit"),
        ]
    else:
        choices = [
            questionary.Choice("Full Inbox — review and clean up", value="cleanup"),
            questionary.Choice("Recent mail — review and clean up", value="run"),
            questionary.Choice("Show current stats", value="status"),
            questionary.Choice("Review pending decisions", value="review"),
            questionary.Choice("List all tracked senders", value="senders"),
            questionary.Choice("View all commands", value="help"),
            questionary.Choice("Exit", value="exit"),
        ]

    selected = _styled_select(choices)

    if selected is None or selected == "exit":
        console.print()
        return

    ctx = click.get_current_context()
    ctx.obj["from_welcome"] = True
    if selected == "init":
        ctx.invoke(init)
    elif selected == "cleanup":
        ctx.invoke(cleanup, apply=False, auto=False, account=(), preview=False)
    elif selected == "run":
        ctx.invoke(run, auto=False, dry_run=False, verbose=False, account=())
    elif selected == "status":
        ctx.invoke(status, learning=False)
    elif selected == "review":
        ctx.invoke(review, show_all=False, show_keep=False, show_unsub=False)
    elif selected == "senders":
        ctx.invoke(senders, status=None, sort="date", as_json=False)
    elif selected == "help":
        alias_names = {"r", "s", "rv", "h", "c"}
        group = ctx.command
        assert isinstance(group, click.Group)
        _select_header("Select a command")
        cmd_choices = []
        for name in sorted(group.commands):
            if name not in alias_names:
                cmd = group.commands[name]
                help_text = cmd.get_short_help_str(limit=50)
                cmd_choices.append(questionary.Choice(f"{name:<12s} {help_text}", value=name))
        cmd_choices.append(questionary.Choice("Back", value="back"))

        cmd_selected = _styled_select(cmd_choices)
        if cmd_selected and cmd_selected != "back":
            cmd_obj = group.commands[cmd_selected]
            try:
                ctx.invoke(cmd_obj)
            except click.UsageError as e:
                console.print(f"[warning]{e.format_message()}[/warning]")


def _show_learning_status(config: Config) -> None:
    """Show learning system status and insights."""
    learner = get_learner()
    summary = learner.get_learning_summary()

    console.print("\n[header]Learning Status[/header]")
    console.print(Rule(style="#808080"))

    # Overall stats
    console.print("\n[header]Training Data[/header]")
    console.print(f"{_L} Total decisions learned from: [count]{summary['total_actions']}[/count]")
    console.print(f"{_L} Corrections (overrode AI): [count]{summary['total_corrections']}[/count]")

    # Learned preferences
    console.print("\n[header]Your Preferences[/header]")

    # Open rate importance
    open_rate_desc = {
        "low": "Low (you often keep unread emails)",
        "high": "High (you rely heavily on open rates)",
        "normal": "Normal (default behavior)",
    }
    importance = summary.get("open_rate_importance", "normal")
    console.print(f"{_L} Open rate importance: {open_rate_desc.get(importance, importance)}")

    # Volume sensitivity
    volume_desc = {
        "low": "Low (you tolerate high-volume senders)",
        "high": "High (you unsub from frequent senders)",
        "normal": "Normal (default behavior)",
    }
    sensitivity = summary.get("volume_sensitivity", "normal")
    console.print(f"{_L} Volume sensitivity: {volume_desc.get(sensitivity, sensitivity)}")

    # Keyword patterns as tree
    keyword_patterns = summary.get("keyword_patterns", [])
    if keyword_patterns:
        tree = Tree(f"[header]Learned Patterns ({len(keyword_patterns)})[/header]")
        keep_branch = tree.add("[keep]Keep patterns[/keep]")
        unsub_branch = tree.add("[unsubscribe]Unsub patterns[/unsubscribe]")

        for pattern in keyword_patterns[:10]:  # Show top 10
            keyword = pattern["keyword"]
            tendency = pattern["tendency"]
            strength = pattern["strength"]
            count = pattern["sample_count"]

            label = f'"{keyword}" ({strength}, {count} examples)'
            if tendency == "keep":
                keep_branch.add(f"[keep]{label}[/keep]")
            else:
                unsub_branch.add(f"[unsubscribe]{label}[/unsubscribe]")

        console.print()
        console.print(tree)
    else:
        console.print(
            "\n[muted]No keyword patterns learned yet. Make more decisions to build patterns.[/muted]"
        )

    # AI analysis prompt
    if summary["total_actions"] >= 10 and config.ai.enabled:
        console.print(
            f"\n[muted]Tip: AI pattern analysis is available with {summary['total_actions']} decisions.[/muted]"
        )

    console.print()


@click.group(invoke_without_command=True)
@click.version_option(version=__version__)
@click.pass_context
def main(ctx):
    """nothx - Smart enough to say no.

    Set it up once. AI handles your inbox forever.
    """
    ctx.ensure_object(dict)
    if ctx.invoked_subcommand is None:
        _show_welcome_screen()


def _add_outlook_account(config: Config, email: str) -> tuple[str, AccountConfig] | None:
    existing_ids = {
        account.client_id
        for account in config.accounts.values()
        if account.provider == "outlook" and account.uses_oauth and account.client_id
    }
    client_id = config.microsoft_client_id
    if not client_id and len(existing_ids) == 1:
        client_id = next(iter(existing_ids))
    if not client_id:
        console.print(
            "[warning]This installation has no nothx Microsoft application registration. "
            "The operator must configure its public application ID once; it is shared "
            "across accounts. Your Microsoft password is never needed.[/warning]"
        )
        console.print("Setup: https://github.com/sainihas/nothx#outlook--live--hotmail-oauth")
        client_id = questionary.text(
            "", qmark="Microsoft application ID (one-time setup):", style=Q_INPUT_STYLE
        ).ask()
    if not client_id or not client_id.strip():
        console.print("[warning]Microsoft sign-in is not configured yet.[/warning]")
        return None
    client_id = client_id.strip()
    try:
        reusable = False
        if msauth.get_consent_status(email, client_id).ready:
            try:
                msauth.get_access_token(email, client_id)
                reusable = True
            except OAuthError as error:
                if error.code not in {
                    ErrorCode.OAUTH_TOKEN_MISSING,
                    ErrorCode.OAUTH_RECONSENT_REQUIRED,
                } and error.details.get("error") not in {
                    "invalid_grant",
                    "interaction_required",
                    "consent_required",
                }:
                    raise
        if not reusable:
            flow = msauth.start_device_flow(client_id)
            verification_uri = str(flow["verification_uri"])
            console.print("\n[header]Sign in with your personal Microsoft account[/header]")
            console.print(f"{_L} Open: [link={verification_uri}]{verification_uri}[/link]")
            console.print(f"{_L} Enter code: [bold]{flow['user_code']}[/bold]")
            console.print(f"{_L} Sign in as {escape(email)} and approve the displayed access.")
            try:
                opened = webbrowser.open(
                    str(flow.get("verification_uri_complete") or verification_uri)
                )
            except Exception as error:
                logger.debug("Could not open OAuth browser: %s", type(error).__name__)
                opened = False
            if not opened:
                console.print(f"{_L} [muted]Open the link above in any browser.[/muted]")
            token = msauth.poll_for_token(
                client_id,
                str(flow["device_code"]),
                int(flow.get("interval", 5)),
                int(flow["expires_in"]),
            )
            msauth.save_token(email, token, client_id)
    except (OAuthError, OSError, ValueError) as error:
        console.print(f"[error]Microsoft sign-in failed: {escape(str(error))}[/error]")
        console.print(
            "[muted]Use a personal Outlook/Live/Hotmail account. The app registration "
            "must allow personal accounts and public-client flows.[/muted]"
        )
        return None
    config.microsoft_client_id = client_id
    previous = next(
        (
            account
            for account in config.accounts.values()
            if account.email.casefold() == email.casefold()
        ),
        None,
    )
    account = (
        replace(
            previous,
            provider="outlook",
            email=email,
            auth="oauth",
            password="",
            client_id=client_id,
        )
        if previous
        else AccountConfig(provider="outlook", email=email, auth="oauth", client_id=client_id)
    )
    with console.status("Checking Microsoft Inbox access...", spinner_style="#ffaf00"):
        success, message = test_account(account)
    if success:
        console.print("[success]✓ Connected with Microsoft sign-in![/success]\n")
    else:
        console.print(
            f"[warning]Sign-in saved, but Inbox access failed: {escape(message)}[/warning]"
        )
        console.print(
            "Open https://outlook.live.com/mail/ → Settings → Mail → Forwarding and IMAP "
            "→ enable 'Let devices and apps use IMAP', then Save. "
            "Check that you signed in as the email address above. "
            "Run `nothx test` to retry; you do not need to sign in again."
        )
    return _unique_account_name(config, email), account


def _add_email_account(config: Config) -> tuple[str, AccountConfig] | None:
    """Interactive flow to add an email account. Returns (name, account) or None if cancelled."""
    # Email provider selection
    _select_header("Select your email provider")
    provider_choices = [
        questionary.Choice("Gmail", value="gmail"),
        questionary.Choice("Outlook / Live / Hotmail", value="outlook"),
        questionary.Choice("Yahoo Mail", value="yahoo"),
        questionary.Choice("iCloud Mail", value="icloud"),
    ]
    provider = _styled_select(provider_choices)

    if provider is None:  # User cancelled
        return None

    console.print()  # Gap after selection

    # Email address with validation
    while True:
        email = questionary.text("", qmark="Email address:", style=Q_INPUT_STYLE).ask()
        if not email:
            return None
        if _is_valid_email(email):
            break
        console.print("[error]Invalid email format. Please enter a valid email address.[/error]")

    if provider == "outlook":
        return _add_outlook_account(config, email)

    # App password instructions
    if instructions := APP_PASSWORD_INSTRUCTIONS.get(provider):
        console.print()
        for line in instructions:
            console.print(f"{_L}{line[1:]}" if line.startswith("  ") else line)
    else:
        console.print("\n[warning]Enter your email password or app password.[/warning]\n")

    password = questionary.password("", qmark="App Password:", style=Q_INPUT_STYLE).ask()
    if not password:
        return None

    # Test connection
    account = AccountConfig(provider=provider, email=email, password=password)
    with console.status("Testing connection...", spinner_style="#ffaf00"):
        success, msg = test_account(account)

    if not success:
        console.print(f"[error]Connection failed: {msg}[/error]")
        return None

    console.print("[success]✓ Connected![/success]\n")

    return _unique_account_name(config, email), account


def _unique_account_name(config: Config, email: str) -> str:
    """Generate a stable, collision-free account name from an address."""
    for name, existing in config.accounts.items():
        if existing.email.casefold() == email.casefold():
            return name
    account_name = email.split("@")[0] if "@" in email else "default"
    # Make unique if name exists
    base_name = account_name
    counter = 1
    while account_name in config.accounts:
        account_name = f"{base_name}_{counter}"
        counter += 1

    return account_name


@main.command()
@click.pass_context
def init(ctx):
    """Set up nothx with your email account and API key."""
    config = Config.load()

    if not (ctx.obj or {}).get("from_welcome"):
        greeting = _get_greeting()
        version_line = _build_version_line(config)
        print_animated_welcome(greeting, version_line)

    # Multi-account loop
    account_count = 0
    while True:
        result = _add_email_account(config)
        if result is None:
            if account_count == 0:
                console.print(
                    "[warning]No accounts configured. Run 'nothx init' to try again.[/warning]"
                )
                return
            break

        account_name, account = result
        config.accounts[account_name] = account
        if config.default_account is None:
            config.default_account = account_name
        account_count += 1

        console.print(f"[success]✓ Added account: {account.email}[/success]")

        # Ask to add another
        if not _styled_confirm("Add another email account?", default=False):
            break

    # AI Provider setup
    console.print("\n[header]AI Classification Setup[/header]")
    console.print("nothx can use AI to classify your emails more accurately.")
    console.print(
        "Your email [bold]headers only[/bold] (never bodies) are sent to the AI provider.\n"
    )

    from .classifier.providers import SUPPORTED_PROVIDERS

    # Build provider choices
    provider_choices = []
    for key, info in SUPPORTED_PROVIDERS.items():
        provider_choices.append(
            questionary.Choice(f"{info['name']} - {info['description']}", value=key)
        )

    _select_header("Select AI provider")
    provider = _styled_select(provider_choices, default="anthropic")

    if provider is None:
        console.print("[warning]AI setup cancelled.[/warning]")
        return

    config.ai.provider = provider

    if provider == "none":
        config.ai.enabled = False
        console.print("Running in heuristics-only mode.\n")
    elif provider == "ollama":
        config.ai.enabled = True
        config.ai.api_key = None

        # Ask for Ollama URL
        console.print()  # Gap after selection
        api_base = questionary.text(
            "",
            default="http://localhost:11434",
            qmark="Ollama URL:",
            style=Q_INPUT_STYLE,
        ).ask()
        config.ai.api_base = api_base

        # Ask for model
        from .classifier.providers.ollama_provider import OllamaProvider

        ollama = OllamaProvider(api_base=api_base)
        available_models = ollama.get_model_options()

        if available_models:
            _select_header("Select model")
            model = _styled_select(available_models, default=available_models[0])
            if model is not None:
                config.ai.model = model
        else:
            config.ai.model = "llama3.2"
            console.print("[warning]Could not fetch models. Using default: llama3.2[/warning]")

        with console.status("Testing Ollama connection...", spinner_style="#ffaf00"):
            success, msg = test_ai_connection(config)

        if success:
            console.print("[success]✓ Ollama working![/success]\n")
        else:
            console.print(f"[warning]Ollama test failed: {msg}[/warning]")
            console.print("Continuing with heuristics-only mode.\n")
            config.ai.enabled = False
    else:
        # Cloud provider - needs API key
        provider_info = SUPPORTED_PROVIDERS[provider]
        config.ai.api_base = None  # Clear any stale Ollama URL

        if provider in API_KEY_INSTRUCTIONS:
            instructions = API_KEY_INSTRUCTIONS[provider]
            console.print()
            for line in instructions:
                console.print(f"{_L}{line[1:]}" if line.startswith("  ") else line)

        api_key = questionary.text(
            "",
            qmark=f"{provider_info['name']} API key (leave empty to skip):",
            style=Q_INPUT_STYLE,
        ).ask()

        if api_key and api_key.strip():
            config.ai.api_key = api_key.strip()
            config.ai.enabled = True

            # Set default model for provider
            from .classifier.providers import get_provider

            temp_provider = get_provider(provider, api_key=config.ai.api_key)
            if temp_provider:
                config.ai.model = temp_provider.default_model

            with console.status(
                f"Testing {provider_info['name']} connection...", spinner_style="#ffaf00"
            ):
                success, msg = test_ai_connection(config)

            if success:
                console.print(f"[success]✓ {provider_info['name']} working![/success]\n")
            else:
                console.print(f"[warning]AI test failed: {msg}[/warning]")
                console.print("Continuing with heuristics-only mode.\n")
                config.ai.enabled = False
        else:
            config.ai.enabled = False
            console.print("Running in heuristics-only mode.\n")

    # Initialize database
    db.init_db()

    # Save config
    config.save()
    console.print(f"[success]✓ Configuration saved to {get_config_dir()}[/success]")

    # First scan
    if _styled_confirm("Run first scan now?", default=True):
        _run_scan(config, verbose=True, dry_run=True, rescan=True)

    console.print(
        f"\nUnsubscribe automation: {'permitted' if config.permits_unsubscribe else 'revoked'}; "
        f"mailbox writes: {'permitted' if config.permits_mailbox_mutation else 'revoked'}."
    )
    console.print("Run [bold]nothx consent[/bold] to inspect or change these permissions.")

    # Schedule setup. Daily scanning makes stored BLOCK policies effective on
    # new deliveries and permits complete post-grace verification.
    schedule_runs = _styled_confirm("Auto-schedule daily runs?", default=True)

    if schedule_runs:
        success, msg = install_schedule("daily")
        if success:
            console.print(f"[success]✓ {msg}[/success]")
        else:
            console.print(f"[warning]{msg}[/warning]")

    console.print("\n[success]Setup complete![/success]")
    console.print("Run [bold]nothx status[/bold] to see current state.")
    console.print("Run [bold]nothx run[/bold] to process emails.")


@main.group(invoke_without_command=True)
@click.pass_context
def account(ctx):
    """Manage email accounts."""
    if ctx.invoked_subcommand is not None:
        return

    # Show interactive selector when no subcommand provided
    choices = [
        questionary.Choice("List configured accounts", value="list"),
        questionary.Choice("Add a new account", value="add"),
        questionary.Choice("Remove an account", value="remove"),
        questionary.Choice("Exit", value="exit"),
    ]

    _select_header("Manage accounts")
    selected = _styled_select(choices)

    if selected is None or selected == "exit":
        return

    if selected == "list":
        ctx.invoke(account_list)
    elif selected == "add":
        ctx.invoke(account_add)
    elif selected == "remove":
        ctx.invoke(account_remove)


@account.command("add")
def account_add():
    """Add a new email account."""
    config = Config.load()

    result = _add_email_account(config)
    if result is None:
        console.print("[warning]Account not added.[/warning]")
        return

    account_name, acc = result
    updating = account_name in config.accounts
    config.accounts[account_name] = acc
    if config.default_account is None:
        config.default_account = account_name
    config.save()

    verb = "Updated" if updating else "Added"
    console.print(f"\n[success]✓ {verb} account: {acc.email}[/success]")
    console.print(f"{_L} Name: {account_name}")
    console.print(f"{_L} Provider: {acc.provider}")


@account.command("list")
def account_list():
    """List configured email accounts."""
    config = Config.load()

    if not config.accounts:
        console.print("[warning]No accounts configured. Run 'nothx init' to add one.[/warning]")
        return

    console.print("\n[header]Configured Accounts[/header]\n")

    table = Table(show_header=True)
    table.add_column("Name")
    table.add_column("Email")
    table.add_column("Provider")
    table.add_column("Auth")
    table.add_column("Default")

    for name, acc in config.accounts.items():
        is_default = "✓" if name == config.default_account else ""
        table.add_row(name, acc.email, acc.provider, acc.auth, is_default)

    console.print(table)


@account.command("remove")
def account_remove():
    """Remove an email account."""
    config = Config.load()

    if not config.accounts:
        console.print("[warning]No accounts configured.[/warning]")
        return

    # Build choices list
    choices = [
        questionary.Choice(f"{name} ({acc.email})", value=name)
        for name, acc in config.accounts.items()
    ]
    choices.append(questionary.Choice("Cancel", value=None))

    _select_header("Select account to remove")
    account_name = _styled_select(choices)

    if account_name is None:
        console.print("Cancelled.")
        return

    # Confirm removal
    acc = config.accounts[account_name]
    if not _styled_confirm(f"Remove {acc.email}?", default=False):
        console.print("Cancelled.")
        return

    # Remove any stale OAuth cache entry as well (the account may previously
    # have used OAuth even if its current config says password).
    msauth.delete_token(acc.email)
    del config.accounts[account_name]

    # Update default if needed
    if config.default_account == account_name:
        if config.accounts:
            config.default_account = next(iter(config.accounts.keys()))
        else:
            config.default_account = None

    config.save()
    console.print(f"[success]✓ Removed account: {acc.email}[/success]")


@main.command()
@click.option("--auto", is_flag=True, help="Run in automatic mode (no prompts)")
@click.option("--dry-run", is_flag=True, help="Preview with local rules; no actions or cloud AI")
@click.option(
    "--preview", is_flag=True, help="Preview with configured AI; no actions or saved changes"
)
@click.option("--verbose", "-v", is_flag=True, help="Show detailed output")
@click.option(
    "--full-history",
    is_flag=True,
    help="Scan all history in Inbox and configured folders; cleanup scans only Inbox",
)
@click.option("--new-only", is_flag=True, help="Only read new UIDs; skips earlier undecided mail")
@click.option(
    "--rescan",
    is_flag=True,
    help="Bypass incremental cursors and repeat the configured lookback",
)
@click.option(
    "--account",
    "-a",
    multiple=True,
    help="Scan specific account(s) - can be specified multiple times (default: all)",
)
def run(
    auto: bool,
    dry_run: bool,
    verbose: bool,
    full_history: bool,
    rescan: bool,
    account: tuple[str, ...],
    preview: bool = False,
    new_only: bool = False,
):
    """Recheck the recent lookback; use cleanup to examine the full Inbox backlog."""
    if dry_run and preview:
        raise click.UsageError("--dry-run and --preview are mutually exclusive")
    if sum((full_history, rescan, new_only)) > 1:
        raise click.UsageError("--full-history, --rescan, and --new-only are mutually exclusive")
    config = Config.load()

    if not config.is_configured():
        console.print("[red]nothx is not configured. Run 'nothx init' first.[/red]")
        return

    # Validate accounts if specified
    accounts_to_scan: list[str] | None = None
    if account:
        # Build email-to-name map for efficient lookup
        email_to_name = {acc_config.email: name for name, acc_config in config.accounts.items()}

        accounts_to_scan = []
        for acc in account:
            # Support both account name and email address
            if acc in config.accounts:
                accounts_to_scan.append(acc)
            elif acc in email_to_name:
                accounts_to_scan.append(email_to_name[acc])
            else:
                console.print(f"[error]Account '{acc}' not found.[/error]")
                console.print(
                    f"Available: {', '.join(f'{n} ({a.email})' for n, a in config.accounts.items())}"
                )
                return

    db.init_db()

    if preview:
        _preview_notice(config)
    if dry_run:
        console.print(
            "[warning]DRY RUN - mailbox changes, unsubscribe requests, and cloud AI calls "
            "are disabled[/warning]\n"
        )

    _run_scan(
        config,
        verbose=verbose,
        dry_run=dry_run or preview,
        ai_preview=preview,
        auto=auto,
        account_names=accounts_to_scan,
        full_history=full_history,
        rescan=rescan or not (full_history or new_only),
    )


def _preview_notice(config: Config) -> None:
    console.print(
        "[warning]PREVIEW — no mailbox actions, unsubscribe requests, or saved decisions. "
        f"Configured AI ({escape(config.ai.provider)}) may receive eligible marketing headers "
        "when enabled; message bodies are never sent.[/warning]"
    )


@main.command()
@click.option("--apply", is_flag=True, hidden=True)
@click.option("--preview", is_flag=True, help="Only show the plan; no actions or saved decisions")
@click.option("--details", is_flag=True, help="Show candidate details before review")
@click.option("--auto", is_flag=True, help="Apply eligible decisions without prompts")
@click.option("--account", "-a", multiple=True, help="Limit cleanup to an account name or email")
def cleanup(
    apply: bool, auto: bool, account: tuple[str, ...], preview: bool = False, details: bool = False
) -> None:
    """Scan the full Inbox, review the plan, and apply approved actions in one run."""
    if preview and (auto or apply):
        raise click.UsageError("--preview cannot be combined with --auto or --apply")
    config = Config.load()
    if not config.is_configured():
        raise click.ClickException("Run 'nothx init' first.")
    names: list[str] = []
    for requested in account:
        matches = [
            name
            for name, value in config.accounts.items()
            if name == requested or value.email.casefold() == requested.casefold()
        ]
        if not matches:
            raise click.BadParameter(f"Account '{requested}' not found", param_hint="--account")
        names.extend(name for name in matches if name not in names)
    db.init_db()
    console.print(
        "[header]Full Inbox cleanup — all dates; Junk and other folders excluded[/header]"
    )
    if preview:
        _preview_notice(config)
    _run_scan(
        config,
        verbose=details,
        dry_run=preview,
        auto=auto,
        account_names=names or None,
        full_history=True,
        inbox_only=True,
        ai_preview=preview,
    )
    if preview:
        console.print("\n[muted]Preview only; no actions were applied.[/muted]")


def _show_scan_coverage(coverage: list[MailboxCoverage], scan_days: int) -> None:
    if not coverage:
        return
    table = Table(title="Scan coverage", show_header=True)
    for label in ("Account", "Folder", "Scope", "In mailbox", "Selected", "Fetched"):
        table.add_column(label)
    for row in coverage:
        scope = f"last {scan_days} days" if row.scope == "lookback" else row.scope
        table.add_row(
            escape(row.account),
            escape(row.mailbox),
            scope,
            str(row.total) if row.total is not None else "unknown",
            str(row.selected),
            str(row.fetched),
        )
        if not row.complete:
            console.print(
                f"[warning]Incomplete scan: {escape(row.account)} / "
                f"{escape(row.mailbox)}; results cover only the headers read.[/warning]"
            )
    console.print(table)
    excluded = sum(
        max(0, row.total - row.selected)
        for row in coverage
        if row.role == "inbox" and row.total is not None
    )
    if excluded:
        console.print(
            f"[warning]{excluded:,} Inbox messages were outside this scan's scope. "
            "Use `nothx cleanup` to review and clean up the full backlog.[/warning]"
        )


def _run_scan(
    config: Config,
    verbose: bool = False,
    dry_run: bool = False,
    auto: bool = False,
    account_names: list[str] | None = None,
    full_history: bool = False,
    rescan: bool = False,
    inbox_only: bool = False,
    ai_preview: bool = False,
):
    """Run the main scan and classification process."""
    stats = RunStats(
        ran_at=datetime.now(UTC),
        mode="auto" if auto else "interactive",
    )

    # Phase 1: Scan inbox
    if account_names:
        if len(account_names) == 1:
            label = f"({account_names[0]})"
        else:
            label = f"({len(account_names)} accounts)"
    else:
        account_count = len(config.accounts)
        label = f"({account_count} account{'s' if account_count != 1 else ''})"
    console.print(f"\n[header]Step 1/3: Scanning inbox {label}[/header]")

    with Progress(
        SpinnerColumn(style="#ffaf00"),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(complete_style="orange1", finished_style="orange1", pulse_style="orange1"),
        TaskProgressColumn(),
        console=console,
        transient=True,
    ) as progress:
        task = progress.add_task("Connecting to mailbox...", total=None)

        scan_errors: list[str] = []

        def on_account_start(email: str, _name: str, current: int, total: int) -> None:
            progress.update(task, total=None, completed=0)
            if total > 1:
                progress.update(
                    task, description=f"Scanning account {current} of {total} · {email}"
                )
            else:
                progress.update(task, description=f"Scanning {email}")

        def on_account_error(email: str, _name: str, error: str) -> None:
            scan_errors.append(f"{email}: {error}")

        def on_mailbox_progress(name: str, mailbox: str, count: int, total: int) -> None:
            progress.update(
                task,
                description=f"{escape(name)} · {escape(mailbox)}: {count:,}/{total:,} headers",
                total=total or None,
                completed=count,
            )

        scan_result = scan_inbox(
            config,
            account_names=account_names,
            on_account_start=on_account_start,
            on_account_error=on_account_error,
            persist=not dry_run,
            full_history=full_history,
            rescan=rescan,
            inbox_only=inbox_only,
            on_mailbox_progress=on_mailbox_progress,
        )
        # The account/List-Id (or account/From) grouping is authoritative.
        # A narrow fallback keeps third-party callers using a pre-v2 ScanResult
        # working without merging real scanner results by domain.
        subscription_stats = getattr(scan_result, "subscription_stats", None)
        authoritative = isinstance(subscription_stats, dict)
        sender_stats = subscription_stats if authoritative else scan_result.sender_stats

    coverage = getattr(scan_result, "coverage", [])
    if isinstance(coverage, list):
        _show_scan_coverage(coverage, config.scan_days)

    incomplete_accounts = (
        {
            config.accounts[row.account].email.casefold()
            for row in coverage
            if not row.complete and row.account in config.accounts
        }
        if isinstance(coverage, list)
        else set()
    )

    if scan_errors:
        for err in scan_errors:
            console.print(f"[warning]! Skipped account: {err}[/warning]")

    skipped_invalid = getattr(scan_result, "skipped_invalid_senders", 0)
    if not isinstance(skipped_invalid, int):
        skipped_invalid = 0
    if skipped_invalid:
        console.print(
            f"[warning]! Left {skipped_invalid} messages with missing or invalid From "
            "addresses unchanged; inspect them in your mail app.[/warning]"
        )

    if not dry_run:
        verification_accounts = (
            {
                config.accounts[name].email.casefold()
                for name in account_names
                if name in config.accounts
            }
            if account_names
            else None
        )
        if isinstance(coverage, list):
            verification_accounts = {
                config.accounts[row.account].email.casefold()
                for row in coverage
                if row.account in config.accounts
                and config.accounts[row.account].email.casefold() not in incomplete_accounts
            }
        _reconcile_due_operations(
            config,
            accounts=verification_accounts,
        )
        if isinstance(coverage, list):
            _reconcile_mailbox_sources(
                config,
                accounts={
                    config.accounts[row.account].email.casefold()
                    for row in coverage
                    if row.account in config.accounts
                    and row.role == "inbox"
                    and row.complete
                    and config.accounts[row.account].email.casefold() not in incomplete_accounts
                },
            )

    if not sender_stats:
        if scan_errors or skipped_invalid:
            console.print(
                "[warning]No processable messages found; see scan warnings above.[/warning]"
            )
        else:
            console.print("[success]✓ No processable headers in this scan scope.[/success]")
        return

    stats.emails_scanned = sum(s.total_emails for s in sender_stats.values())
    stats.unique_senders = len(sender_stats)

    console.print(
        f"[success]✓ Read {stats.emails_scanned} message headers in "
        f"{stats.unique_senders} account/list groups[/success]"
    )

    # Phase 2: Classify senders
    console.print("\n[header]Step 2/3: Classifying senders[/header]")
    engine = ClassificationEngine(config)

    with Progress(
        SpinnerColumn(style="#ffaf00"),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(complete_style="orange1", finished_style="orange1", pulse_style="orange1"),
        TaskProgressColumn(),
        TimeElapsedColumn(),
        console=console,
        transient=True,
    ) as progress:
        task = progress.add_task("Analyzing senders...", total=len(sender_stats))

        def on_ai_progress(completed: int, total: int) -> None:
            progress.update(
                task,
                description=f"AI processing: {completed:,}/{total:,} eligible groups",
                total=total,
                completed=completed,
                refresh=True,
            )

        classification_options: dict[str, Any] = {
            "persist": not dry_run,
            "on_ai_progress": on_ai_progress,
        }
        if ai_preview:
            classification_options["allow_ai"] = True
        for sender in sender_stats.values():
            if not (sender.account_key and sender.identity_kind and sender.identity_value):
                continue
            subscription = db.get_subscription(
                account=sender.account_key,
                identity_kind=sender.identity_kind,
                identity_value=sender.identity_value,
            )
            if subscription is not None:
                stored = _stored_folder_evidence(subscription["id"])
                sender.stored_inbox_evidence = stored.inbox or stored.not_junk
        classifications = engine.classify_batch(
            list(sender_stats.values()), **classification_options
        )
        progress.update(
            task,
            total=len(sender_stats),
            completed=len(sender_stats),
            description="Classification complete",
        )

    cache_hits = engine.ai.last_cache_hits
    if type(cache_hits) is int and cache_hits:
        console.print(f"[muted]Reused {cache_hits:,} unchanged AI classifications.[/muted]")

    # Persist AI's content type and its recommended action as separate facts,
    # even when authentication/safety policy transformed the executable action
    # to REVIEW or BLOCK. This keeps later corrections grounded in what AI
    # actually recommended rather than the final local disposition.
    if authoritative and not dry_run:
        for key, sender in sender_stats.items():
            classification = classifications.get(sender.classification_key) or classifications.get(
                key
            )
            if classification is None or not (
                classification.source == "ai" or classification.original_source == "ai"
            ):
                continue
            if not (sender.account_key and sender.identity_kind and sender.identity_value):
                continue
            subscription = db.get_subscription(
                account=sender.account_key,
                identity_kind=sender.identity_kind,
                identity_value=sender.identity_value,
            )
            if subscription is not None:
                db.update_subscription_classification(
                    subscription["id"],
                    ai_email_type=classification.email_type.value,
                    ai_recommended_action=(
                        classification.recommended_action or classification.action
                    ).value,
                    classification_source="ai",
                    unwanted_confidence=classification.confidence,
                )

    # Durable account/list policy wins on future scans. This keeps accepted
    # unsubscribe lifecycles from being reclassified away and makes BLOCK
    # suppress every later matching Inbox delivery.
    if authoritative:
        for _key, sender in sender_stats.items():
            if not (sender.account_key and sender.identity_kind and sender.identity_value):
                continue
            subscription = db.get_subscription(
                account=sender.account_key,
                identity_kind=sender.identity_kind,
                identity_value=sender.identity_value,
            )
            persisted_threat = (
                _persisted_threat_action(subscription["id"], sender=sender)
                if subscription is not None
                else None
            )
            mixed_threat = persisted_threat is Action.REVIEW or sender.has_threat_conflict
            if sender.authentication_failed_emails >= sender.total_emails > 0 and not mixed_threat:
                classifications[sender.classification_key] = Classification(
                    email_type=EmailType.UNKNOWN,
                    action=Action.BLOCK,
                    confidence=1.0,
                    reasoning="Every observed delivery has a trusted authentication failure",
                    source="auth_policy",
                )
                if (
                    not dry_run
                    and subscription is not None
                    and subscription.get("policy_action") != "block"
                ):
                    db.set_subscription_policy(subscription["id"], "block", source="automatic")
                continue
            current = classifications.get(sender.classification_key)
            explicit_action = None
            if (
                subscription is not None
                and subscription.get("policy_source") == "manual"
                and subscription.get("policy_action") in {"keep", "block"}
            ):
                explicit_action = Action(subscription["policy_action"])
            elif (
                current is not None
                and current.source == "user_rule"
                and current.action in {Action.KEEP, Action.BLOCK}
            ):
                explicit_action = current.action
            if explicit_action is not None and (
                mixed_threat
                or (
                    (
                        subscription is None
                        or _persisted_threat_action(subscription["id"], folder_evidence=False)
                        is None
                    )
                    and not (sender.provider_threat or sender.phishing_emails)
                )
            ):
                classifications[sender.classification_key] = Classification(
                    email_type=EmailType.UNKNOWN,
                    action=explicit_action,
                    confidence=1.0,
                    reasoning="Explicit local policy resolves soft folder evidence",
                    source="user_rule",
                )
                continue
            if subscription is not None and persisted_threat is not None:
                if not dry_run and persisted_threat is Action.BLOCK:
                    db.set_subscription_policy(subscription["id"], "block", source="automatic")
                classifications[sender.classification_key] = Classification(
                    email_type=EmailType.UNKNOWN,
                    action=persisted_threat,
                    confidence=1.0,
                    reasoning=(
                        "Stored Inbox/Junk conflict requires review"
                        if persisted_threat is Action.REVIEW
                        else "Persisted Junk/phishing evidence requires local suppression"
                    ),
                    source="provider_policy",
                )
                continue
            if (
                current is not None
                and current.action is Action.REVIEW
                and current.source in {"transactional_policy", "safety_policy", "auth_policy"}
            ):
                continue
            if (
                current is not None
                and current.action is Action.REVIEW
                and current.source == "engagement_policy"
                and (subscription is None or subscription.get("policy_source") != "manual")
            ):
                continue
            if (
                current is not None
                and current.action is Action.REVIEW
                and current.email_type is EmailType.UNKNOWN
                and (current.source == "ai" or current.original_source == "ai")
                and (subscription is None or subscription.get("policy_source") != "manual")
            ):
                continue
            policy = subscription.get("policy_action") if subscription else None
            if policy in {"block", "unsub"} or (
                policy == "keep"
                and subscription is not None
                and subscription.get("policy_source") != "automatic"
            ):
                if policy == "keep" and (
                    sender.provider_threat
                    or sender.phishing_emails
                    or sender.junk_emails
                    or sender.junk_keyword_emails
                ):
                    continue
                action = Action(policy)
                classifications[sender.classification_key] = Classification(
                    email_type=EmailType.UNKNOWN,
                    action=action,
                    confidence=1.0,
                    reasoning=f"Stored subscription policy: {policy}",
                    source="stored_policy",
                )

            # Threat evidence is an unconditional local disposition. It must
            # never be turned into unsubscribe traffic by an old domain rule.
            if (
                (sender.provider_threat or sender.phishing_emails)
                and not sender.has_threat_conflict
            ) or (
                not sender.has_junk_conflict and (sender.junk_emails or sender.junk_keyword_emails)
            ):
                classifications[sender.classification_key] = Classification(
                    email_type=EmailType.COLD_OUTREACH,
                    action=Action.BLOCK,
                    confidence=1.0,
                    reasoning="Provider junk/phishing evidence requires local suppression",
                    source="provider_policy",
                )
            elif sender.has_threat_conflict:
                classifications[sender.classification_key] = Classification(
                    email_type=EmailType.UNKNOWN,
                    action=Action.REVIEW,
                    confidence=0.5,
                    reasoning="Conflicting clean and flagged messages require review without sender contact",
                    source="provider_policy",
                )
            elif sender.authentication_failed_emails >= sender.total_emails > 0:
                classifications[sender.classification_key] = Classification(
                    email_type=EmailType.UNKNOWN,
                    action=Action.BLOCK,
                    confidence=1.0,
                    reasoning=("Every observed delivery has a trusted authentication failure"),
                    source="auth_policy",
                )
            elif sender.authentication_failed_emails:
                current = classifications.get(sender.classification_key)
                if current is not None and current.action in (Action.BLOCK, Action.UNSUB):
                    classifications[sender.classification_key] = Classification(
                        email_type=current.email_type,
                        action=Action.REVIEW,
                        confidence=current.confidence,
                        reasoning=(
                            f"{current.reasoning}; mixed authentication evidence requires review"
                        ),
                        source="auth_policy",
                        recommended_action=current.recommended_action or current.action,
                        original_source=current.original_source or current.source,
                    )

    # Process results
    to_unsub = []
    to_keep = []
    to_review = []
    to_block = []
    outside_cleanup_review = []

    min_emails = config.thresholds.min_emails_before_action
    dormant_groups = 0
    deterministic_block_sources = {
        "user_rule",
        "provider_policy",
        "auth_policy",
        "retry_policy",
        "stored_policy",
    }

    for key, sender in sender_stats.items():
        classification = classifications.get(sender.classification_key)
        if classification is None:
            # Compatibility for classifiers that still return their input key.
            classification = classifications.get(key)
        if classification is None:
            logger.warning("No classification returned for %s", sender.classification_key)
            continue

        if (
            classification.action is Action.BLOCK
            and classification.source != "user_rule"
            and (
                sender.protected_subject_emails
                or classification.email_type in {EmailType.TRANSACTIONAL, EmailType.SECURITY}
            )
            and not _confirmed_provider_threat(sender)
        ):
            classification = replace(
                classification,
                action=Action.REVIEW,
                source="safety_policy",
                reasoning="Protected non-marketing mail is outside automatic cleanup; authentication failure alone does not establish phishing",
                recommended_action=classification.recommended_action or classification.action,
                original_source=classification.original_source or classification.source,
            )

        if sender.account_key in incomplete_accounts and classification.action in (
            Action.UNSUB,
            Action.BLOCK,
        ):
            classification = Classification(
                email_type=classification.email_type,
                action=Action.REVIEW,
                confidence=classification.confidence,
                source="scan_policy",
                reasoning="Incomplete mailbox scan; retry before applying this action",
                recommended_action=classification.recommended_action or classification.action,
                original_source=classification.original_source or classification.source,
            )

        if (
            classification.action in (Action.UNSUB, Action.REVIEW)
            and classification.source not in {"user_rule", "stored_policy"}
            and sender.last_seen is not None
            and ensure_utc(sender.last_seen) < utcnow() - timedelta(days=DORMANT_SENDER_DAYS)
        ):
            if classification.action is Action.UNSUB or _is_marketing_candidate(
                sender, classification
            ):
                dormant_groups += 1
            outside_cleanup_review.append(
                (
                    key,
                    sender,
                    replace(
                        classification,
                        action=Action.REVIEW,
                        source="dormant_policy",
                        reasoning=f"No mail in over {DORMANT_SENDER_DAYS} days; nothing to stop",
                        recommended_action=classification.recommended_action
                        or classification.action,
                        original_source=classification.original_source or classification.source,
                    ),
                )
            )
            continue

        # Don't auto-act on senders we've barely seen — defer to review.
        # Explicit user rules/overrides (source="user_rule") always take
        # highest priority and are never deferred by the email-count guard.
        if (
            classification.action in (Action.UNSUB, Action.BLOCK)
            and classification.source not in {"user_rule", "stored_policy"}
            and not (
                classification.action is Action.BLOCK
                and (
                    classification.source in deterministic_block_sources
                    or classification.email_type is EmailType.COLD_OUTREACH
                )
            )
            and sender.total_emails < min_emails
            and not (
                config.cleanup_level == "thorough"
                and classification.action is Action.UNSUB
                and classification.email_type in {EmailType.MARKETING, EmailType.NEWSLETTER}
                and sender.has_unsubscribe
            )
        ):
            logger.debug(
                "Deferring %s to review: only %d emails (< %d)",
                sender.classification_key,
                sender.total_emails,
                min_emails,
            )
            classification = Classification(
                email_type=classification.email_type,
                action=Action.REVIEW,
                confidence=classification.confidence,
                source="volume_policy",
                reasoning=f"Only {sender.total_emails} messages observed; "
                f"at least {min_emails} are required before automatic action",
                recommended_action=classification.recommended_action or classification.action,
                original_source=classification.original_source or classification.source,
            )
            if _is_marketing_candidate(sender, classification):
                to_review.append((key, sender, classification))
            else:
                outside_cleanup_review.append((key, sender, classification))
            continue

        if classification.action == Action.UNSUB:
            to_unsub.append((key, sender, classification))
        elif classification.action == Action.KEEP:
            to_keep.append((key, sender, classification))
        elif classification.action == Action.BLOCK:
            to_block.append((key, sender, classification))
        elif _is_marketing_candidate(sender, classification):
            to_review.append((key, sender, classification))
        else:
            outside_cleanup_review.append((key, sender, classification))

    # Summary as tree
    tree = Tree("[success]✓ Classification complete[/success]")
    unsubscribe_states = [_unsubscribe_execution_state(sender) for _, sender, _ in to_unsub]
    new_requests = unsubscribe_states.count("ready")
    manual_requests = unsubscribe_states.count("needs_user")
    retry_blocks = unsubscribe_states.count("retry_block")
    existing_requests = len(to_unsub) - new_requests - manual_requests - retry_blocks
    tree.add(f"[unsubscribe]{new_requests} to unsubscribe now[/unsubscribe]")
    if existing_requests:
        tree.add(f"[muted]{existing_requests} existing requests; no repeat planned[/muted]")
    if manual_requests:
        tree.add(f"[review]{manual_requests} unsubscribe requests need manual action[/review]")
    if retry_blocks:
        tree.add(f"[block]{retry_blocks} exhausted retries require local suppression[/block]")
    inbox_blocks = sum(sender.inbox_emails for _, sender, _ in to_block)
    existing_junk = sum(sender.junk_emails for _, sender, _ in to_block)
    tree.add(
        f"[block]{len(to_block)} block policies; {inbox_blocks} Inbox messages to move[/block]"
    )
    if existing_junk:
        tree.add(f"[muted]{existing_junk} matching messages already in Junk[/muted]")
    tree.add(f"[keep]{len(to_keep)} to keep[/keep]")
    tree.add(f"[review]{len(to_review)} marketing/spam groups need review[/review]")
    if dormant_groups:
        tree.add(
            f"[muted]{dormant_groups} marketing groups silent for over a year; "
            "nothing to unsubscribe[/muted]"
        )
    if len(outside_cleanup_review) > dormant_groups:
        tree.add(
            f"[muted]{len(outside_cleanup_review) - dormant_groups} other groups left unchanged, "
            "outside cleanup review[/muted]"
        )
    console.print(tree)

    if verbose:
        _show_details(to_unsub, to_keep, to_review, to_block)

    if (
        not auto
        and not dry_run
        and (
            to_unsub
            or to_review
            or to_block
            or any(
                _is_marketing_candidate(sender, classification)
                for _, sender, classification in to_keep
            )
        )
    ):
        if _styled_confirm("Review or change sender decisions?", default=False):
            _review_scan_decisions(
                to_unsub,
                to_keep,
                to_review,
                to_block,
                incomplete_accounts=frozenset(incomplete_accounts),
            )
            updated_tree = Tree("[header]Updated decisions[/header]")
            updated_tree.add(f"[unsubscribe]{len(to_unsub)} unsubscribe candidates[/unsubscribe]")
            updated_tree.add(f"[block]{len(to_block)} to block[/block]")
            updated_tree.add(f"[keep]{len(to_keep)} to keep[/keep]")
            updated_tree.add(f"[review]{len(to_review)} need review[/review]")
            console.print(updated_tree)

    for pending in (to_unsub, to_block):
        for row in pending[:]:
            key, sender, classification = row
            if sender.account_key in incomplete_accounts:
                pending.remove(row)
                deferred = replace(
                    classification,
                    action=Action.REVIEW,
                    source="scan_policy",
                    reasoning="Incomplete mailbox scan; no destructive actions are permitted",
                )
                if _is_marketing_candidate(sender, deferred):
                    to_review.append((key, sender, deferred))
                else:
                    outside_cleanup_review.append((key, sender, deferred))

    new_requests = sum(_unsubscribe_execution_state(sender) == "ready" for _, sender, _ in to_unsub)

    # Phase 3: execute two strictly separate paths. BLOCK is a mailbox action
    # and must never fall through to the network unsubscribe executor.
    if not dry_run and (to_unsub or to_block):
        if config.operation_mode == "confirm" and auto:
            console.print(
                "\n[warning]Confirm mode is on — skipping network and mailbox actions. "
                "Run without --auto to approve interactively.[/warning]"
            )
        elif auto or _styled_confirm(
            f"Apply {new_requests} unsubscribe requests and {len(to_block)} block policies?",
            default=True,
        ):
            console.print("\n[header]Step 3/3: Applying approved actions[/header]")

            with Progress(
                SpinnerColumn(style="#ffaf00"),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(
                    complete_style="orange1", finished_style="orange1", pulse_style="orange1"
                ),
                TaskProgressColumn(),
                console=console,
                transient=True,
            ) as progress:
                task = progress.add_task("Processing...", total=len(to_unsub) + len(to_block))
                suppressed_locally = 0

                for key, sender, classification in to_block:
                    headers = scan_result.get_emails_for_subscription(key) if authoritative else []
                    if not headers:
                        sample = scan_result.get_email_for_domain(sender.domain)
                        headers = [sample] if sample else []
                    if not headers:
                        stats.failed += 1
                        progress.advance(task)
                        continue
                    if not config.permits_mailbox_mutation:
                        if authoritative:
                            _record_block_needs_consent(sender, headers, classification)
                        console.print(
                            f"[warning]Skipped block for {_subscription_label(sender)}: "
                            "mailbox-action consent is missing. Run "
                            "`nothx consent --mailbox-actions --yes`.[/warning]"
                        )
                        stats.review_queued += 1
                        progress.advance(task)
                        continue
                    moved, move_failed = _block_subscription(
                        config, sender, headers, classification
                    )
                    if moved or not move_failed:
                        db.update_sender_status(sender.domain, SenderStatus.BLOCKED)
                    stats.failed += move_failed
                    progress.advance(task)

                for key, sender, classification in to_unsub:
                    headers = scan_result.get_emails_for_subscription(key) if authoritative else []
                    if not headers:
                        sample = scan_result.get_email_for_domain(sender.domain)
                        headers = [sample] if sample else []
                    if not headers:
                        stats.failed += 1
                        progress.advance(task)
                        continue
                    if authoritative and not config.permits_unsubscribe:
                        _record_unsubscribe_needs_consent(
                            sender,
                            headers,
                            classification,
                        )
                        console.print(
                            f"[warning]Skipped unsubscribe for {_subscription_label(sender)}: "
                            "unsubscribe-contact consent is missing. Run "
                            "`nothx consent --unsubscribe --yes`.[/warning]"
                        )
                        stats.review_queued += 1
                        progress.advance(task)
                        continue
                    account_config = _matching_account(config, headers)
                    try:
                        if authoritative:
                            subscription, messages = _persist_subscription_records(
                                sender, headers, classification
                            )
                            db.set_subscription_policy(
                                subscription["id"],
                                "unsub",
                                source="manual"
                                if classification.source == "user_rule"
                                else "automatic",
                            )
                            execute, exclusions, retry_generation, escalate = (
                                _unsubscribe_operation_plan(subscription)
                            )
                            consent_resume = _is_unsubscribe_consent_resume(
                                subscription,
                                config,
                            )
                            if escalate:
                                if config.permits_mailbox_mutation:
                                    block_classification = Classification(
                                        email_type=EmailType.UNKNOWN,
                                        action=Action.BLOCK,
                                        confidence=1.0,
                                        reasoning="The allowed unsubscribe retry was exhausted",
                                        source="retry_policy",
                                        recommended_action=(
                                            classification.recommended_action
                                            or classification.action
                                        ),
                                        original_source=(
                                            classification.original_source or classification.source
                                        ),
                                    )
                                    moved, move_failed = _block_subscription(
                                        config, sender, headers, block_classification
                                    )
                                    if moved or not move_failed:
                                        db.update_sender_status(sender.domain, SenderStatus.BLOCKED)
                                    stats.failed += move_failed
                                else:
                                    console.print(
                                        f"[warning]{_subscription_label(sender)} is still "
                                        "mailing after the allowed retry and needs Junk/block "
                                        "consent.[/warning]"
                                    )
                                    stats.review_queued += 1
                                progress.advance(task)
                                continue
                            if not execute:
                                _, move_failed = _clean_unwanted_inbox(
                                    config, subscription, messages
                                )
                                stats.failed += move_failed
                                logger.info(
                                    "Not repeating an accepted or in-grace request for %s",
                                    sender.classification_key,
                                )
                                progress.advance(task)
                                continue
                            claim_owner = uuid.uuid4().hex
                            claimed_operation, acquired = db.claim_unsubscribe_operation(
                                subscription["id"],
                                _operation_key("unsubscribe", sender, headers),
                                claim_owner,
                                allow_consent_resume=consent_resume,
                                trigger_message_ref_id=(messages[0][1]["id"] if messages else None),
                                retry_generation=retry_generation,
                            )
                            if not acquired:
                                if claimed_operation.get("outcome") == "needs_user":
                                    stats.review_queued += 1
                                logger.info(
                                    "Unsubscribe source is already claimed or completed for %s",
                                    sender.classification_key,
                                )
                                progress.advance(task)
                                continue
                            result = unsubscribe_subscription(
                                headers,
                                config,
                                account_config,
                                automatic=True,
                                exclude_fingerprints=exclusions,
                            )
                            exhausted_retry = (
                                retry_generation >= 1
                                and result.attempts == 0
                                and result.error
                                in {
                                    "No fresh unsubscribe endpoint is available",
                                    "No safe unsubscribe method is available",
                                }
                            )
                            if exhausted_retry:
                                result.outcome = UnsubscribeOutcome.FAILED
                                result.needs_confirmation = False
                            _record_unsubscribe_result(
                                sender,
                                headers,
                                classification,
                                result,
                                retry_generation=retry_generation,
                                operation_id=claimed_operation["id"],
                                claim_owner=claim_owner,
                            )
                            _, move_failed = _clean_unwanted_inbox(config, subscription, messages)
                            stats.failed += move_failed
                            refused = result.outcome is UnsubscribeOutcome.BLOCKED
                            if exhausted_retry or refused:
                                block_classification = Classification(
                                    email_type=EmailType.UNKNOWN,
                                    action=Action.BLOCK,
                                    confidence=1.0,
                                    reasoning=(
                                        "Provider flagged this mail as junk; blocked without "
                                        "contacting the sender"
                                        if refused
                                        else "No fresh endpoint remained after the allowed retry"
                                    ),
                                    source="provider_policy" if refused else "retry_policy",
                                )
                                suppressed_locally += refused
                                if config.permits_mailbox_mutation:
                                    moved, move_failed = _block_subscription(
                                        config,
                                        sender,
                                        headers,
                                        block_classification,
                                    )
                                    if moved or not move_failed:
                                        db.update_sender_status(sender.domain, SenderStatus.BLOCKED)
                                    stats.failed += move_failed
                                else:
                                    _record_block_needs_consent(
                                        sender,
                                        headers,
                                        block_classification,
                                    )
                                    stats.review_queued += 1
                                progress.advance(task)
                                continue
                        else:
                            # Legacy ScanResult compatibility for callers that
                            # have not yet adopted subscription grouping. Use
                            # the same grouped policy gates rather than the
                            # legacy executor, which permits
                            # authentication-unknown traffic.
                            result = unsubscribe_subscription(
                                headers,
                                config,
                                account_config,
                                automatic=True,
                            )
                    except UnsafeUnsubscribeError:
                        logger.info("Protected subscription needs review: %s", sender.domain)
                        stats.review_queued += 1
                        progress.advance(task)
                        continue
                    if result.success:
                        stats.auto_unsubbed += 1
                    elif result.needs_confirmation:
                        stats.review_queued += 1
                    elif result.outcome is UnsubscribeOutcome.BLOCKED:
                        suppressed_locally += 1
                    else:
                        stats.failed += 1
                    progress.advance(task)

            console.print(
                f"\n[success]✓ {stats.auto_unsubbed} unsubscribe request(s) accepted[/success]"
            )
            if suppressed_locally:
                console.print(
                    f"[muted]{suppressed_locally} junk-flagged sender(s) blocked locally "
                    "instead of contacted[/muted]"
                )
            if stats.failed:
                console.print(f"[warning]! {stats.failed} action(s) failed[/warning]")
            if to_block:
                console.print(
                    "[muted]Portable IMAP Junk movement is best-effort; provider spam "
                    "training is not guaranteed.[/muted]"
                )
            console.print(
                "\n[muted]`nothx undo` changes future local policy; it cannot resubscribe "
                "you with an external sender.[/muted]"
            )

    # Update stats
    stats.kept = len(to_keep) + len(outside_cleanup_review)
    stats.review_queued += len(to_review)

    # REVIEW is authoritative per account/list. Without this row, the legacy
    # domain queue can merge independent lists and hide one behind another's
    # KEEP decision.
    if not dry_run and authoritative:
        for key, sender, classification in to_review:
            headers = scan_result.get_emails_for_subscription(key)
            if headers:
                _persist_subscription_records(
                    sender,
                    headers,
                    classification,
                    policy_action="review",
                )

    if not dry_run and authoritative:
        for key, sender, classification in outside_cleanup_review:
            headers = scan_result.get_emails_for_subscription(key)
            if headers:
                _persist_subscription_records(
                    sender,
                    headers,
                    replace(
                        classification,
                        action=Action.KEEP,
                        source="cleanup_scope",
                        recommended_action=classification.recommended_action
                        or classification.action,
                        original_source=classification.original_source or classification.source,
                    ),
                    policy_action="keep",
                )

    # Mark keep senders (dry-run must not mutate the database)
    if not dry_run:
        for key, sender, classification in to_keep:
            db.update_sender_status(sender.domain, SenderStatus.KEEP)
            if authoritative:
                headers = scan_result.get_emails_for_subscription(key)
                if headers:
                    _persist_subscription_records(
                        sender,
                        headers,
                        classification,
                        policy_action="keep",
                    )

    # Log run
    if not dry_run:
        db.log_run(stats)

    # Prompt about review queue
    if to_review and not auto:
        console.print(f"\n[warning]{len(to_review)} senders need manual review.[/warning]")
        console.print("Run [bold]nothx review[/bold] to process them.")


_DecisionRow = tuple[str, SenderStats, Classification]
_REVIEW_PAGE_SIZE = 20


def _confirmed_provider_threat(sender: SenderStats) -> bool:
    if sender.provider_threat or sender.phishing_emails:
        return True
    if not (sender.account_key and sender.identity_kind and sender.identity_value):
        return False
    subscription = db.get_subscription(
        account=sender.account_key,
        identity_kind=sender.identity_kind,
        identity_value=sender.identity_value,
    )
    return (
        subscription is not None
        and _persisted_threat_action(subscription["id"], folder_evidence=False, include_auth=False)
        is Action.BLOCK
    )


def _is_marketing_candidate(sender: SenderStats, classification: Classification) -> bool:
    if classification.email_type in {
        EmailType.MARKETING,
        EmailType.NEWSLETTER,
        EmailType.COLD_OUTREACH,
    }:
        return True
    bulk = bool(sender.esp_name or sender.provider_bulk_emails)
    promotional = sender.promotional_subject_emails > 0 or any(
        has_promotional_subject(subject) for subject in sender.sample_subjects
    )
    list_evidence = bool(
        sender.has_unsubscribe
        or sender.list_id
        or sender.bulk_precedence
        or sender.has_feedback_id
        or bulk
    )
    if classification.email_type in {EmailType.TRANSACTIONAL, EmailType.SECURITY}:
        return promotional and list_evidence
    explicit_offer = sender.authenticated_emails > 0 and any(
        has_explicit_offer_subject(subject) for subject in sender.sample_subjects
    )
    return (promotional and (list_evidence or explicit_offer)) or (
        bulk and not sender.protected_subject_emails
    )


def _review_sender_label(sender: SenderStats) -> str:
    identity = _subscription_label(sender)
    if sender.identity_kind != "from" and sender.sample_senders:
        identity += f" · From: {sender.sample_senders[0]}"
    identity = re.sub(r"[\x00-\x1f\x7f]", " ", identity)
    return f"{identity} · {sender.total_emails:,} messages"


def _review_scan_decisions(
    to_unsub: list[_DecisionRow],
    to_keep: list[_DecisionRow],
    to_review: list[_DecisionRow],
    to_block: list[_DecisionRow],
    *,
    incomplete_accounts: frozenset[str] = frozenset(),
) -> None:
    groups = {
        "review": ("Needs review", to_review),
        "block": ("Block candidates", to_block),
        "unsub": ("Unsubscribe candidates and existing requests", to_unsub),
        "keep": ("Kept marketing senders", to_keep),
    }

    def visible(group: str, row: _DecisionRow) -> bool:
        return group != "keep" or _is_marketing_candidate(row[1], row[2])

    def stop_action(row: _DecisionRow) -> Action | None:
        _key, sender, classification = row
        recommended = classification.recommended_action or classification.action
        if (
            sender.account_key in incomplete_accounts
            or classification.source == "scan_policy"
            or (sender.protected_subject_emails and not _confirmed_provider_threat(sender))
            or not (
                recommended in {Action.UNSUB, Action.BLOCK}
                or classification.email_type
                in {EmailType.MARKETING, EmailType.NEWSLETTER, EmailType.COLD_OUTREACH}
            )
        ):
            return None
        if (
            recommended is Action.BLOCK
            or classification.email_type is EmailType.COLD_OUTREACH
            or not (sender.has_unsubscribe or sender.can_unsubscribe_emails > 0)
        ):
            return Action.BLOCK
        return Action.UNSUB

    def recommended_stop(row: _DecisionRow) -> bool:
        classification = row[2]
        return stop_action(row) is not None and (
            (classification.recommended_action or classification.action)
            in {Action.UNSUB, Action.BLOCK}
        )

    def stop(rows: list[_DecisionRow], chosen: list[_DecisionRow]) -> None:
        counts = {Action.UNSUB: 0, Action.BLOCK: 0}
        for row in chosen:
            action = stop_action(row)
            if action is None or row not in rows:
                continue
            rows.remove(row)
            key, sender, classification = row
            groups[action.value][1].append(
                (key, sender, _manual_classification(classification, action))
            )
            counts[action] += 1
        console.print(
            f"[success]✓ {counts[Action.UNSUB]:,} set to unsubscribe, "
            f"{counts[Action.BLOCK]:,} set to block[/success]"
        )

    _select_header("Review marketing and spam by sender")
    console.print(
        "[muted]Choose a group, then search or select a sender. "
        "Accounts and mailing lists stay separate. Finish when ready.[/muted]"
    )
    while True:
        recommended = [row for row in to_review if recommended_stop(row)]
        bulk_choices = (
            [
                questionary.Choice(
                    f"Stop all {len(recommended):,} recommended senders "
                    "(unsubscribe, or block when there is no unsubscribe method)",
                    value="stop_recommended",
                )
            ]
            if recommended
            else []
        )
        group = questionary.select(
            "Which decisions would you like to inspect?",
            choices=bulk_choices
            + [
                questionary.Choice(
                    f"{title} ({sum(visible(key, row) for row in rows):,})", value=key
                )
                for key, (title, rows) in groups.items()
                if any(visible(key, row) for row in rows)
            ]
            + [questionary.Choice("Finish review", value="finish")],
            default=bulk_choices[0].value if bulk_choices else "finish",
            **Q_COMMON,
        ).ask()
        if group is None or group == "finish":
            return
        if group == "stop_recommended":
            stop(to_review, recommended)
            continue
        if group not in groups:
            continue
        title, rows = groups[group]
        page = 0
        query = ""
        while True:
            filtered = [
                row
                for row in rows
                if visible(group, row)
                and query
                in " ".join(
                    [
                        _review_sender_label(row[1]),
                        row[1].domain,
                        *row[1].sample_subjects,
                        *row[1].promotional_sample_subjects,
                        *row[1].sample_senders,
                    ]
                ).casefold()
            ]
            last_page = max(0, (len(filtered) - 1) // _REVIEW_PAGE_SIZE)
            page = min(page, last_page)
            shown = filtered[page * _REVIEW_PAGE_SIZE : (page + 1) * _REVIEW_PAGE_SIZE]
            choices = [
                questionary.Choice(_review_sender_label(sender), value=f"sender:{key}")
                for key, sender, _ in shown
            ]
            stoppable = [
                row for row in filtered if group in {"review", "keep"} and stop_action(row)
            ]
            if stoppable:
                choices.insert(
                    0,
                    questionary.Choice(
                        f"Select several to stop at once ({len(stoppable):,} eligible)",
                        value="bulk",
                    ),
                )
            choices.append(
                questionary.Choice("Search by sender, account, list, or subject", value="search")
            )
            if page < last_page:
                choices.append(questionary.Choice("Next page", value="next"))
            if page:
                choices.append(questionary.Choice("Previous page", value="previous"))
            choices.extend(
                [
                    questionary.Choice("Back to groups", value="back"),
                    questionary.Choice("Finish review", value="finish"),
                ]
            )
            selected = questionary.select(
                f"{title} · {len(filtered):,} matches · page {page + 1}/{last_page + 1}",
                choices=choices,
                default="back",
                **Q_COMMON,
            ).ask()
            if selected is None or selected == "finish":
                return
            if selected == "back":
                break
            if selected in {"next", "previous"}:
                page += 1 if selected == "next" else -1
                page = max(0, page)
                continue
            if selected == "bulk":
                picked = questionary.checkbox(
                    "Senders to stop (space toggles, enter applies)",
                    choices=[
                        questionary.Choice(
                            f"{_review_sender_label(row[1])} · {stop_action(row).value}",  # type: ignore[union-attr]
                            value=index,
                            checked=recommended_stop(row),
                        )
                        for index, row in enumerate(stoppable)
                    ],
                    style=Q_STYLE,
                ).ask()
                if picked:
                    stop(rows, [stoppable[index] for index in picked])
                continue
            if selected == "search":
                entered = questionary.text(
                    "Sender, account, list, or subject (empty clears search):",
                    default=query,
                    style=Q_INPUT_STYLE,
                ).ask()
                if entered is not None:
                    query = entered.strip().casefold()
                    page = 0
                continue
            row = next((row for row in shown if selected == f"sender:{row[0]}"), None)
            if row is None:
                continue
            key, sender, classification = row
            console.print(
                Panel(
                    f"{escape(_review_sender_label(sender))}\n"
                    f"Decision: {classification.action.value} · {classification.email_type.value}\n"
                    f"Reason: {escape(classification.reasoning)}\n"
                    f"Marked read: {sender.open_rate:.0f}%\n"
                    f"Recent subjects: {escape(' / '.join(sender.sample_subjects[:3]))}\n"
                    f"Promotional subjects in scan: {sender.promotional_subject_emails:,}\n"
                    f"Promotional examples: {escape(' / '.join(sender.promotional_sample_subjects))}",
                    title="Sender details",
                )
            )
            if sender.protected_subject_emails and sender.promotional_subject_emails:
                console.print(
                    "This sender mixes service mail and promotions. Leave for later review, "
                    "then use `nothx review` to choose a specific newsletter source."
                )
            allowed = {"keep", "skip", "unchanged"}
            action_choices = [questionary.Choice("Keep future mail", value="keep")]
            if (
                sender.account_key not in incomplete_accounts
                and classification.source != "scan_policy"
                and (not sender.protected_subject_emails or _confirmed_provider_threat(sender))
            ):
                allowed.add("block")
                action_choices.append(
                    questionary.Choice(
                        "Block this sender/list and move its Inbox mail to Junk", value="block"
                    )
                )
                if sender.has_unsubscribe or sender.can_unsubscribe_emails > 0:
                    allowed.add("unsub")
                    action_choices.append(
                        questionary.Choice(
                            "Request unsubscribe (safety checks still apply)", value="unsub"
                        )
                    )
            action_choices.extend(
                [
                    questionary.Choice("Leave for later review", value="skip"),
                    questionary.Choice("Leave unchanged", value="unchanged"),
                ]
            )
            action = questionary.select(
                f"Action for {_subscription_label(sender)}?",
                choices=action_choices,
                default="unchanged",
                **Q_COMMON,
            ).ask()
            if action is None:
                return
            if action not in allowed or action == "unchanged":
                continue
            rows.remove(row)
            destination = "review" if action == "skip" else action
            result = (
                classification
                if action == "skip"
                else _manual_classification(classification, Action(action))
            )
            groups[destination][1].append((key, sender, result))
            console.print(
                f"[muted]Decision updated for {escape(_subscription_label(sender))}: {destination}[/muted]"
            )


def _show_details(to_unsub, to_keep, to_review, to_block):
    """Show detailed classification results."""
    if to_unsub:
        console.print("\n[bold red]Unsubscribe candidates and existing requests:[/bold red]")
        table = Table(show_header=True)
        table.add_column("Account / List identity")
        table.add_column("Domain")
        table.add_column("Emails")
        table.add_column("Marked read")
        table.add_column("Reason")
        table.add_column("Recent subjects")
        table.add_column("Request state")
        for _key, sender, classification in to_unsub:
            table.add_row(
                _subscription_label(sender),
                sender.domain,
                str(sender.total_emails),
                f"{sender.open_rate:.0f}%",
                escape(classification.reasoning),
                escape(" / ".join(sender.sample_subjects[:3])),
                _unsubscribe_execution_state(sender),
            )
        console.print(table)

    marketing_kept = [row for row in to_keep if _is_marketing_candidate(row[1], row[2])]
    if marketing_kept:
        console.print("\n[bold green]Marketing left unchanged:[/bold green]")
        table = Table(show_header=True)
        table.add_column("Account / List identity")
        table.add_column("Domain")
        table.add_column("Emails")
        table.add_column("Marked read")
        table.add_column("Reason")
        for _key, sender, classification in marketing_kept[:10]:
            table.add_row(
                _subscription_label(sender),
                sender.domain,
                str(sender.total_emails),
                f"{sender.open_rate:.0f}%",
                classification.reasoning[:50],
            )
        console.print(table)

    actionable_blocks = [row for row in to_block if row[1].total_emails > row[1].junk_emails]
    if actionable_blocks:
        console.print("\n[bold red]To Block / Move to Junk:[/bold red]")
        table = Table(show_header=True)
        table.add_column("Account / List identity")
        table.add_column("Domain")
        table.add_column("Inbox")
        table.add_column("Reason")
        table.add_column("Recent subjects")
        for _key, sender, classification in actionable_blocks:
            table.add_row(
                _subscription_label(sender),
                sender.domain,
                str(sender.inbox_emails),
                escape(classification.reasoning),
                escape(" / ".join(sender.sample_subjects[:3])),
            )
        console.print(table)


@main.command()
@click.option("--learning", is_flag=True, help="Show learning insights and preferences")
def status(learning: bool):
    """Show current nothx status."""
    config = Config.load()

    if not config.is_configured():
        console.print("[error]nothx is not configured. Run 'nothx init' first.[/error]")
        return

    db.init_db()

    # If --learning flag, show learning status instead
    if learning:
        _show_learning_status(config)
        return

    console.print("\n[header]nothx Status[/header]")
    console.print(Rule(style="#808080"))

    # Stats summary as columns
    stats = db.get_stats()
    subscription_stats = db.get_subscription_stats()
    successful, failed = db.get_unsub_success_rate()
    total_unsub_attempts = successful + failed
    success_rate = (successful / total_unsub_attempts * 100) if total_unsub_attempts > 0 else 0

    panel_data = [
        (f"[count]{stats['total_senders']}[/count]", "Senders"),
        (f"[count]{stats['unsubscribed']}[/count]", "Unsubbed"),
        (f"[count]{stats['kept']}[/count]", "Kept"),
        (f"[count]{success_rate:.0f}%[/count]", "Success"),
    ]
    if subscription_stats["total"]:
        panel_data = [
            (f"[count]{subscription_stats['total']}[/count]", "Subscriptions"),
            (f"[count]{subscription_stats['requested']}[/count]", "Requested"),
            (f"[count]{subscription_stats['kept']}[/count]", "Kept"),
            (f"[count]{subscription_stats['verified_quiet']}[/count]", "Quiet"),
        ]
    stat_panels = [
        Panel(
            f"{value}\n[muted]{label}[/muted]",
            width=max(14, len(label) + 4),
            border_style="#808080",
        )
        for value, label in panel_data
    ]
    console.print(Columns(stat_panels, padding=(0, 1)))

    # Account info
    console.print("\n[header]Accounts[/header]")
    for name, acc in config.accounts.items():
        is_default = " [muted](default)[/muted]" if name == config.default_account else ""
        console.print(f"{_L} {acc.email} ({acc.provider}){is_default}")

    # AI status
    console.print("\n[header]Configuration[/header]")
    if config.ai.enabled:
        console.print(f"{_L} AI: [success]enabled[/success] ({config.ai.provider})")
    else:
        console.print(f"{_L} AI: [warning]disabled[/warning] (heuristics only)")
    console.print(f"{_L} Mode: {config.operation_mode}")
    console.print(f"{_L} Scan days: {config.scan_days}")

    # Detailed stats
    console.print("\n[header]Details[/header]")
    if total_unsub_attempts > 0:
        console.print(
            f"{_L} Unsubscribe results: [success]{successful} successful[/success], "
            f"[error]{failed} failed[/error]"
        )

    pending_review = (
        subscription_stats["pending_review"]
        if subscription_stats["total"]
        else stats["pending_review"]
    )
    console.print(f"{_L} Pending review: [count]{pending_review}[/count]")
    console.print(f"{_L} Total runs: [count]{stats['total_runs']}[/count]")

    grouped = db.get_grouped_metrics()
    outcomes = grouped["operations"]
    active_manual = [
        subscription
        for subscription in db.list_subscriptions(outcome="needs_user", limit=10_000)
        if subscription.get("policy_action") != "keep"
    ]
    cleanup_operations = [
        row
        for row in db.list_unsubscribe_operations(include_mailbox_cleanup=True, limit=100_000)
        if not row["affects_subscription"] and row["outcome"] in {None, "failed", "needs_user"}
    ]
    if cleanup_operations:
        console.print(
            f"\nInbox cleanup: {len(cleanup_operations)} recorded unsuccessful or pending attempt(s)"
        )
        for row in cleanup_operations[:10]:
            console.print(
                f"  Subscription #{row['subscription_id']}: "
                f"{row['error_code'] or 'in progress'}; run `nothx cleanup` to recheck sources and retry eligible moves"
            )
        console.print(
            "[muted]Ambiguous moves are never retried. If their sources remain in Inbox, "
            "inspect Inbox and Junk manually.[/muted]"
        )
    if any(outcomes.values()) or active_manual:
        console.print("\n[header]Subscription operations[/header]")
        console.print(
            f"{_L} Requested: [count]{outcomes['requested']}[/count] · "
            f"Verified quiet: [count]{outcomes['verified_quiet']}[/count] · "
            f"Ineffective: [count]{outcomes['ineffective']}[/count]"
        )
        console.print(
            f"{_L} Blocked: [count]{outcomes['blocked']}[/count] · "
            f"Needs user: [count]{outcomes['needs_user']}[/count] · "
            f"Failed: [count]{outcomes['failed']}[/count]"
        )
        parked_blocks = db.count_consent_parked_blocks()
        console.print(
            f"{_L} Manual-action queue: [count]{len(active_manual) - parked_blocks}[/count]"
            + (
                f" · queued blocks awaiting apply: [count]{parked_blocks}[/count]"
                if parked_blocks
                else ""
            )
        )
        console.print(
            f"{_L} [muted]Requested means the endpoint accepted delivery; it does not "
            "guarantee mail has stopped. verified_quiet requires a complete post-grace "
            "scan.[/muted]"
        )

        recent_subscriptions = db.list_subscriptions(limit=10)
        if recent_subscriptions:
            table = Table(show_header=True)
            table.add_column("ID")
            table.add_column("Account")
            table.add_column("List identity")
            table.add_column("Policy")
            table.add_column("Outcome")
            for subscription in recent_subscriptions:
                table.add_row(
                    str(subscription["id"]),
                    subscription["account"],
                    f"{subscription['identity_kind']}:{subscription['identity_value']}",
                    subscription.get("policy_action") or "—",
                    subscription.get("last_outcome") or "—",
                )
            console.print(table)
            if active_manual:
                console.print(
                    f"{_L} [muted]For a needs_user row, run "
                    "`nothx open-unsubscribe <ID>` to rescan and explicitly open "
                    "a page.[/muted]"
                )

    # Senders still mailing after a "successful" unsubscribe (Gmail/Yahoo allow
    # ~48h; anything past the grace window is a candidate to escalate to block).
    offenders = db.get_post_unsub_offenders()
    if offenders:
        console.print(
            f"\n[warning]{len(offenders)} sender(s) still mailing after unsubscribe:[/warning]"
        )
        for row in offenders[:10]:
            console.print(
                f"{_L} {row['domain']} "
                f"[muted]({row['total_emails']} emails; unsubscribed {row['unsubscribed_at'][:10]})[/muted]"
            )
        console.print("[muted]Consider blocking these: nothx rule <domain> block[/muted]")

    if stats["last_run"]:
        try:
            last_run_dt = datetime.fromisoformat(stats["last_run"])
            relative_time = humanize.naturaltime(last_run_dt)
            console.print(f"{_L} Last run: {relative_time}")
        except (ValueError, TypeError):
            console.print(f"{_L} Last run: {stats['last_run']}")

    # Schedule status
    schedule = get_schedule_status()
    if schedule:
        console.print("\n[header]Schedule[/header]")
        console.print(f"{_L} Type: {schedule['type']}")
        console.print(f"{_L} Frequency: {schedule['frequency']}")
        if schedule["frequency"] != "daily":
            console.print(
                f"{_L} [warning]Daily scans are recommended so BLOCK policies and "
                "48-hour verification run promptly. Upgrade with "
                "`nothx schedule --daily`.[/warning]"
            )
    else:
        console.print("\n[warning]No automatic schedule configured[/warning]")
        console.print("Run [bold]nothx schedule --daily[/bold] to set up")

    console.print()


def _pick_saved_reviews(rows: list[tuple[str, str]]) -> Iterator[str]:
    pending = rows[:]
    page = 0
    query = ""
    while pending:
        matches = [row for row in pending if query in row[1].casefold()]
        last_page = max(0, (len(matches) - 1) // _REVIEW_PAGE_SIZE)
        page = min(page, last_page)
        shown = matches[page * _REVIEW_PAGE_SIZE : (page + 1) * _REVIEW_PAGE_SIZE]
        choices = [
            questionary.Choice(re.sub(r"[\x00-\x1f\x7f]", " ", label), value=f"row:{key}")
            for key, label in shown
        ]
        choices.append(questionary.Choice("Search by sender, account, or list", value="search"))
        if page < last_page:
            choices.append(questionary.Choice("Next page", value="next"))
        if page:
            choices.append(questionary.Choice("Previous page", value="previous"))
        choices.append(questionary.Choice("Finish review", value="finish"))
        selected = questionary.select(
            f"Saved decisions · {len(matches):,} matches · page {page + 1}/{last_page + 1}",
            choices=choices,
            default="finish",
            **Q_COMMON,
        ).ask()
        if selected is None or selected == "finish":
            return
        if selected in {"next", "previous"}:
            page = max(0, page + (1 if selected == "next" else -1))
            continue
        if selected == "search":
            entered = questionary.text(
                "Sender, account, or list (empty clears search):",
                default=query,
                style=Q_INPUT_STYLE,
            ).ask()
            if entered is not None:
                query = entered.strip().casefold()
                page = 0
            continue
        row = next((row for row in shown if selected == f"row:{row[0]}"), None)
        if row is not None:
            yield row[0]
            pending.remove(row)


@main.command()
@click.option("--all", "show_all", is_flag=True, help="Show all pending senders")
@click.option("--keep", "show_keep", is_flag=True, help="Review senders marked to keep")
@click.option("--unsub", "show_unsub", is_flag=True, help="Review senders marked to unsubscribe")
@click.option(
    "--apply-pending",
    is_flag=True,
    help="Apply block decisions queued while mailbox consent was missing, then exit",
)
def review(show_all: bool, show_keep: bool, show_unsub: bool, apply_pending: bool):
    """Review senders that need manual decision.

    By default, shows only senders that need review (uncertain classification).
    Use --all to see all pending senders, or --keep/--unsub to filter by classification.
    """
    config = Config.load()

    if not config.is_configured():
        console.print("[error]nothx is not configured. Run 'nothx init' first.[/error]")
        return

    db.init_db()

    if apply_pending:
        parked = db.count_consent_parked_blocks()
        if not parked:
            console.print("[success]✓ No queued block decisions to apply[/success]")
            return
        if not config.permits_mailbox_mutation:
            console.print(
                f"[warning]{parked} block decision(s) are queued but mailbox-action "
                "consent is missing. Run `nothx consent --mailbox-actions --yes`.[/warning]"
            )
            return
        drained, moved, failed = _drain_consent_parked_blocks(config)
        console.print(
            f"[success]✓ Applied {drained} queued block(s)[/success]: "
            f"{moved} message(s) moved to Junk"
            + (f", {failed} message action(s) failed" if failed else "")
        )
        return

    manual_subscriptions: list[dict[str, Any]] = []
    handled_manual_domains: set[str] = set()
    if show_keep or show_unsub:
        manual_subscriptions = db.list_subscriptions(
            policy_action="keep" if show_keep else "unsub", limit=None
        )
    else:
        parked_ids = {row["id"] for row in db.list_consent_parked_blocks()}
        pages = [
            db.list_subscriptions(outcome="needs_user", limit=None),
            db.list_subscriptions(outcome="failed", limit=None),
            db.list_subscriptions(policy_action="review", limit=None),
        ]
        by_id: dict[int, dict[str, Any]] = {}
        for subscription in (row for page in pages for row in page):
            if (
                subscription.get("policy_action") == "keep"
                or subscription.get("last_outcome") in {"requested", "verified_quiet"}
                or subscription["id"] in parked_ids
            ):
                continue
            by_id[subscription["id"]] = subscription
        manual_subscriptions = list(by_id.values())

    # Determine which senders to show
    if show_keep:
        senders = db.get_senders_by_status(SenderStatus.KEEP)
        filter_label = "marked to keep"
    elif show_unsub:
        senders = db.get_senders_by_status(SenderStatus.UNSUBSCRIBED)
        filter_label = "marked to unsubscribe"
    elif show_all:
        senders = db.get_senders_by_status(SenderStatus.UNKNOWN)
        filter_label = "pending"
    else:
        # Default: only senders that need review (uncertain)
        senders = db.get_senders_for_review()
        filter_label = "needing review"

    handled_manual_domains.update(
        row["sender_domain"].casefold()
        for row in db.list_subscriptions(limit=None)
        if row.get("sender_domain")
    )
    senders = [
        sender for sender in senders if sender["domain"].casefold() not in handled_manual_domains
    ]

    if manual_subscriptions and senders:
        group = questionary.select(
            "Which saved decisions would you like to review?",
            choices=[
                questionary.Choice(
                    f"Account/list decisions ({len(manual_subscriptions):,})", value="subscriptions"
                ),
                questionary.Choice(
                    f"Legacy-only pending domains ({len(senders):,})", value="legacy"
                ),
                questionary.Choice("Finish review", value="finish"),
            ],
            default="finish",
            **Q_COMMON,
        ).ask()
        if group == "legacy":
            manual_subscriptions = []
        elif group != "subscriptions":
            return

    if manual_subscriptions:
        console.print(
            f"\n[header]{len(manual_subscriptions):,} saved account/list decisions to review[/header]"
        )
        saved_by_id = {str(row["id"]): row for row in manual_subscriptions}
        labels = [
            (
                str(row["id"]),
                f"#{row['id']} · {row['account']} · {row['identity_kind']}:{row['identity_value']}"
                f" · {row.get('policy_action') or 'review'} · {row.get('last_outcome') or 'no request'}",
            )
            for row in manual_subscriptions
        ]
        for selected_id in _pick_saved_reviews(labels):
            subscription = saved_by_id[selected_id]
            scope = {
                int(message["id"])
                for message in db.list_message_refs(
                    subscription_id=subscription["id"], mailbox_role="inbox", limit=100_000
                )
            }
            console.print(
                Panel(
                    f"{escape(subscription['account'])} · "
                    f"{escape(subscription['identity_kind'] + ':' + subscription['identity_value'])}\n"
                    f"Stored Inbox refs: {len(scope):,} across recorded history. "
                    "These locators may no longer be present.",
                    title="Saved sender/list decision",
                )
            )
            identity = f"{subscription['identity_kind']}:{subscription['identity_value']}"
            choices = []
            if (
                subscription.get("policy_action") != "block"
                and subscription.get("last_outcome") != "blocked"
                and not _subscription_has_persisted_threat(subscription["id"])
            ):
                choices.extend(
                    [
                        questionary.Choice("Resolve unsubscribe in Nothx", value="resolve"),
                        questionary.Choice("Rescan and open an unsubscribe page", value="open"),
                        questionary.Choice(
                            "Record provider confirmation from browser", value="completed"
                        ),
                    ]
                )
            choices.extend(
                [
                    questionary.Choice("Keep future mail", value="keep"),
                    questionary.Choice(
                        f"Block future mail and move {len(scope)} stored Inbox refs",
                        value="block",
                    ),
                    questionary.Choice("Leave for later", value="skip"),
                    questionary.Choice("Finish review", value="finish"),
                ]
            )
            choice = questionary.select(
                f"{subscription['account']} · {identity}",
                choices=choices,
                default="skip",
                **Q_COMMON,
            ).ask()
            if choice is None or choice == "finish":
                return
            if choice in {"resolve", "completed"}:
                try:
                    click.get_current_context().invoke(
                        resolve_subscription,
                        subscription_id=subscription["id"],
                        retry=bool(subscription.get("last_outcome"))
                        if choice == "resolve"
                        else False,
                        dry_run=False,
                        source_uid=None,
                        completed=choice == "completed",
                        yes=False,
                    )
                except click.ClickException as error:
                    console.print(f"[warning]{escape(error.format_message())}[/warning]")
                    continue
            elif choice == "open":
                click.get_current_context().invoke(
                    open_unsubscribe,
                    subscription_id=subscription["id"],
                    yes=False,
                )
            elif choice == "block":
                moved, failed = _apply_manual_subscription_block(
                    config, subscription, message_ids=scope
                )
                _learn_subscription_policy(subscription, choice)
                if domain := subscription.get("sender_domain"):
                    handled_manual_domains.add(domain.casefold())
                if not config.permits_mailbox_mutation:
                    console.print(f"{_L} Future BLOCK stored; Junk movement needs consent")
                else:
                    console.print(f"{_L} Blocked: {moved} moved, {failed} partial/failed")
            elif choice == "keep":
                db.set_subscription_policy(subscription["id"], choice)
                _learn_subscription_policy(subscription, choice)
                if domain := subscription.get("sender_domain"):
                    handled_manual_domains.add(domain.casefold())
                console.print(f"{_L} Future policy set to {choice}")
        _report_consent_parked_blocks(config)
        return

    if not senders and not manual_subscriptions:
        console.print(f"[success]No senders {filter_label}![/success]")
        _report_consent_parked_blocks(config)
        return
    if not senders:
        _report_consent_parked_blocks(config)
        return

    _select_header(f"{len(senders)} senders {filter_label}")

    legacy_by_domain = {sender["domain"]: sender for sender in senders}
    for domain in _pick_saved_reviews([(sender["domain"], sender["domain"]) for sender in senders]):
        sender = legacy_by_domain[domain]
        total = sender["total_emails"]
        subjects = sender.get("sample_subjects", "").split("|")[:3]

        console.print(f"[bold][{total} emails] [domain]{domain}[/domain][/bold]")
        if sender.get("ai_classification"):
            confidence = sender.get("ai_confidence", 0)
            console.print(
                f"{_L} [muted]AI says: {sender['ai_classification']} ({confidence:.0%} confident)[/muted]"
            )
        if subjects and subjects[0]:
            console.print(f"{_L} [muted]Subjects: {', '.join(s for s in subjects if s)}[/muted]")

        # Interactive selector with clear labels
        choice = questionary.select(
            f"What would you like to do with {domain}?",
            choices=[
                questionary.Choice("Unsubscribe - Stop receiving emails", value="unsub"),
                questionary.Choice("Keep - Continue receiving", value="keep"),
                questionary.Choice("Block - Block sender entirely", value="block"),
                questionary.Choice("Skip - Decide later", value="skip"),
                questionary.Choice("Finish review", value="finish"),
            ],
            default="skip",
            **Q_COMMON,
        ).ask()

        if choice is None or choice == "finish":
            break

        if choice in ("unsub", "keep", "block"):
            _change_sender_status(domain, choice, sender=sender, config=config)
        else:
            console.print(f"{_L} [review]\u2192 Skipped[/review]")

        console.print()


@main.command("resolve")
@click.argument("subscription_id", type=int)
@click.option(
    "--retry", is_flag=True, help="Explicitly allow one bounded retry of a failed/manual case"
)
@click.option(
    "--dry-run", is_flag=True, help="Refresh and show sources; send no requests or database writes"
)
@click.option("--source-uid", type=int, help="Choose the displayed source UID for a mixed sender")
@click.option(
    "--completed", is_flag=True, help="Record that you saw provider confirmation in the browser"
)
@click.option(
    "--yes", is_flag=True, help="Confirm the selected account/list action without a prompt"
)
def resolve_subscription(
    subscription_id: int,
    retry: bool,
    dry_run: bool,
    source_uid: int | None,
    completed: bool,
    yes: bool,
) -> None:
    """Finish a saved account/list decision using fresh, revalidated sources.

    Login, CAPTCHA and preference choices remain explicit browser steps. After
    seeing provider confirmation, use --completed to record your acknowledgement.
    This records a request, not proof that future deliveries have stopped.
    """
    from .resolution import refresh_sources
    from .unsubscriber import (
        _endpoint_fingerprint,
        _safe_legacy_method,
        _strict_one_click_target,
        declared_one_click_targets,
    )

    if completed and (retry or dry_run or source_uid is not None):
        raise click.UsageError(
            "--completed cannot be combined with source, retry or dry-run options"
        )
    config = Config.load()
    db.init_db()
    subscription = db.get_subscription(subscription_id)
    if subscription is None:
        raise click.ClickException("Subscription not found")
    if (
        subscription.get("policy_action") == "block"
        or subscription.get("last_outcome") == "blocked"
        or _subscription_has_persisted_threat(subscription_id)
    ):
        raise click.ClickException("This identity is blocked or has persisted threat evidence")
    if not config.permits_unsubscribe:
        raise click.ClickException(
            "Run `nothx consent --unsubscribe --yes` before contacting senders"
        )
    operations = [
        op
        for op in db.list_unsubscribe_operations(subscription_id=subscription_id)
        if op["kind"] == "unsubscribe"
    ]
    if subscription.get("last_outcome") in {"requested", "verified_quiet"}:
        console.print("Already accepted or verified quiet; no duplicate request sent.")
        return
    if any(op["outcome"] is None for op in operations):
        raise click.ClickException("An operation is still unresolved; no request will be replayed")
    if completed:
        if not yes and not _styled_confirm(
            "Did the provider explicitly confirm your unsubscribe?", False
        ):
            return
        try:
            operation = db.acknowledge_browser_confirmation(subscription_id)
        except ValueError as error:
            raise click.ClickException(str(error)) from None
        console.print(
            "Recorded your browser confirmation. "
            + (
                "This source-level request cannot verify quietness for the whole sender."
                if operation["verification_scope"] == "source"
                else "A complete scan after 48 hours verifies delivery."
            )
        )
        return
    attempts_by_operation = {
        operation["id"]: db.list_unsubscribe_attempts(operation["id"]) for operation in operations
    }
    acknowledged = max(
        (
            operation["id"]
            for operation in operations
            if any(
                a.get("error_code") == "user_confirmed_browser"
                for a in attempts_by_operation[operation["id"]]
            )
        ),
        default=0,
    )
    unresolved_operations = [op for op in operations if op["id"] > acknowledged]
    if any(
        a["ambiguous_send"] for op in unresolved_operations for a in attempts_by_operation[op["id"]]
    ) or any(op.get("error_code") == "execution_claim_expired" for op in unresolved_operations):
        raise click.ClickException(
            "A previous request may have succeeded; check it in the browser before retrying"
        )
    attempts = [a for values in attempts_by_operation.values() for a in values]
    contacted = [
        op
        for op in operations
        if any(
            a["ambiguous_send"]
            or (
                a["method"] != "none"
                and a["outcome"] != "skipped"
                and a.get("error_code") != "local_rate_limit"
            )
            or a.get("error_code") == "user_confirmed_browser"
            for a in attempts_by_operation[op["id"]]
        )
    ]
    generation = max((op["retry_generation"] for op in contacted), default=0)
    if contacted:
        if generation >= 1:
            if dry_run:
                console.print(
                    "Retry exhausted; a real resolve will refuse to send another request."
                )
            else:
                raise click.ClickException(
                    "The bounded retry is exhausted; use open-unsubscribe and record confirmation with --completed"
                )
        if not dry_run and not retry:
            raise click.ClickException(
                "Use --retry for one explicit retry, or open-unsubscribe for browser help"
            )
        generation += 1
    console.print(
        f"Refreshing saved Inbox sources for #{subscription_id} · {escape(subscription['account'])}…"
    )
    try:
        stats, headers = refresh_sources(config, subscription, source_uid=source_uid)
    except (IMAPError, imaplib.IMAP4.error, OSError, ValueError) as error:
        raise click.ClickException(
            _redact_failure_detail(str(error)) or "Source refresh failed"
        ) from None
    permitted_headers = [header for header in headers if is_contact_permitted(header, config)]
    excluded_sources = len(headers) - len(permitted_headers)
    if excluded_sources:
        if not dry_run or not permitted_headers:
            raise click.ClickException(
                "Fresh source evidence does not permit contacting this sender"
            )
        console.print(
            f"[warning]{excluded_sources} source(s) excluded by contact policy. "
            "An unscoped request remains blocked.[/warning]"
        )
        headers = permitted_headers
    # Only interactive GETs are safe to revisit after an explicit retry. Failed
    # SMTP/POSTs and every accepted endpoint remain excluded.
    exclusions = {
        attempt["endpoint_fingerprint"]
        for attempt in attempts
        if attempt.get("error_code") != "local_rate_limit"
        and not (
            attempt["method"] == "get"
            and attempt["outcome"] == "needs_user"
            and attempt.get("error_code") == "interactive_response"
        )
    }
    sources = [
        header
        for header in headers
        if any(
            _safe_legacy_method(target) is not None
            and (
                target not in declared_one_click_targets(header)
                or target == _strict_one_click_target(header)
            )
            and _endpoint_fingerprint(target).hex() not in exclusions
            for target in (
                *header.list_unsubscribe_targets,
                *(candidate.uri for candidate in header.footer_unsubscribe_candidates),
            )
        )
    ]
    if subscription["identity_kind"] == "list_id" and source_uid is None:
        sources = [h for h in sources if h.normalized_list_id == subscription["identity_value"]]
    for header in sources:
        console.print(f"  UID {header.uid} · {escape(header.subject)}")
    if not sources:
        console.print(
            "No eligible untried method found in the refreshed sources. Enable bounded footer scanning with `nothx config --footer-scan on`, or run `nothx cleanup` to refresh history."
        )
        return
    if dry_run:
        if excluded_sources:
            console.print("Choose one displayed source with --source-uid to resolve it.")
        console.print(
            f"{len(sources)} candidate source(s); no request sent and no decisions changed."
        )
        return
    if source_uid is not None:
        sources = [header for header in sources if header.uid == source_uid]
        if len(sources) != 1:
            raise click.ClickException("Choose one unique source UID shown by --dry-run")
    elif subscription["identity_kind"] == "from" and len(headers) > 1:
        if yes:
            raise click.ClickException(
                "This sender has multiple sources; select a newsletter with --source-uid"
            )
        chosen = _styled_select(
            [
                questionary.Choice(f"UID {header.uid} · {header.subject}", value=str(index))
                for index, header in enumerate(sources)
            ]
            + [questionary.Choice("Cancel", value=None)]
        )
        if chosen is None:
            return
        sources = [sources[int(chosen)]]
    else:
        sources = sources[:3]
    if not yes and not _styled_confirm(
        f"Unsubscribe #{subscription_id} using these refreshed sources?", False
    ):
        return
    classification = Classification(
        email_type=EmailType.MARKETING,
        action=Action.UNSUB,
        confidence=1.0,
        reasoning="Explicit account/list resolution",
        source="user_rule",
    )
    _, messages = _persist_subscription_records(stats, sources, classification)
    source_scoped = subscription["identity_kind"] == "from" or any(
        h.normalized_list_id != subscription["identity_value"] for h in sources
    )
    owner = uuid.uuid4().hex
    operation, acquired = db.claim_unsubscribe_operation(
        subscription_id,
        f"resolve-v1-{generation}-{len(operations)}-{_operation_key('unsubscribe', stats, sources)}",
        owner,
        retry_generation=generation,
        allow_no_contact_resume=True,
        verification_scope="source" if source_scoped else "subscription",
        trigger_message_ref_id=messages[0][1]["id"] if messages else None,
    )
    if not acquired:
        console.print("Another process already claimed or completed this request; nothing sent.")
        return
    result = unsubscribe_subscription(
        sources,
        config,
        _matching_account(config, sources),
        automatic=False,
        exclude_fingerprints=exclusions,
    )
    _record_unsubscribe_result(
        stats,
        sources,
        classification,
        result,
        retry_generation=generation,
        operation_id=operation["id"],
        claim_owner=owner,
    )
    if result.success:
        if not source_scoped:
            db.set_subscription_policy(subscription_id, "unsub")
        console.print(
            "Request accepted. "
            + (
                "This source-level request cannot verify quietness for the whole sender."
                if source_scoped
                else "Delivery is verified by a complete scan after 48 hours."
            )
        )
        _clean_unwanted_inbox(config, subscription, messages)
    else:
        console.print(
            f"{escape(result.error or 'This provider needs a browser step')}\nRun `nothx open-unsubscribe {subscription_id}`. After provider confirmation, run `nothx resolve {subscription_id} --completed`."
        )


@main.command("open-unsubscribe")
@click.argument("subscription_id", type=int)
@click.option(
    "--yes",
    is_flag=True,
    help="Open the first rescanned HTTPS destination without another prompt",
)
def open_unsubscribe(subscription_id: int, yes: bool):
    """Rescan and explicitly open a manual unsubscribe page in your browser.

    The raw URL exists only in memory and is passed directly to the browser.
    Terminal output and database history show only a hashed host and redacted path.
    """
    config = Config.load()
    db.init_db()
    subscription = db.get_subscription(subscription_id)
    if subscription is None:
        console.print("[error]Subscription not found.[/error]")
        return
    if (
        subscription.get("policy_action") == "block"
        or subscription.get("last_outcome") == "blocked"
        or _subscription_has_persisted_threat(subscription_id)
    ):
        console.print(
            "[warning]This subscription is blocked or has Junk/phishing evidence; "
            "nothx will not contact its unsubscribe destination.[/warning]"
        )
        return
    if not config.permits_unsubscribe:
        console.print(
            "[warning]Current versioned unsubscribe-contact consent is required; "
            "no destination was scanned or opened.[/warning]"
        )
        return

    from .resolution import refresh_sources
    from .unsubscriber import declared_one_click_targets

    try:
        _stats, matching_headers = refresh_sources(config, subscription)
    except (IMAPError, imaplib.IMAP4.error, OSError, ValueError) as error:
        console.print(
            f"[warning]Source refresh failed: {escape(_redact_failure_detail(str(error)) or 'Unavailable')}[/warning]"
        )
        return
    if any(not is_contact_permitted(h, config) for h in matching_headers):
        console.print(
            "[warning]Fresh source evidence does not permit contacting this sender.[/warning]"
        )
        return
    if subscription["identity_kind"] == "list_id":
        matching_headers = [
            h for h in matching_headers if h.normalized_list_id == subscription["identity_value"]
        ]
    post_only = {target for h in matching_headers for target in declared_one_click_targets(h)}
    candidates: list[str] = []
    for header in sorted(matching_headers, key=lambda h: h.received_at or h.date, reverse=True):
        for target in (
            *header.list_unsubscribe_targets,
            *(candidate.uri for candidate in header.footer_unsubscribe_candidates),
        ):
            if (
                target.casefold().startswith("https://")
                and target not in candidates
                and target not in post_only
            ):
                candidates.append(target)
    candidates = candidates[:5]
    if not candidates:
        console.print(
            "[warning]No HTTPS unsubscribe page was found in the bounded rescan.[/warning]"
        )
        return

    target = candidates[0]
    if not yes:
        choices = [
            questionary.Choice(_redacted_destination(candidate), value=candidate)
            for candidate in candidates
        ]
        choices.append(questionary.Choice("Cancel", value=None))
        _select_header("Choose a rescanned destination to open")
        selected = _styled_select(choices)
        if selected is None:
            console.print("Cancelled.")
            return
        target = selected
        if not _styled_confirm(
            f"Open {_redacted_destination(target)} in your browser?", default=False
        ):
            console.print("Cancelled.")
            return

    console.print(f"Opening [bold]{_redacted_destination(target)}[/bold]")
    try:
        opened = webbrowser.open(target)
    except Exception as error:
        logger.debug("Could not open manual unsubscribe browser: %s", type(error).__name__)
        opened = False
    if not opened:
        console.print(
            "[warning]The browser could not be opened automatically. No URL was logged.[/warning]"
        )


@main.command()
@click.argument("domain", required=False)
def undo(domain: str | None):
    """Change future local policy; this cannot externally resubscribe you."""
    db.init_db()

    if domain:
        # Undo specific domain - this is a correction (user changed their mind)
        db.set_user_override(domain, "keep")
        db.update_sender_status(domain, SenderStatus.KEEP)
        db.log_correction(domain, "unsub", "keep")
        authoritative_updates = 0
        for subscription in db.list_subscriptions(limit=10_000):
            if (subscription.get("sender_domain") or "").casefold() == domain.casefold():
                authoritative_updates += int(db.set_subscription_policy(subscription["id"], "keep"))

        # Get sender info for learning
        sender = db.get_sender(domain)
        if sender:
            seen = sender.get("seen_emails", 0)
            total = sender.get("total_emails", 0)
            open_rate = (seen / total * 100) if total > 0 else 0

            # Log the action for learning
            action_record = UserAction(
                domain=domain,
                action=Action.KEEP,
                timestamp=datetime.now(UTC),
                ai_recommendation=Action.UNSUB,  # Undo means AI/system said unsub
                heuristic_score=None,
                open_rate=open_rate,
                email_count=total,
            )
            db.log_user_action(action_record)

            # Update learner
            learner = get_learner()
            learner.update_from_action(action_record)

        console.print(f"[success]✓ Marked {domain} as 'keep'[/success]")
        console.print(
            "[muted]Learning from this correction. Any external unsubscribe request "
            "already sent cannot be undone here.[/muted]"
        )
        if authoritative_updates:
            console.print(
                f"[muted]Updated future policy for {authoritative_updates} account/list "
                "subscription(s).[/muted]"
            )
        return

    # Show recent unsubscribes
    recent = db.get_recent_unsubscribes(days=30)

    if not recent:
        console.print("No recent unsubscribes to undo.")
        return

    console.print("\n[header]Recent unsubscribes (last 30 days):[/header]\n")

    for i, item in enumerate(recent[:20], 1):
        console.print(
            f"{_L} {i}. {item['domain']} ({item['total_emails']} emails) - {item['attempted_at'][:10]}"
        )

    console.print("\nTo undo, run: [bold]nothx undo <domain>[/bold]")


@main.command()
@click.option("--monthly", is_flag=True, help="Schedule monthly runs")
@click.option("--weekly", is_flag=True, help="Schedule weekly runs")
@click.option("--daily", is_flag=True, help="Schedule daily runs (recommended)")
@click.option("--off", is_flag=True, help="Disable scheduled runs")
@click.option("--status", "show_status", is_flag=True, help="Show current schedule")
def schedule(monthly: bool, weekly: bool, daily: bool, off: bool, show_status: bool):
    """Manage automatic scheduling."""
    selected = sum((monthly, weekly, daily, off))
    if selected > 1:
        raise click.UsageError("Choose only one schedule frequency or --off")
    if show_status or (not monthly and not weekly and not daily and not off):
        status = get_schedule_status()
        if status:
            console.print("\n[header]Current Schedule[/header]")
            console.print(f"{_L} Type: {status['type']}")
            console.print(f"{_L} Frequency: {status['frequency']}")
            console.print(f"{_L} Path: {status['path']}")
            if status["frequency"] != "daily":
                console.print(
                    f"{_L} [warning]Daily is recommended for prompt spam suppression and "
                    "unsubscribe verification.[/warning]"
                )
        else:
            console.print("[warning]No schedule configured[/warning]")
        return

    if off:
        success, msg = uninstall_schedule()
        if success:
            console.print(f"[green]✓ {msg}[/green]")
        else:
            console.print(f"[red]{msg}[/red]")
        return

    frequency = "monthly" if monthly else "weekly" if weekly else "daily"
    success, msg = install_schedule(frequency)

    if success:
        console.print(f"[green]✓ {msg}[/green]")
    else:
        console.print(f"[red]{msg}[/red]")


@main.command("browser-setup")
def browser_setup() -> None:
    """Install the isolated browser runtime and enable page completion."""
    import importlib.util

    if importlib.util.find_spec("playwright") is None:
        raise click.ClickException(
            "Install browser support first: `pipx inject nothx playwright`. Then run this command again."
        )
    try:
        subprocess.run(
            [sys.executable, "-m", "playwright", "install", "chromium", "--only-shell"],
            check=True,
        )
        sync_api = importlib.import_module("playwright.sync_api")
        with sync_api.sync_playwright() as playwright:
            browser = playwright.chromium.launch(
                headless=True, chromium_sandbox=True, timeout=15_000
            )
            browser.close()
    except Exception:
        raise click.ClickException(
            "Browser installation or launch failed; fallback remains unchanged"
        ) from None
    config = Config.load()
    config.browser_fallback_enabled = True
    config.save()
    console.print(
        "Browser fallback enabled. Pending confirmation pages can use `nothx resolve ID --retry`."
    )


@main.command("config")
@click.option("--show", is_flag=True, help="Show current config")
@click.option("--ai", type=click.Choice(["on", "off"]), help="Enable/disable AI")
@click.option(
    "--footer-scan",
    type=click.Choice(["on", "off"]),
    help="Enable/disable bounded local footer fallback scanning",
)
@click.option(
    "--mode", type=click.Choice(["hands_off", "notify", "confirm"]), help="Set operation mode"
)
@click.option(
    "--engaged-marketing",
    type=click.Choice(["review", "allow"]),
    help="Review or allow automatic actions on marketing with at least 25% marked read",
)
@click.option(
    "--browser-fallback",
    type=click.Choice(["on", "off"]),
    help="Enable/disable isolated browser completion after browser-setup",
)
@click.option(
    "--cleanup",
    type=click.Choice(CLEANUP_LEVELS),
    help="thorough unsubscribes from every marketing list and newsletter; "
    "receipts, security and protected senders stay safe",
)
@click.option(
    "--unwanted-mail",
    type=click.Choice(["keep", "junk"]),
    help="Keep approved unsubscribe mail in Inbox or move it to Junk after request acceptance",
)
def config_cmd(
    show: bool,
    ai: str | None,
    footer_scan: str | None,
    mode: str | None,
    engaged_marketing: str | None = None,
    unwanted_mail: str | None = None,
    browser_fallback: str | None = None,
    cleanup: str | None = None,
):
    """View or modify configuration."""
    config = Config.load()

    if cleanup:
        config.cleanup_level = cleanup
        config.save()
        console.print(f"Cleanup level: {cleanup}")

    if ai:
        config.ai.enabled = ai == "on"
        config.save()
        console.print(f"AI: {'enabled' if config.ai.enabled else 'disabled'}")

    if mode:
        config.operation_mode = mode
        config.save()
        console.print(f"Mode: {mode}")

    if footer_scan:
        config.footer_scan_enabled = footer_scan == "on"
        config.save()
        state = "enabled" if config.footer_scan_enabled else "disabled"
        console.print(f"Footer scan: {state} (local-only, bounded, and never sent to AI)")

    if engaged_marketing:
        config.review_engaged_marketing = engaged_marketing == "review"
        config.save()
        console.print(f"Engaged marketing: {engaged_marketing}")

    if browser_fallback:
        config.browser_fallback_enabled = browser_fallback == "on"
        config.save()
        console.print(f"Browser fallback: {browser_fallback}")

    if unwanted_mail:
        config.move_unwanted_to_junk = unwanted_mail == "junk"
        config.save()
        console.print(f"Approved unwanted mail: {unwanted_mail}")
        if config.move_unwanted_to_junk:
            console.print("Run `nothx cleanup` to include older Inbox messages.")
            if not config.permits_mailbox_mutation:
                console.print("Mailbox consent is missing; Junk movement remains disabled.")

    if show or (
        not ai
        and not mode
        and not footer_scan
        and not engaged_marketing
        and not unwanted_mail
        and not browser_fallback
        and not cleanup
    ):
        console.print("\n[header]Current Configuration[/header]")
        console.print(f"{_L} Config dir: {get_config_dir()}")
        console.print(f"{_L} AI enabled: {config.ai.enabled}")
        console.print(f"{_L} AI provider: {config.ai.provider}")
        console.print(f"{_L} Operation mode: {config.operation_mode}")
        console.print(f"{_L} Cleanup level: {config.cleanup_level}")
        console.print(f"{_L} Scan days: {config.scan_days}")
        console.print(f"{_L} Scan Junk: {config.scan_junk}")
        console.print(
            f"{_L} Engaged marketing: "
            f"{'review' if config.review_engaged_marketing else 'allow automatic actions'}"
        )
        console.print(
            f"{_L} Approved unwanted mail: {'junk' if config.move_unwanted_to_junk else 'keep'}"
        )
        console.print(f"{_L} Browser fallback: {config.browser_fallback_enabled}")
        console.print(f"{_L} Footer scan: {config.footer_scan_enabled}")
        console.print(f"{_L} Unsubscribe contact consent: {config.permits_unsubscribe}")
        console.print(f"{_L} Mailbox mutation consent: {config.permits_mailbox_mutation}")
        console.print(f"{_L} Unsub confidence: {config.thresholds.unsub_confidence}")
        console.print(f"{_L} Keep confidence: {config.thresholds.keep_confidence}")


@main.command()
@click.option(
    "--unsubscribe/--no-unsubscribe",
    default=None,
    help="Grant/revoke outbound HTTPS, SMTP, or browser unsubscribe contact",
)
@click.option(
    "--mailbox-actions/--no-mailbox-actions",
    default=None,
    help="Grant/revoke IMAP flag and move-to-Junk writes",
)
@click.option("--all", "grant_all", is_flag=True, help="Grant both current permissions")
@click.option("--revoke-all", is_flag=True, help="Revoke both permissions")
@click.option("--yes", is_flag=True, help="Confirm the requested consent change non-interactively")
def consent(
    unsubscribe: bool | None,
    mailbox_actions: bool | None,
    grant_all: bool,
    revoke_all: bool,
    yes: bool,
):
    """View or explicitly change versioned automation consent.

    Unsubscribe consent permits outbound HTTPS/SMTP requests and explicit
    browser opening for authenticated subscription endpoints. Mailbox-action
    consent permits IMAP flag changes and moving exact UIDs to the
    server-advertised Junk mailbox.
    """
    config = Config.load()
    if grant_all and revoke_all:
        raise click.UsageError("--all and --revoke-all cannot be combined")
    if grant_all:
        unsubscribe = True
        mailbox_actions = True
    if revoke_all:
        unsubscribe = False
        mailbox_actions = False

    if unsubscribe is None and mailbox_actions is None:
        console.print("\n[header]Automation Consent[/header]")
        console.print(
            f"{_L} Outbound unsubscribe requests: "
            f"{'granted' if config.permits_unsubscribe else 'not granted'}"
        )
        console.print(
            f"{_L} IMAP flag/Junk mailbox writes: "
            f"{'granted' if config.permits_mailbox_mutation else 'not granted'}"
        )
        console.print(
            "\n[muted]Grant explicitly with `nothx consent --all --yes`; "
            "revoke with `nothx consent --revoke-all --yes`.[/muted]"
        )
        return

    changes: list[str] = []
    if unsubscribe is not None:
        changes.append(
            "allow outbound HTTPS/SMTP/browser unsubscribe contact"
            if unsubscribe
            else "revoke outbound unsubscribe permission"
        )
    if mailbox_actions is not None:
        changes.append(
            "allow IMAP flag changes and exact-UID moves to Junk"
            if mailbox_actions
            else "revoke IMAP mailbox-write permission"
        )
    if not yes and not click.confirm("Confirm: " + "; ".join(changes) + "?", default=False):
        console.print("Cancelled.")
        return

    if unsubscribe is not None:
        config.unsubscribe_consent_version = (
            CURRENT_UNSUBSCRIBE_CONSENT_VERSION if unsubscribe else CONSENT_REVOKED
        )
    if mailbox_actions is not None:
        config.mailbox_mutation_consent_version = (
            CURRENT_MAILBOX_MUTATION_CONSENT_VERSION if mailbox_actions else CONSENT_REVOKED
        )
    config.save()
    console.print("[success]✓ Automation consent updated[/success]")

    # Granting mailbox consent unblocks every BLOCK that a prior run had to
    # park. Without this sweep those rows sit in the review queue forever,
    # because nothing else ever revisits them.
    if mailbox_actions:
        db.init_db()
        parked = db.count_consent_parked_blocks()
        if parked and (
            yes
            or click.confirm(
                f"Apply {parked} block decision(s) queued while consent was missing?",
                default=True,
            )
        ):
            drained, moved, failed = _drain_consent_parked_blocks(config)
            console.print(
                f"{_L} Applied {drained} queued block(s): {moved} message(s) moved to Junk"
                + (f", {failed} message action(s) failed" if failed else "")
            )


@main.command()
@click.argument("pattern")
@click.argument("action", type=click.Choice(["keep", "unsub", "block"]))
def rule(pattern: str, action: str):
    """Add a classification rule.

    Example: nothx rule "*.spam.com" unsub
    """
    db.init_db()
    db.add_rule(pattern, action)
    console.print(f"[green]✓ Added rule: {pattern} → {action}[/green]")


@main.command()
def rules():
    """List all classification rules."""
    db.init_db()
    rules_list = db.get_rules()

    if not rules_list:
        console.print("No rules configured.")
        console.print("Add rules with: [bold]nothx rule <pattern> <action>[/bold]")
        return

    table = Table(show_header=True)
    table.add_column("Pattern")
    table.add_column("Action")
    table.add_column("Created")

    for rule in rules_list:
        table.add_row(rule["pattern"], rule["action"], rule["created_at"][:10])

    console.print(table)


@main.command()
@click.option(
    "--status",
    type=click.Choice(["keep", "unsub", "blocked"]),
    help="Filter by status",
)
@click.option(
    "--sort",
    type=click.Choice(["emails", "domain", "date"]),
    default="date",
    help="Sort by field",
)
@click.option("--json", "as_json", is_flag=True, help="Output as JSON")
def senders(status: str | None, sort: str, as_json: bool):
    """List all tracked senders."""
    db.init_db()

    # Map CLI options to db function params
    status_map = {"unsub": "unsubscribed", "keep": "keep", "blocked": "blocked"}
    sort_map = {"emails": "emails", "domain": "domain", "date": "last_seen"}

    status_filter = status_map.get(status) if status else None
    all_senders = db.get_all_senders(status_filter=status_filter, sort_by=sort_map[sort])

    if not all_senders:
        console.print("[muted]No senders tracked yet. Run 'nothx run' to scan your inbox.[/muted]")
        return

    if as_json:
        click.echo(json.dumps(all_senders, indent=2, default=str))
        return

    status_label = f" ({status})" if status else ""
    console.print(f"\n[header]Tracked Senders{status_label} ({len(all_senders)} total)[/header]\n")

    table = Table(show_header=True)
    table.add_column("Domain", style="domain")
    table.add_column("Emails", style="count", justify="right")
    table.add_column("Status")
    table.add_column("Last Seen")

    status_styles = {
        "unsubscribed": "unsubscribe",
        "keep": "keep",
        "blocked": "block",
        "unknown": "review",
    }

    for sender in all_senders[:50]:  # Limit display to 50
        sender_status = sender.get("status", "unknown")
        style = status_styles.get(sender_status)
        status_display = (
            f"[{style}]{sender_status.title()}[/{style}]" if style else sender_status.title()
        )

        last_seen = sender.get("last_seen", "")
        if last_seen:
            try:
                last_dt = datetime.fromisoformat(last_seen)
                last_seen = humanize.naturaltime(last_dt)
            except (ValueError, TypeError):
                last_seen = last_seen[:10] if last_seen else "-"

        table.add_row(
            sender["domain"],
            str(sender.get("total_emails", 0)),
            status_display,
            last_seen or "-",
        )

    console.print(table)

    if len(all_senders) > 50:
        console.print(f"\n[muted]Showing first 50 of {len(all_senders)} senders[/muted]")

    # Bulk action mode when filtering by status (skip for JSON output or non-TTY)
    if not as_json and all_senders and status and console.is_terminal:
        _senders_bulk_action(all_senders, status)


def _senders_bulk_action(all_senders: list[dict], status_filter: str) -> None:
    """Show bulk action menu for filtered senders."""
    _select_header("Actions")

    bulk_choices = [
        questionary.Choice(f"Change all {len(all_senders)} to Keep", value="keep"),
        questionary.Choice(f"Change all {len(all_senders)} to Unsubscribe", value="unsub"),
        questionary.Choice(f"Change all {len(all_senders)} to Block", value="block"),
        questionary.Choice("Pick individual sender", value="pick"),
        questionary.Choice("Exit", value=None),
    ]

    # Remove the option matching current filter (no-op change)
    filter_action_map = {"keep": "keep", "unsub": "unsub", "blocked": "block"}
    current_action = filter_action_map.get(status_filter)
    bulk_choices = [c for c in bulk_choices if c.value != current_action]

    bulk_action = _styled_select(bulk_choices)

    if bulk_action is None:
        return

    if bulk_action == "pick":
        _senders_pick_individual(all_senders[:50])
        return

    # Confirm bulk action
    if not _styled_confirm(f"Change all {len(all_senders)} senders to {bulk_action}?"):
        console.print("[muted]Cancelled.[/muted]")
        return

    config = Config.load()
    changed = 0
    for sender_item in all_senders:
        if _change_sender_status(
            sender_item["domain"],
            bulk_action,
            sender=sender_item,
            config=config,
        ):
            changed += 1

    console.print(f"\n[success]\u2713 Changed {changed} senders[/success]")


def _senders_pick_individual(displayed_senders: list[dict]) -> None:
    """Show domain picker for individual status change."""
    _select_header("Change a sender's status")

    domain_choices = []
    for sender_item in displayed_senders:
        s_domain = sender_item["domain"]
        s_status = sender_item.get("status", "unknown")
        s_emails = sender_item.get("total_emails", 0)
        label = f"{s_domain} ({s_status}, {s_emails} emails)"
        domain_choices.append(questionary.Choice(label, value=s_domain))
    domain_choices.append(questionary.Choice("Exit", value=None))

    selected_domain = _styled_select(domain_choices)

    if selected_domain is None:
        return

    sender_data = next((s for s in displayed_senders if s["domain"] == selected_domain), None)
    if not sender_data:
        return

    current = sender_data.get("status", "unknown")
    console.print(f"\n{_L} Current status: [bold]{current.title()}[/bold]")

    _select_header("New status")
    status_choices = [
        questionary.Choice("Keep", value="keep"),
        questionary.Choice("Unsubscribe", value="unsub"),
        questionary.Choice("Block", value="block"),
        questionary.Choice("Cancel", value=None),
    ]
    new = _styled_select(status_choices)

    if new is not None:
        _change_sender_status(
            selected_domain,
            new,
            sender=sender_data,
            config=Config.load(),
        )
    console.print()


@main.command()
@click.argument("domain")
def change(domain: str):
    """Change a sender's status.

    Example: nothx change marketing.example.com
    """
    db.init_db()
    config = Config.load()

    sender = db.get_sender(domain)
    if not sender:
        console.print(f"[warning]Sender '{domain}' not found.[/warning]")
        console.print(f"Try [bold]nothx search {domain}[/bold] to find it.")
        return

    # Display current info
    current_status = sender.get("status", "unknown")
    status_styles = {
        "unsubscribed": "unsubscribe",
        "keep": "keep",
        "blocked": "block",
        "unknown": "review",
    }
    style = status_styles.get(current_status)
    status_display = (
        f"[{style}]{current_status.title()}[/{style}]" if style else current_status.title()
    )

    last_seen = sender.get("last_seen", "")
    if last_seen:
        try:
            last_dt = datetime.fromisoformat(last_seen)
            last_seen = humanize.naturaltime(last_dt)
        except (ValueError, TypeError):
            last_seen = last_seen[:10] if last_seen else "-"

    console.print(f"\n[header]{domain}[/header]")
    console.print(f"{_L} Status: {status_display}")
    console.print(f"{_L} Emails: [count]{sender.get('total_emails', 0)}[/count]")
    if last_seen:
        console.print(f"{_L} Last seen: {last_seen}")

    # Status picker
    _select_header("Change status")
    choices = [
        questionary.Choice("Keep - Continue receiving", value="keep"),
        questionary.Choice("Unsubscribe - Stop receiving emails", value="unsub"),
        questionary.Choice("Block - Block sender entirely", value="block"),
        questionary.Choice("Cancel", value=None),
    ]
    new_status = _styled_select(choices)

    if new_status is None:
        console.print("[muted]Cancelled.[/muted]")
        return

    # For keep/block, skip a no-op change. For unsub, always proceed — the
    # user may be retrying a failed (or previously attempted) unsubscribe.
    new_status_value = {"keep": "keep", "unsub": "unsubscribed", "block": "blocked"}[new_status]
    if new_status != "unsub" and current_status == new_status_value:
        console.print("[muted]Status unchanged.[/muted]")
        return

    _change_sender_status(domain, new_status, sender=sender, config=config)
    console.print()


@main.command()
@click.argument("pattern")
@click.option("--json", "as_json", is_flag=True, help="Output as JSON")
def search(pattern: str, as_json: bool):
    """Search for a sender by domain pattern."""
    db.init_db()

    results = db.search_senders(pattern)

    if not results:
        console.print(f"[muted]No senders found matching '{pattern}'[/muted]")
        return

    if as_json:
        click.echo(json.dumps(results, indent=2, default=str))
        return

    console.print(f"\n[header]Found {len(results)} sender(s) matching '{pattern}':[/header]\n")

    for sender in results:
        domain = sender["domain"]
        status = sender.get("status", "unknown")
        total = sender.get("total_emails", 0)
        subjects = sender.get("sample_subjects", "").split("|")[:3]

        status_styles = {
            "unsubscribed": "unsubscribe",
            "keep": "keep",
            "blocked": "block",
            "unknown": "review",
        }
        style = status_styles.get(status, "")

        last_seen = sender.get("last_seen", "")
        if last_seen:
            try:
                last_dt = datetime.fromisoformat(last_seen)
                last_seen = humanize.naturaltime(last_dt)
            except (ValueError, TypeError):
                last_seen = last_seen[:10] if last_seen else ""

        console.print(f"{_L} [domain]{domain}[/domain]")
        console.print(
            f"{_L}   Status: [{style}]{status.title()}[/{style}]"
            + (f" ({last_seen})" if last_seen else "")
        )
        console.print(f"{_L}   Emails: [count]{total}[/count] total")
        if subjects and subjects[0]:
            console.print(f"{_L}   Subjects: {', '.join(s for s in subjects[:3] if s)}")
        console.print()


@main.command()
@click.option("--limit", default=20, help="Number of entries to show")
@click.option("--failures", is_flag=True, help="Show only failures")
@click.option("--json", "as_json", is_flag=True, help="Output as JSON")
def history(limit: int, failures: bool, as_json: bool):
    """Show recent activity log."""
    db.init_db()

    activity = [
        {
            **entry,
            "error": _redact_failure_detail(entry.get("error")),
        }
        for entry in db.get_activity_log(limit=limit, failures_only=failures)
    ]
    operations = db.list_unsubscribe_operations(
        outcome="failed" if failures else None,
        limit=limit,
    )

    if not activity and not operations:
        console.print("[muted]No activity recorded yet.[/muted]")
        return

    if as_json:
        # Both sources contain redacted destinations/details only. Preserve
        # the historical list-shaped JSON interface while tagging new rows.
        operation_rows = [
            {"type": "subscription_operation", **operation} for operation in operations
        ]
        click.echo(json.dumps([*operation_rows, *activity], indent=2, default=str))
        return

    label = " (failures only)" if failures else ""
    console.print(f"\n[header]Recent Activity{label}[/header]\n")

    for operation in operations:
        timestamp = operation.get("completed_at") or operation.get("created_at") or ""
        try:
            date_str = datetime.fromisoformat(timestamp).strftime("%b %d, %I:%M %p")
        except (ValueError, TypeError):
            date_str = timestamp
        identity = f"{operation['identity_kind']}:{operation['identity_value']}"
        outcome = operation.get("outcome") or "in progress"
        detail = _redact_failure_detail(operation.get("detail_redacted"))
        line = (
            f"[muted]{date_str}[/muted]  {operation['account']} · {identity} "
            f"→ [bold]{outcome}[/bold]"
        )
        if detail:
            line += f" [muted]({detail})[/muted]"
        console.print(line)

    for entry in activity:
        timestamp = entry.get("timestamp", "")
        try:
            ts_dt = datetime.fromisoformat(timestamp)
            date_str = ts_dt.strftime("%b %d, %I:%M %p")
        except (ValueError, TypeError):
            date_str = timestamp

        if entry["type"] == "run":
            scanned = entry.get("emails_scanned", 0)
            senders = entry.get("unique_senders", 0)
            unsubbed = entry.get("auto_unsubbed", 0)
            failed = entry.get("failed", 0)
            console.print(
                f"[muted]{date_str}[/muted]  ◉ Scan completed: {scanned} emails, {senders} senders, {unsubbed} unsubscribed"
                + (f", {failed} failed" if failed else "")
            )
        else:
            domain = entry.get("domain", "unknown")
            success = entry.get("success", False)
            if success:
                console.print(
                    f"[muted]{date_str}[/muted]  [success]✓[/success] Unsubscribed from [domain]{domain}[/domain]"
                )
            else:
                error = entry.get("error") or "unknown error"
                console.print(
                    f"[muted]{date_str}[/muted]  [error]✗[/error] Failed to unsubscribe from [domain]{domain}[/domain] ({error[:30]})"
                )


@main.command()
@click.argument("type_", metavar="TYPE", type=click.Choice(["senders", "history"]))
@click.option("--output", "-o", required=True, help="Output file path")
def export(type_: str, output: str):
    """Export data to CSV.

    TYPE is either 'senders' or 'history'.
    """
    db.init_db()

    if type_ == "senders":
        data = db.get_all_senders()
        if not data:
            console.print("[warning]No senders to export.[/warning]")
            return
        fieldnames = [
            "domain",
            "total_emails",
            "seen_emails",
            "status",
            "first_seen",
            "last_seen",
            "has_unsubscribe",
            "sample_subjects",
        ]
    else:
        legacy_data = [
            {
                **entry,
                "error": _redact_failure_detail(entry.get("error")),
            }
            for entry in db.get_activity_log(limit=1000)
        ]
        operation_data = [
            {
                "type": "subscription_operation",
                "timestamp": operation.get("completed_at") or operation.get("created_at"),
                "account": operation.get("account"),
                "identity_kind": operation.get("identity_kind"),
                "identity_value": operation.get("identity_value"),
                "outcome": operation.get("outcome"),
                "error": _redact_failure_detail(operation.get("detail_redacted")),
            }
            for operation in db.list_unsubscribe_operations(limit=1000)
        ]
        data = [*operation_data, *legacy_data]
        if not data:
            console.print("[warning]No history to export.[/warning]")
            return
        fieldnames = [
            "type",
            "timestamp",
            "domain",
            "success",
            "method",
            "error",
            "account",
            "identity_kind",
            "identity_value",
            "outcome",
            "emails_scanned",
            "unique_senders",
            "auto_unsubbed",
            "failed",
            "mode",
        ]

    try:
        with open(output, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
            writer.writeheader()
            writer.writerows(data)
        console.print(f"[success]✓ Exported {len(data)} records to {output}[/success]")
    except OSError as e:
        console.print(f"[error]Failed to write {output}: {e}[/error]")


@main.command("test")
@click.option("--ai", "check_ai", is_flag=True, help="Also test the configured AI provider")
def test_connection(check_ai: bool = False):
    """Test email connections and optionally the configured AI provider."""
    config = Config.load()

    if not config.accounts and not check_ai:
        console.print("[error]No accounts configured. Run 'nothx init' first.[/error]")
        return

    for _name, account in config.accounts.items():
        console.print(f"\n[header]Testing connection to {account.email}...[/header]")

        if account.provider == "outlook" and not account.uses_oauth:
            console.print(
                "[warning]This Outlook account uses legacy password authentication. "
                "Microsoft OAuth is recommended; remove and re-add the account to authorize "
                "IMAP and SMTP safely.[/warning]"
            )
        elif account.uses_oauth and account.client_id:
            consent_status = msauth.get_consent_status(account.email, account.client_id)
            if not consent_status.ready:
                missing = ", ".join(consent_status.missing_scopes)
                detail = f" Missing scopes: {missing}." if missing else ""
                console.print(
                    f"[warning]Microsoft re-consent is required ({consent_status.reason})."
                    f"{detail} Remove and re-add this account to authorize IMAP, SMTP, "
                    "and offline access.[/warning]"
                )

        with console.status("Connecting...", spinner_style="#ffaf00"):
            success, msg = test_account(account)

        if success:
            console.print("[success]✓ IMAP connection successful[/success]")
            console.print("[success]✓ Authentication successful[/success]")
            console.print("[success]✓ Inbox accessible[/success]")
        else:
            console.print(f"[error]✗ Connection failed: {msg}[/error]")
            console.print("\n[muted]Suggestions:[/muted]")
            console.print(f"{_L} • Check your internet connection")
            if tips := TROUBLESHOOTING_TIPS.get(account.provider):
                for tip in tips:
                    console.print(f"{_L}{tip[1:]}" if tip.startswith("  ") else tip)
            console.print(f"{_L} • Make sure IMAP is enabled in your email settings")

    if check_ai:
        console.print(f"\n[header]Testing AI provider: {config.ai.provider}[/header]")
        if not config.ai.enabled:
            console.print(
                "[warning]AI is disabled; scans currently use local heuristics.[/warning]"
            )
        with console.status("Testing AI connection...", spinner_style="#ffaf00"):
            success, msg = test_ai_connection(config)
        if success:
            console.print(f"[success]✓ {msg}[/success]")
            if not config.ai.enabled and config.ai.provider != "none":
                console.print("Run [bold]nothx config --ai on[/bold] to enable this provider.")
        else:
            console.print(f"[error]✗ AI connection failed: {_redact_failure_detail(msg)}[/error]")
            packages = {
                "anthropic": "anthropic",
                "openai": "openai",
                "gemini": "google-generativeai",
            }
            if "not installed" in msg and config.ai.provider in packages:
                console.print(
                    f"For pipx installs, run [bold]pipx inject nothx {packages[config.ai.provider]}"
                    "[/bold], then retry [bold]nothx test --ai[/bold]."
                )


# This exported Click command is imported by CLI tests; prevent pytest from
# mistaking the command object for a test function solely because of its name.
test_connection.__dict__["__test__"] = False


@main.command()
@click.option("--keep-config", is_flag=True, help="Keep accounts and API key, only clear data")
def reset(keep_config: bool):
    """Clear all data and start fresh."""
    from .config import get_config_path

    db.init_db()
    stats = db.get_stats()

    console.print("\n[warning]⚠️  This will delete all nothx data:[/warning]")
    console.print(f"{_L} • {stats['total_senders']} tracked senders")
    console.print(f"{_L} • {stats['unsubscribed']} unsubscribe records")
    console.print(f"{_L} • All classification history")

    if not keep_config:
        console.print(f"{_L} • All user rules")
        console.print(f"{_L} • [warning]Configuration file (accounts, API key)[/warning]")

    console.print()

    # Require typing "reset" to confirm
    confirm = questionary.text("", qmark='Type "reset" to confirm:', style=Q_INPUT_STYLE).ask()

    if confirm != "reset":
        console.print("Cancelled.")
        return

    # Reset database
    senders_deleted, unsubs_deleted = db.reset_database(keep_config=keep_config)

    # Delete config file if not keeping
    if not keep_config:
        config_path = get_config_path()
        if config_path.exists():
            config_path.unlink()
            console.print("[success]✓ Configuration file deleted[/success]")
        msauth.clear_token_cache()

    console.print(
        f"[success]✓ Cleared {senders_deleted} senders and {unsubs_deleted} unsubscribe logs[/success]"
    )
    console.print("\nRun [bold]nothx init[/bold] to start fresh.")


@main.command()
@click.argument("shell", type=click.Choice(["bash", "zsh", "fish"]))
def completion(shell: str):
    """Generate shell completion script.

    To enable completions, add to your shell config:

    \b
    Bash: eval "$(nothx completion bash)"
    Zsh:  eval "$(nothx completion zsh)"
    Fish: nothx completion fish | source
    """

    # Click provides built-in completion support
    prog_name = "nothx"

    if shell == "bash":
        # Bash completion script
        script = f"""
_nothx_completion() {{
    local IFS=$'\\n'
    COMPREPLY=( $(env COMP_WORDS="${{COMP_WORDS[*]}}" \\
                     COMP_CWORD=$COMP_CWORD \\
                     _{prog_name.upper()}_COMPLETE=bash_complete $1) )
    return 0
}}
complete -o default -F _nothx_completion {prog_name}
"""
    elif shell == "zsh":
        # Zsh completion script
        script = f"""
#compdef {prog_name}

_nothx_completion() {{
    local -a completions
    local -a completions_with_descriptions
    local -a response
    (( ! $+commands[{prog_name}] )) && return 1

    response=("${{(@f)$(env COMP_WORDS="${{words[*]}}" \\
                            COMP_CWORD=$((CURRENT-1)) \\
                            _{prog_name.upper()}_COMPLETE=zsh_complete {prog_name})}}")

    for key descr in ${{(kv)response}}; do
      if [[ "$descr" == "_" ]]; then
          completions+=("$key")
      else
          completions_with_descriptions+=("$key":"$descr")
      fi
    done

    if [ -n "$completions_with_descriptions" ]; then
        _describe -V unsorted completions_with_descriptions -U
    fi

    if [ -n "$completions" ]; then
        compadd -U -V unsorted -a completions
    fi
}}

compdef _nothx_completion {prog_name}
"""
    else:  # fish
        # Fish completion script
        script = f"""
function _nothx_completion;
    set -l response (env _{prog_name.upper()}_COMPLETE=fish_complete COMP_WORDS=(commandline -cp) COMP_CWORD=(commandline -t) {prog_name});

    for completion in $response;
        set -l metadata (string split "," -- $completion);

        if [ $metadata[1] = "dir" ];
            __fish_complete_directories $metadata[2];
        else if [ $metadata[1] = "file" ];
            __fish_complete_path $metadata[2];
        else if [ $metadata[1] = "plain" ];
            echo $metadata[2];
        end;
    end;
end;

complete --no-files --command {prog_name} --arguments "(_nothx_completion)";
"""

    click.echo(script.strip())


def _detect_install_method() -> str:
    """Identify how nothx was installed, so updates use the matching upgrader.

    Returns ``"pipx"`` or ``"pip"``. pipx owns both the virtualenv and the
    launcher symlinks in its bin directory, and records what it installed in
    ``pipx_metadata.json``. Running pip inside that venv swaps the package out
    from under pipx and leaves the metadata pinned to the old version, so
    ``pipx list`` misreports and ``pipx upgrade-all`` skips the package.
    """
    import sys
    from pathlib import Path

    venv_root = Path(sys.prefix)
    if (venv_root / "pipx_metadata.json").is_file():
        return "pipx"
    # Older pipx versions predate the metadata file; fall back to the layout
    # pipx has always used: <pipx home>/venvs/<package>.
    if venv_root.parent.name == "venvs" and "pipx" in venv_root.parts:
        return "pipx"
    return "pip"


@main.command()
@click.option("--check", is_flag=True, help="Only check for updates, don't install")
def update(check: bool):
    """Check for and install updates.

    Updates nothx to the latest version using pipx or pip, whichever
    installed it.
    """
    import shutil
    import subprocess
    import sys
    import urllib.error
    import urllib.request

    console.print(f"\n[header]Current version:[/header] {__version__}")

    installer = _detect_install_method()
    if installer == "pipx":
        upgrade_hint = "pipx upgrade nothx"
        git_hint = "pipx install --force git+https://github.com/sainihas/nothx.git"
    else:
        upgrade_hint = "pip install --upgrade nothx"
        git_hint = "pip install --upgrade git+https://github.com/sainihas/nothx.git"

    # Check for latest version on PyPI using the JSON API
    with console.status("Checking for updates...", spinner_style="#ffaf00"):
        try:
            url = "https://pypi.org/pypi/nothx/json"
            with urllib.request.urlopen(url, timeout=10) as response:
                data = json.loads(response.read().decode("utf-8"))
                latest = data.get("info", {}).get("version")
        except (urllib.error.URLError, urllib.error.HTTPError, json.JSONDecodeError, OSError):
            latest = None

    if latest:
        console.print(f"[header]Latest version:[/header]  {latest}")

        if latest == __version__:
            console.print("\n[success]✓ You're already on the latest version![/success]")
            return

        if check:
            console.print(f"\n[info]Run 'nothx update' to upgrade to {latest}[/info]")
            return

        # Perform update
        if not _styled_confirm(f"Update to version {latest}?", default=True):
            console.print("Cancelled.")
            return

        if installer == "pipx":
            pipx_path = shutil.which("pipx")
            if pipx_path is None:
                console.print(
                    "\n[warning]nothx was installed with pipx, but pipx is not on PATH.[/warning]"
                )
                console.print("[muted]Upgrading with pip would desync pipx. Run instead:[/muted]")
                console.print(f"{_L} [info]{upgrade_hint}[/info]")
                return
            command = [pipx_path, "upgrade", "nothx"]
        else:
            command = [sys.executable, "-m", "pip", "install", "--upgrade", "nothx"]

        console.print("\n[header]Updating...[/header]")
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=120,
            )
            if result.returncode == 0:
                console.print(f"[success]✓ Updated to {latest}[/success]")
                console.print("\n[muted]Restart nothx to use the new version.[/muted]")
            else:
                console.print(f"[error]Update failed: {result.stderr.strip()}[/error]")
                console.print(f"\n[muted]Try running manually:[/muted] {upgrade_hint}")
        except subprocess.TimeoutExpired:
            console.print("[error]Update timed out. Try running manually:[/error]")
            console.print(f"{_L} {upgrade_hint}")
            return
    else:
        console.print("\n[warning]Could not check PyPI for updates.[/warning]")
        console.print("[muted]nothx may not be published yet, or you're offline.[/muted]")
        console.print("\nTo update manually:")
        console.print(f"{_L} [info]{upgrade_hint}[/info]")
        console.print(f"{_L} [muted]or from git:[/muted]")
        console.print(f"{_L} [info]{git_hint}[/info]")


# Command aliases for power users
main.add_command(run, name="r")
main.add_command(status, name="s")
main.add_command(review, name="rv")
main.add_command(history, name="h")
main.add_command(change, name="c")


if __name__ == "__main__":
    main()
