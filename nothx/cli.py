"""Command-line interface for nothx."""

import csv
import hashlib
import json
import logging
import re
import uuid
import webbrowser
from datetime import UTC, datetime
from typing import Any

import click
import humanize
import questionary
from questionary import Style as QStyle
from rich.columns import Columns
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TaskProgressColumn, TextColumn
from rich.rule import Rule
from rich.table import Table
from rich.tree import Tree

from . import __version__, db, msauth
from .classifier import ClassificationEngine, get_learner
from .classifier.ai import test_ai_connection
from .config import (
    CURRENT_MAILBOX_MUTATION_CONSENT_VERSION,
    CURRENT_UNSUBSCRIBE_CONSENT_VERSION,
    AccountConfig,
    Config,
    get_config_dir,
)
from .errors import IMAPError, OAuthError
from .imap import IMAPConnection, test_account
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
from .scanner import scan_inbox
from .scheduler import get_schedule_status, install_schedule, uninstall_schedule
from .theme import console, print_animated_welcome
from .unsubscriber import (
    UnsafeUnsubscribeError,
    contact_suppression_reason,
    is_contact_permitted,
    unsubscribe_subscription,
)

logger = logging.getLogger(__name__)


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
        db.set_subscription_policy(subscription["id"], "block")
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


def _subscription_has_persisted_threat(subscription_id: int) -> bool:
    """Return whether stored server evidence forbids contacting this sender."""
    for message in db.list_message_refs(subscription_id=subscription_id, limit=100_000):
        if message.get("mailbox_role") == "junk" or message.get("provider_verdict"):
            return True
        try:
            flags = json.loads(message.get("flags_json") or "[]")
        except (TypeError, json.JSONDecodeError):
            flags = []
        normalized = {str(flag).casefold() for flag in flags}
        if normalized & {"$junk", r"\junk", "$phishing", "spam", r"\spam"}:
            return True
    return False


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
    for header in headers:
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
    allow_mailbox_actions: bool = True,
    accounts: set[str] | None = None,
) -> None:
    """Verify post-grace quietness and escalate a second failed request."""
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
        if int(operation.get("retry_generation") or 0) < 1:
            # The normal classification/execution pass may now use one fresh
            # endpoint while excluding every previously accepted fingerprint.
            continue

        db.set_subscription_policy(operation["subscription_id"], "block")
        if not allow_mailbox_actions or not config.permits_mailbox_mutation:
            block_operation = db.get_or_create_unsubscribe_operation(
                operation["subscription_id"],
                "post-retry-block-consent-v1",
                kind="block",
            )
            db.update_unsubscribe_operation_outcome(
                block_operation["id"],
                "needs_user",
                error_code="mailbox_approval_required",
                detail_redacted="Post-retry Junk movement requires consent and approval",
            )
            continue

        subscription = db.get_subscription(operation["subscription_id"])
        if subscription is None:
            continue
        claim_owner = uuid.uuid4().hex
        block_operation, acquired = db.claim_unsubscribe_operation(
            subscription["id"],
            f"post-retry-block-v1-{operation['id']}",
            kind="block",
            claim_owner=claim_owner,
        )
        if not acquired:
            continue
        moved, failed = _move_persisted_subscription_to_junk(
            config,
            subscription,
            block_operation["id"],
            claim_owner=claim_owner,
        )
        sender_domain = subscription.get("sender_domain")
        if sender_domain and (moved or not failed):
            db.update_sender_status(sender_domain, SenderStatus.BLOCKED)


def _block_subscription(
    config: Config,
    sender: SenderStats,
    headers: list[EmailHeader],
    classification: Classification,
) -> tuple[int, int]:
    """Apply the spam path: move every matching Inbox UID and never unsubscribe."""
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
    )


def _move_persisted_subscription_to_junk(
    config: Config,
    subscription: dict[str, Any],
    operation_id: int,
    *,
    claim_owner: str,
) -> tuple[int, int]:
    """Move every persisted Inbox locator for one account/list identity."""
    inbox_messages = db.list_message_refs(
        subscription_id=subscription["id"],
        mailbox_role="inbox",
        limit=100_000,
    )
    if not inbox_messages:
        db.update_unsubscribe_operation_outcome(
            operation_id,
            "blocked",
            claim_owner=claim_owner,
        )
        return 0, 0

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
                previous = existing.get((message["id"], action_key))
                if previous and previous["outcome"] in {
                    "moved",
                    "already_junk",
                    "not_found",
                }:
                    moved += 1
                    continue
                if previous and not bool(previous.get("retryable", 1)):
                    # COPY may already have placed this message in Junk. A
                    # non-retryable partial is durably terminal so a later run
                    # cannot create another destination copy.
                    failed += 1
                    continue
                locator = MessageRef(
                    message["account"],
                    message["mailbox"],
                    int(message["uidvalidity"]),
                    int(message["uid"]),
                )
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
    except (IMAPError, OSError) as error:
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


def _apply_manual_subscription_block(
    config: Config,
    subscription: dict[str, Any],
) -> tuple[int, int]:
    """Apply an explicitly approved account/list BLOCK to persisted Inbox refs."""
    db.set_subscription_policy(subscription["id"], "block")
    if not config.permits_mailbox_mutation:
        _record_persisted_block_needs_consent(subscription)
        return 0, 0
    inbox_messages = db.list_message_refs(
        subscription_id=subscription["id"],
        mailbox_role="inbox",
        limit=100_000,
    )
    newest_message_id = max((int(row["id"]) for row in inbox_messages), default=0)
    claim_owner = uuid.uuid4().hex
    operation, acquired = db.claim_unsubscribe_operation(
        subscription["id"],
        f"manual-block-v2-{newest_message_id}",
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
        timestamp=datetime.now(),
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
        "[warning]For Outlook/Live/Hotmail, you need an App Password:[/warning]",
        "  1. Go to [link=https://account.live.com/proofs/AppPassword]account.live.com/proofs/AppPassword[/link]",
        "  2. You may need to enable 2FA first at [link=https://account.microsoft.com/security]account.microsoft.com/security[/link]",
        "  3. Generate a new app password and copy it\n",
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
        "  • Verify your app password at [link=https://account.live.com/proofs/AppPassword]account.live.com/proofs/AppPassword[/link]",
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
            questionary.Choice("Scan inbox and unsubscribe", value="run"),
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

    # Microsoft consumer mail supports IMAP/SMTP through OAuth device flow.
    # Keep password auth available for existing/custom deployments, but make
    # its compatibility limitations explicit.
    if provider == "outlook":
        _select_header("Choose Outlook authentication")
        auth_method = _styled_select(
            [
                questionary.Choice("Microsoft sign-in (recommended)", value="oauth"),
                questionary.Choice("App password (legacy)", value="password"),
            ]
        )
        if auth_method is None:
            return None
        if auth_method == "oauth":
            client_id = questionary.text(
                "",
                qmark="Microsoft public-client application ID:",
                style=Q_INPUT_STYLE,
            ).ask()
            if not client_id or not client_id.strip():
                console.print("[warning]A Microsoft application client ID is required.[/warning]")
                return None
            try:
                flow = msauth.start_device_flow(client_id.strip())
                verification_uri = str(flow["verification_uri"])
                console.print("\n[header]Authorize nothx with Microsoft[/header]")
                console.print(f"{_L} Open: [link={verification_uri}]{verification_uri}[/link]")
                console.print(f"{_L} Enter code: [bold]{flow['user_code']}[/bold]")
                # Browser launch is convenience only; the printed URI/code is
                # always sufficient when launch is unavailable.
                try:
                    if not webbrowser.open(
                        str(flow.get("verification_uri_complete") or verification_uri)
                    ):
                        console.print(f"{_L} [muted]Open the link above in any browser.[/muted]")
                except Exception as error:
                    logger.debug("Could not open OAuth browser: %s", type(error).__name__)
                    console.print(f"{_L} [muted]Open the link above in any browser.[/muted]")
                token = msauth.poll_for_token(
                    client_id.strip(),
                    str(flow["device_code"]),
                    int(flow.get("interval", 5)),
                    int(flow["expires_in"]),
                )
                msauth.save_token(email, token, client_id.strip())
            except (OAuthError, OSError, ValueError) as error:
                console.print(f"[error]Microsoft sign-in failed: {error}[/error]")
                return None

            account = AccountConfig(
                provider=provider,
                email=email,
                auth="oauth",
                client_id=client_id.strip(),
            )
            with console.status("Testing connection...", spinner_style="#ffaf00"):
                success, msg = test_account(account)
            if not success:
                msauth.delete_token(email)
                console.print(f"[error]Connection failed: {msg}[/error]")
                return None
            console.print("[success]✓ Connected with Microsoft OAuth![/success]\n")
            return _unique_account_name(config, email), account

        console.print(
            "[warning]Microsoft may reject basic/app-password IMAP authentication. "
            "OAuth is recommended and is required for XOAUTH2 SMTP unsubscribe mail.[/warning]"
        )

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
        _run_scan(config, verbose=True, dry_run=True)

    console.print(
        "\n[warning]Unsubscribe and mailbox-write automation are disabled until you "
        "explicitly grant consent.[/warning]"
    )
    console.print(
        "Run [bold]nothx consent --all --yes[/bold] after reviewing the network and "
        "mailbox-write permissions."
    )

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
    config.accounts[account_name] = acc
    if config.default_account is None:
        config.default_account = account_name
    config.save()

    console.print(f"\n[success]✓ Added account: {acc.email}[/success]")
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
@click.option("--dry-run", is_flag=True, help="Show what would happen without taking action")
@click.option("--verbose", "-v", is_flag=True, help="Show detailed output")
@click.option(
    "--full-history",
    is_flag=True,
    help="Scan all available history instead of only incremental/new messages",
)
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
):
    """Scan inbox and process marketing emails."""
    if full_history and rescan:
        raise click.UsageError("--full-history and --rescan are mutually exclusive")
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

    if dry_run:
        console.print(
            "[warning]DRY RUN - mailbox changes, unsubscribe requests, and cloud AI calls "
            "are disabled[/warning]\n"
        )

    _run_scan(
        config,
        verbose=verbose,
        dry_run=dry_run,
        auto=auto,
        account_names=accounts_to_scan,
        full_history=full_history,
        rescan=rescan,
    )


def _run_scan(
    config: Config,
    verbose: bool = False,
    dry_run: bool = False,
    auto: bool = False,
    account_names: list[str] | None = None,
    full_history: bool = False,
    rescan: bool = False,
):
    """Run the main scan and classification process."""
    stats = RunStats(
        ran_at=datetime.now(),
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
            if total > 1:
                progress.update(
                    task, description=f"Scanning account {current} of {total} · {email}"
                )
            else:
                progress.update(task, description=f"Scanning {email}")

        def on_account_error(email: str, _name: str, error: str) -> None:
            scan_errors.append(f"{email}: {error}")

        scan_result = scan_inbox(
            config,
            account_names=account_names,
            on_account_start=on_account_start,
            on_account_error=on_account_error,
            persist=not dry_run,
            full_history=full_history,
            rescan=rescan,
        )
        # The account/List-Id (or account/From) grouping is authoritative.
        # A narrow fallback keeps third-party callers using a pre-v2 ScanResult
        # working without merging real scanner results by domain.
        subscription_stats = getattr(scan_result, "subscription_stats", None)
        authoritative = isinstance(subscription_stats, dict)
        sender_stats = subscription_stats if authoritative else scan_result.sender_stats

    if scan_errors:
        for err in scan_errors:
            console.print(f"[warning]! Skipped account: {err}[/warning]")

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
        _reconcile_due_operations(
            config,
            allow_mailbox_actions=config.operation_mode != "confirm",
            accounts=verification_accounts,
        )

    if not sender_stats:
        console.print("[success]✓ No marketing emails found.[/success]")
        return

    stats.emails_scanned = sum(s.total_emails for s in sender_stats.values())
    stats.unique_senders = len(sender_stats)

    console.print(
        f"[success]✓ Found {stats.emails_scanned} emails from {stats.unique_senders} senders[/success]"
    )

    # Phase 2: Classify senders
    console.print("\n[header]Step 2/3: Classifying senders[/header]")
    engine = ClassificationEngine(config)

    with Progress(
        SpinnerColumn(style="#ffaf00"),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(complete_style="orange1", finished_style="orange1", pulse_style="orange1"),
        TaskProgressColumn(),
        console=console,
        transient=True,
    ) as progress:
        task = progress.add_task("Analyzing senders...", total=len(sender_stats))
        classifications = engine.classify_batch(list(sender_stats.values()), persist=not dry_run)
        progress.update(task, completed=len(sender_stats))

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
            if subscription is not None and _subscription_has_persisted_threat(subscription["id"]):
                if not dry_run:
                    db.set_subscription_policy(subscription["id"], "block")
                classifications[sender.classification_key] = Classification(
                    email_type=EmailType.COLD_OUTREACH,
                    action=Action.BLOCK,
                    confidence=1.0,
                    reasoning=("Persisted Junk/phishing evidence requires local suppression"),
                    source="provider_policy",
                )
                continue
            policy = subscription.get("policy_action") if subscription else None
            if policy in {"block", "keep", "unsub"}:
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
                    source="user_rule",
                )

            # Threat evidence is an unconditional local disposition. It must
            # never be turned into unsubscribe traffic by an old domain rule.
            if (
                sender.provider_threat
                or sender.phishing_emails
                or (
                    not sender.not_junk_emails
                    and (sender.junk_emails or sender.junk_keyword_emails)
                )
            ):
                classifications[sender.classification_key] = Classification(
                    email_type=EmailType.COLD_OUTREACH,
                    action=Action.BLOCK,
                    confidence=1.0,
                    reasoning="Provider junk/phishing evidence requires local suppression",
                    source="provider_policy",
                )
            elif sender.authentication_failed_emails > sender.authenticated_emails:
                classifications[sender.classification_key] = Classification(
                    email_type=EmailType.UNKNOWN,
                    action=Action.BLOCK,
                    confidence=1.0,
                    reasoning=("Trusted authentication failures dominate authenticated deliveries"),
                    source="auth_policy",
                )
            elif sender.authentication_failed_emails and sender.authenticated_emails:
                current = classifications.get(sender.classification_key)
                if (
                    current is not None
                    and current.action is Action.BLOCK
                    and current.source != "user_rule"
                ):
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

    min_emails = config.thresholds.min_emails_before_action
    deterministic_block_sources = {
        "user_rule",
        "provider_policy",
        "auth_policy",
        "method_policy",
        "retry_policy",
    }

    for key, sender in sender_stats.items():
        classification = classifications.get(sender.classification_key)
        if classification is None:
            # Compatibility for classifiers that still return their input key.
            classification = classifications.get(key)
        if classification is None:
            logger.warning("No classification returned for %s", sender.classification_key)
            continue

        # Don't auto-act on senders we've barely seen — defer to review.
        # Explicit user rules/overrides (source="user_rule") always take
        # highest priority and are never deferred by the email-count guard.
        if (
            classification.action in (Action.UNSUB, Action.BLOCK)
            and classification.source != "user_rule"
            and not (
                classification.action is Action.BLOCK
                and (
                    classification.source in deterministic_block_sources
                    or classification.email_type is EmailType.COLD_OUTREACH
                )
            )
            and sender.total_emails < min_emails
        ):
            logger.debug(
                "Deferring %s to review: only %d emails (< %d)",
                sender.classification_key,
                sender.total_emails,
                min_emails,
            )
            to_review.append((key, sender, classification))
            continue

        if classification.action == Action.UNSUB:
            to_unsub.append((key, sender, classification))
        elif classification.action == Action.KEEP:
            to_keep.append((key, sender, classification))
        elif classification.action == Action.BLOCK:
            to_block.append((key, sender, classification))
        else:
            to_review.append((key, sender, classification))

    # Summary as tree
    tree = Tree("[success]✓ Classification complete[/success]")
    tree.add(f"[unsubscribe]{len(to_unsub)} to unsubscribe[/unsubscribe]")
    tree.add(f"[block]{len(to_block)} to block[/block]")
    tree.add(f"[keep]{len(to_keep)} to keep[/keep]")
    tree.add(f"[review]{len(to_review)} need review[/review]")
    console.print(tree)

    if verbose:
        _show_details(to_unsub, to_keep, to_review, to_block)

    # Optional manual review of decisions (not in auto mode)
    if not auto and not dry_run and (to_unsub or to_keep):
        if _styled_confirm("Review decisions before proceeding?", default=False):
            _select_header("Manual Review")
            console.print("[muted]Change any decisions you disagree with:[/muted]\n")

            # Review items marked for unsubscribe
            review_cancelled = False
            for key, sender, classification in to_unsub[:]:  # Slice to allow modification
                action = questionary.select(
                    f"[{sender.total_emails} emails] {sender.domain}",
                    choices=[
                        questionary.Choice("Unsubscribe (AI recommendation)", value="unsub"),
                        questionary.Choice("Keep instead", value="keep"),
                        questionary.Choice("Skip for now", value="skip"),
                    ],
                    default="unsub",
                    **Q_COMMON,
                ).ask()

                if action is None:
                    console.print("[muted]Review cancelled[/muted]")
                    review_cancelled = True
                    break

                if action == "keep":
                    to_unsub.remove((key, sender, classification))
                    to_keep.append((key, sender, classification))
                    console.print(f"{_L} [keep]→ Changed to keep[/keep]")
                elif action == "skip":
                    to_unsub.remove((key, sender, classification))
                    to_review.append((key, sender, classification))
                    console.print(f"{_L} [review]→ Moved to review[/review]")

            # Review items marked to keep (only if not cancelled)
            if not review_cancelled:
                for key, sender, classification in to_keep[:]:  # Slice to allow modification
                    action = questionary.select(
                        f"[{sender.total_emails} emails] {sender.domain}",
                        choices=[
                            questionary.Choice("Keep (AI recommendation)", value="keep"),
                            questionary.Choice("Unsubscribe instead", value="unsub"),
                            questionary.Choice("Skip for now", value="skip"),
                        ],
                        default="keep",
                        **Q_COMMON,
                    ).ask()

                    if action is None:
                        console.print("[muted]Review cancelled[/muted]")
                        break

                    if action == "unsub":
                        to_keep.remove((key, sender, classification))
                        to_unsub.append((key, sender, classification))
                        console.print(f"{_L} [unsubscribe]→ Changed to unsubscribe[/unsubscribe]")
                    elif action == "skip":
                        to_keep.remove((key, sender, classification))
                        to_review.append((key, sender, classification))
                        console.print(f"{_L} [review]→ Moved to review[/review]")

            # Updated summary
            # Updated summary as tree
            updated_tree = Tree("[header]Updated decisions[/header]")
            updated_tree.add(f"[unsubscribe]{len(to_unsub)} to unsubscribe[/unsubscribe]")
            updated_tree.add(f"[keep]{len(to_keep)} to keep[/keep]")
            updated_tree.add(f"[review]{len(to_review)} need review[/review]")
            console.print()
            console.print(updated_tree)

    # Phase 3: execute two strictly separate paths. BLOCK is a mailbox action
    # and must never fall through to the network unsubscribe executor.
    if not dry_run and (to_unsub or to_block):
        if config.operation_mode == "confirm" and auto:
            console.print(
                "\n[warning]Confirm mode is on — skipping network and mailbox actions. "
                "Run without --auto to approve interactively.[/warning]"
            )
        elif auto or _styled_confirm(
            f"Apply {len(to_unsub)} unsubscribe and {len(to_block)} Junk/block actions?",
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
                            db.set_subscription_policy(subscription["id"], "unsub")
                            execute, exclusions, retry_generation, escalate = (
                                _unsubscribe_operation_plan(subscription)
                            )
                            consent_resume = _is_unsubscribe_consent_resume(
                                subscription,
                                config,
                            )
                            if escalate:
                                if config.permits_mailbox_mutation:
                                    moved, move_failed = _block_subscription(
                                        config, sender, headers, classification
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
                            if exhausted_retry:
                                block_classification = Classification(
                                    email_type=EmailType.UNKNOWN,
                                    action=Action.BLOCK,
                                    confidence=1.0,
                                    reasoning="No fresh endpoint remained after the allowed retry",
                                    source="retry_policy",
                                )
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
                    else:
                        stats.failed += 1
                    progress.advance(task)

            console.print(
                f"\n[success]✓ {stats.auto_unsubbed} unsubscribe request(s) accepted[/success]"
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
    stats.kept = len(to_keep)
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


def _show_details(to_unsub, to_keep, to_review, to_block):
    """Show detailed classification results."""
    if to_unsub:
        console.print("\n[bold red]To Unsubscribe:[/bold red]")
        table = Table(show_header=True)
        table.add_column("Account / List identity")
        table.add_column("Domain")
        table.add_column("Emails")
        table.add_column("Open Rate")
        table.add_column("Reason")
        for _key, sender, classification in to_unsub[:10]:
            table.add_row(
                _subscription_label(sender),
                sender.domain,
                str(sender.total_emails),
                f"{sender.open_rate:.0f}%",
                classification.reasoning[:50],
            )
        console.print(table)

    if to_keep:
        console.print("\n[bold green]To Keep:[/bold green]")
        table = Table(show_header=True)
        table.add_column("Account / List identity")
        table.add_column("Domain")
        table.add_column("Emails")
        table.add_column("Open Rate")
        table.add_column("Reason")
        for _key, sender, classification in to_keep[:10]:
            table.add_row(
                _subscription_label(sender),
                sender.domain,
                str(sender.total_emails),
                f"{sender.open_rate:.0f}%",
                classification.reasoning[:50],
            )
        console.print(table)

    if to_block:
        console.print("\n[bold red]To Block / Move to Junk:[/bold red]")
        table = Table(show_header=True)
        table.add_column("Account / List identity")
        table.add_column("Domain")
        table.add_column("Inbox")
        table.add_column("Reason")
        for _key, sender, classification in to_block[:10]:
            table.add_row(
                _subscription_label(sender),
                sender.domain,
                str(sender.inbox_emails),
                classification.reasoning[:50],
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
    successful, failed = db.get_unsub_success_rate()
    total_unsub_attempts = successful + failed
    success_rate = (successful / total_unsub_attempts * 100) if total_unsub_attempts > 0 else 0

    panel_data = [
        (f"[count]{stats['total_senders']}[/count]", "Senders"),
        (f"[count]{stats['unsubscribed']}[/count]", "Unsubbed"),
        (f"[count]{stats['kept']}[/count]", "Kept"),
        (f"[count]{success_rate:.0f}%[/count]", "Success"),
    ]
    stat_panels = [
        Panel(f"{value}\n[muted]{label}[/muted]", width=14, border_style="#808080")
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

    console.print(f"{_L} Pending review: [count]{stats['pending_review']}[/count]")
    console.print(f"{_L} Total runs: [count]{stats['total_runs']}[/count]")

    grouped = db.get_grouped_metrics()
    outcomes = grouped["operations"]
    active_manual = [
        subscription
        for subscription in db.list_subscriptions(outcome="needs_user", limit=10_000)
        if subscription.get("policy_action") != "keep"
    ]
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
        console.print(f"{_L} Manual-action queue: [count]{len(active_manual)}[/count]")
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


@main.command()
@click.option("--all", "show_all", is_flag=True, help="Show all pending senders")
@click.option("--keep", "show_keep", is_flag=True, help="Review senders marked to keep")
@click.option("--unsub", "show_unsub", is_flag=True, help="Review senders marked to unsubscribe")
def review(show_all: bool, show_keep: bool, show_unsub: bool):
    """Review senders that need manual decision.

    By default, shows only senders that need review (uncertain classification).
    Use --all to see all pending senders, or --keep/--unsub to filter by classification.
    """
    config = Config.load()

    if not config.is_configured():
        console.print("[error]nothx is not configured. Run 'nothx init' first.[/error]")
        return

    db.init_db()

    manual_subscriptions: list[dict[str, Any]] = []
    handled_manual_domains: set[str] = set()
    if not show_keep and not show_unsub:
        by_id: dict[int, dict[str, Any]] = {}
        for subscription in (
            *db.list_subscriptions(outcome="needs_user", limit=500),
            *db.list_subscriptions(policy_action="review", limit=500),
        ):
            if subscription.get("policy_action") != "keep":
                by_id[subscription["id"]] = subscription
        manual_subscriptions = list(by_id.values())

    if manual_subscriptions:
        console.print(
            f"\n[header]{len(manual_subscriptions)} subscription(s) need manual action[/header]"
        )
        table = Table(show_header=True)
        table.add_column("ID")
        table.add_column("Account")
        table.add_column("List identity")
        table.add_column("Outcome")
        for subscription in manual_subscriptions:
            table.add_row(
                str(subscription["id"]),
                subscription["account"],
                f"{subscription['identity_kind']}:{subscription['identity_value']}",
                subscription.get("last_outcome") or "review",
            )
        console.print(table)

        for subscription in manual_subscriptions:
            identity = f"{subscription['identity_kind']}:{subscription['identity_value']}"
            choices = []
            if (
                subscription.get("policy_action") != "block"
                and subscription.get("last_outcome") != "blocked"
                and not _subscription_has_persisted_threat(subscription["id"])
            ):
                choices.append(
                    questionary.Choice("Rescan and open an unsubscribe page", value="open")
                )
            choices.extend(
                [
                    questionary.Choice("Keep future mail", value="keep"),
                    questionary.Choice("Block future mail / move to Junk", value="block"),
                    questionary.Choice("Skip", value="skip"),
                ]
            )
            choice = questionary.select(
                f"{subscription['account']} · {identity}",
                choices=choices,
                **Q_COMMON,
            ).ask()
            if choice is None:
                break
            if choice == "open":
                click.get_current_context().invoke(
                    open_unsubscribe,
                    subscription_id=subscription["id"],
                    yes=False,
                )
            elif choice == "block":
                moved, failed = _apply_manual_subscription_block(config, subscription)
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

    # A manual account/list decision may create/update its compatibility
    # sender row for learning. Do not immediately ask for (and execute) the
    # same domain-level decision a second time in this review invocation.
    senders = [
        sender for sender in senders if sender["domain"].casefold() not in handled_manual_domains
    ]

    if not senders and not manual_subscriptions:
        console.print(f"[success]No senders {filter_label}![/success]")
        return
    if not senders:
        return

    _select_header(f"{len(senders)} senders {filter_label}")

    for sender in senders:
        domain = sender["domain"]
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
            ],
            **Q_COMMON,
        ).ask()

        if choice is None:
            # User cancelled (Ctrl+C or ESC)
            console.print(f"{_L} [muted]Cancelled[/muted]")
            break

        if choice in ("unsub", "keep", "block"):
            _change_sender_status(domain, choice, sender=sender, config=config)
        else:
            console.print(f"{_L} [review]\u2192 Skipped[/review]")

        console.print()


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

    account_entry = next(
        (
            (name, account)
            for name, account in config.accounts.items()
            if account.email.casefold() == subscription["account"].casefold()
        ),
        None,
    )
    if account_entry is None:
        console.print("[error]The matching configured account is unavailable.[/error]")
        return
    account_name, _account = account_entry
    try:
        scanned = scan_inbox(
            config,
            account_names=[account_name],
            persist=False,
            rescan=True,
        )
    except (IMAPError, OSError) as error:
        console.print(f"[error]Mailbox rescan failed: {_redact_failure_detail(str(error))}[/error]")
        return

    candidates: list[str] = []
    for key, sender in scanned.subscription_stats.items():
        if not (
            sender.account_key == subscription["account"]
            and sender.identity_kind == subscription["identity_kind"]
            and sender.identity_value == subscription["identity_value"]
        ):
            continue
        matching_headers = scanned.get_emails_for_subscription(key)
        denied_header = next(
            (header for header in matching_headers if not is_contact_permitted(header, config)),
            None,
        )
        if denied_header is not None:
            reason = contact_suppression_reason(denied_header) or "Contact is not permitted"
            console.print(f"[warning]{reason}; no destination was opened.[/warning]")
            return
        for header in sorted(
            matching_headers,
            key=lambda item: item.received_at or item.date,
            reverse=True,
        ):
            for target in header.list_unsubscribe_targets:
                if target.casefold().startswith("https://") and target not in candidates:
                    candidates.append(target)
            for footer in header.footer_unsubscribe_candidates:
                if footer.uri.casefold().startswith("https://") and footer.uri not in candidates:
                    candidates.append(footer.uri)
            if len(candidates) >= 5:
                break
        break

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
                timestamp=datetime.now(),
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
def config_cmd(show: bool, ai: str | None, footer_scan: str | None, mode: str | None):
    """View or modify configuration."""
    config = Config.load()

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

    if show or (not ai and not mode and not footer_scan):
        console.print("\n[header]Current Configuration[/header]")
        console.print(f"{_L} Config dir: {get_config_dir()}")
        console.print(f"{_L} AI enabled: {config.ai.enabled}")
        console.print(f"{_L} AI provider: {config.ai.provider}")
        console.print(f"{_L} Operation mode: {config.operation_mode}")
        console.print(f"{_L} Scan days: {config.scan_days}")
        console.print(f"{_L} Scan Junk: {config.scan_junk}")
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
            CURRENT_UNSUBSCRIBE_CONSENT_VERSION if unsubscribe else 0
        )
    if mailbox_actions is not None:
        config.mailbox_mutation_consent_version = (
            CURRENT_MAILBOX_MUTATION_CONSENT_VERSION if mailbox_actions else 0
        )
    config.save()
    console.print("[success]✓ Automation consent updated[/success]")


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
def test_connection():
    """Test email connection."""
    config = Config.load()

    if not config.accounts:
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


@main.command()
@click.option("--check", is_flag=True, help="Only check for updates, don't install")
def update(check: bool):
    """Check for and install updates.

    Updates nothx to the latest version using pip.
    """
    import subprocess
    import sys
    import urllib.error
    import urllib.request

    console.print(f"\n[header]Current version:[/header] {__version__}")

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

        console.print("\n[header]Updating...[/header]")
        try:
            result = subprocess.run(
                [sys.executable, "-m", "pip", "install", "--upgrade", "nothx"],
                capture_output=True,
                text=True,
                timeout=120,
            )
            if result.returncode == 0:
                console.print(f"[success]✓ Updated to {latest}[/success]")
                console.print("\n[muted]Restart nothx to use the new version.[/muted]")
            else:
                console.print(f"[error]Update failed: {result.stderr}[/error]")
        except subprocess.TimeoutExpired:
            console.print("[error]Update timed out. Try running manually:[/error]")
            console.print(f"{_L} pip install --upgrade nothx")
            return
    else:
        console.print("\n[warning]Could not check PyPI for updates.[/warning]")
        console.print("[muted]nothx may not be published yet, or you're offline.[/muted]")
        console.print("\nTo update manually:")
        console.print(f"{_L} [info]pip install --upgrade nothx[/info]")
        console.print(f"{_L} [muted]or from git:[/muted]")
        console.print(
            f"{_L} [info]pip install --upgrade git+https://github.com/nothx/nothx.git[/info]"
        )


# Command aliases for power users
main.add_command(run, name="r")
main.add_command(status, name="s")
main.add_command(review, name="rv")
main.add_command(history, name="h")
main.add_command(change, name="c")


if __name__ == "__main__":
    main()
