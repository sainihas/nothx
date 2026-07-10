"""Email scanning and sender aggregation for nothx."""

import hashlib
import logging
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable

from . import db
from .authres import has_aligned_dkim_pass
from .config import Config
from .errors import IMAPError
from .footer import MAX_MESSAGES_PER_ACCOUNT
from .imap import IMAPConnection
from .mailbox import MailboxDiscovery
from .models import AuthResult, EmailHeader, SenderStats, SubscriptionIdentity

logger = logging.getLogger(__name__)


@dataclass
class _MailboxBatch:
    """One fully attempted mailbox scan and its durable checkpoint metadata."""

    name: str
    role: str
    headers: list[EmailHeader]
    uidvalidity: int | None
    high_water_uid: int
    complete: bool


def _delivery_time(header: EmailHeader) -> datetime:
    """Use immutable IMAP delivery time; legacy synthetic headers fall back to Date."""
    return header.received_at or header.date


def _effective_identity(
    header: EmailHeader,
    aliases: dict[tuple[str, str], str],
) -> SubscriptionIdentity:
    """Resolve a safe in-run From -> List-Id promotion, if one exists."""
    identity = header.subscription_identity
    if identity.kind == "from" and header.sender_address:
        promoted = aliases.get((identity.account_key, header.sender_address))
        if promoted:
            return SubscriptionIdentity(identity.account_key, "list_id", promoted)
    return identity


def _promotion_aliases(headers: list[EmailHeader]) -> dict[tuple[str, str], str]:
    """Return only unambiguous account/from-address List-Id mappings."""
    candidates: dict[tuple[str, str], set[str]] = defaultdict(set)
    for header in headers:
        if header.account_key and header.sender_address and header.normalized_list_id:
            candidates[(header.account_key, header.sender_address)].add(header.normalized_list_id)
    return {key: next(iter(values)) for key, values in candidates.items() if len(values) == 1}


def _aliases_with_stored_promotions(
    headers: list[EmailHeader],
) -> dict[tuple[str, str], str]:
    """Combine current evidence with durable promotions without overriding conflicts."""
    current_candidates: dict[tuple[str, str], set[str]] = defaultdict(set)
    for header in headers:
        if header.account_key and header.sender_address and header.normalized_list_id:
            current_candidates[(header.account_key, header.sender_address)].add(
                header.normalized_list_id
            )
    result = _promotion_aliases(headers)
    for account in {header.account_key for header in headers if header.account_key}:
        stored_candidates: dict[tuple[str, str], set[str]] = defaultdict(set)
        for row in db.list_subscriptions(account=account):
            promoted_from = row.get("promoted_from_value")
            if row.get("identity_kind") == "list_id" and promoted_from:
                stored_candidates[(account, str(promoted_from))].add(str(row["identity_value"]))
        for key, values in stored_candidates.items():
            if len(values) != 1:
                continue
            stored = next(iter(values))
            observed = current_candidates.get(key)
            if observed is not None and observed != {stored}:
                # A newly observed different/multiple List-Id is evidence that
                # this From address is shared. Do not reuse the old alias for
                # fallback messages in this run.
                result.pop(key, None)
                continue
            result.setdefault(key, stored)
    return result


def _footer_eligible(header: EmailHeader) -> bool:
    """Apply the default-off footer scanner's strict local admission policy."""
    authenticated = header.authentication.trusted and (
        header.authentication.dmarc is AuthResult.PASS
        or has_aligned_dkim_pass(header.authentication, header.domain)
    )
    bulk_or_list = bool(
        header.normalized_list_id
        or header.is_bulk_precedence
        or header.feedback_id
        or header.provider_bulk
        or header.esp
    )
    return (
        header.mailbox_role == "inbox"
        and authenticated
        and bulk_or_list
        and not _has_usable_header_method(header)
        and not header.server_junk
        and not header.server_phishing
    )


def _auth_evidence(header: EmailHeader) -> dict[str, object]:
    evidence = header.authentication
    return {
        "trusted": evidence.trusted,
        "spf": evidence.spf.value,
        "dkim": evidence.dkim.value,
        "dmarc": evidence.dmarc.value,
        "arc": evidence.arc.value,
        "dkim_domains": list(evidence.dkim_domains),
        "dkim_selectors": list(evidence.dkim_selectors),
        "results": [
            {
                "method": result.method,
                "result": result.result.value,
                "identifier": result.identifier,
                "domain": result.domain,
                "selector": result.selector,
            }
            for result in evidence.results
        ],
        "dkim_covers_unsubscribe": header.dkim_covers_unsubscribe,
    }


def _endpoint_fingerprints(header: EmailHeader) -> list[str]:
    """Fingerprint targets without persisting raw addresses or opaque tokens."""
    targets = [
        *header.list_unsubscribe_targets,
        *(candidate.uri for candidate in header.footer_unsubscribe_candidates),
    ]
    return sorted(
        {
            hashlib.sha256(value.encode("utf-8", errors="surrogatepass")).hexdigest()
            for value in targets
        }
    )


def _has_usable_header_method(header: EmailHeader) -> bool:
    return any(
        target.casefold().startswith(("https://", "mailto:"))
        for target in header.list_unsubscribe_targets
    )


def _persist_headers(
    account: str,
    headers: list[EmailHeader],
    aliases: dict[tuple[str, str], str],
    promotion_headers: list[EmailHeader] | None = None,
) -> None:
    """Persist real messages and account/list identities using redacted evidence."""
    # Promote old fallback rows before inserting a target List-Id.  The in-run
    # mapping and historical list rows must both be unambiguous.
    promotion_source = promotion_headers if promotion_headers is not None else headers
    existing = db.list_subscriptions(account=account)
    existing_list_ids_by_from: dict[str, set[str]] = defaultdict(set)
    for row in existing:
        if row.get("identity_kind") == "list_id" and row.get("from_address"):
            existing_list_ids_by_from[str(row["from_address"])].add(str(row["identity_value"]))
    for (alias_account, from_address), list_id in aliases.items():
        if alias_account != account:
            continue
        other_ids = existing_list_ids_by_from.get(from_address, set()) - {list_id}
        if other_ids:
            continue
        fallback = db.get_subscription(
            account=account,
            identity_kind="from",
            identity_value=from_address,
        )
        target = db.get_subscription(
            account=account,
            identity_kind="list_id",
            identity_value=list_id,
        )
        if fallback is None and target is None:
            fallback_headers = [
                header
                for header in promotion_source
                if header.account_key == account
                and header.sender_address == from_address
                and header.normalized_list_id is None
            ]
            if fallback_headers:
                # Seed the fallback from a real observed message, then use the
                # database's transactional promotion API. This records the
                # durable alias needed when a later delivery omits List-Id.
                fallback = db.upsert_subscription(
                    account,
                    "from",
                    from_address,
                    from_address=from_address,
                    sender_domain=fallback_headers[0].domain,
                    first_seen=min(_delivery_time(item) for item in fallback_headers),
                    last_seen=max(_delivery_time(item) for item in fallback_headers),
                    last_delivery_at=max(_delivery_time(item) for item in fallback_headers),
                )
        if fallback is not None and target is None:
            try:
                db.promote_subscription_identity(account, from_address, list_id)
            except ValueError:
                # A concurrent scheduler may have created a target.  Never
                # merge on a guess; normal upserts below remain idempotent.
                logger.info(
                    "Skipped ambiguous subscription identity promotion for %s",
                    account,
                )

    for header in headers:
        identity = _effective_identity(header, aliases)
        effective_list_id: str | None = (
            identity.value if identity.kind == "list_id" else header.normalized_list_id
        )
        sender_address: str | None = header.sender_address or None
        subscription = db.upsert_subscription(
            account,
            identity.kind,
            identity.value,
            list_id=effective_list_id,
            from_address=sender_address,
            sender_domain=header.domain if header.domain != "unknown" else None,
            first_seen=_delivery_time(header),
            last_seen=_delivery_time(header),
            last_delivery_at=_delivery_time(header),
        )
        locator = header.message_ref
        if locator is None:
            continue
        provider_verdict = header.provider_threat
        if provider_verdict is None and header.server_junk:
            provider_verdict = "junk"
        db.upsert_message_ref(
            int(subscription["id"]),
            account,
            locator.mailbox,
            header.mailbox_role,
            locator.uidvalidity,
            locator.uid,
            message_id=header.message_id or None,
            from_address=sender_address,
            list_id=header.normalized_list_id,
            received_at=_delivery_time(header),
            flags=[*header.system_flags, *header.keywords, *header.gmail_labels],
            auth_evidence=_auth_evidence(header),
            bulk_evidence={
                "list_id": header.normalized_list_id,
                "precedence": header.precedence,
                "feedback_id": bool(header.feedback_id),
                "esp": header.esp,
                "provider_bulk": header.provider_bulk,
            },
            provider_verdict=provider_verdict,
            endpoint_fingerprints=_endpoint_fingerprints(header),
            has_header_method=_has_usable_header_method(header),
            can_unsubscribe=header.server_can_unsubscribe,
        )


def _most_common(values: "Iterable[str | None]") -> str | None:
    """Return the most frequent non-null value, or None."""
    counter = Counter(v for v in values if v)
    return counter.most_common(1)[0][0] if counter else None


def _agg_verdict(values: "Iterable[bool | None]") -> bool | None:
    """Fail-dominant aggregate: any False -> False, else True if any known, else None."""
    known = [v for v in values if v is not None]
    if not known:
        return None
    return all(known)


class ScanResult:
    """Result of scanning inbox, containing stats and cached email headers."""

    def __init__(
        self,
        sender_stats: dict[str, SenderStats],
        domain_emails: dict[str, list[EmailHeader]],
        subscription_stats: dict[str, SenderStats] | None = None,
        subscription_emails: dict[str, list[EmailHeader]] | None = None,
    ):
        self.sender_stats = sender_stats
        self.domain_emails = domain_emails
        self.subscription_stats = subscription_stats or sender_stats
        self.subscription_emails = subscription_emails or domain_emails

    def get_email_for_domain(self, domain: str) -> EmailHeader | None:
        """Get the best sample email to act on for a domain.

        Prefers a DKIM-passing one-click email (the safest, most reliable
        unsubscribe path), then any email with an unsubscribe header, then
        the first email seen.
        """
        emails = self.domain_emails.get(domain, [])
        if not emails:
            return None

        def rank(e: EmailHeader) -> int:
            if e.list_unsubscribe and e.list_unsubscribe_post and e.dkim_pass:
                return 3
            if e.list_unsubscribe and e.list_unsubscribe_post:
                return 2
            if e.list_unsubscribe:
                return 1
            return 0

        best = max(emails, key=rank)
        return best

    def get_emails_for_subscription(self, key: str) -> list[EmailHeader]:
        """Return all recent messages for one account-scoped subscription."""
        return list(self.subscription_emails.get(key, ()))


def _stats_for_emails(
    domain: str,
    emails: list[EmailHeader],
    identity: SubscriptionIdentity | None = None,
) -> SenderStats:
    """Aggregate a homogeneous group of message headers."""
    total = len(emails)
    seen = sum(1 for email in emails if email.is_seen)
    dates = [_delivery_time(email) for email in emails]
    sorted_emails = sorted(emails, key=_delivery_time, reverse=True)
    sample_subjects = [email.subject for email in sorted_emails[:5]]
    sample_senders: list[str] = []
    for header in sorted_emails:
        address = header.sender_address
        if address and address not in sample_senders:
            sample_senders.append(address)
        if len(sample_senders) >= 5:
            break

    identity = identity or (sorted_emails[0].subscription_identity if sorted_emails else None)
    return SenderStats(
        domain=domain,
        total_emails=total,
        seen_emails=seen,
        first_seen=min(dates) if dates else None,
        last_seen=max(dates) if dates else None,
        sample_subjects=sample_subjects,
        sample_senders=sample_senders,
        has_unsubscribe=any(header.list_unsubscribe_targets for header in emails),
        list_id=_most_common(header.list_id for header in emails),
        bulk_precedence=any(header.is_bulk_precedence for header in emails),
        auto_submitted=any(header.is_auto_submitted for header in emails),
        has_feedback_id=any(header.feedback_id for header in emails),
        esp_name=_most_common(header.esp for header in emails),
        return_path_mismatch=any(header.return_path_mismatch for header in emails),
        dkim_pass=_agg_verdict(header.dkim_pass for header in emails),
        spf_pass=_agg_verdict(header.spf_pass for header in emails),
        dmarc_pass=_agg_verdict(header.dmarc_pass for header in emails),
        account_key=identity.account_key if identity else None,
        identity_kind=identity.kind if identity else None,
        identity_value=identity.value if identity else None,
        inbox_emails=sum(header.mailbox_role == "inbox" for header in emails),
        junk_emails=sum(header.mailbox_role == "junk" for header in emails),
        junk_keyword_emails=sum(header.server_junk for header in emails),
        not_junk_emails=sum(header.server_not_junk for header in emails),
        phishing_emails=sum(header.server_phishing for header in emails),
        can_unsubscribe_emails=sum(header.server_can_unsubscribe for header in emails),
        authenticated_emails=sum(
            header.authentication.trusted
            and (
                header.authentication.dmarc is AuthResult.PASS
                or has_aligned_dkim_pass(header.authentication, header.domain)
            )
            for header in emails
        ),
        authentication_failed_emails=sum(
            header.strongly_failed_authentication for header in emails
        ),
        authentication_unknown_emails=sum(header.authentication_unknown for header in emails),
        provider_bulk_emails=sum(header.provider_bulk for header in emails),
        provider_threat=any(header.provider_threat for header in emails),
    )


def scan_inbox(
    config: Config,
    account_names: list[str] | None = None,
    on_account_start: "Callable[[str, str, int, int], None] | None" = None,
    on_account_error: "Callable[[str, str, str], None] | None" = None,
    persist: bool = True,
    full_history: bool = False,
    rescan: bool = False,
) -> ScanResult:
    """
    Scan inbox for marketing emails and aggregate by sender domain.
    Returns a ScanResult containing sender stats and cached email headers.

    If account_names is provided, scans only those accounts.
    Otherwise, scans ALL configured accounts.

    Args:
        config: The configuration object
        account_names: Optional list of account names to scan
        on_account_start: Optional callback(email, name, current, total) called when starting each account
        on_account_error: Optional callback(email, name, error) called when an account fails
        persist: When False (dry-run), no scan state or message data is written.
        full_history: Ignore the cursor and scan every UID in selected mailboxes.
        rescan: Ignore the cursor and repeat the configured lookback only.
    """
    if full_history and rescan:
        raise ValueError("full_history and rescan are mutually exclusive")
    # Determine which accounts to scan
    if account_names:
        accounts_to_scan = []
        for name in account_names:
            account = config.get_account(name)
            if not account:
                raise ValueError(f"Account not found: {name}")
            accounts_to_scan.append((name, account))
    else:
        if not config.accounts:
            raise ValueError("No accounts configured")
        accounts_to_scan = list(config.accounts.items())

    # Aggregate all locally scanned headers. Domain summaries remain for
    # backward-compatible reporting; subscription identity is authoritative.
    domain_emails: dict[str, list[EmailHeader]] = defaultdict(list)
    all_headers: list[EmailHeader] = []
    total_accounts = len(accounts_to_scan)

    for idx, (account_name, account) in enumerate(accounts_to_scan, 1):
        # Notify progress callback
        if on_account_start:
            on_account_start(account.email, account_name, idx, total_accounts)

        account_key = account.email.casefold()
        account_batches: list[_MailboxBatch] = []
        footer_scanned = 0
        try:
            with IMAPConnection(account) as conn:
                mailboxes: list[tuple[str, str]] = [("INBOX", "inbox")]
                discover = getattr(conn, "discover_mailboxes", None)
                if callable(discover) and getattr(config, "scan_junk", True):
                    discovered = discover(junk_override=getattr(account, "junk_mailbox", None))
                    if isinstance(discovered, MailboxDiscovery):
                        if discovered.junk is not None and discovered.junk.selectable:
                            if discovered.junk.wire_name.casefold() != "inbox":
                                mailboxes.append((discovered.junk.wire_name, "junk"))
                        elif discovered.junk_is_ambiguous:
                            logger.warning(
                                "Multiple SPECIAL-USE Junk mailboxes for %s; configure junk_mailbox",
                                account.email,
                            )
                        for discovery_error in discovered.errors:
                            logger.info(
                                "Mailbox discovery note for %s: %s",
                                account.email,
                                discovery_error,
                            )
                for extra in getattr(account, "extra_scan_mailboxes", ()) or ():
                    if extra.casefold() != "inbox" and all(
                        extra.casefold() != name.casefold() for name, _ in mailboxes
                    ):
                        mailboxes.append((extra, "custom"))

                for mailbox_name, role in mailboxes:
                    try:
                        state = db.get_mailbox_state(account_key, mailbox_name)
                        use_cursor = not full_history and not rescan and state is not None
                        since_uid: int | None = None
                        expected_uidvalidity: int | None = None
                        if use_cursor and state is not None:
                            if state.get("scan_complete"):
                                since_uid = int(state["last_uid"])
                            if state.get("uidvalidity") is not None:
                                expected_uidvalidity = int(state["uidvalidity"])
                        fetched = conn.fetch_marketing_emails(
                            days=config.scan_days,
                            folder=mailbox_name,
                            mailbox_role=role,
                            since_uid=since_uid,
                            expected_uidvalidity=expected_uidvalidity,
                            full_history=full_history,
                        )
                        headers = list(fetched)
                        for header in headers:
                            header.account_name = account_name
                            header.account_key = account_key
                            if (
                                getattr(config, "footer_scan_enabled", False)
                                and footer_scanned < MAX_MESSAGES_PER_ACCOUNT
                                and _footer_eligible(header)
                            ):
                                footer_scanned += 1
                                try:
                                    header.footer_unsubscribe_candidates = (
                                        conn.fetch_footer_candidates(header)
                                    )
                                except (IMAPError, OSError, ValueError) as footer_error:
                                    logger.info(
                                        "Footer scan skipped for %s/%s/%s: %s",
                                        account.email,
                                        mailbox_name,
                                        header.uid,
                                        footer_error,
                                    )
                            domain_emails[header.domain].append(header)
                            all_headers.append(header)

                        fetch_complete_value = getattr(conn, "last_fetch_complete", True)
                        fetch_complete = (
                            fetch_complete_value if isinstance(fetch_complete_value, bool) else True
                        )
                        uidvalidity_value = getattr(conn, "last_fetch_uidvalidity", None)
                        uidvalidity = (
                            uidvalidity_value
                            if isinstance(uidvalidity_value, int)
                            and not isinstance(uidvalidity_value, bool)
                            else next(
                                (
                                    header.uidvalidity
                                    for header in headers
                                    if header.uidvalidity is not None
                                ),
                                expected_uidvalidity,
                            )
                        )
                        high_water_value = getattr(conn, "last_fetch_highest_uid", 0)
                        high_water_uid = (
                            high_water_value
                            if isinstance(high_water_value, int)
                            and not isinstance(high_water_value, bool)
                            else 0
                        )
                        if high_water_uid <= 0:
                            high_water_uid = max(
                                (header.uid or 0 for header in headers),
                                default=int(state["last_uid"]) if state else 0,
                            )
                        account_batches.append(
                            _MailboxBatch(
                                mailbox_name,
                                role,
                                headers,
                                uidvalidity,
                                high_water_uid,
                                fetch_complete,
                            )
                        )
                    except (IMAPError, OSError) as error:
                        logger.warning(
                            "Failed to scan mailbox %s for %s: %s",
                            mailbox_name,
                            account.email,
                            error,
                        )
                        if role == "inbox":
                            raise
        except (IMAPError, OSError) as e:
            logger.warning("Failed to scan %s: %s", account.email, e)
            if on_account_error:
                on_account_error(account.email, account_name, str(e))

        if persist:
            complete_headers = [
                header
                for batch in account_batches
                if batch.complete and batch.uidvalidity is not None
                for header in batch.headers
            ]
            aliases = _aliases_with_stored_promotions(complete_headers)
            for batch in account_batches:
                if not batch.complete or batch.uidvalidity is None:
                    logger.warning(
                        "Not checkpointing incomplete mailbox scan %s for %s",
                        batch.name,
                        account.email,
                    )
                    continue
                # Persist all real messages first.  Only after those idempotent
                # writes complete is it safe to advance past their UIDs.
                _persist_headers(account_key, batch.headers, aliases, complete_headers)
                db.upsert_mailbox_state(
                    account_key,
                    batch.name,
                    batch.role,
                    uidvalidity=batch.uidvalidity,
                    last_uid=batch.high_water_uid,
                    scan_complete=True,
                    allow_uid_regression=full_history,
                )

    aliases = _aliases_with_stored_promotions(all_headers)
    subscription_emails: dict[str, list[EmailHeader]] = defaultdict(list)
    for header in all_headers:
        subscription_emails[_effective_identity(header, aliases).key].append(header)

    sender_stats = {
        domain: _stats_for_emails(domain, emails) for domain, emails in domain_emails.items()
    }
    subscription_stats = {
        key: _stats_for_emails(
            emails[0].domain,
            emails,
            _effective_identity(emails[0], aliases),
        )
        for key, emails in subscription_emails.items()
        if emails
    }

    if persist:
        for domain, stats in sender_stats.items():
            db.upsert_sender(
                domain=domain,
                total_emails=stats.total_emails,
                seen_emails=stats.seen_emails,
                sample_subjects=stats.sample_subjects,
                has_unsubscribe=stats.has_unsubscribe,
                first_seen=stats.first_seen,
                last_seen=stats.last_seen,
            )

    return ScanResult(
        sender_stats,
        dict(domain_emails),
        subscription_stats,
        dict(subscription_emails),
    )


def get_emails_for_domain(
    config: Config, domain: str, account_name: str | None = None
) -> list[EmailHeader]:
    """Get all marketing emails for a specific domain."""
    if account_name:
        account = config.get_account(account_name)
        if not account:
            raise ValueError("No account configured")
        accounts_to_scan = [(account_name, account)]
    else:
        accounts_to_scan = list(config.accounts.items())
        if not accounts_to_scan:
            raise ValueError("No account configured")

    emails = []
    for name, account in accounts_to_scan:
        if not account:
            continue
        with IMAPConnection(account) as conn:
            for header in conn.fetch_marketing_emails(days=config.scan_days):
                if header.domain == domain:
                    # Track the account so mailto unsubscribes use the right
                    # SMTP credentials.
                    header.account_name = name
                    emails.append(header)

    return emails
