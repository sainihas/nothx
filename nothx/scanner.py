"""Email scanning and sender aggregation for nothx."""

import logging
from collections import defaultdict
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Callable

from . import db
from .config import Config
from .errors import IMAPError
from .imap import IMAPConnection
from .models import EmailHeader, SenderStats

logger = logging.getLogger(__name__)


class ScanResult:
    """Result of scanning inbox, containing stats and cached email headers."""

    def __init__(
        self, sender_stats: dict[str, SenderStats], domain_emails: dict[str, list[EmailHeader]]
    ):
        self.sender_stats = sender_stats
        self.domain_emails = domain_emails

    def get_email_for_domain(self, domain: str) -> EmailHeader | None:
        """Get a sample email with unsubscribe header for a domain."""
        emails = self.domain_emails.get(domain, [])
        # Prefer emails with unsubscribe links
        for email in emails:
            if email.list_unsubscribe:
                return email
        return emails[0] if emails else None


def scan_inbox(
    config: Config,
    account_names: list[str] | None = None,
    on_account_start: "Callable[[str, str, int, int], None] | None" = None,
    on_account_error: "Callable[[str, str, str], None] | None" = None,
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
    """
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

    # Aggregate emails by domain across all accounts
    domain_emails: dict[str, list[EmailHeader]] = defaultdict(list)
    total_accounts = len(accounts_to_scan)

    for idx, (account_name, account) in enumerate(accounts_to_scan, 1):
        # Notify progress callback
        if on_account_start:
            on_account_start(account.email, account_name, idx, total_accounts)

        try:
            with IMAPConnection(account) as conn:
                for header in conn.fetch_marketing_emails(days=config.scan_days):
                    # Track which account this email came from (for mailto unsubscribes)
                    header.account_name = account_name
                    domain_emails[header.domain].append(header)
        except (IMAPError, OSError) as e:
            logger.warning("Failed to scan %s: %s", account.email, e)
            if on_account_error:
                on_account_error(account.email, account_name, str(e))

    # Convert to SenderStats
    sender_stats: dict[str, SenderStats] = {}

    for domain, emails in domain_emails.items():
        total = len(emails)
        seen = sum(1 for e in emails if e.is_seen)

        # Get date range
        dates = [e.date for e in emails]
        first_seen = min(dates) if dates else None
        last_seen = max(dates) if dates else None

        # Get sample subjects (most recent)
        sorted_emails = sorted(emails, key=lambda e: e.date, reverse=True)
        sample_subjects = [e.subject for e in sorted_emails[:5]]

        # Check if any have unsubscribe links
        has_unsub = any(e.list_unsubscribe for e in emails)

        stats = SenderStats(
            domain=domain,
            total_emails=total,
            seen_emails=seen,
            first_seen=first_seen,
            last_seen=last_seen,
            sample_subjects=sample_subjects,
            has_unsubscribe=has_unsub,
        )
        sender_stats[domain] = stats

        # Update database
        db.upsert_sender(
            domain=domain,
            total_emails=total,
            seen_emails=seen,
            sample_subjects=sample_subjects,
            has_unsubscribe=has_unsub,
            first_seen=first_seen,
            last_seen=last_seen,
        )

    return ScanResult(sender_stats, dict(domain_emails))


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
    for _, account in accounts_to_scan:
        if not account:
            continue
        with IMAPConnection(account) as conn:
            for header in conn.fetch_marketing_emails(days=config.scan_days):
                if header.domain == domain:
                    emails.append(header)

    return emails
