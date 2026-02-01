"""Email scanning and sender aggregation for nothx."""

from collections import defaultdict

from . import db
from .config import Config
from .imap import IMAPConnection
from .models import EmailHeader, SenderStats


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


def scan_inbox(config: Config, account_names: list[str] | None = None) -> ScanResult:
    """
    Scan inbox for marketing emails and aggregate by sender domain.
    Returns a ScanResult containing sender stats and cached email headers.

    If account_names is provided, scans only those accounts.
    Otherwise, scans ALL configured accounts.
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

    for account_name, account in accounts_to_scan:
        with IMAPConnection(account) as conn:
            for header in conn.fetch_marketing_emails(days=config.scan_days):
                # Track which account this email came from (for mailto unsubscribes)
                header.account_name = account_name
                domain_emails[header.domain].append(header)

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
    account = config.get_account(account_name)
    if not account:
        raise ValueError("No account configured")

    emails = []
    with IMAPConnection(account) as conn:
        for header in conn.fetch_marketing_emails(days=config.scan_days):
            if header.domain == domain:
                emails.append(header)

    return emails
