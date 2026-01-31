"""Email scanning and sender aggregation for nothx."""

from collections import defaultdict
from datetime import datetime
from typing import Optional

from .config import Config
from .imap import IMAPConnection
from .models import EmailHeader, SenderStats
from . import db


def scan_inbox(config: Config, account_name: Optional[str] = None) -> dict[str, SenderStats]:
    """
    Scan inbox for marketing emails and aggregate by sender domain.
    Returns a dictionary mapping domain -> SenderStats.
    """
    account = config.get_account(account_name)
    if not account:
        raise ValueError("No account configured")

    # Aggregate emails by domain
    domain_emails: dict[str, list[EmailHeader]] = defaultdict(list)

    with IMAPConnection(account) as conn:
        for header in conn.fetch_marketing_emails(days=config.scan_days):
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

    return sender_stats


def get_emails_for_domain(
    config: Config,
    domain: str,
    account_name: Optional[str] = None
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
