"""Refresh saved account/list sources for the interactive resolution workflow."""

from typing import Any

from . import db
from .config import Config
from .imap import IMAPConnection
from .models import EmailHeader, MessageRef, SenderStats, SubscriptionIdentity
from .scanner import _footer_eligible, _stats_for_emails


def refresh_sources(
    config: Config, subscription: dict[str, Any], *, source_uid: int | None = None
) -> tuple[SenderStats, list[EmailHeader]]:
    """Revalidate up to 50 stored Inbox refs; inspect at most three footer tails.

    Stored history is a locator index, never authority to contact an endpoint.
    UIDVALIDITY, UID, Message-ID, From and list identity must still match.
    """
    entry = next(
        (
            (name, account)
            for name, account in config.accounts.items()
            if account.email.casefold() == subscription["account"].casefold()
        ),
        None,
    )
    if entry is None:
        raise ValueError("The matching configured account is unavailable")
    name, account = entry
    refs = db.list_message_refs(
        subscription_id=subscription["id"],
        mailbox_role="inbox",
        limit=50,
        prioritize_methods=True,
        source_uid=source_uid,
    )
    if source_uid is None:
        # Reserve space for fresh tokens even when many old promotional refs
        # rank ahead of recent service-like subjects in the discovery shortlist.
        newest = db.list_message_refs(
            subscription_id=subscription["id"], mailbox_role="inbox", limit=3
        )
        refs = list({ref["id"]: ref for ref in [*newest, *refs]}.values())[:50]
    headers: list[EmailHeader] = []
    with IMAPConnection(account) as connection:
        for ref in refs:
            locator = MessageRef(ref["account"], ref["mailbox"], ref["uidvalidity"], ref["uid"])
            header = connection.fetch_header(locator)
            if header is None:
                continue
            if (
                (header.message_id or None) != (ref["message_id"] or None)
                or header.sender_address.casefold() != (ref["from_address"] or "").casefold()
                or header.normalized_list_id != (ref["list_id"] or None)
            ):
                raise ValueError("Stored source identity changed; run a full scan")
            identity = header.subscription_identity
            exact = (identity.kind, identity.value) == (
                subscription["identity_kind"],
                subscription["identity_value"],
            )
            promoted = (
                identity.kind == "from"
                and subscription.get("promoted_from_kind") == "from"
                and identity.value == subscription.get("promoted_from_value")
            )
            aliased = (
                identity.kind == "from"
                and subscription["identity_kind"] == "list_id"
                and identity.value == (subscription.get("from_address") or "").casefold()
            )
            if not (exact or promoted or aliased):
                raise ValueError(
                    "Stored source belongs to a different subscription; run a full scan"
                )
            header.account_name = name
            headers.append(header)
        headers.sort(key=lambda h: h.received_at or h.date, reverse=True)
        # A targeted resolution can recover footer alternatives even when an
        # unusable header method was present. Consent and admission still apply.
        if config.footer_scan_enabled:
            eligible = [
                header for header in headers if _footer_eligible(header, allow_header_method=True)
            ]
            # Prefer sources already carrying a method, then newest sources.
            eligible.sort(key=lambda h: bool(h.list_unsubscribe_targets), reverse=True)
            for header in eligible[:3]:
                header.footer_unsubscribe_candidates = connection.fetch_footer_candidates(header)
    if not headers:
        raise ValueError("No stored Inbox sources remain; run `nothx cleanup` first")
    identity = SubscriptionIdentity(
        subscription["account"], subscription["identity_kind"], subscription["identity_value"]
    )
    stats = _stats_for_emails(headers[0].domain, headers, identity)
    return stats, headers
