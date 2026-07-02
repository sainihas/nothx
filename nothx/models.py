"""Data models for nothx."""

import email.utils
import re
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum

# RFC 2369: List-Unsubscribe contains one or more angle-bracket-enclosed URIs.
# Match bracket groups rather than splitting on commas, which appear inside URLs.
_UNSUB_TARGET_RE = re.compile(r"<([^>]*)>")

_ALLOWED_UNSUB_SCHEMES = ("https://", "http://", "mailto:")


class EmailType(Enum):
    """Types of emails that can be classified."""

    MARKETING = "marketing"
    TRANSACTIONAL = "transactional"
    SECURITY = "security"
    NEWSLETTER = "newsletter"
    COLD_OUTREACH = "cold_outreach"
    UNKNOWN = "unknown"


class Action(Enum):
    """Actions that can be taken on an email sender."""

    KEEP = "keep"
    UNSUB = "unsub"
    BLOCK = "block"
    REVIEW = "review"


class SenderStatus(Enum):
    """Status of a sender in the database."""

    UNKNOWN = "unknown"
    KEEP = "keep"
    UNSUBSCRIBED = "unsubscribed"
    BLOCKED = "blocked"
    FAILED = "failed"


class UnsubMethod(Enum):
    """Methods for unsubscribing."""

    ONE_CLICK = "one-click"
    GET = "get"
    MAILTO = "mailto"


@dataclass
class EmailHeader:
    """Represents email header information."""

    sender: str
    subject: str
    date: datetime
    message_id: str
    list_unsubscribe: str | None = None
    list_unsubscribe_post: str | None = None
    x_mailer: str | None = None
    is_seen: bool = False
    account_name: str | None = None  # Track which account this email came from

    @property
    def sender_address(self) -> str:
        """Extract the addr-spec from the From header, or '' if invalid."""
        try:
            _, addr = email.utils.parseaddr(self.sender)
            if not addr:
                # parseaddr rejects malformed input like '<a@b.com> extra';
                # retry on just the angle-bracket group so protected-domain
                # checks still see the real domain.
                match = re.search(r"<([^>]*)>", self.sender or "")
                if match:
                    _, addr = email.utils.parseaddr(match.group(1))
        except (TypeError, AttributeError):
            return ""
        addr = addr.lower().strip()
        if "@" not in addr:
            return ""
        domain = addr.rsplit("@", 1)[1]
        if (
            not domain
            or " " in domain
            or "." not in domain
            or domain.startswith(".")
            or domain.endswith(".")
        ):
            return ""
        return addr

    @property
    def domain(self) -> str:
        """Extract domain from sender email.

        Returns the domain part of the email address, or 'unknown' if invalid.
        """
        addr = self.sender_address
        if not addr:
            return "unknown"
        return addr.rsplit("@", 1)[1]

    @property
    def list_unsubscribe_targets(self) -> list[str]:
        """All URIs from List-Unsubscribe, in RFC 2369 preference order.

        Extracts angle-bracket groups (URLs may contain commas, and comments
        may appear between entries), strips whitespace introduced by header
        folding, and keeps only http(s)/mailto URIs.
        """
        if not self.list_unsubscribe:
            return []
        raw_uris = _UNSUB_TARGET_RE.findall(self.list_unsubscribe)
        if not raw_uris:
            # Non-compliant senders sometimes omit the angle brackets entirely
            raw_uris = [self.list_unsubscribe]
        targets = []
        for raw in raw_uris:
            uri = "".join(raw.split())  # folded headers leave WSP/CRLF inside
            if uri.lower().startswith(_ALLOWED_UNSUB_SCHEMES):
                targets.append(uri)
        return targets

    @property
    def list_unsubscribe_url(self) -> str | None:
        """First http(s) URL from List-Unsubscribe, if any."""
        for uri in self.list_unsubscribe_targets:
            if uri.lower().startswith(("https://", "http://")):
                return uri
        return None

    @property
    def list_unsubscribe_mailto(self) -> str | None:
        """First mailto URI from List-Unsubscribe, if any."""
        for uri in self.list_unsubscribe_targets:
            if uri.lower().startswith("mailto:"):
                return uri
        return None


@dataclass
class SenderStats:
    """Statistics about a sender."""

    domain: str
    total_emails: int = 0
    seen_emails: int = 0
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    sample_subjects: list[str] = field(default_factory=list)
    sample_senders: list[str] = field(default_factory=list)
    has_unsubscribe: bool = False

    @property
    def open_rate(self) -> float:
        """Calculate open rate as percentage."""
        if self.total_emails == 0:
            return 0.0
        return (self.seen_emails / self.total_emails) * 100


@dataclass
class Classification:
    """Result of classifying an email/sender."""

    email_type: EmailType
    action: Action
    confidence: float
    reasoning: str
    source: str  # "user_rule", "preset", "ai", "heuristics", "uncertain"


@dataclass
class UnsubResult:
    """Result of an unsubscribe attempt."""

    success: bool
    method: UnsubMethod | None
    http_status: int | None = None
    error: str | None = None
    response_snippet: str | None = None
    # The endpoint responded with a page that requires further interaction
    # (e.g. "click to confirm") — not a success, but worth surfacing.
    needs_confirmation: bool = False


@dataclass
class RunStats:
    """Statistics from a single run."""

    ran_at: datetime
    mode: str
    emails_scanned: int = 0
    unique_senders: int = 0
    auto_unsubbed: int = 0
    kept: int = 0
    review_queued: int = 0
    failed: int = 0


@dataclass
class UserAction:
    """A user's decision on a sender, used for learning."""

    domain: str
    action: Action
    timestamp: datetime
    ai_recommendation: Action | None = None
    heuristic_score: int | None = None
    open_rate: float | None = None
    email_count: int | None = None

    @property
    def was_correction(self) -> bool:
        """Check if this action differed from AI recommendation."""
        return self.ai_recommendation is not None and self.action != self.ai_recommendation


@dataclass
class UserPreference:
    """A learned user preference for classification."""

    feature: str  # e.g., "open_rate_weight", "keyword:bank", "volume_threshold"
    value: float
    confidence: float
    sample_count: int
    last_updated: datetime
    source: str = "learned"  # "learned", "ai", "default"
