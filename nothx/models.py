"""Data models for nothx."""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional


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
    list_unsubscribe: Optional[str] = None
    list_unsubscribe_post: Optional[str] = None
    x_mailer: Optional[str] = None
    is_seen: bool = False

    @property
    def domain(self) -> str:
        """Extract domain from sender email."""
        if "<" in self.sender:
            email = self.sender.split("<")[1].rstrip(">")
        else:
            email = self.sender
        return email.split("@")[-1].lower()

    @property
    def list_unsubscribe_url(self) -> Optional[str]:
        """Extract HTTPS URL from List-Unsubscribe header."""
        if not self.list_unsubscribe:
            return None
        for part in self.list_unsubscribe.split(","):
            part = part.strip().strip("<>")
            if part.startswith("https://") or part.startswith("http://"):
                return part
        return None

    @property
    def list_unsubscribe_mailto(self) -> Optional[str]:
        """Extract mailto from List-Unsubscribe header."""
        if not self.list_unsubscribe:
            return None
        for part in self.list_unsubscribe.split(","):
            part = part.strip().strip("<>")
            if part.startswith("mailto:"):
                return part
        return None


@dataclass
class SenderStats:
    """Statistics about a sender."""
    domain: str
    total_emails: int = 0
    seen_emails: int = 0
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    sample_subjects: list[str] = field(default_factory=list)
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
    method: Optional[UnsubMethod]
    http_status: Optional[int] = None
    error: Optional[str] = None
    response_snippet: Optional[str] = None


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
