"""Data models for nothx."""

import email.utils
import hashlib
import re
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum

# RFC 2369: List-Unsubscribe contains one or more angle-bracket-enclosed URIs.
# Match bracket groups rather than splitting on commas, which appear inside URLs.
_UNSUB_TARGET_RE = re.compile(r"<([^>]*)>")

_ALLOWED_UNSUB_SCHEMES = ("https://", "http://", "mailto:")
_LIST_ID_RE = re.compile(r"^[A-Za-z0-9!#$%&'*+\-/=?^_`{|}~.]{1,255}$")


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


class AuthResult(Enum):
    """A complete Authentication-Results method verdict."""

    PASS = "pass"
    FAIL = "fail"
    SOFTFAIL = "softfail"
    NEUTRAL = "neutral"
    NONE = "none"
    TEMPERROR = "temperror"
    PERMERROR = "permerror"
    POLICY = "policy"
    UNKNOWN = "unknown"


class UnsubscribeOutcome(Enum):
    """Grouped outcome for a subscription-level unsubscribe operation."""

    REQUESTED = "requested"
    NEEDS_USER = "needs_user"
    VERIFIED_QUIET = "verified_quiet"
    INEFFECTIVE = "ineffective"
    FAILED = "failed"
    BLOCKED = "blocked"


class MailboxActionOutcome(Enum):
    """Result of applying a mailbox-side spam action."""

    FLAGGED = "flagged"
    MOVED = "moved"
    PARTIAL = "partial"
    ALREADY_JUNK = "already_junk"
    NOT_FOUND = "not_found"
    FAILED = "failed"


@dataclass(frozen=True)
class SubscriptionIdentity:
    """Stable account-scoped identity for one mailing list/subscription."""

    account_key: str
    kind: str
    value: str

    @property
    def key(self) -> str:
        material = f"{self.account_key.casefold()}\0{self.kind}\0{self.value.casefold()}"
        return hashlib.sha256(material.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class MessageRef:
    """Stable IMAP locator. A UID is meaningful only with its UIDVALIDITY."""

    account_key: str
    mailbox: str
    uidvalidity: int
    uid: int


@dataclass(frozen=True)
class MailboxInfo:
    """A decoded IMAP mailbox and its advertised SPECIAL-USE attributes."""

    name: str
    wire_name: str
    delimiter: str | None = None
    attributes: tuple[str, ...] = ()
    selectable: bool = True

    @property
    def is_junk(self) -> bool:
        return any(value.casefold() == r"\junk" for value in self.attributes)


@dataclass(frozen=True)
class FooterUnsubscribeCandidate:
    """Locally inferred footer target; never eligible for RFC 8058 POST."""

    uri: str
    source: str
    evidence: str = ""


@dataclass(frozen=True)
class AuthenticationResultEvidence:
    """One method result with identifiers kept on the same result instance."""

    method: str
    result: AuthResult
    identifier: str | None = None
    domain: str | None = None
    selector: str | None = None


@dataclass(frozen=True)
class AuthenticationEvidence:
    """Structured, provider-trusted authentication evidence for one message."""

    spf: AuthResult = AuthResult.UNKNOWN
    dkim: AuthResult = AuthResult.UNKNOWN
    dmarc: AuthResult = AuthResult.UNKNOWN
    arc: AuthResult = AuthResult.UNKNOWN
    dkim_domains: tuple[str, ...] = ()
    dkim_selectors: tuple[str, ...] = ()
    results: tuple[AuthenticationResultEvidence, ...] = ()
    trusted: bool = False


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
    account_key: str | None = None  # Normalized mailbox address; stable across config renames
    # Immutable server delivery time from IMAP INTERNALDATE. RFC 5322 Date is
    # sender-controlled and must remain display/ordering data only.
    received_at: datetime | None = None
    # Bulk/marketing signals (headers only — see RFC 2919/3834/8601)
    list_id: str | None = None
    precedence: str | None = None
    auto_submitted: str | None = None
    feedback_id: str | None = None
    return_path: str | None = None
    esp: str | None = None  # detected ESP fingerprint, e.g. "sendgrid"
    dkim_pass: bool | None = None
    spf_pass: bool | None = None
    dmarc_pass: bool | None = None
    # Stable mailbox locator and server-side verdicts.
    mailbox_name: str = "INBOX"
    mailbox_role: str = "inbox"  # "inbox", "junk", or "custom"
    uid: int | None = None
    uidvalidity: int | None = None
    system_flags: tuple[str, ...] = ()
    keywords: tuple[str, ...] = ()
    gmail_labels: tuple[str, ...] = ()
    provider_threat: str | None = None
    provider_bulk: bool = False
    authentication: AuthenticationEvidence = field(default_factory=AuthenticationEvidence)
    dkim_covers_unsubscribe: bool = False
    list_unsubscribe_count: int = 0
    list_unsubscribe_post_count: int = 0
    footer_unsubscribe_candidates: tuple[FooterUnsubscribeCandidate, ...] = ()
    footer_requires_user: bool = False

    @property
    def is_bulk_precedence(self) -> bool:
        return (self.precedence or "").strip().lower() in ("bulk", "junk", "list")

    @property
    def is_auto_submitted(self) -> bool:
        value = (self.auto_submitted or "").strip().lower()
        return bool(value) and value != "no"

    @property
    def server_junk(self) -> bool:
        flags = {value.casefold() for value in (*self.system_flags, *self.keywords)}
        labels = {value.casefold() for value in self.gmail_labels}
        return (
            self.mailbox_role == "junk"
            or "$junk" in flags
            or "\\junk" in flags
            or bool(labels & {"spam", "junk", "\\spam", "\\junk", "$junk"})
        )

    @property
    def server_not_junk(self) -> bool:
        flags = {value.casefold() for value in (*self.system_flags, *self.keywords)}
        labels = {value.casefold() for value in self.gmail_labels}
        return "$notjunk" in flags or bool(labels & {"notjunk", "\\notjunk", "$notjunk"})

    @property
    def server_phishing(self) -> bool:
        flags = {value.casefold() for value in (*self.system_flags, *self.keywords)}
        return "$phishing" in flags or bool(self.provider_threat)

    @property
    def server_can_unsubscribe(self) -> bool:
        return "$canunsubscribe" in {
            value.casefold() for value in (*self.system_flags, *self.keywords)
        }

    @property
    def strongly_failed_authentication(self) -> bool:
        """True only for a trusted, unmitigated failure of every alignment path."""
        evidence = self.authentication
        return (
            evidence.trusted
            and evidence.arc is not AuthResult.PASS
            and evidence.dkim is AuthResult.FAIL
            and evidence.spf is AuthResult.FAIL
            and evidence.dmarc is AuthResult.FAIL
        )

    @property
    def authentication_unknown(self) -> bool:
        evidence = self.authentication
        if not evidence.trusted:
            return True
        known = {AuthResult.PASS, AuthResult.FAIL, AuthResult.SOFTFAIL, AuthResult.NEUTRAL}
        return not any(result in known for result in (evidence.dkim, evidence.spf, evidence.dmarc))

    @property
    def return_path_mismatch(self) -> bool:
        """True if Return-Path domain differs from the From domain (ESP/VERP)."""
        if not self.return_path:
            return False
        rp = self.return_path.strip().strip("<>").lower()
        if "@" not in rp:
            return False
        rp_domain = rp.rsplit("@", 1)[1]
        from_domain = self.domain
        if from_domain == "unknown" or not rp_domain:
            return False
        return rp_domain != from_domain

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

    @property
    def normalized_list_id(self) -> str | None:
        """Return the RFC 2919 identifier inside angle brackets."""
        if not self.list_id:
            return None
        match = re.search(r"<\s*([^<>\s]+)\s*>", self.list_id)
        if not match:
            return None
        value = match.group(1).casefold()
        if "." not in value or not _LIST_ID_RE.fullmatch(value):
            return None
        return value

    @property
    def subscription_identity(self) -> SubscriptionIdentity:
        account = (self.account_key or self.account_name or "unknown").casefold()
        if list_id := self.normalized_list_id:
            return SubscriptionIdentity(account, "list_id", list_id)
        address = self.sender_address or self.domain
        return SubscriptionIdentity(account, "from", address.casefold())

    @property
    def message_ref(self) -> MessageRef | None:
        account = self.account_key or self.account_name
        if self.uid is None or self.uidvalidity is None or not account:
            return None
        return MessageRef(account.casefold(), self.mailbox_name, self.uidvalidity, self.uid)

    @property
    def has_compliant_one_click(self) -> bool:
        """Whether header syntax and server/DKIM evidence permit RFC 8058 POST."""
        exact_post = (self.list_unsubscribe_post or "").strip().casefold()
        unsubscribe_url = self.list_unsubscribe_url
        return (
            self.list_unsubscribe_count == 1
            and self.list_unsubscribe_post_count == 1
            and exact_post == "list-unsubscribe=one-click"
            and unsubscribe_url is not None
            and unsubscribe_url.lower().startswith("https://")
            and (self.server_can_unsubscribe or self.dkim_covers_unsubscribe)
        )


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
    # Aggregated bulk/marketing signals
    list_id: str | None = None
    bulk_precedence: bool = False
    auto_submitted: bool = False
    has_feedback_id: bool = False
    esp_name: str | None = None
    return_path_mismatch: bool = False
    dkim_pass: bool | None = None
    spf_pass: bool | None = None
    dmarc_pass: bool | None = None
    account_key: str | None = None
    identity_kind: str | None = None
    identity_value: str | None = None
    inbox_emails: int = 0
    junk_emails: int = 0
    junk_keyword_emails: int = 0
    not_junk_emails: int = 0
    phishing_emails: int = 0
    can_unsubscribe_emails: int = 0
    authenticated_emails: int = 0
    authentication_failed_emails: int = 0
    authentication_unknown_emails: int = 0
    provider_bulk_emails: int = 0
    provider_threat: bool = False

    @property
    def open_rate(self) -> float:
        """Calculate open rate as percentage."""
        if self.total_emails == 0:
            return 0.0
        return (self.seen_emails / self.total_emails) * 100

    @property
    def classification_key(self) -> str:
        if self.account_key and self.identity_kind and self.identity_value:
            return SubscriptionIdentity(
                self.account_key, self.identity_kind, self.identity_value
            ).key
        return self.domain


@dataclass
class Classification:
    """Result of classifying an email/sender."""

    email_type: EmailType
    action: Action
    confidence: float
    reasoning: str
    source: str  # "user_rule", "preset", "ai", "heuristics", "uncertain"
    # AI's preference recommendation remains distinct when executable policy
    # safely transforms it (for example, UNSUB -> REVIEW on unknown auth).
    recommended_action: Action | None = None
    original_source: str | None = None


@dataclass
class UnsubscribeAttemptResult:
    """A redacted, persistable endpoint-attempt result."""

    method: UnsubMethod
    outcome: str
    endpoint_fingerprint: str
    target_display: str
    http_status: int | None = None
    error_code: str | None = None
    ambiguous_send: bool = False
    message_ref: MessageRef | None = None


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
    outcome: UnsubscribeOutcome | None = None
    target_display: str | None = None
    attempts: int = 1
    attempt_results: tuple[UnsubscribeAttemptResult, ...] = ()


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
