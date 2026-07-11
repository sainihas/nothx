"""Configuration management for nothx."""

from __future__ import annotations

import json
import logging
import os
import stat
from dataclasses import asdict, dataclass, field
from pathlib import Path
from urllib.parse import urlparse

logger = logging.getLogger("nothx.config")

# The operator who runs nothx is its only user, and every mutating run already
# gates behind an interactive "Apply N actions?" confirmation (or an explicit
# --auto). Automation consent is therefore granted by default; the only way to
# turn it off is an explicit `nothx consent --revoke-*`, which stores the
# CONSENT_REVOKED sentinel. Any other value — including a legacy stored 0 from
# an earlier build, a missing key, or the current version — counts as granted.
CURRENT_UNSUBSCRIBE_CONSENT_VERSION = 1
CURRENT_MAILBOX_MUTATION_CONSENT_VERSION = 1
CONSENT_REVOKED = -1


def get_config_dir() -> Path:
    """Get the nothx config directory (owner-only permissions)."""
    config_dir = Path.home() / ".nothx"
    config_dir.mkdir(parents=True, exist_ok=True)
    # Restrict to owner: the dir holds credentials and the SQLite database.
    try:
        config_dir.chmod(stat.S_IRWXU)  # 0700
    except OSError:
        pass
    return config_dir


def get_config_path() -> Path:
    """Get the path to config.json."""
    return get_config_dir() / "config.json"


def get_db_path() -> Path:
    """Get the path to the SQLite database."""
    return get_config_dir() / "nothx.db"


@dataclass
class AccountConfig:
    """Configuration for an email account."""

    provider: str  # "gmail" or "outlook"
    email: str
    # Password remains the default so existing Gmail/Yahoo/iCloud and custom
    # provider configurations continue to load unchanged. OAuth accounts keep
    # this empty and store refresh credentials only in tokens.json.
    password: str = ""
    auth: str = "password"  # "password" or "oauth"
    client_id: str | None = None  # Microsoft public-client application ID
    junk_mailbox: str | None = None  # Explicit override when SPECIAL-USE is ambiguous
    extra_scan_mailboxes: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        """Normalize and validate the authentication selector."""
        self.auth = self.auth.strip().lower()
        if self.auth not in {"password", "oauth"}:
            raise ValueError(f"Unsupported account authentication method: {self.auth}")

    @property
    def uses_oauth(self) -> bool:
        """Return whether this account authenticates with OAuth2."""
        return self.auth == "oauth"


def validate_api_base(api_base: str | None) -> str | None:
    """Validate and sanitize API base URL.

    - Requires valid URL format
    - Enforces HTTPS for non-localhost URLs
    - Returns normalized URL or None

    Raises:
        ValueError: If URL is invalid or insecure.
    """
    if api_base is None:
        return None

    api_base = api_base.strip()
    if not api_base:
        return None

    try:
        parsed = urlparse(api_base)
    except ValueError as e:
        raise ValueError(f"Invalid API base URL: {e}") from e

    # Must have a scheme
    if not parsed.scheme:
        raise ValueError("API base URL must include scheme (http:// or https://)")

    # Must be http or https
    if parsed.scheme not in ("http", "https"):
        raise ValueError(f"API base URL must use http or https, not {parsed.scheme}")

    # Must have a host
    if not parsed.netloc:
        raise ValueError("API base URL must include a host")

    # For non-localhost, require HTTPS
    is_localhost = parsed.hostname in ("localhost", "127.0.0.1", "::1") or (
        parsed.hostname and parsed.hostname.endswith(".local")
    )
    if not is_localhost and parsed.scheme != "https":
        raise ValueError(f"API base URL must use HTTPS for non-localhost hosts. Got: {api_base}")

    return api_base


@dataclass
class AIConfig:
    """Configuration for AI features."""

    enabled: bool = True
    provider: str = "anthropic"  # "anthropic", "openai", "gemini", "ollama", or "none"
    api_key: str | None = None
    model: str = "claude-haiku-4-5"
    confidence_threshold: float = 0.80
    api_base: str | None = None  # Custom API endpoint (for Ollama or proxies)

    def __post_init__(self):
        """Validate configuration after initialization."""
        if self.api_base is not None:
            try:
                self.api_base = validate_api_base(self.api_base)
            except ValueError as e:
                logger.warning("Invalid api_base, ignoring: %s", e)
                self.api_base = None


@dataclass
class NotificationConfig:
    """Configuration for notifications."""

    enabled: bool = False
    on_unsubscribe: bool = False
    on_error: bool = True
    on_new_senders: bool = False
    digest_frequency: str = "never"  # "never", "weekly", "monthly"


@dataclass
class ScoringConfig:
    """Configuration for heuristic scoring weights and adjustments.

    All scores start at base_score (50 = neutral).
    Adjustments modify the score: positive = more likely spam, negative = more likely keep.
    Final score: 0-25 = keep, 25-75 = uncertain, 75-100 = unsub/block.
    """

    # Base score (neutral starting point)
    base_score: int = 50

    # Open rate adjustments
    open_rate_never_opened: int = 25  # 0% open rate with 5+ emails
    open_rate_very_low: int = 15  # <10% open rate
    open_rate_low: int = 5  # 10-25% open rate
    open_rate_moderate: int = -10  # 25-50% open rate
    open_rate_high: int = -20  # 50-75% open rate
    open_rate_very_high: int = -30  # >75% open rate

    # Volume adjustments
    volume_high: int = 10  # >50 emails
    volume_medium: int = 5  # 20-50 emails

    # Subject pattern adjustments
    subject_spam_pattern: int = 5  # Each spam pattern match
    subject_safe_pattern: int = -10  # Each safe/transactional pattern match
    subject_cold_outreach: int = 15  # Cold outreach patterns

    # Domain pattern adjustments
    domain_spam_pattern: int = 10  # Marketing/spam domain patterns
    domain_safe_pattern: int = -15  # Safe domain patterns (security@, etc.)

    # Other signals
    no_unsubscribe_link: int = -5  # Missing unsubscribe = slightly safer

    # Bulk/marketing header signals (RFC 2919/3834/8601, ESP fingerprints).
    # Capped in aggregate by bulk_signal_max so legitimate transactional-bulk
    # (SES receipts, alerts) isn't pushed past the unsub threshold.
    precedence_bulk: int = 10  # Precedence: bulk/junk/list
    auto_submitted: int = 5  # Auto-Submitted (also fires on some alerts)
    feedback_id_present: int = 8  # Gmail FBL header — high-volume ESP mail
    esp_fingerprint: int = 10  # Known ESP sending infrastructure
    list_id_present: int = 5  # RFC 2919 mailing-list identity
    return_path_mismatch: int = 5  # Return-Path/From mismatch (bulk, not spam)
    bulk_signal_max: int = 25  # Cap on the sum of the above bulk signals

    # Keyword boost limits from learning
    keyword_boost_max: int = 30  # Max absolute value for learned keyword boosts

    # Minimum emails to trust open rate at 0%
    min_emails_for_never_opened: int = 5


@dataclass
class ThresholdConfig:
    """Configuration for auto-decision thresholds."""

    unsub_confidence: float = 0.80
    keep_confidence: float = 0.80
    min_emails_before_action: int = 3

    # Heuristic score thresholds
    unsub_score_threshold: int = 75  # Score >= this = unsub/block
    keep_score_threshold: int = 25  # Score <= this = keep


@dataclass
class SafetyConfig:
    """Safety configuration."""

    never_unsub_domains: list[str] = field(default_factory=lambda: ["*.gov", "*bank*", "*health*"])
    always_confirm_domains: list[str] = field(default_factory=list)
    dry_run: bool = False


@dataclass
class Config:
    """Main configuration for nothx."""

    accounts: dict[str, AccountConfig] = field(default_factory=dict)
    default_account: str | None = None
    ai: AIConfig = field(default_factory=AIConfig)
    operation_mode: str = "hands_off"  # "hands_off", "notify", "confirm"
    notifications: NotificationConfig = field(default_factory=NotificationConfig)
    thresholds: ThresholdConfig = field(default_factory=ThresholdConfig)
    safety: SafetyConfig = field(default_factory=SafetyConfig)
    scoring: ScoringConfig = field(default_factory=ScoringConfig)
    scan_days: int = 30
    scan_junk: bool = True
    footer_scan_enabled: bool = False
    # Granted by default (see the CONSENT_REVOKED note above). Revoking stores
    # CONSENT_REVOKED; anything else — including the version constant — permits.
    unsubscribe_consent_version: int = CURRENT_UNSUBSCRIBE_CONSENT_VERSION
    mailbox_mutation_consent_version: int = CURRENT_MAILBOX_MUTATION_CONSENT_VERSION
    # Deprecated compatibility key. Every recent header is now admitted to
    # local policy regardless of this value; retain it only so older config
    # files round-trip without a destructive migration.
    scan_bulk_without_unsubscribe: bool = False

    def save(self) -> None:
        """Save configuration to disk with secure permissions."""
        config_path = get_config_path()
        data = self._to_dict()
        # Create the file 0600 from the start: writing then chmod-ing leaves a
        # window where credentials are world-readable under a permissive umask.
        fd = os.open(
            config_path,
            os.O_WRONLY | os.O_CREAT | os.O_TRUNC,
            stat.S_IRUSR | stat.S_IWUSR,
        )
        with os.fdopen(fd, "w") as f:
            json.dump(data, f, indent=2)
        # Re-assert 0600 in case the file pre-existed with looser permissions.
        config_path.chmod(stat.S_IRUSR | stat.S_IWUSR)

    def _to_dict(self) -> dict:
        """Convert config to dictionary for JSON serialization."""
        return {
            "accounts": {name: asdict(acc) for name, acc in self.accounts.items()},
            "default_account": self.default_account,
            "ai": asdict(self.ai),
            "operation_mode": self.operation_mode,
            "notifications": asdict(self.notifications),
            "thresholds": asdict(self.thresholds),
            "safety": asdict(self.safety),
            "scoring": asdict(self.scoring),
            "scan_days": self.scan_days,
            "scan_junk": self.scan_junk,
            "footer_scan_enabled": self.footer_scan_enabled,
            "unsubscribe_consent_version": self.unsubscribe_consent_version,
            "mailbox_mutation_consent_version": self.mailbox_mutation_consent_version,
            "scan_bulk_without_unsubscribe": self.scan_bulk_without_unsubscribe,
        }

    @classmethod
    def load(cls) -> Config:
        """Load configuration from disk."""
        config_path = get_config_path()
        if not config_path.exists():
            return cls()

        with open(config_path) as f:
            data = json.load(f)

        config = cls()

        # Load accounts with validation
        for name, acc_data in data.get("accounts", {}).items():
            try:
                config.accounts[name] = AccountConfig(**acc_data)
            except (TypeError, KeyError, ValueError) as e:
                logger.warning(
                    "Failed to load account '%s': %s. Skipping.",
                    name,
                    e,
                )

        config.default_account = data.get("default_account")

        # Load AI config
        if "ai" in data:
            config.ai = AIConfig(**data["ai"])

        # Check environment variables for secrets (override file config)
        # This allows secure deployment without storing secrets in config files
        env_api_key = os.environ.get("NOTHX_API_KEY") or os.environ.get("ANTHROPIC_API_KEY")
        if env_api_key:
            config.ai.api_key = env_api_key

        # Also check for OpenAI key if using OpenAI provider
        if config.ai.provider == "openai":
            openai_key = os.environ.get("OPENAI_API_KEY")
            if openai_key:
                config.ai.api_key = openai_key

        # Check for Gemini key
        if config.ai.provider == "gemini":
            gemini_key = os.environ.get("GOOGLE_API_KEY") or os.environ.get("GEMINI_API_KEY")
            if gemini_key:
                config.ai.api_key = gemini_key

        config.operation_mode = data.get("operation_mode", "hands_off")

        # Load notifications
        if "notifications" in data:
            config.notifications = NotificationConfig(**data["notifications"])

        # Load thresholds
        if "thresholds" in data:
            config.thresholds = ThresholdConfig(**data["thresholds"])

        # Load safety
        if "safety" in data:
            config.safety = SafetyConfig(**data["safety"])

        # Load scoring
        if "scoring" in data:
            config.scoring = ScoringConfig(**data["scoring"])

        config.scan_days = data.get("scan_days", 30)
        config.scan_junk = data.get("scan_junk", True)
        config.footer_scan_enabled = data.get("footer_scan_enabled", False)
        config.unsubscribe_consent_version = data.get(
            "unsubscribe_consent_version", CURRENT_UNSUBSCRIBE_CONSENT_VERSION
        )
        config.mailbox_mutation_consent_version = data.get(
            "mailbox_mutation_consent_version", CURRENT_MAILBOX_MUTATION_CONSENT_VERSION
        )
        config.scan_bulk_without_unsubscribe = data.get("scan_bulk_without_unsubscribe", False)

        return config

    def get_account(self, name: str | None = None) -> AccountConfig | None:
        """Get an account by name or the default account."""
        if name:
            return self.accounts.get(name)
        if self.default_account:
            return self.accounts.get(self.default_account)
        if self.accounts:
            return next(iter(self.accounts.values()))
        return None

    @property
    def permits_unsubscribe(self) -> bool:
        """Outbound unsubscribe contact is permitted unless explicitly revoked."""
        return self.unsubscribe_consent_version != CONSENT_REVOKED

    @property
    def permits_automatic_unsubscribe(self) -> bool:
        """Compatibility alias for the unsubscribe-contact consent."""
        return self.permits_unsubscribe

    @property
    def permits_mailbox_mutation(self) -> bool:
        """Junk/mailbox writes are permitted unless explicitly revoked."""
        return self.mailbox_mutation_consent_version != CONSENT_REVOKED

    def is_configured(self) -> bool:
        """Check if nothx is configured."""
        return bool(self.accounts) and bool(self.ai.api_key or self.ai.provider == "none")
