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


def get_config_dir() -> Path:
    """Get the nothx config directory."""
    config_dir = Path.home() / ".nothx"
    config_dir.mkdir(parents=True, exist_ok=True)
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
    password: str  # App password for Gmail


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
    model: str = "claude-sonnet-4-20250514"
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

    def save(self) -> None:
        """Save configuration to disk with secure permissions."""
        config_path = get_config_path()
        data = self._to_dict()
        with open(config_path, "w") as f:
            json.dump(data, f, indent=2)
        # Set file permissions to owner read/write only (0600)
        # This protects sensitive data like API keys and app passwords
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
            except (TypeError, KeyError) as e:
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

    def is_configured(self) -> bool:
        """Check if nothx is configured."""
        return bool(self.accounts) and bool(self.ai.api_key or self.ai.provider == "none")
