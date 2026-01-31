"""Configuration management for nothx."""

import json
import stat
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Optional


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


@dataclass
class AIConfig:
    """Configuration for AI features."""
    enabled: bool = True
    provider: str = "anthropic"  # "anthropic", "ollama", or "none"
    api_key: Optional[str] = None
    model: str = "claude-sonnet-4-20250514"
    confidence_threshold: float = 0.80


@dataclass
class NotificationConfig:
    """Configuration for notifications."""
    enabled: bool = False
    on_unsubscribe: bool = False
    on_error: bool = True
    on_new_senders: bool = False
    digest_frequency: str = "never"  # "never", "weekly", "monthly"


@dataclass
class ThresholdConfig:
    """Configuration for auto-decision thresholds."""
    unsub_confidence: float = 0.80
    keep_confidence: float = 0.80
    min_emails_before_action: int = 3


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
    default_account: Optional[str] = None
    ai: AIConfig = field(default_factory=AIConfig)
    operation_mode: str = "hands_off"  # "hands_off", "notify", "confirm"
    notifications: NotificationConfig = field(default_factory=NotificationConfig)
    thresholds: ThresholdConfig = field(default_factory=ThresholdConfig)
    safety: SafetyConfig = field(default_factory=SafetyConfig)
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
            "accounts": {
                name: asdict(acc) for name, acc in self.accounts.items()
            },
            "default_account": self.default_account,
            "ai": asdict(self.ai),
            "operation_mode": self.operation_mode,
            "notifications": asdict(self.notifications),
            "thresholds": asdict(self.thresholds),
            "safety": asdict(self.safety),
            "scan_days": self.scan_days,
        }

    @classmethod
    def load(cls) -> "Config":
        """Load configuration from disk."""
        config_path = get_config_path()
        if not config_path.exists():
            return cls()

        with open(config_path) as f:
            data = json.load(f)

        config = cls()

        # Load accounts
        for name, acc_data in data.get("accounts", {}).items():
            config.accounts[name] = AccountConfig(**acc_data)

        config.default_account = data.get("default_account")

        # Load AI config
        if "ai" in data:
            config.ai = AIConfig(**data["ai"])

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

        config.scan_days = data.get("scan_days", 30)

        return config

    def get_account(self, name: Optional[str] = None) -> Optional[AccountConfig]:
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
