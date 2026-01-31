"""Tests for configuration management."""

import pytest
import tempfile
import stat
from pathlib import Path
from unittest.mock import patch

from nothx.config import (
    Config,
    AccountConfig,
    AIConfig,
    ThresholdConfig,
    SafetyConfig,
    get_config_dir,
    get_config_path,
)


@pytest.fixture
def temp_config_dir():
    """Create a temporary config directory for testing."""
    with tempfile.TemporaryDirectory() as tmpdir:
        config_dir = Path(tmpdir) / ".nothx"
        with patch("nothx.config.get_config_dir", return_value=config_dir):
            with patch("nothx.config.get_config_path", return_value=config_dir / "config.json"):
                config_dir.mkdir(parents=True, exist_ok=True)
                yield config_dir


class TestConfigBasics:
    """Tests for basic config functionality."""

    def test_default_config(self):
        """Test default configuration values."""
        config = Config()

        assert config.accounts == {}
        assert config.default_account is None
        assert config.ai.enabled is True
        assert config.ai.provider == "anthropic"
        assert config.operation_mode == "hands_off"
        assert config.scan_days == 30

    def test_ai_config_defaults(self):
        """Test AI configuration defaults."""
        ai = AIConfig()

        assert ai.enabled is True
        assert ai.provider == "anthropic"
        assert ai.api_key is None
        assert ai.confidence_threshold == 0.80

    def test_threshold_config_defaults(self):
        """Test threshold configuration defaults."""
        thresholds = ThresholdConfig()

        assert thresholds.unsub_confidence == 0.80
        assert thresholds.keep_confidence == 0.80
        assert thresholds.min_emails_before_action == 3

    def test_safety_config_defaults(self):
        """Test safety configuration defaults."""
        safety = SafetyConfig()

        assert "*.gov" in safety.never_unsub_domains
        assert "*bank*" in safety.never_unsub_domains
        assert safety.dry_run is False


class TestConfigSaveLoad:
    """Tests for config persistence."""

    def test_save_and_load(self, temp_config_dir):
        """Test saving and loading configuration."""
        config = Config()
        config.accounts["default"] = AccountConfig(
            provider="gmail",
            email="test@example.com",
            password="secret123"
        )
        config.default_account = "default"
        config.ai.api_key = "test-api-key"
        config.operation_mode = "confirm"

        config.save()

        # Load it back
        loaded = Config.load()

        assert loaded.default_account == "default"
        assert "default" in loaded.accounts
        assert loaded.accounts["default"].email == "test@example.com"
        assert loaded.ai.api_key == "test-api-key"
        assert loaded.operation_mode == "confirm"

    def test_save_sets_permissions(self, temp_config_dir):
        """Test that save sets secure file permissions."""
        config = Config()
        config.accounts["default"] = AccountConfig(
            provider="gmail",
            email="test@example.com",
            password="secret123"
        )
        config.save()

        config_path = temp_config_dir / "config.json"
        file_stat = config_path.stat()

        # Check that only owner has read/write permissions (0600)
        assert file_stat.st_mode & 0o777 == stat.S_IRUSR | stat.S_IWUSR

    def test_load_nonexistent(self, temp_config_dir):
        """Test loading when no config file exists."""
        config = Config.load()

        # Should return default config
        assert config.accounts == {}
        assert config.default_account is None


class TestConfigMethods:
    """Tests for config helper methods."""

    def test_get_account_by_name(self):
        """Test getting account by name."""
        config = Config()
        config.accounts["work"] = AccountConfig(
            provider="outlook",
            email="work@company.com",
            password="pass"
        )
        config.accounts["personal"] = AccountConfig(
            provider="gmail",
            email="personal@gmail.com",
            password="pass"
        )

        account = config.get_account("work")
        assert account is not None
        assert account.email == "work@company.com"

    def test_get_account_default(self):
        """Test getting default account."""
        config = Config()
        config.accounts["main"] = AccountConfig(
            provider="gmail",
            email="main@gmail.com",
            password="pass"
        )
        config.default_account = "main"

        account = config.get_account()
        assert account is not None
        assert account.email == "main@gmail.com"

    def test_get_account_fallback(self):
        """Test fallback to first account when no default."""
        config = Config()
        config.accounts["only"] = AccountConfig(
            provider="gmail",
            email="only@gmail.com",
            password="pass"
        )

        account = config.get_account()
        assert account is not None
        assert account.email == "only@gmail.com"

    def test_get_account_none(self):
        """Test getting account when none configured."""
        config = Config()

        account = config.get_account()
        assert account is None

    def test_is_configured_true(self):
        """Test is_configured returns True when properly configured."""
        config = Config()
        config.accounts["default"] = AccountConfig(
            provider="gmail",
            email="test@gmail.com",
            password="pass"
        )
        config.ai.api_key = "test-key"

        assert config.is_configured() is True

    def test_is_configured_false_no_account(self):
        """Test is_configured returns False without accounts."""
        config = Config()
        config.ai.api_key = "test-key"

        assert config.is_configured() is False

    def test_is_configured_false_no_api_key(self):
        """Test is_configured returns False without API key."""
        config = Config()
        config.accounts["default"] = AccountConfig(
            provider="gmail",
            email="test@gmail.com",
            password="pass"
        )

        assert config.is_configured() is False

    def test_is_configured_provider_none(self):
        """Test is_configured with provider='none' (heuristics only)."""
        config = Config()
        config.accounts["default"] = AccountConfig(
            provider="gmail",
            email="test@gmail.com",
            password="pass"
        )
        config.ai.provider = "none"

        assert config.is_configured() is True
