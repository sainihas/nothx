"""Tests for configuration management."""

import json
import stat
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

from nothx.config import (
    CONSENT_REVOKED,
    CURRENT_MAILBOX_MUTATION_CONSENT_VERSION,
    CURRENT_UNSUBSCRIBE_CONSENT_VERSION,
    AccountConfig,
    AIConfig,
    Config,
    SafetyConfig,
    ThresholdConfig,
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
        assert config.scan_junk is True
        assert config.footer_scan_enabled is False
        # Automation consent is granted by default; only an explicit revoke removes it.
        assert config.permits_automatic_unsubscribe is True
        assert config.permits_mailbox_mutation is True

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

    def test_account_auth_defaults_preserve_password_providers(self):
        account = AccountConfig(provider="gmail", email="me@gmail.com", password="app-pass")

        assert account.auth == "password"
        assert account.uses_oauth is False
        assert account.client_id is None
        assert account.junk_mailbox is None
        assert account.extra_scan_mailboxes == []

    def test_oauth_account_can_omit_password(self):
        account = AccountConfig(
            provider="outlook",
            email="me@outlook.com",
            auth="OAUTH",
            client_id="client-123",
        )

        assert account.password == ""
        assert account.auth == "oauth"
        assert account.uses_oauth is True

    def test_invalid_account_auth_is_rejected(self):
        with pytest.raises(ValueError, match="authentication method"):
            AccountConfig(provider="outlook", email="me@outlook.com", auth="basic")

    def test_current_consent_versions_enable_their_specific_side_effects(self):
        config = Config(
            unsubscribe_consent_version=CURRENT_UNSUBSCRIBE_CONSENT_VERSION,
            mailbox_mutation_consent_version=CURRENT_MAILBOX_MUTATION_CONSENT_VERSION,
        )

        assert config.permits_automatic_unsubscribe is True
        assert config.permits_mailbox_mutation is True

    def test_revoked_sentinel_disables_each_side_effect(self):
        config = Config(
            unsubscribe_consent_version=CONSENT_REVOKED,
            mailbox_mutation_consent_version=CONSENT_REVOKED,
        )

        assert config.permits_automatic_unsubscribe is False
        assert config.permits_mailbox_mutation is False

    def test_legacy_stored_zero_still_permits(self):
        # Earlier builds persisted 0 to mean "not yet granted"; that value must
        # not keep permanently blocking the operator who is already running nothx.
        config = Config(
            unsubscribe_consent_version=0,
            mailbox_mutation_consent_version=0,
        )

        assert config.permits_automatic_unsubscribe is True
        assert config.permits_mailbox_mutation is True


class TestConfigSaveLoad:
    """Tests for config persistence."""

    def test_save_and_load(self, temp_config_dir):
        """Test saving and loading configuration."""
        config = Config()
        config.accounts["default"] = AccountConfig(
            provider="gmail", email="test@example.com", password="secret123"
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
            provider="gmail", email="test@example.com", password="secret123"
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

    def test_legacy_password_account_loads_without_auth_fields(self, temp_config_dir):
        config_data = {
            "accounts": {
                "legacy": {
                    "provider": "gmail",
                    "email": "legacy@gmail.com",
                    "password": "app-password",
                }
            },
            "ai": {"provider": "none"},
        }
        (temp_config_dir / "config.json").write_text(json.dumps(config_data))

        loaded = Config.load()

        account = loaded.accounts["legacy"]
        assert account.auth == "password"
        assert account.password == "app-password"
        assert account.client_id is None

    def test_oauth_and_mailbox_fields_round_trip(self, temp_config_dir):
        config = Config(
            accounts={
                "outlook": AccountConfig(
                    provider="outlook",
                    email="me@outlook.com",
                    auth="oauth",
                    client_id="client-123",
                    junk_mailbox="Junk Email",
                    extra_scan_mailboxes=["Newsletters"],
                )
            },
            scan_junk=False,
            footer_scan_enabled=True,
            unsubscribe_consent_version=2,
            mailbox_mutation_consent_version=3,
        )

        config.save()
        loaded = Config.load()

        account = loaded.accounts["outlook"]
        assert account.password == ""
        assert account.auth == "oauth"
        assert account.client_id == "client-123"
        assert account.junk_mailbox == "Junk Email"
        assert account.extra_scan_mailboxes == ["Newsletters"]
        assert loaded.scan_junk is False
        assert loaded.footer_scan_enabled is True
        assert loaded.unsubscribe_consent_version == 2
        assert loaded.mailbox_mutation_consent_version == 3


class TestConfigMethods:
    """Tests for config helper methods."""

    def test_get_account_by_name(self):
        """Test getting account by name."""
        config = Config()
        config.accounts["work"] = AccountConfig(
            provider="outlook", email="work@company.com", password="pass"
        )
        config.accounts["personal"] = AccountConfig(
            provider="gmail", email="personal@gmail.com", password="pass"
        )

        account = config.get_account("work")
        assert account is not None
        assert account.email == "work@company.com"

    def test_get_account_default(self):
        """Test getting default account."""
        config = Config()
        config.accounts["main"] = AccountConfig(
            provider="gmail", email="main@gmail.com", password="pass"
        )
        config.default_account = "main"

        account = config.get_account()
        assert account is not None
        assert account.email == "main@gmail.com"

    def test_get_account_fallback(self):
        """Test fallback to first account when no default."""
        config = Config()
        config.accounts["only"] = AccountConfig(
            provider="gmail", email="only@gmail.com", password="pass"
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
            provider="gmail", email="test@gmail.com", password="pass"
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
            provider="gmail", email="test@gmail.com", password="pass"
        )

        assert config.is_configured() is False

    def test_is_configured_provider_none(self):
        """Test is_configured with provider='none' (heuristics only)."""
        config = Config()
        config.accounts["default"] = AccountConfig(
            provider="gmail", email="test@gmail.com", password="pass"
        )
        config.ai.provider = "none"

        assert config.is_configured() is True
