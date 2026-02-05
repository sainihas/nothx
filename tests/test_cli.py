"""Tests for the CLI interface."""

import json
import tempfile
from datetime import datetime
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

from nothx import db
from nothx.cli import (
    account_add,
    account_list,
    account_remove,
    completion,
    config_cmd,
    export,
    history,
    init,
    main,
    reset,
    review,
    rule,
    rules,
    run,
    schedule,
    search,
    senders,
    status,
    test_connection,
    undo,
    update,
)
from nothx.config import AccountConfig, Config
from nothx.models import (
    RunStats,
    SenderStatus,
    UnsubMethod,
)


@pytest.fixture
def runner():
    """Create a CLI runner for testing."""
    return CliRunner()


@pytest.fixture
def temp_config_dir():
    """Create a temporary config directory for testing."""
    with tempfile.TemporaryDirectory() as tmpdir:
        config_dir = Path(tmpdir) / ".nothx"
        config_dir.mkdir(parents=True, exist_ok=True)
        db_path = config_dir / "nothx.db"
        config_path = config_dir / "config.json"

        with patch("nothx.config.get_config_dir", return_value=config_dir):
            with patch("nothx.config.get_config_path", return_value=config_path):
                with patch("nothx.db.get_db_path", return_value=db_path):
                    db.init_db()
                    yield config_dir


@pytest.fixture
def configured_env(temp_config_dir):
    """Set up a configured environment with accounts and AI."""
    config = Config()
    config.accounts["default"] = AccountConfig(
        provider="gmail", email="test@example.com", password="secret"
    )
    config.default_account = "default"
    config.ai.api_key = "test-key"
    config.ai.provider = "anthropic"
    config.save()
    return config


class TestMainCommand:
    """Tests for the main command and welcome screen."""

    def test_version_option(self, runner):
        """Test --version flag."""
        result = runner.invoke(main, ["--version"])
        assert result.exit_code == 0
        assert "nothx" in result.output or "version" in result.output.lower()

    def test_help_option(self, runner):
        """Test --help flag."""
        result = runner.invoke(main, ["--help"])
        assert result.exit_code == 0
        assert "nothx" in result.output
        assert "run" in result.output
        assert "status" in result.output

    @patch("nothx.cli.NothxApp")
    def test_main_no_subcommand_shows_welcome(self, mock_app_class, runner, temp_config_dir):
        """Test that running without subcommand shows welcome screen."""
        mock_app = MagicMock()
        mock_app.run.return_value = None  # User pressed ESC
        mock_app_class.return_value = mock_app

        result = runner.invoke(main, [])
        # Should attempt to show welcome screen
        assert result.exit_code == 0


class TestInitCommand:
    """Tests for the init command."""

    @patch("nothx.cli.questionary.select")
    @patch("nothx.cli.questionary.text")
    @patch("nothx.cli.questionary.password")
    @patch("nothx.cli.questionary.confirm")
    @patch("nothx.cli.test_account")
    @patch("nothx.cli.test_ai_connection")
    def test_init_full_flow(
        self,
        mock_ai_test,
        mock_account_test,
        mock_confirm,
        mock_password,
        mock_text,
        mock_select,
        runner,
        temp_config_dir,
    ):
        """Test full init flow with email and AI setup."""
        # Mock user inputs
        mock_select.return_value.ask.side_effect = [
            "gmail",  # Provider selection
            "anthropic",  # AI provider selection
        ]
        mock_text.return_value.ask.side_effect = [
            "user@gmail.com",  # Email
            "test-api-key",  # API key
        ]
        mock_password.return_value.ask.return_value = "app-password"
        mock_confirm.return_value.ask.side_effect = [
            False,  # Add another account
            False,  # Run first scan
            False,  # Schedule runs
        ]
        mock_account_test.return_value = (True, "Connected")
        mock_ai_test.return_value = (True, "AI working")

        result = runner.invoke(init, [])

        assert result.exit_code == 0
        assert "Setup complete" in result.output

    @patch("nothx.cli.questionary.select")
    def test_init_cancelled_at_provider(self, mock_select, runner, temp_config_dir):
        """Test init cancelled at provider selection."""
        mock_select.return_value.ask.return_value = None

        result = runner.invoke(init, [])

        assert "No accounts configured" in result.output


class TestAccountCommands:
    """Tests for account management commands."""

    def test_account_list_empty(self, runner, temp_config_dir):
        """Test listing accounts when none configured."""
        result = runner.invoke(account_list, [])

        assert result.exit_code == 0
        assert "No accounts configured" in result.output

    def test_account_list_with_accounts(self, runner, configured_env, temp_config_dir):
        """Test listing accounts when configured."""
        result = runner.invoke(account_list, [])

        assert result.exit_code == 0
        assert "test@example.com" in result.output

    @patch("nothx.cli.questionary.select")
    @patch("nothx.cli.questionary.text")
    @patch("nothx.cli.questionary.password")
    @patch("nothx.cli.test_account")
    def test_account_add(
        self, mock_test, mock_password, mock_text, mock_select, runner, temp_config_dir
    ):
        """Test adding an account."""
        mock_select.return_value.ask.return_value = "gmail"
        mock_text.return_value.ask.return_value = "new@example.com"
        mock_password.return_value.ask.return_value = "password123"
        mock_test.return_value = (True, "Connected")

        result = runner.invoke(account_add, [])

        assert result.exit_code == 0
        assert "Added account" in result.output

    @patch("nothx.cli.questionary.select")
    @patch("nothx.cli.questionary.confirm")
    def test_account_remove(
        self, mock_confirm, mock_select, runner, configured_env, temp_config_dir
    ):
        """Test removing an account."""
        mock_select.return_value.ask.return_value = "default"
        mock_confirm.return_value.ask.return_value = True

        result = runner.invoke(account_remove, [])

        assert result.exit_code == 0
        assert "Removed account" in result.output

    @patch("nothx.cli.questionary.select")
    @patch("nothx.cli.questionary.confirm")
    def test_account_remove_cancelled(
        self, mock_confirm, mock_select, runner, configured_env, temp_config_dir
    ):
        """Test cancelling account removal."""
        mock_select.return_value.ask.return_value = "default"
        mock_confirm.return_value.ask.return_value = False

        result = runner.invoke(account_remove, [])

        assert result.exit_code == 0
        assert "Cancelled" in result.output


class TestRunCommand:
    """Tests for the run command."""

    def test_run_not_configured(self, runner, temp_config_dir):
        """Test run when not configured."""
        result = runner.invoke(run, [])

        assert result.exit_code == 1
        assert "not configured" in result.output

    @patch("nothx.cli.scan_inbox")
    @patch("nothx.cli.ClassificationEngine")
    def test_run_dry_run(
        self, mock_engine_class, mock_scan, runner, configured_env, temp_config_dir
    ):
        """Test run with --dry-run flag."""
        mock_scan.return_value = MagicMock(sender_stats={}, get_email_for_domain=lambda x: None)
        mock_engine = MagicMock()
        mock_engine_class.return_value = mock_engine
        mock_engine.classify_batch.return_value = {}

        result = runner.invoke(run, ["--dry-run"])

        assert result.exit_code == 0
        assert "DRY RUN" in result.output

    @patch("nothx.cli.scan_inbox")
    @patch("nothx.cli.ClassificationEngine")
    def test_run_no_emails(
        self, mock_engine_class, mock_scan, runner, configured_env, temp_config_dir
    ):
        """Test run when no marketing emails found."""
        mock_scan.return_value = MagicMock(sender_stats={}, get_email_for_domain=lambda x: None)

        result = runner.invoke(run, ["--dry-run"])

        assert result.exit_code == 0
        assert "No marketing emails found" in result.output

    def test_run_invalid_account(self, runner, configured_env, temp_config_dir):
        """Test run with invalid account name."""
        result = runner.invoke(run, ["--account", "nonexistent"])

        assert result.exit_code == 1
        assert "not found" in result.output


class TestStatusCommand:
    """Tests for the status command."""

    def test_status_not_configured(self, runner, temp_config_dir):
        """Test status when not configured."""
        result = runner.invoke(status, [])

        assert result.exit_code == 1
        assert "not configured" in result.output

    def test_status_configured(self, runner, configured_env, temp_config_dir):
        """Test status with configuration."""
        result = runner.invoke(status, [])

        assert result.exit_code == 0
        assert "Status" in result.output

    @patch("nothx.cli.get_learner")
    def test_status_learning_flag(self, mock_learner, runner, configured_env, temp_config_dir):
        """Test status with --learning flag."""
        mock_learner.return_value.get_learning_summary.return_value = {
            "total_actions": 10,
            "total_corrections": 2,
            "open_rate_importance": "normal",
            "volume_sensitivity": "normal",
            "keyword_patterns": [],
        }

        result = runner.invoke(status, ["--learning"])

        assert result.exit_code == 0
        assert "Learning Status" in result.output


class TestReviewCommand:
    """Tests for the review command."""

    def test_review_not_configured(self, runner, temp_config_dir):
        """Test review when not configured."""
        result = runner.invoke(review, [])

        assert result.exit_code == 1
        assert "not configured" in result.output

    def test_review_empty(self, runner, configured_env, temp_config_dir):
        """Test review when no senders to review."""
        result = runner.invoke(review, [])

        assert result.exit_code == 0
        assert "No senders" in result.output

    @patch("nothx.cli.questionary.select")
    def test_review_with_senders(self, mock_select, runner, configured_env, temp_config_dir):
        """Test review with pending senders."""
        # Add a sender to review
        db.upsert_sender("marketing.com", 5, 1, ["Buy now!"], True)

        # User selects to keep
        mock_select.return_value.ask.return_value = "keep"

        # Use the --keep filter since sender is unknown by default
        result = runner.invoke(review, ["--all"])

        assert result.exit_code == 0


class TestUndoCommand:
    """Tests for the undo command."""

    def test_undo_no_recent(self, runner, temp_config_dir):
        """Test undo with no recent unsubscribes."""
        result = runner.invoke(undo, [])

        assert result.exit_code == 0
        assert "No recent unsubscribes" in result.output

    def test_undo_specific_domain(self, runner, temp_config_dir):
        """Test undoing a specific domain."""
        # Set up a sender that was unsubscribed
        db.upsert_sender("test.com", 5, 2, ["Subject"], True)
        db.update_sender_status("test.com", SenderStatus.UNSUBSCRIBED)

        result = runner.invoke(undo, ["test.com"])

        assert result.exit_code == 0
        assert "Marked test.com as 'keep'" in result.output

    def test_undo_shows_recent(self, runner, temp_config_dir):
        """Test undo shows recent unsubscribes."""
        # Need both a sender and an unsub_log entry (they're joined in the query)
        db.upsert_sender("recent.com", 5, 2, ["Subject"], True)
        db.log_unsub_attempt("recent.com", True, UnsubMethod.ONE_CLICK)

        result = runner.invoke(undo, [])

        assert result.exit_code == 0
        assert "Recent unsubscribes" in result.output


class TestScheduleCommand:
    """Tests for the schedule command."""

    @patch("nothx.cli.get_schedule_status")
    def test_schedule_status_none(self, mock_status, runner):
        """Test schedule status when not scheduled."""
        mock_status.return_value = None

        result = runner.invoke(schedule, ["--status"])

        assert result.exit_code == 0
        assert "No schedule configured" in result.output

    @patch("nothx.cli.get_schedule_status")
    def test_schedule_status_configured(self, mock_status, runner):
        """Test schedule status when scheduled."""
        mock_status.return_value = {
            "type": "launchd",
            "frequency": "monthly",
            "path": "/tmp/test.plist",
        }

        result = runner.invoke(schedule, ["--status"])

        assert result.exit_code == 0
        assert "monthly" in result.output

    @patch("nothx.cli.install_schedule")
    def test_schedule_monthly(self, mock_install, runner):
        """Test enabling monthly schedule."""
        mock_install.return_value = (True, "Scheduled monthly")

        result = runner.invoke(schedule, ["--monthly"])

        assert result.exit_code == 0
        assert "Scheduled monthly" in result.output

    @patch("nothx.cli.uninstall_schedule")
    def test_schedule_off(self, mock_uninstall, runner):
        """Test disabling schedule."""
        mock_uninstall.return_value = (True, "Schedule removed")

        result = runner.invoke(schedule, ["--off"])

        assert result.exit_code == 0
        assert "Schedule removed" in result.output


class TestConfigCommand:
    """Tests for the config command."""

    def test_config_show(self, runner, configured_env, temp_config_dir):
        """Test showing configuration."""
        result = runner.invoke(config_cmd, ["--show"])

        assert result.exit_code == 0
        assert "Configuration" in result.output

    def test_config_ai_on(self, runner, configured_env, temp_config_dir):
        """Test enabling AI."""
        result = runner.invoke(config_cmd, ["--ai", "on"])

        assert result.exit_code == 0
        assert "enabled" in result.output

    def test_config_ai_off(self, runner, configured_env, temp_config_dir):
        """Test disabling AI."""
        result = runner.invoke(config_cmd, ["--ai", "off"])

        assert result.exit_code == 0
        assert "disabled" in result.output

    def test_config_mode(self, runner, configured_env, temp_config_dir):
        """Test setting operation mode."""
        result = runner.invoke(config_cmd, ["--mode", "confirm"])

        assert result.exit_code == 0
        assert "confirm" in result.output


class TestRuleCommands:
    """Tests for rule management commands."""

    def test_add_rule(self, runner, temp_config_dir):
        """Test adding a rule."""
        result = runner.invoke(rule, ["*.spam.com", "unsub"])

        assert result.exit_code == 0
        assert "Added rule" in result.output

    def test_list_rules_empty(self, runner, temp_config_dir):
        """Test listing rules when none exist."""
        result = runner.invoke(rules, [])

        assert result.exit_code == 0
        assert "No rules configured" in result.output

    def test_list_rules_with_data(self, runner, temp_config_dir):
        """Test listing rules."""
        db.add_rule("*.spam.com", "block")
        db.add_rule("*.important.com", "keep")

        result = runner.invoke(rules, [])

        assert result.exit_code == 0
        assert "spam.com" in result.output
        assert "important.com" in result.output


class TestSendersCommand:
    """Tests for the senders command."""

    def test_senders_empty(self, runner, temp_config_dir):
        """Test senders when none tracked."""
        result = runner.invoke(senders, [])

        assert result.exit_code == 0
        assert "No senders tracked" in result.output

    def test_senders_with_data(self, runner, temp_config_dir):
        """Test listing senders."""
        db.upsert_sender("marketing.com", 10, 2, ["Buy now"], True)
        db.upsert_sender("newsletter.com", 5, 5, ["Weekly digest"], True)

        result = runner.invoke(senders, [])

        assert result.exit_code == 0
        assert "marketing.com" in result.output
        assert "newsletter.com" in result.output

    def test_senders_filter_by_status(self, runner, temp_config_dir):
        """Test filtering senders by status."""
        db.upsert_sender("keep.com", 5, 5, [], False)
        db.update_sender_status("keep.com", SenderStatus.KEEP)
        db.upsert_sender("unsub.com", 10, 0, [], True)
        db.update_sender_status("unsub.com", SenderStatus.UNSUBSCRIBED)

        result = runner.invoke(senders, ["--status", "keep"])

        assert result.exit_code == 0
        assert "keep.com" in result.output
        assert "unsub.com" not in result.output

    def test_senders_json_output(self, runner, temp_config_dir):
        """Test JSON output for senders."""
        db.upsert_sender("test.com", 5, 2, [], True)

        result = runner.invoke(senders, ["--json"])

        assert result.exit_code == 0
        data = json.loads(result.output)
        assert isinstance(data, list)
        assert data[0]["domain"] == "test.com"


class TestSearchCommand:
    """Tests for the search command."""

    def test_search_no_results(self, runner, temp_config_dir):
        """Test search with no matches."""
        db.upsert_sender("example.com", 5, 2, [], True)

        result = runner.invoke(search, ["nonexistent"])

        assert result.exit_code == 0
        assert "No senders found" in result.output

    def test_search_with_results(self, runner, temp_config_dir):
        """Test search with matches."""
        db.upsert_sender("marketing.example.com", 5, 2, [], True)
        db.upsert_sender("info.example.com", 3, 1, [], True)

        result = runner.invoke(search, ["example"])

        assert result.exit_code == 0
        assert "marketing.example.com" in result.output
        assert "info.example.com" in result.output

    def test_search_json_output(self, runner, temp_config_dir):
        """Test JSON output for search."""
        db.upsert_sender("test.com", 5, 2, [], True)

        result = runner.invoke(search, ["test", "--json"])

        assert result.exit_code == 0
        data = json.loads(result.output)
        assert isinstance(data, list)


class TestHistoryCommand:
    """Tests for the history command."""

    def test_history_empty(self, runner, temp_config_dir):
        """Test history with no activity."""
        result = runner.invoke(history, [])

        assert result.exit_code == 0
        assert "No activity yet" in result.output

    def test_history_with_runs(self, runner, temp_config_dir):
        """Test history with run logs."""
        stats = RunStats(
            ran_at=datetime.now(),
            mode="interactive",
            emails_scanned=100,
            unique_senders=25,
        )
        db.log_run(stats)

        result = runner.invoke(history, [])

        assert result.exit_code == 0
        assert "Scan completed" in result.output

    def test_history_with_unsubscribes(self, runner, temp_config_dir):
        """Test history with unsubscribe logs."""
        db.log_unsub_attempt("success.com", True, UnsubMethod.ONE_CLICK)
        db.log_unsub_attempt("failed.com", False, UnsubMethod.GET, error="timeout")

        result = runner.invoke(history, [])

        assert result.exit_code == 0
        assert "success.com" in result.output
        assert "failed.com" in result.output

    def test_history_failures_only(self, runner, temp_config_dir):
        """Test filtering for failures only."""
        db.log_unsub_attempt("success.com", True, UnsubMethod.ONE_CLICK)
        db.log_unsub_attempt("failed.com", False, UnsubMethod.GET, error="timeout")

        result = runner.invoke(history, ["--failures"])

        assert result.exit_code == 0
        assert "failed.com" in result.output
        assert "success.com" not in result.output

    def test_history_json_output(self, runner, temp_config_dir):
        """Test JSON output for history."""
        db.log_unsub_attempt("test.com", True, UnsubMethod.ONE_CLICK)

        result = runner.invoke(history, ["--json"])

        assert result.exit_code == 0
        data = json.loads(result.output)
        assert isinstance(data, list)


class TestExportCommand:
    """Tests for the export command."""

    def test_export_senders(self, runner, temp_config_dir):
        """Test exporting senders to CSV."""
        db.upsert_sender("test.com", 5, 2, ["Subject"], True)

        with tempfile.NamedTemporaryFile(suffix=".csv", delete=False) as f:
            output_path = f.name

        try:
            result = runner.invoke(export, ["senders", "--output", output_path])

            assert result.exit_code == 0
            assert "Exported" in result.output

            # Verify CSV content
            with open(output_path) as f:
                content = f.read()
                assert "test.com" in content
        finally:
            Path(output_path).unlink(missing_ok=True)

    def test_export_history(self, runner, temp_config_dir):
        """Test exporting history to CSV."""
        db.log_unsub_attempt("test.com", True, UnsubMethod.ONE_CLICK)

        with tempfile.NamedTemporaryFile(suffix=".csv", delete=False) as f:
            output_path = f.name

        try:
            result = runner.invoke(export, ["history", "--output", output_path])

            assert result.exit_code == 0
            assert "Exported" in result.output
        finally:
            Path(output_path).unlink(missing_ok=True)

    def test_export_senders_empty(self, runner, temp_config_dir):
        """Test exporting when no data."""
        with tempfile.NamedTemporaryFile(suffix=".csv", delete=False) as f:
            output_path = f.name

        try:
            result = runner.invoke(export, ["senders", "--output", output_path])

            assert result.exit_code == 0
            assert "No senders to export" in result.output
        finally:
            Path(output_path).unlink(missing_ok=True)


class TestTestConnectionCommand:
    """Tests for the test connection command."""

    def test_test_no_accounts(self, runner, temp_config_dir):
        """Test when no accounts configured."""
        result = runner.invoke(test_connection, [])

        assert result.exit_code == 1
        assert "No accounts configured" in result.output

    @patch("nothx.cli.test_account")
    def test_test_success(self, mock_test, runner, configured_env, temp_config_dir):
        """Test successful connection test."""
        mock_test.return_value = (True, "Connected successfully")

        result = runner.invoke(test_connection, [])

        assert result.exit_code == 0
        assert "successful" in result.output

    @patch("nothx.cli.test_account")
    def test_test_failure(self, mock_test, runner, configured_env, temp_config_dir):
        """Test failed connection test."""
        mock_test.return_value = (False, "Authentication failed")

        result = runner.invoke(test_connection, [])

        assert result.exit_code == 1
        assert "failed" in result.output


class TestResetCommand:
    """Tests for the reset command."""

    @patch("nothx.cli.questionary.text")
    def test_reset_cancelled(self, mock_text, runner, temp_config_dir):
        """Test reset cancelled by user."""
        mock_text.return_value.ask.return_value = "no"

        result = runner.invoke(reset, [])

        assert result.exit_code == 0
        assert "Cancelled" in result.output

    @patch("nothx.cli.questionary.text")
    def test_reset_confirmed(self, mock_text, runner, temp_config_dir):
        """Test reset confirmed by user."""
        # Add some data
        db.upsert_sender("test.com", 5, 2, [], True)

        mock_text.return_value.ask.return_value = "reset"

        result = runner.invoke(reset, [])

        assert result.exit_code == 0
        assert "Cleared" in result.output

    @patch("nothx.cli.questionary.text")
    def test_reset_keep_config(self, mock_text, runner, temp_config_dir):
        """Test reset with --keep-config flag."""
        db.add_rule("*.spam.com", "block")
        db.upsert_sender("test.com", 5, 2, [], True)

        mock_text.return_value.ask.return_value = "reset"

        result = runner.invoke(reset, ["--keep-config"])

        assert result.exit_code == 0
        # Rules should be preserved
        rules_list = db.get_rules()
        assert len(rules_list) == 1


class TestCompletionCommand:
    """Tests for the completion command."""

    def test_completion_bash(self, runner):
        """Test bash completion script generation."""
        result = runner.invoke(completion, ["bash"])

        assert result.exit_code == 0
        assert "_nothx_completion" in result.output
        assert "complete" in result.output

    def test_completion_zsh(self, runner):
        """Test zsh completion script generation."""
        result = runner.invoke(completion, ["zsh"])

        assert result.exit_code == 0
        assert "compdef" in result.output

    def test_completion_fish(self, runner):
        """Test fish completion script generation."""
        result = runner.invoke(completion, ["fish"])

        assert result.exit_code == 0
        assert "function" in result.output


class TestUpdateCommand:
    """Tests for the update command."""

    @patch("urllib.request.urlopen")
    def test_update_check_up_to_date(self, mock_urlopen, runner):
        """Test update check when already on latest."""
        from nothx import __version__

        mock_response = MagicMock()
        mock_response.read.return_value = json.dumps({"info": {"version": __version__}}).encode()
        mock_response.__enter__ = MagicMock(return_value=mock_response)
        mock_response.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_response

        result = runner.invoke(update, ["--check"])

        assert result.exit_code == 0
        assert "latest version" in result.output

    @patch("urllib.request.urlopen")
    def test_update_check_new_version(self, mock_urlopen, runner):
        """Test update check when new version available."""
        mock_response = MagicMock()
        mock_response.read.return_value = json.dumps({"info": {"version": "99.99.99"}}).encode()
        mock_response.__enter__ = MagicMock(return_value=mock_response)
        mock_response.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_response

        result = runner.invoke(update, ["--check"])

        assert result.exit_code == 0
        assert "99.99.99" in result.output

    @patch("urllib.request.urlopen")
    def test_update_check_offline(self, mock_urlopen, runner):
        """Test update check when offline."""
        import urllib.error

        mock_urlopen.side_effect = urllib.error.URLError("Network error")

        result = runner.invoke(update, ["--check"])

        assert result.exit_code == 0
        assert "Could not check" in result.output


class TestCommandAliases:
    """Tests for command aliases."""

    def test_alias_r(self, runner, temp_config_dir):
        """Test 'r' alias for run."""
        result = runner.invoke(main, ["r", "--help"])

        assert result.exit_code == 0
        assert "Scan inbox" in result.output

    def test_alias_s(self, runner, temp_config_dir):
        """Test 's' alias for status."""
        result = runner.invoke(main, ["s", "--help"])

        assert result.exit_code == 0
        assert "status" in result.output.lower()

    def test_alias_rv(self, runner, temp_config_dir):
        """Test 'rv' alias for review."""
        result = runner.invoke(main, ["rv", "--help"])

        assert result.exit_code == 0
        assert "review" in result.output.lower()

    def test_alias_h(self, runner, temp_config_dir):
        """Test 'h' alias for history."""
        result = runner.invoke(main, ["h", "--help"])

        assert result.exit_code == 0
        assert "activity" in result.output.lower()


class TestEdgeCases:
    """Tests for edge cases and error handling."""

    def test_run_verbose_flag(self, runner, configured_env, temp_config_dir):
        """Test verbose output with -v flag."""
        with patch("nothx.cli.scan_inbox") as mock_scan:
            mock_scan.return_value = MagicMock(sender_stats={}, get_email_for_domain=lambda x: None)

            result = runner.invoke(run, ["--dry-run", "-v"])

            assert result.exit_code == 0

    def test_senders_sort_options(self, runner, temp_config_dir):
        """Test different sort options for senders."""
        db.upsert_sender("a.com", 10, 5, [], True)
        db.upsert_sender("z.com", 5, 2, [], True)

        # Sort by domain
        result = runner.invoke(senders, ["--sort", "domain"])
        assert result.exit_code == 0
        # a.com should appear before z.com in output
        a_pos = result.output.find("a.com")
        z_pos = result.output.find("z.com")
        assert a_pos < z_pos

        # Sort by emails
        result = runner.invoke(senders, ["--sort", "emails"])
        assert result.exit_code == 0

    def test_history_limit(self, runner, temp_config_dir):
        """Test history with custom limit."""
        for i in range(10):
            db.log_unsub_attempt(f"domain{i}.com", True, UnsubMethod.ONE_CLICK)

        result = runner.invoke(history, ["--limit", "3"])

        assert result.exit_code == 0
        # Should only show 3 entries
        assert result.output.count("Unsubscribed from") == 3

    def test_run_multiple_accounts(self, runner, temp_config_dir):
        """Test run with multiple account selection."""
        config = Config()
        config.accounts["work"] = AccountConfig(
            provider="outlook", email="work@example.com", password="pass1"
        )
        config.accounts["personal"] = AccountConfig(
            provider="gmail", email="personal@example.com", password="pass2"
        )
        config.default_account = "work"
        config.ai.api_key = "test-key"
        config.save()

        with patch("nothx.cli.scan_inbox") as mock_scan:
            mock_scan.return_value = MagicMock(sender_stats={}, get_email_for_domain=lambda x: None)

            result = runner.invoke(run, ["--dry-run", "-a", "work", "-a", "personal"])

            assert result.exit_code == 0


class TestAppPasswordInstructions:
    """Tests for app password instruction display."""

    def test_gmail_instructions_exist(self):
        """Test Gmail instructions are defined."""
        from nothx.cli import APP_PASSWORD_INSTRUCTIONS

        assert "gmail" in APP_PASSWORD_INSTRUCTIONS
        assert len(APP_PASSWORD_INSTRUCTIONS["gmail"]) > 0

    def test_outlook_instructions_exist(self):
        """Test Outlook instructions are defined."""
        from nothx.cli import APP_PASSWORD_INSTRUCTIONS

        assert "outlook" in APP_PASSWORD_INSTRUCTIONS

    def test_yahoo_instructions_exist(self):
        """Test Yahoo instructions are defined."""
        from nothx.cli import APP_PASSWORD_INSTRUCTIONS

        assert "yahoo" in APP_PASSWORD_INSTRUCTIONS

    def test_icloud_instructions_exist(self):
        """Test iCloud instructions are defined."""
        from nothx.cli import APP_PASSWORD_INSTRUCTIONS

        assert "icloud" in APP_PASSWORD_INSTRUCTIONS


class TestTroubleshootingTips:
    """Tests for troubleshooting tips."""

    def test_troubleshooting_tips_defined(self):
        """Test troubleshooting tips are defined for all providers."""
        from nothx.cli import TROUBLESHOOTING_TIPS

        assert "gmail" in TROUBLESHOOTING_TIPS
        assert "outlook" in TROUBLESHOOTING_TIPS
        assert "yahoo" in TROUBLESHOOTING_TIPS
        assert "icloud" in TROUBLESHOOTING_TIPS
