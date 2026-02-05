"""Tests for the Textual TUI screens."""

import pytest
from textual.widgets import DataTable, OptionList, Static

from nothx.tui import (
    NothxApp,
    ReviewApp,
    SendersApp,
    StatusApp,
    UndoApp,
)


@pytest.fixture
def welcome_app():
    """Create a welcome app for testing."""
    return NothxApp(
        greeting="Good morning!",
        version_line="v0.1.2 · not configured",
        run_summary=None,
        is_configured=False,
    )


@pytest.fixture
def welcome_app_configured():
    """Create a configured welcome app for testing."""
    return NothxApp(
        greeting="Good afternoon!",
        version_line="v0.1.2 · 1 account",
        run_summary="Last run 2 hours ago · unsubscribed from 3 senders",
        is_configured=True,
    )


@pytest.fixture
def sample_senders():
    """Sample sender data for review/senders screens."""
    return [
        {
            "domain": "newsletter.example.com",
            "total_emails": 42,
            "ai_classification": "unsub",
            "ai_confidence": 0.9,
            "status": "unknown",
            "last_seen": "2026-01-15T10:00:00",
            "sample_subjects": "Weekly digest|New features|Updates",
        },
        {
            "domain": "important.company.com",
            "total_emails": 5,
            "ai_classification": "keep",
            "ai_confidence": 0.85,
            "status": "keep",
            "last_seen": "2026-02-01T10:00:00",
            "sample_subjects": "Account update",
        },
        {
            "domain": "spam.marketing.io",
            "total_emails": 100,
            "ai_classification": "unsub",
            "ai_confidence": 0.95,
            "status": "unknown",
            "last_seen": "2026-02-03T10:00:00",
            "sample_subjects": "Sale|Promo|Deal",
        },
    ]


@pytest.fixture
def sample_unsubs():
    """Sample recent unsubscribe data."""
    return [
        {
            "domain": "old-newsletter.com",
            "total_emails": 20,
            "attempted_at": "2026-01-20T12:00:00",
        },
        {
            "domain": "promo.shop.com",
            "total_emails": 35,
            "attempted_at": "2026-01-25T12:00:00",
        },
    ]


@pytest.fixture
def sample_status_data():
    """Sample status data for the dashboard."""
    return {
        "stats": {
            "total_senders": 150,
            "unsubscribed": 45,
            "kept": 80,
            "pending_review": 25,
            "total_runs": 10,
        },
        "success_rate": 92.0,
        "successful_unsubs": 42,
        "failed_unsubs": 3,
        "last_run_display": "2 hours ago",
        "accounts": {
            "default": {"email": "user@gmail.com", "provider": "gmail"},
        },
        "default_account": "default",
        "ai": {"enabled": True, "provider": "anthropic"},
        "operation_mode": "confirm",
        "scan_days": 90,
        "schedule": {"type": "launchd", "frequency": "monthly"},
    }


# ============================================================================
# Welcome Screen Tests
# ============================================================================


class TestWelcomeScreen:
    """Tests for the welcome screen TUI."""

    @pytest.mark.asyncio
    async def test_welcome_renders_banner(self, welcome_app):
        """Test that the welcome screen renders the banner widget."""
        async with welcome_app.run_test() as pilot:
            banner = welcome_app.screen.query_one("#banner", Static)
            assert banner is not None

    @pytest.mark.asyncio
    async def test_welcome_renders_menu(self, welcome_app):
        """Test that the welcome screen renders the menu."""
        async with welcome_app.run_test() as pilot:
            menu = welcome_app.screen.query_one("#menu", OptionList)
            assert menu is not None
            assert menu.option_count == 2  # init + help for unconfigured

    @pytest.mark.asyncio
    async def test_welcome_configured_menu(self, welcome_app_configured):
        """Test that configured welcome screen shows all menu items."""
        async with welcome_app_configured.run_test() as pilot:
            menu = welcome_app_configured.screen.query_one("#menu", OptionList)
            assert menu.option_count == 5  # run, status, review, senders, help

    @pytest.mark.asyncio
    async def test_welcome_shows_run_summary(self, welcome_app_configured):
        """Test that run summary is shown when available."""
        async with welcome_app_configured.run_test() as pilot:
            summary = welcome_app_configured.screen.query_one("#run-summary", Static)
            assert summary is not None

    @pytest.mark.asyncio
    async def test_welcome_escape_exits(self, welcome_app):
        """Test that pressing escape exits the app with None."""
        async with welcome_app.run_test() as pilot:
            await pilot.press("escape")

    @pytest.mark.asyncio
    async def test_welcome_menu_selection(self, welcome_app):
        """Test that selecting a menu item exits with the command value."""
        async with welcome_app.run_test() as pilot:
            await pilot.press("enter")  # Select first item


# ============================================================================
# Review Screen Tests
# ============================================================================


class TestReviewScreen:
    """Tests for the review screen TUI."""

    @pytest.mark.asyncio
    async def test_review_renders_table(self, sample_senders):
        """Test that the review screen renders a DataTable."""
        app = ReviewApp(senders=sample_senders)
        async with app.run_test() as pilot:
            table = app.screen.query_one("#review-table", DataTable)
            assert table is not None
            assert table.row_count == 3

    @pytest.mark.asyncio
    async def test_review_summary_bar(self, sample_senders):
        """Test that the summary bar renders."""
        app = ReviewApp(senders=sample_senders)
        async with app.run_test() as pilot:
            summary = app.screen.query_one("#review-summary", Static)
            assert summary is not None

    @pytest.mark.asyncio
    async def test_review_set_decision(self, sample_senders):
        """Test that pressing u sets unsub decision."""
        app = ReviewApp(senders=sample_senders)
        async with app.run_test() as pilot:
            await pilot.press("u")  # Set unsub on first row

    @pytest.mark.asyncio
    async def test_review_confirm_exits(self, sample_senders):
        """Test that pressing enter confirms and exits."""
        app = ReviewApp(senders=sample_senders)
        async with app.run_test() as pilot:
            await pilot.press("u")  # Set a decision
            await pilot.press("enter")  # Confirm

    @pytest.mark.asyncio
    async def test_review_escape_exits(self, sample_senders):
        """Test that escape exits without confirming."""
        app = ReviewApp(senders=sample_senders)
        async with app.run_test() as pilot:
            await pilot.press("escape")


# ============================================================================
# Senders Screen Tests
# ============================================================================


class TestSendersScreen:
    """Tests for the senders screen TUI."""

    @pytest.mark.asyncio
    async def test_senders_renders_table(self, sample_senders):
        """Test that the senders screen renders a DataTable."""
        app = SendersApp(senders=sample_senders)
        async with app.run_test() as pilot:
            table = app.screen.query_one("#senders-table", DataTable)
            assert table is not None
            assert table.row_count == 3

    @pytest.mark.asyncio
    async def test_senders_escape_exits(self, sample_senders):
        """Test that escape exits the senders screen."""
        app = SendersApp(senders=sample_senders)
        async with app.run_test() as pilot:
            await pilot.press("escape")


# ============================================================================
# Undo Screen Tests
# ============================================================================


class TestUndoScreen:
    """Tests for the undo screen TUI."""

    @pytest.mark.asyncio
    async def test_undo_renders_table(self, sample_unsubs):
        """Test that the undo screen renders a DataTable."""
        app = UndoApp(recent_unsubs=sample_unsubs)
        async with app.run_test() as pilot:
            table = app.screen.query_one("#undo-table", DataTable)
            assert table is not None
            assert table.row_count == 2

    @pytest.mark.asyncio
    async def test_undo_toggle_selection(self, sample_unsubs):
        """Test that enter toggles undo selection."""
        app = UndoApp(recent_unsubs=sample_unsubs)
        async with app.run_test() as pilot:
            await pilot.press("enter")  # Toggle first row

    @pytest.mark.asyncio
    async def test_undo_escape_exits(self, sample_unsubs):
        """Test that escape exits with selections."""
        app = UndoApp(recent_unsubs=sample_unsubs)
        async with app.run_test() as pilot:
            await pilot.press("escape")


# ============================================================================
# Status Dashboard Tests
# ============================================================================


class TestStatusScreen:
    """Tests for the status dashboard TUI."""

    @pytest.mark.asyncio
    async def test_status_renders(self, sample_status_data):
        """Test that the status dashboard renders."""
        app = StatusApp(status_data=sample_status_data)
        async with app.run_test() as pilot:
            # Should have stat panels
            panels = app.screen.query(".stat-panel")
            assert len(panels) == 4

    @pytest.mark.asyncio
    async def test_status_escape_exits(self, sample_status_data):
        """Test that escape exits the status screen."""
        app = StatusApp(status_data=sample_status_data)
        async with app.run_test() as pilot:
            await pilot.press("escape")
