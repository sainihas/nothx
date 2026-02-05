"""Textual TUI screens for nothx."""

from __future__ import annotations

import os
from typing import Any

from rich.panel import Panel
from rich.style import Style
from rich.text import Text
from textual import on
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.screen import Screen
from textual.timer import Timer
from textual.widgets import DataTable, Footer, Header, OptionList, Static
from textual.widgets.option_list import Option

from .theme import (
    BANNER_LINES,
    GRADIENT_COLORS,
    apply_gradient,
    build_welcome_panel,
)

# ---------------------------------------------------------------------------
# Shared CSS theme — orange accent matching nothx branding
# ---------------------------------------------------------------------------

NOTHX_CSS = """
Screen {
    background: $surface;
}

#banner {
    width: 100%;
    height: auto;
}

#run-summary {
    width: 100%;
    color: $text-muted;
    margin: 0 0 0 0;
}

#get-started {
    width: 100%;
    margin: 1 0 0 0;
    color: $text;
}

#menu {
    width: 100%;
    height: auto;
    max-height: 12;
    margin: 0 0 1 0;
}

OptionList > .option-list--option-highlighted {
    background: #ffaf00 20%;
    color: #ffaf00;
}

OptionList:focus > .option-list--option-highlighted {
    background: #ffaf00 30%;
    color: #ffaf00;
}

/* --- Review / Senders / Undo DataTable screens --- */

.screen-title {
    width: 100%;
    margin: 1 0 0 0;
    color: $text;
    text-style: bold;
}

.summary-bar {
    width: 100%;
    height: 1;
    margin: 0 0 0 0;
    color: $text-muted;
}

.search-row {
    width: 100%;
    height: 3;
    margin: 0 0 0 0;
}

.search-row Input {
    width: 100%;
}

#filter-bar {
    width: 100%;
    height: 3;
    margin: 0 0 0 0;
}

#filter-bar Button {
    min-width: 12;
    margin: 0 1 0 0;
}

DataTable {
    height: 1fr;
}

DataTable > .datatable--cursor {
    background: #ffaf00 20%;
    color: #ffaf00;
}

/* --- Status dashboard --- */

.stat-panel {
    width: 1fr;
    height: auto;
    min-height: 5;
    margin: 0 1 0 0;
    border: solid #ffaf00;
    padding: 1 2;
    text-align: center;
}

.stat-panel:last-of-type {
    margin: 0;
}

.stat-value {
    text-style: bold;
    color: #ff00ff;
}

.stat-label {
    color: $text-muted;
}

#stats-row {
    width: 100%;
    height: auto;
    margin: 1 0 1 0;
}

.status-section {
    width: 100%;
    margin: 1 0 0 0;
}

.status-section-title {
    color: $text;
    text-style: bold;
    margin: 0 0 0 0;
}

.status-item {
    color: $text-muted;
    margin: 0 0 0 2;
}
"""


# ============================================================================
# Welcome Screen
# ============================================================================


class WelcomeScreen(Screen):
    """Welcome screen with animated gradient banner and command menu."""

    BINDINGS = [
        Binding("escape", "quit", "Quit", show=True),
        Binding("q", "quit", "Quit", show=False),
    ]

    def __init__(
        self,
        greeting: str,
        version_line: str,
        run_summary: str | None,
        is_configured: bool,
    ) -> None:
        super().__init__()
        self._greeting = greeting
        self._version_line = version_line
        self._run_summary = run_summary
        self._is_configured = is_configured
        self._visible_cols = 0
        self._max_cols = max(len(line) for line in BANNER_LINES)
        self._animation_timer: Timer | None = None

    def compose(self) -> ComposeResult:
        yield Static("", id="banner")
        if self._run_summary:
            yield Static(self._run_summary, id="run-summary")
        yield Static("Get started", id="get-started")

        menu = OptionList(id="menu")
        if not self._is_configured:
            menu.add_option(Option("Set up email accounts and API key", id="init"))
            menu.add_option(Option("View all commands", id="help"))
        else:
            menu.add_option(Option("Scan inbox and unsubscribe", id="run"))
            menu.add_option(Option("Show current stats", id="status"))
            menu.add_option(Option("Review pending decisions", id="review"))
            menu.add_option(Option("List all tracked senders", id="senders"))
            menu.add_option(Option("View all commands", id="help"))
        yield menu
        yield Footer()

    def on_mount(self) -> None:
        """Start the banner animation (or render static if animations disabled)."""
        if os.environ.get("NOTHX_NO_ANIMATION"):
            self._render_full_banner()
        else:
            self._render_banner_frame()
            self._animation_timer = self.set_interval(0.012, self._advance_animation)
        # Focus the menu
        self.query_one("#menu", OptionList).focus()

    def _advance_animation(self) -> None:
        """Advance the typewriter animation by one column."""
        self._visible_cols += 1
        self._render_banner_frame()
        if self._visible_cols >= self._max_cols:
            if self._animation_timer is not None:
                self._animation_timer.stop()
                self._animation_timer = None

    def _render_banner_frame(self) -> None:
        """Render the banner at the current animation frame."""
        banner_text = apply_gradient(BANNER_LINES, visible_cols=self._visible_cols)
        panel = build_welcome_panel(self._greeting, banner_text, self._version_line)
        self.query_one("#banner", Static).update(panel)

    def _render_full_banner(self) -> None:
        """Render the full banner without animation."""
        banner_text = apply_gradient(BANNER_LINES)
        panel = build_welcome_panel(self._greeting, banner_text, self._version_line)
        self.query_one("#banner", Static).update(panel)

    @on(OptionList.OptionSelected)
    def on_menu_selected(self, event: OptionList.OptionSelected) -> None:
        """Handle menu item selection."""
        self.app.exit(result=event.option.id)

    def action_quit(self) -> None:
        """Exit the app with no selection."""
        self.app.exit(result=None)


class NothxApp(App):
    """Main nothx TUI application — launches the welcome screen."""

    CSS = NOTHX_CSS
    TITLE = "nothx"

    def __init__(
        self,
        greeting: str,
        version_line: str,
        run_summary: str | None = None,
        is_configured: bool = False,
    ) -> None:
        super().__init__()
        self._greeting = greeting
        self._version_line = version_line
        self._run_summary = run_summary
        self._is_configured = is_configured

    def on_mount(self) -> None:
        self.push_screen(
            WelcomeScreen(
                greeting=self._greeting,
                version_line=self._version_line,
                run_summary=self._run_summary,
                is_configured=self._is_configured,
            )
        )


# ============================================================================
# Review Screen
# ============================================================================


class ReviewScreen(Screen):
    """DataTable-based review of senders needing decisions."""

    BINDINGS = [
        Binding("escape", "quit", "Done", show=True),
        Binding("u", "set_unsub", "Unsub", show=True),
        Binding("k", "set_keep", "Keep", show=True),
        Binding("b", "set_block", "Block", show=True),
        Binding("s", "set_skip", "Skip", show=True),
        Binding("enter", "confirm", "Confirm all", show=True),
    ]

    def __init__(self, senders: list[dict[str, Any]], title: str = "Review Senders") -> None:
        super().__init__()
        self._senders = senders
        self._title = title
        # Track decisions: domain -> action string
        self._decisions: dict[str, str | None] = {s["domain"]: None for s in senders}

    def compose(self) -> ComposeResult:
        yield Static(self._title, classes="screen-title")
        yield Static("", id="review-summary", classes="summary-bar")
        table = DataTable(id="review-table")
        table.cursor_type = "row"
        yield table
        yield Footer()

    def on_mount(self) -> None:
        table = self.query_one("#review-table", DataTable)
        table.add_column("Domain", key="domain")
        table.add_column("Emails", key="emails")
        table.add_column("AI Rec", key="ai_rec")
        table.add_column("Confidence", key="confidence")
        self._decision_col = table.add_column("Decision", key="decision")
        for sender in self._senders:
            ai_class = sender.get("ai_classification", "-")
            confidence = sender.get("ai_confidence")
            conf_str = f"{confidence:.0%}" if confidence else "-"
            table.add_row(
                sender["domain"],
                str(sender.get("total_emails", 0)),
                ai_class or "-",
                conf_str,
                "-",
                key=sender["domain"],
            )
        self._update_summary()
        table.focus()

    def _set_decision(self, action: str) -> None:
        """Set the decision for the currently highlighted row."""
        table = self.query_one("#review-table", DataTable)
        if table.row_count == 0:
            return
        row_key, _ = table.coordinate_to_cell_key(table.cursor_coordinate)
        domain = str(row_key.value)
        self._decisions[domain] = action

        # Update the Decision column in the table
        labels = {"unsub": "[red]Unsub[/red]", "keep": "[green]Keep[/green]",
                  "block": "[bold red]Block[/bold red]", "skip": "[yellow]Skip[/yellow]"}
        label = Text.from_markup(labels.get(action, action))
        table.update_cell(row_key, self._decision_col, label)

        # Move to next row
        if table.cursor_coordinate.row < table.row_count - 1:
            table.move_cursor(row=table.cursor_coordinate.row + 1)

        self._update_summary()

    def _update_summary(self) -> None:
        """Update the summary bar with decision counts."""
        counts: dict[str, int] = {}
        for action in self._decisions.values():
            if action:
                counts[action] = counts.get(action, 0) + 1
        decided = sum(counts.values())
        total = len(self._decisions)
        parts = [f"{decided}/{total} decided"]
        if counts.get("unsub"):
            parts.append(f"[red]{counts['unsub']} unsub[/red]")
        if counts.get("keep"):
            parts.append(f"[green]{counts['keep']} keep[/green]")
        if counts.get("block"):
            parts.append(f"[bold red]{counts['block']} block[/bold red]")
        if counts.get("skip"):
            parts.append(f"[yellow]{counts['skip']} skip[/yellow]")
        self.query_one("#review-summary", Static).update(Text.from_markup(" · ".join(parts)))

    def action_set_unsub(self) -> None:
        self._set_decision("unsub")

    def action_set_keep(self) -> None:
        self._set_decision("keep")

    def action_set_block(self) -> None:
        self._set_decision("block")

    def action_set_skip(self) -> None:
        self._set_decision("skip")

    def action_confirm(self) -> None:
        """Exit with all decisions."""
        self.app.exit(result=self._decisions)

    def action_quit(self) -> None:
        """Exit without confirming (returns None)."""
        self.app.exit(result=None)


class ReviewApp(App):
    """Short-lived app for reviewing senders."""

    CSS = NOTHX_CSS
    TITLE = "nothx — Review"

    def __init__(self, senders: list[dict[str, Any]], title: str = "Review Senders") -> None:
        super().__init__()
        self._senders = senders
        self._title = title

    def on_mount(self) -> None:
        self.push_screen(ReviewScreen(senders=self._senders, title=self._title))


# ============================================================================
# Senders Screen
# ============================================================================


class SendersScreen(Screen):
    """Browsable DataTable of all tracked senders."""

    BINDINGS = [
        Binding("escape", "quit", "Exit", show=True),
        Binding("u", "set_unsub", "Unsub", show=True),
        Binding("k", "set_keep", "Keep", show=True),
        Binding("/", "focus_search", "Search", show=True),
    ]

    def __init__(self, senders: list[dict[str, Any]]) -> None:
        super().__init__()
        self._all_senders = senders
        self._filtered_senders = senders
        self._status_changes: dict[str, str] = {}

    def compose(self) -> ComposeResult:
        from textual.widgets import Input

        yield Static(
            f"[bold]Tracked Senders[/bold] ({len(self._all_senders)} total)",
            classes="screen-title",
        )
        yield Input(placeholder="Type to filter by domain...", id="sender-search")
        yield Static("", id="senders-summary", classes="summary-bar")
        table = DataTable(id="senders-table")
        table.cursor_type = "row"
        yield table
        yield Footer()

    def on_mount(self) -> None:
        self._populate_table(self._all_senders)
        self.query_one("#senders-table", DataTable).focus()

    def _populate_table(self, senders: list[dict[str, Any]]) -> None:
        """Populate or repopulate the table with the given senders."""
        table = self.query_one("#senders-table", DataTable)
        table.clear(columns=True)
        table.add_column("Domain", key="domain")
        table.add_column("Emails", key="emails")
        self._status_col = table.add_column("Status", key="status")
        table.add_column("Last Seen", key="last_seen")
        status_styles = {
            "unsubscribed": "[red]Unsubscribed[/red]",
            "keep": "[green]Keep[/green]",
            "blocked": "[bold red]Blocked[/bold red]",
            "unknown": "[yellow]Pending[/yellow]",
        }
        for sender in senders:
            status = sender.get("status", "unknown")
            status_display = Text.from_markup(status_styles.get(status, status.title()))
            last_seen = sender.get("last_seen", "-")
            if last_seen and last_seen != "-":
                try:
                    from datetime import datetime

                    import humanize

                    last_dt = datetime.fromisoformat(last_seen)
                    last_seen = humanize.naturaltime(last_dt)
                except (ValueError, TypeError, ImportError):
                    last_seen = last_seen[:10] if last_seen else "-"
            table.add_row(
                sender["domain"],
                str(sender.get("total_emails", 0)),
                status_display,
                last_seen or "-",
                key=sender["domain"],
            )
        # Update count
        self.query_one(".screen-title", Static).update(
            Text.from_markup(f"[bold]Tracked Senders[/bold] ({len(senders)} shown)")
        )

    @on(DataTable.HeaderSelected)
    def on_header_click(self, event: DataTable.HeaderSelected) -> None:
        """Sort the table when a column header is clicked."""
        col_key = str(event.column_key.value) if event.column_key else ""
        key_map = {
            "domain": "domain",
            "emails": "total_emails",
            "status": "status",
            "last_seen": "last_seen",
        }
        sort_key = key_map.get(col_key, "domain")
        reverse = sort_key == "total_emails"  # Numbers sort descending
        self._filtered_senders = sorted(
            self._filtered_senders,
            key=lambda s: s.get(sort_key, ""),
            reverse=reverse,
        )
        self._populate_table(self._filtered_senders)

    def _on_input_changed(self, event: Any) -> None:
        """Filter senders as user types in the search box."""
        from textual.widgets import Input

        if not isinstance(event.input, Input) or event.input.id != "sender-search":
            return
        query = event.value.lower().strip()
        if query:
            self._filtered_senders = [
                s for s in self._all_senders if query in s.get("domain", "").lower()
            ]
        else:
            self._filtered_senders = self._all_senders
        self._populate_table(self._filtered_senders)

    @on(DataTable.RowSelected)
    def on_row_selected(self, event: DataTable.RowSelected) -> None:
        """Show sender details when a row is selected (Enter)."""
        domain = str(event.row_key.value)
        sender = next((s for s in self._all_senders if s["domain"] == domain), None)
        if sender:
            subjects = sender.get("sample_subjects", "").split("|")[:3]
            subjects_str = ", ".join(s for s in subjects if s) or "None"
            details = (
                f"[bold]{domain}[/bold]\n"
                f"  Emails: {sender.get('total_emails', 0)}\n"
                f"  Status: {sender.get('status', 'unknown')}\n"
                f"  Subjects: {subjects_str}"
            )
            self.query_one("#senders-summary", Static).update(
                Text.from_markup(details)
            )

    def _change_status(self, new_status: str) -> None:
        """Change the status of the currently selected sender."""
        table = self.query_one("#senders-table", DataTable)
        if table.row_count == 0:
            return
        row_key, _ = table.coordinate_to_cell_key(table.cursor_coordinate)
        domain = str(row_key.value)
        self._status_changes[domain] = new_status
        status_styles = {
            "unsub": "[red]Unsub[/red]",
            "keep": "[green]Keep[/green]",
        }
        label = Text.from_markup(status_styles.get(new_status, new_status))
        table.update_cell(row_key, self._status_col, label)

    def action_set_unsub(self) -> None:
        self._change_status("unsub")

    def action_set_keep(self) -> None:
        self._change_status("keep")

    def action_focus_search(self) -> None:
        from textual.widgets import Input

        self.query_one("#sender-search", Input).focus()

    def action_quit(self) -> None:
        self.app.exit(result=self._status_changes)


class SendersApp(App):
    """Short-lived app for browsing senders."""

    CSS = NOTHX_CSS
    TITLE = "nothx — Senders"

    def __init__(self, senders: list[dict[str, Any]]) -> None:
        super().__init__()
        self._senders = senders

    def on_mount(self) -> None:
        self.push_screen(SendersScreen(senders=self._senders))


# ============================================================================
# Undo Screen
# ============================================================================


class UndoScreen(Screen):
    """DataTable of recent unsubscribes with select-to-undo."""

    BINDINGS = [
        Binding("escape", "quit", "Exit", show=True),
        Binding("enter", "toggle_undo", "Undo selected", show=True),
        Binding("space", "toggle_undo", "Undo selected", show=False),
    ]

    def __init__(self, recent_unsubs: list[dict[str, Any]]) -> None:
        super().__init__()
        self._recent_unsubs = recent_unsubs
        self._to_undo: set[str] = set()

    def compose(self) -> ComposeResult:
        yield Static(
            "[bold]Recent Unsubscribes[/bold] (last 30 days)",
            classes="screen-title",
        )
        yield Static("Select senders to undo, then press Escape to apply", id="undo-hint",
                      classes="summary-bar")
        table = DataTable(id="undo-table")
        table.cursor_type = "row"
        yield table
        yield Footer()

    def on_mount(self) -> None:
        table = self.query_one("#undo-table", DataTable)
        self._undo_col = table.add_column("Undo?", key="undo")
        table.add_column("Domain", key="domain")
        table.add_column("Emails", key="emails")
        table.add_column("Date", key="date")
        for item in self._recent_unsubs:
            date_str = item.get("attempted_at", "")[:10] if item.get("attempted_at") else "-"
            table.add_row(
                " ",
                item["domain"],
                str(item.get("total_emails", 0)),
                date_str,
                key=item["domain"],
            )
        table.focus()

    def action_toggle_undo(self) -> None:
        """Toggle the undo marker for the current row."""
        table = self.query_one("#undo-table", DataTable)
        if table.row_count == 0:
            return
        row_key, _ = table.coordinate_to_cell_key(table.cursor_coordinate)
        domain = str(row_key.value)
        if domain in self._to_undo:
            self._to_undo.discard(domain)
            table.update_cell(row_key, self._undo_col, " ")
        else:
            self._to_undo.add(domain)
            table.update_cell(row_key, self._undo_col, Text("✓", style=Style(color="green")))

        # Move to next row
        if table.cursor_coordinate.row < table.row_count - 1:
            table.move_cursor(row=table.cursor_coordinate.row + 1)

        count = len(self._to_undo)
        hint = f"{count} selected to undo" if count else "Select senders to undo, then press Escape to apply"
        self.query_one("#undo-hint", Static).update(hint)

    def action_quit(self) -> None:
        self.app.exit(result=self._to_undo)


class UndoApp(App):
    """Short-lived app for undoing unsubscribes."""

    CSS = NOTHX_CSS
    TITLE = "nothx — Undo"

    def __init__(self, recent_unsubs: list[dict[str, Any]]) -> None:
        super().__init__()
        self._recent_unsubs = recent_unsubs

    def on_mount(self) -> None:
        self.push_screen(UndoScreen(recent_unsubs=self._recent_unsubs))


# ============================================================================
# Status Dashboard
# ============================================================================


class StatusScreen(Screen):
    """Dashboard showing nothx stats, accounts, config, and recent activity."""

    BINDINGS = [
        Binding("escape", "quit", "Exit", show=True),
        Binding("q", "quit", "Exit", show=False),
    ]

    def __init__(self, status_data: dict[str, Any]) -> None:
        super().__init__()
        self._data = status_data

    def compose(self) -> ComposeResult:
        yield Static("[bold]nothx Status[/bold]", classes="screen-title")

        # Stat panels row
        stats = self._data.get("stats", {})
        success_rate = self._data.get("success_rate", 0)
        with Horizontal(id="stats-row"):
            yield Static(
                Text.from_markup(
                    f"[bold magenta]{stats.get('total_senders', 0)}[/bold magenta]\nSenders"
                ),
                classes="stat-panel",
            )
            yield Static(
                Text.from_markup(
                    f"[bold magenta]{stats.get('unsubscribed', 0)}[/bold magenta]\nUnsubbed"
                ),
                classes="stat-panel",
            )
            yield Static(
                Text.from_markup(
                    f"[bold magenta]{stats.get('kept', 0)}[/bold magenta]\nKept"
                ),
                classes="stat-panel",
            )
            yield Static(
                Text.from_markup(
                    f"[bold magenta]{success_rate:.0f}%[/bold magenta]\nSuccess"
                ),
                classes="stat-panel",
            )

        # Accounts section
        accounts = self._data.get("accounts", {})
        if accounts:
            yield Static("Accounts", classes="status-section-title")
            for name, acc in accounts.items():
                default_mark = " (default)" if name == self._data.get("default_account") else ""
                yield Static(
                    f"  {acc.get('email', name)} ({acc.get('provider', '?')}){default_mark}",
                    classes="status-item",
                )

        # Configuration section
        yield Static("Configuration", classes="status-section-title")
        ai_data = self._data.get("ai", {})
        if ai_data.get("enabled"):
            yield Static(
                Text.from_markup(f"  AI: [green]enabled[/green] ({ai_data.get('provider', '?')})"),
                classes="status-item",
            )
        else:
            yield Static(
                Text.from_markup("  AI: [yellow]disabled[/yellow] (heuristics only)"),
                classes="status-item",
            )
        yield Static(f"  Mode: {self._data.get('operation_mode', '?')}", classes="status-item")
        yield Static(f"  Scan days: {self._data.get('scan_days', '?')}", classes="status-item")

        # Details section
        yield Static("Details", classes="status-section-title")
        successful = self._data.get("successful_unsubs", 0)
        failed = self._data.get("failed_unsubs", 0)
        if successful + failed > 0:
            yield Static(
                Text.from_markup(
                    f"  Unsubscribe results: [green]{successful} successful[/green], "
                    f"[red]{failed} failed[/red]"
                ),
                classes="status-item",
            )
        yield Static(
            f"  Pending review: {stats.get('pending_review', 0)}",
            classes="status-item",
        )
        yield Static(f"  Total runs: {stats.get('total_runs', 0)}", classes="status-item")
        last_run = self._data.get("last_run_display")
        if last_run:
            yield Static(f"  Last run: {last_run}", classes="status-item")

        # Schedule section
        schedule = self._data.get("schedule")
        if schedule:
            yield Static("Schedule", classes="status-section-title")
            yield Static(f"  Type: {schedule.get('type', '?')}", classes="status-item")
            yield Static(f"  Frequency: {schedule.get('frequency', '?')}", classes="status-item")
        else:
            yield Static(
                Text.from_markup("[yellow]No automatic schedule configured[/yellow]"),
                classes="status-item",
            )

        yield Footer()

    def action_quit(self) -> None:
        self.app.exit(result=None)


class StatusApp(App):
    """Short-lived app for the status dashboard."""

    CSS = NOTHX_CSS
    TITLE = "nothx — Status"

    def __init__(self, status_data: dict[str, Any]) -> None:
        super().__init__()
        self._status_data = status_data

    def on_mount(self) -> None:
        self.push_screen(StatusScreen(status_data=self._status_data))
