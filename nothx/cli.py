"""Command-line interface for nothx."""

import csv
import json
import re
from datetime import datetime
from typing import Any

import click
import humanize
import questionary
from questionary import Style as QStyle
from rich.columns import Columns
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TaskProgressColumn, TextColumn
from rich.prompt import Confirm
from rich.rule import Rule
from rich.table import Table
from rich.tree import Tree

from . import __version__, db
from .classifier import ClassificationEngine, get_learner
from .classifier.ai import test_ai_connection
from .config import AccountConfig, Config, get_config_dir
from .imap import test_account
from .models import Action, RunStats, SenderStatus, UserAction
from .scanner import scan_inbox
from .scheduler import get_schedule_status, install_schedule, uninstall_schedule
from .theme import console, print_animated_welcome
from .unsubscriber import unsubscribe

# Questionary style — orange1 highlight matching our logo color
Q_STYLE = QStyle(
    [
        ("highlighted", "fg:#ffaf00"),
        ("pointer", "fg:#ffaf00"),
        ("selected", "fg:#ffaf00"),
        ("questionmark", "fg:green"),
        ("answer", "fg:green"),
    ]
)
Q_POINTER = "›"
Q_COMMON: dict[str, Any] = {"instruction": " ", "style": Q_STYLE, "pointer": Q_POINTER}


def _key(k: str) -> str:
    """Render a single keycap with rounded pill shape using half-block edges."""
    return f"[grey19]▐[/][grey50 on grey19] {k} [/][grey19]▌[/]"


_key_hints_shown = False


def _styled_select(choices: list, **kwargs) -> str | None:
    """Run a styled questionary.select, replacing answer line with ✓ confirmation."""
    result = questionary.select(
        "",
        choices=choices,
        instruction=" ",
        style=Q_STYLE,
        qmark="",
        pointer=Q_POINTER,
        **kwargs,
    ).ask()
    if result is not None:
        # Find display label from Choice objects or plain strings
        label = str(result)
        for c in choices:
            if isinstance(c, questionary.Choice) and c.value == result:
                label = str(c.title) if c.title is not None else label
                break
        # Overwrite questionary's answer line with styled ✓ version
        # The \n ensures 1 blank line between the preceding header and ✓,
        # matching the gap questionary's blank prompt provided during browsing.
        console.file.write("\033[1A\033[2K\r")
        console.file.flush()
        console.print(f"\n  [green]✓ {label}[/green]")
    return result


def _select_header(label: str) -> None:
    """Print a section header with key hints on first call, plain header after."""
    global _key_hints_shown
    if not _key_hints_shown:
        _key_hints_shown = True
        console.print(
            f"\n\n[header]{label}[/header]    "
            f"{_key('↑')} {_key('↓')} [dim]navigate[/dim]  "
            f"{_key('⏎')} [dim]select[/dim]"
        )
    else:
        console.print(f"\n[header]{label}[/header]")


# Simple email validation regex
EMAIL_REGEX = re.compile(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")


def _is_valid_email(email: str) -> bool:
    """Validate email address format."""
    if not email:
        return False
    return bool(EMAIL_REGEX.match(email.strip()))


# Provider-specific app password instructions
APP_PASSWORD_INSTRUCTIONS: dict[str, tuple[str, ...]] = {
    "gmail": (
        "[warning]For Gmail, you need an App Password:[/warning]",
        "  1. Go to [link=https://myaccount.google.com/apppasswords]myaccount.google.com/apppasswords[/link]",
        "  2. Generate a new password for 'nothx'",
        "  3. Copy the 16-character code\n",
    ),
    "outlook": (
        "[warning]For Outlook/Live/Hotmail, you need an App Password:[/warning]",
        "  1. Go to [link=https://account.live.com/proofs/AppPassword]account.live.com/proofs/AppPassword[/link]",
        "  2. You may need to enable 2FA first at account.microsoft.com/security",
        "  3. Generate a new app password and copy it\n",
    ),
    "yahoo": (
        "[warning]For Yahoo Mail, you need an App Password:[/warning]",
        "  1. Go to [link=https://login.yahoo.com/account/security]login.yahoo.com/account/security[/link]",
        "  2. Enable 2-Step Verification if not already enabled",
        "  3. Click 'Generate app password' and select 'Other App'",
        "  4. Copy the generated password\n",
    ),
    "icloud": (
        "[warning]For iCloud Mail, you need an App-Specific Password:[/warning]",
        "  1. Go to [link=https://appleid.apple.com/account/manage]appleid.apple.com[/link]",
        "  2. Sign in and go to 'Sign-In and Security' > 'App-Specific Passwords'",
        "  3. Click '+' to generate a new password for 'nothx'",
        "  4. Copy the generated password\n",
    ),
}

# Provider-specific troubleshooting tips
TROUBLESHOOTING_TIPS: dict[str, tuple[str, ...]] = {
    "gmail": (
        "  • Verify your app password at [link=https://myaccount.google.com/apppasswords]myaccount.google.com/apppasswords[/link]",
    ),
    "outlook": (
        "  • Verify your app password at [link=https://account.live.com/proofs/AppPassword]account.live.com/proofs/AppPassword[/link]",
    ),
    "yahoo": (
        "  • Verify your app password at [link=https://login.yahoo.com/account/security]login.yahoo.com/account/security[/link]",
        "  • Make sure 2-Step Verification is enabled",
    ),
    "icloud": (
        "  • Verify your app password at [link=https://appleid.apple.com/account/manage]appleid.apple.com[/link]",
        "  • Go to 'Sign-In and Security' > 'App-Specific Passwords'",
    ),
}


def _get_greeting() -> str:
    """Get time-based greeting with user's first name if available."""
    import os as _os

    hour = datetime.now().hour
    if 5 <= hour < 12:
        emoji, greeting = "☀️", "Good morning"
    elif 12 <= hour < 17:
        emoji, greeting = "🌤️", "Good afternoon"
    elif 17 <= hour < 21:
        emoji, greeting = "🌆", "Good evening"
    else:
        emoji, greeting = "🌙", "Hey there"

    name = None
    for var in ("USER", "USERNAME", "LOGNAME"):
        if username := _os.environ.get(var):
            name = username.split(".")[0].capitalize()
            break

    if name:
        return f"{emoji}  {greeting}, {name}!"
    return f"{emoji}  {greeting}!"


def _build_version_line(config: Config) -> str:
    """Build the version + status string for display."""
    import sqlite3

    status_parts = [f"v{__version__}"]

    account_count = len(config.accounts)
    if account_count > 0:
        status_parts.append(f"{account_count} account{'s' if account_count != 1 else ''}")
    else:
        status_parts.append("not configured")

    try:
        db.init_db()
        stats = db.get_stats()
        if stats.get("last_run"):
            try:
                last_run = datetime.fromisoformat(stats["last_run"])
                status_parts.append(f"last scan {humanize.naturaltime(last_run)}")
            except (ValueError, TypeError):
                pass
        if stats.get("pending_review", 0) > 0:
            status_parts.append(f"{stats['pending_review']} pending")
    except (sqlite3.Error, OSError):
        pass

    return " · ".join(status_parts)


def _get_previous_run_summary_text() -> str | None:
    """Get brief summary text from the last run, or None."""
    import sqlite3

    try:
        activity = db.get_activity_log(limit=1)
        if activity and activity[0].get("type") == "run":
            r = activity[0]
            timestamp = r.get("timestamp", "")
            try:
                ts_dt = datetime.fromisoformat(timestamp)
                time_ago = humanize.naturaltime(ts_dt)
            except (ValueError, TypeError):
                time_ago = "recently"

            unsubbed = r.get("auto_unsubbed", 0)
            if unsubbed > 0:
                return f"Last run {time_ago} · unsubscribed from {unsubbed} sender{'s' if unsubbed != 1 else ''}"
    except (sqlite3.Error, OSError):
        pass
    return None


def _show_welcome_screen() -> None:
    """Show welcome screen with gradient panel and interactive command selector."""
    config = Config.load()
    greeting = _get_greeting()
    version_line = _build_version_line(config)

    # Animated gradient banner in a panel
    print_animated_welcome(greeting, version_line)

    # Show last run summary if available
    run_summary = _get_previous_run_summary_text()
    if run_summary:
        console.print(f"[muted]{run_summary}[/muted]")

    _select_header("Get started")

    if not config.accounts:
        choices = [
            questionary.Choice("Set up email accounts and API key", value="init"),
            questionary.Choice("View all commands", value="help"),
            questionary.Choice("Exit", value="exit"),
        ]
    else:
        choices = [
            questionary.Choice("Scan inbox and unsubscribe", value="run"),
            questionary.Choice("Show current stats", value="status"),
            questionary.Choice("Review pending decisions", value="review"),
            questionary.Choice("List all tracked senders", value="senders"),
            questionary.Choice("View all commands", value="help"),
            questionary.Choice("Exit", value="exit"),
        ]

    selected = _styled_select(choices)

    if selected is None or selected == "exit":
        console.print()
        return

    ctx = click.get_current_context()
    ctx.obj["from_welcome"] = True
    if selected == "init":
        ctx.invoke(init)
    elif selected == "run":
        ctx.invoke(run, auto=False, dry_run=False, verbose=False, account=())
    elif selected == "status":
        ctx.invoke(status, learning=False)
    elif selected == "review":
        ctx.invoke(review, show_all=False, show_keep=False, show_unsub=False)
    elif selected == "senders":
        ctx.invoke(senders, status=None, sort="date", as_json=False)
    elif selected == "help":
        console.print(ctx.get_help())


def _show_learning_status(config: Config) -> None:
    """Show learning system status and insights."""
    learner = get_learner()
    summary = learner.get_learning_summary()

    console.print("\n[header]Learning Status[/header]")
    console.print(Rule(style="dim"))

    # Overall stats
    console.print("\n[header]Training Data[/header]")
    console.print(f"  Total decisions learned from: [count]{summary['total_actions']}[/count]")
    console.print(f"  Corrections (overrode AI): [count]{summary['total_corrections']}[/count]")

    # Learned preferences
    console.print("\n[header]Your Preferences[/header]")

    # Open rate importance
    open_rate_desc = {
        "low": "Low (you often keep unread emails)",
        "high": "High (you rely heavily on open rates)",
        "normal": "Normal (default behavior)",
    }
    importance = summary.get("open_rate_importance", "normal")
    console.print(f"  Open rate importance: {open_rate_desc.get(importance, importance)}")

    # Volume sensitivity
    volume_desc = {
        "low": "Low (you tolerate high-volume senders)",
        "high": "High (you unsub from frequent senders)",
        "normal": "Normal (default behavior)",
    }
    sensitivity = summary.get("volume_sensitivity", "normal")
    console.print(f"  Volume sensitivity: {volume_desc.get(sensitivity, sensitivity)}")

    # Keyword patterns as tree
    keyword_patterns = summary.get("keyword_patterns", [])
    if keyword_patterns:
        tree = Tree(f"[header]Learned Patterns ({len(keyword_patterns)})[/header]")
        keep_branch = tree.add("[keep]Keep patterns[/keep]")
        unsub_branch = tree.add("[unsubscribe]Unsub patterns[/unsubscribe]")

        for pattern in keyword_patterns[:10]:  # Show top 10
            keyword = pattern["keyword"]
            tendency = pattern["tendency"]
            strength = pattern["strength"]
            count = pattern["sample_count"]

            label = f'"{keyword}" ({strength}, {count} examples)'
            if tendency == "keep":
                keep_branch.add(f"[keep]{label}[/keep]")
            else:
                unsub_branch.add(f"[unsubscribe]{label}[/unsubscribe]")

        console.print()
        console.print(tree)
    else:
        console.print(
            "\n[muted]No keyword patterns learned yet. Make more decisions to build patterns.[/muted]"
        )

    # AI analysis prompt
    if summary["total_actions"] >= 10 and config.ai.enabled:
        console.print(
            f"\n[muted]Tip: AI pattern analysis is available with {summary['total_actions']} decisions.[/muted]"
        )

    console.print()


@click.group(invoke_without_command=True)
@click.version_option(version=__version__)
@click.pass_context
def main(ctx):
    """nothx - Smart enough to say no.

    Set it up once. AI handles your inbox forever.
    """
    ctx.ensure_object(dict)
    if ctx.invoked_subcommand is None:
        _show_welcome_screen()


def _add_email_account(config: Config) -> tuple[str, AccountConfig] | None:
    """Interactive flow to add an email account. Returns (name, account) or None if cancelled."""
    # Email provider selection
    _select_header("Select your email provider")
    provider_choices = [
        questionary.Choice("Gmail", value="gmail"),
        questionary.Choice("Outlook / Live / Hotmail", value="outlook"),
        questionary.Choice("Yahoo Mail", value="yahoo"),
        questionary.Choice("iCloud Mail", value="icloud"),
    ]
    provider = _styled_select(provider_choices)

    if provider is None:  # User cancelled
        return None

    console.print()  # Gap after selection

    # Email address with validation
    while True:
        email = questionary.text("Email address:").ask()
        if not email:
            return None
        if _is_valid_email(email):
            break
        console.print("[error]Invalid email format. Please enter a valid email address.[/error]")

    # App password instructions
    if instructions := APP_PASSWORD_INSTRUCTIONS.get(provider):
        console.print()
        for line in instructions:
            console.print(line)
    else:
        console.print("\n[warning]Enter your email password or app password.[/warning]\n")

    password = questionary.password("App Password:").ask()
    if not password:
        return None

    # Test connection
    account = AccountConfig(provider=provider, email=email, password=password)
    with console.status("Testing connection..."):
        success, msg = test_account(account)

    if not success:
        console.print(f"[error]Connection failed: {msg}[/error]")
        return None

    console.print("[success]✓ Connected![/success]\n")

    # Generate account name from email
    account_name = email.split("@")[0] if "@" in email else "default"
    # Make unique if name exists
    base_name = account_name
    counter = 1
    while account_name in config.accounts:
        account_name = f"{base_name}_{counter}"
        counter += 1

    return account_name, account


@main.command()
@click.pass_context
def init(ctx):
    """Set up nothx with your email account and API key."""
    config = Config.load()

    if not (ctx.obj or {}).get("from_welcome"):
        greeting = _get_greeting()
        version_line = _build_version_line(config)
        print_animated_welcome(greeting, version_line)

    # Multi-account loop
    account_count = 0
    while True:
        result = _add_email_account(config)
        if result is None:
            if account_count == 0:
                console.print(
                    "[warning]No accounts configured. Run 'nothx init' to try again.[/warning]"
                )
                return
            break

        account_name, account = result
        config.accounts[account_name] = account
        if config.default_account is None:
            config.default_account = account_name
        account_count += 1

        console.print(f"[success]✓ Added account: {account.email}[/success]\n")

        # Ask to add another
        add_another = questionary.confirm(
            "Add another email account?",
            default=False,
        ).ask()

        if not add_another:
            break

    # AI Provider setup
    console.print("\n[header]AI Classification Setup[/header]")
    console.print("nothx can use AI to classify your emails more accurately.")
    console.print(
        "Your email [bold]headers only[/bold] (never bodies) are sent to the AI provider.\n"
    )

    from .classifier.providers import SUPPORTED_PROVIDERS

    # Build provider choices
    provider_choices = []
    for key, info in SUPPORTED_PROVIDERS.items():
        provider_choices.append(
            questionary.Choice(f"{info['name']} - {info['description']}", value=key)
        )

    _select_header("Select AI provider")
    provider = _styled_select(provider_choices, default="anthropic")

    if provider is None:
        console.print("[warning]AI setup cancelled.[/warning]")
        return

    config.ai.provider = provider

    if provider == "none":
        config.ai.enabled = False
        console.print("Running in heuristics-only mode.\n")
    elif provider == "ollama":
        config.ai.enabled = True
        config.ai.api_key = None

        # Ask for Ollama URL
        console.print()  # Gap after selection
        api_base = questionary.text(
            "Ollama URL:",
            default="http://localhost:11434",
        ).ask()
        config.ai.api_base = api_base

        # Ask for model
        from .classifier.providers.ollama_provider import OllamaProvider

        ollama = OllamaProvider(api_base=api_base)
        available_models = ollama.get_model_options()

        if available_models:
            _select_header("Select model")
            model = _styled_select(available_models, default=available_models[0])
            if model is not None:
                config.ai.model = model
        else:
            config.ai.model = "llama3.2"
            console.print("[warning]Could not fetch models. Using default: llama3.2[/warning]")

        with console.status("Testing Ollama connection..."):
            success, msg = test_ai_connection(config)

        if success:
            console.print("[success]✓ Ollama working![/success]\n")
        else:
            console.print(f"[warning]Ollama test failed: {msg}[/warning]")
            console.print("Continuing with heuristics-only mode.\n")
            config.ai.enabled = False
    else:
        # Cloud provider - needs API key
        provider_info = SUPPORTED_PROVIDERS[provider]
        config.ai.api_base = None  # Clear any stale Ollama URL

        console.print(f"\nGet your API key from: [link]{provider_info['key_url']}[/link]")

        api_key = questionary.text(
            f"{provider_info['name']} API key (leave empty to skip):",
        ).ask()

        if api_key and api_key.strip():
            config.ai.api_key = api_key.strip()
            config.ai.enabled = True

            # Set default model for provider
            from .classifier.providers import get_provider

            temp_provider = get_provider(provider, api_key=config.ai.api_key)
            if temp_provider:
                config.ai.model = temp_provider.default_model

            with console.status(f"Testing {provider_info['name']} connection..."):
                success, msg = test_ai_connection(config)

            if success:
                console.print(f"[success]✓ {provider_info['name']} working![/success]\n")
            else:
                console.print(f"[warning]AI test failed: {msg}[/warning]")
                console.print("Continuing with heuristics-only mode.\n")
                config.ai.enabled = False
        else:
            config.ai.enabled = False
            console.print("Running in heuristics-only mode.\n")

    # Initialize database
    db.init_db()

    # Save config
    config.save()
    console.print(f"[success]✓ Configuration saved to {get_config_dir()}[/success]\n")

    # First scan
    run_scan = questionary.confirm(
        "Run first scan now?",
        default=True,
    ).ask()

    if run_scan:
        _run_scan(config, verbose=True, dry_run=True)

    # Schedule setup
    schedule_runs = questionary.confirm(
        "Auto-schedule monthly runs?",
        default=True,
    ).ask()

    if schedule_runs:
        success, msg = install_schedule("monthly")
        if success:
            console.print(f"[success]✓ {msg}[/success]")
        else:
            console.print(f"[warning]{msg}[/warning]")

    console.print("\n[success]Setup complete![/success]")
    console.print("Run [bold]nothx status[/bold] to see current state.")
    console.print("Run [bold]nothx run[/bold] to process emails.")


@main.group(invoke_without_command=True)
@click.pass_context
def account(ctx):
    """Manage email accounts."""
    if ctx.invoked_subcommand is not None:
        return

    # Show interactive selector when no subcommand provided
    choices = [
        questionary.Choice("List configured accounts", value="list"),
        questionary.Choice("Add a new account", value="add"),
        questionary.Choice("Remove an account", value="remove"),
        questionary.Choice("Exit", value="exit"),
    ]

    _select_header("Manage accounts")
    selected = _styled_select(choices)

    if selected is None or selected == "exit":
        return

    if selected == "list":
        ctx.invoke(account_list)
    elif selected == "add":
        ctx.invoke(account_add)
    elif selected == "remove":
        ctx.invoke(account_remove)


@account.command("add")
def account_add():
    """Add a new email account."""
    config = Config.load()

    result = _add_email_account(config)
    if result is None:
        console.print("[warning]Account not added.[/warning]")
        return

    account_name, acc = result
    config.accounts[account_name] = acc
    if config.default_account is None:
        config.default_account = account_name
    config.save()

    console.print(f"\n[success]✓ Added account: {acc.email}[/success]")
    console.print(f"  Name: {account_name}")
    console.print(f"  Provider: {acc.provider}")


@account.command("list")
def account_list():
    """List configured email accounts."""
    config = Config.load()

    if not config.accounts:
        console.print("[warning]No accounts configured. Run 'nothx init' to add one.[/warning]")
        return

    console.print("\n[header]Configured Accounts[/header]\n")

    table = Table(show_header=True)
    table.add_column("Name")
    table.add_column("Email")
    table.add_column("Provider")
    table.add_column("Default")

    for name, acc in config.accounts.items():
        is_default = "✓" if name == config.default_account else ""
        table.add_row(name, acc.email, acc.provider, is_default)

    console.print(table)


@account.command("remove")
def account_remove():
    """Remove an email account."""
    config = Config.load()

    if not config.accounts:
        console.print("[warning]No accounts configured.[/warning]")
        return

    # Build choices list
    choices = [
        questionary.Choice(f"{name} ({acc.email})", value=name)
        for name, acc in config.accounts.items()
    ]
    choices.append(questionary.Choice("Cancel", value=None))

    _select_header("Select account to remove")
    account_name = _styled_select(choices)

    if account_name is None:
        console.print("Cancelled.")
        return

    # Confirm removal
    acc = config.accounts[account_name]
    confirm = questionary.confirm(
        f"Remove {acc.email}?",
        default=False,
    ).ask()

    if not confirm:
        console.print("Cancelled.")
        return

    del config.accounts[account_name]

    # Update default if needed
    if config.default_account == account_name:
        if config.accounts:
            config.default_account = next(iter(config.accounts.keys()))
        else:
            config.default_account = None

    config.save()
    console.print(f"[success]✓ Removed account: {acc.email}[/success]")


@main.command()
@click.option("--auto", is_flag=True, help="Run in automatic mode (no prompts)")
@click.option("--dry-run", is_flag=True, help="Show what would happen without taking action")
@click.option("--verbose", "-v", is_flag=True, help="Show detailed output")
@click.option(
    "--account",
    "-a",
    multiple=True,
    help="Scan specific account(s) - can be specified multiple times (default: all)",
)
def run(auto: bool, dry_run: bool, verbose: bool, account: tuple[str, ...]):
    """Scan inbox and process marketing emails."""
    config = Config.load()

    if not config.is_configured():
        console.print("[red]nothx is not configured. Run 'nothx init' first.[/red]")
        return

    # Validate accounts if specified
    accounts_to_scan: list[str] | None = None
    if account:
        # Build email-to-name map for efficient lookup
        email_to_name = {acc_config.email: name for name, acc_config in config.accounts.items()}

        accounts_to_scan = []
        for acc in account:
            # Support both account name and email address
            if acc in config.accounts:
                accounts_to_scan.append(acc)
            elif acc in email_to_name:
                accounts_to_scan.append(email_to_name[acc])
            else:
                console.print(f"[error]Account '{acc}' not found.[/error]")
                console.print(
                    f"Available: {', '.join(f'{n} ({a.email})' for n, a in config.accounts.items())}"
                )
                return

    db.init_db()

    if dry_run:
        console.print("[yellow]DRY RUN - no changes will be made[/yellow]\n")

    _run_scan(config, verbose=verbose, dry_run=dry_run, auto=auto, account_names=accounts_to_scan)


def _run_scan(
    config: Config,
    verbose: bool = False,
    dry_run: bool = False,
    auto: bool = False,
    account_names: list[str] | None = None,
):
    """Run the main scan and classification process."""
    stats = RunStats(
        ran_at=datetime.now(),
        mode="auto" if auto else "interactive",
    )

    # Phase 1: Scan inbox
    if account_names:
        if len(account_names) == 1:
            label = f"({account_names[0]})"
        else:
            label = f"({len(account_names)} accounts)"
    else:
        account_count = len(config.accounts)
        label = f"({account_count} account{'s' if account_count != 1 else ''})"
    console.print(f"\n[header]Phase 1/3: Scanning inbox {label}[/header]")

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
        transient=True,
    ) as progress:
        task = progress.add_task("Connecting to mailbox...", total=None)

        def on_account_start(email: str, _name: str, current: int, total: int) -> None:
            if total > 1:
                progress.update(task, description=f"Scanning {email}... ({current}/{total})")
            else:
                progress.update(task, description=f"Scanning {email}...")

        scan_result = scan_inbox(
            config, account_names=account_names, on_account_start=on_account_start
        )
        sender_stats = scan_result.sender_stats

    if not sender_stats:
        console.print("[success]✓ No marketing emails found.[/success]")
        return

    stats.emails_scanned = sum(s.total_emails for s in sender_stats.values())
    stats.unique_senders = len(sender_stats)

    console.print(
        f"[success]✓ Found [count]{stats.emails_scanned}[/count] emails from [count]{stats.unique_senders}[/count] senders[/success]"
    )

    # Phase 2: Classify senders
    console.print("\n[header]Phase 2/3: Classifying senders[/header]")
    engine = ClassificationEngine(config)

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        console=console,
        transient=True,
    ) as progress:
        task = progress.add_task("Analyzing senders...", total=len(sender_stats))
        classifications = engine.classify_batch(list(sender_stats.values()))
        progress.update(task, completed=len(sender_stats))

    # Process results
    to_unsub = []
    to_keep = []
    to_review = []
    to_block = []

    for domain, classification in classifications.items():
        sender = sender_stats[domain]

        if classification.action == Action.UNSUB:
            to_unsub.append((sender, classification))
        elif classification.action == Action.KEEP:
            to_keep.append((sender, classification))
        elif classification.action == Action.BLOCK:
            to_block.append((sender, classification))
        else:
            to_review.append((sender, classification))

    # Summary as tree
    tree = Tree("[success]✓ Classification complete[/success]")
    tree.add(f"[unsubscribe]{len(to_unsub)} to unsubscribe[/unsubscribe]")
    tree.add(f"[block]{len(to_block)} to block[/block]")
    tree.add(f"[keep]{len(to_keep)} to keep[/keep]")
    tree.add(f"[review]{len(to_review)} need review[/review]")
    console.print(tree)

    if verbose:
        _show_details(to_unsub, to_keep, to_review, to_block)

    # Optional manual review of decisions (not in auto mode)
    if not auto and not dry_run and (to_unsub or to_keep):
        console.print()
        review_decisions = questionary.confirm(
            "Review decisions before proceeding?",
            default=False,
        ).ask()

        if review_decisions:
            _select_header("Manual Review")
            console.print("[muted]Change any decisions you disagree with:[/muted]\n")

            # Review items marked for unsubscribe
            review_cancelled = False
            for sender, classification in to_unsub[:]:  # Slice to allow modification
                action = questionary.select(
                    f"[{sender.total_emails} emails] {sender.domain}",
                    choices=[
                        questionary.Choice("Unsubscribe (AI recommendation)", value="unsub"),
                        questionary.Choice("Keep instead", value="keep"),
                        questionary.Choice("Skip for now", value="skip"),
                    ],
                    default="unsub",
                    **Q_COMMON,
                ).ask()

                if action is None:
                    console.print("[muted]Review cancelled[/muted]")
                    review_cancelled = True
                    break

                if action == "keep":
                    to_unsub.remove((sender, classification))
                    to_keep.append((sender, classification))
                    console.print("  [keep]→ Changed to keep[/keep]")
                elif action == "skip":
                    to_unsub.remove((sender, classification))
                    to_review.append((sender, classification))
                    console.print("  [review]→ Moved to review[/review]")

            # Review items marked to keep (only if not cancelled)
            if not review_cancelled:
                for sender, classification in to_keep[:]:  # Slice to allow modification
                    action = questionary.select(
                        f"[{sender.total_emails} emails] {sender.domain}",
                        choices=[
                            questionary.Choice("Keep (AI recommendation)", value="keep"),
                            questionary.Choice("Unsubscribe instead", value="unsub"),
                            questionary.Choice("Skip for now", value="skip"),
                        ],
                        default="keep",
                        **Q_COMMON,
                    ).ask()

                    if action is None:
                        console.print("[muted]Review cancelled[/muted]")
                        break

                    if action == "unsub":
                        to_keep.remove((sender, classification))
                        to_unsub.append((sender, classification))
                        console.print("  [unsubscribe]→ Changed to unsubscribe[/unsubscribe]")
                    elif action == "skip":
                        to_keep.remove((sender, classification))
                        to_review.append((sender, classification))
                        console.print("  [review]→ Moved to review[/review]")

            # Updated summary
            # Updated summary as tree
            updated_tree = Tree("[header]Updated decisions[/header]")
            updated_tree.add(f"[unsubscribe]{len(to_unsub)} to unsubscribe[/unsubscribe]")
            updated_tree.add(f"[keep]{len(to_keep)} to keep[/keep]")
            updated_tree.add(f"[review]{len(to_review)} need review[/review]")
            console.print()
            console.print(updated_tree)

    # Phase 3: Execute unsubscribes (if not dry run)
    if not dry_run and (to_unsub or to_block):
        console.print()

        if auto or Confirm.ask(
            f"Unsubscribe from {len(to_unsub) + len(to_block)} senders?", default=True
        ):
            console.print("\n[header]Phase 3/3: Unsubscribing[/header]")

            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TaskProgressColumn(),
                console=console,
            ) as progress:
                task = progress.add_task("Processing...", total=len(to_unsub) + len(to_block))

                for sender, _ in to_unsub + to_block:
                    # Get a sample email with unsubscribe header from cache
                    email = scan_result.get_email_for_domain(sender.domain)
                    if email:
                        # Use the account the email came from (for correct mailto credentials)
                        account = config.get_account(email.account_name)
                        result = unsubscribe(email, config, account)
                        if result.success:
                            stats.auto_unsubbed += 1
                        else:
                            stats.failed += 1
                    progress.advance(task)

            console.print(f"\n[success]✓ Unsubscribed from {stats.auto_unsubbed} senders[/success]")
            if stats.failed:
                console.print(f"[warning]! {stats.failed} failed (logged for retry)[/warning]")

            # Undo reminder
            console.print("\n[muted]⏱  Run `nothx undo` to restore if needed[/muted]")

    # Update stats
    stats.kept = len(to_keep)
    stats.review_queued = len(to_review)

    # Mark keep senders
    for sender, _ in to_keep:
        db.update_sender_status(sender.domain, SenderStatus.KEEP)

    # Log run
    if not dry_run:
        db.log_run(stats)

    # Prompt about review queue
    if to_review and not auto:
        console.print(f"\n[yellow]{len(to_review)} senders need manual review.[/yellow]")
        console.print("Run [bold]nothx review[/bold] to process them.")


def _show_details(to_unsub, to_keep, to_review, to_block):
    """Show detailed classification results."""
    if to_unsub:
        console.print("\n[bold red]To Unsubscribe:[/bold red]")
        table = Table(show_header=True)
        table.add_column("Domain")
        table.add_column("Emails")
        table.add_column("Open Rate")
        table.add_column("Reason")
        for sender, classification in to_unsub[:10]:
            table.add_row(
                sender.domain,
                str(sender.total_emails),
                f"{sender.open_rate:.0f}%",
                classification.reasoning[:50],
            )
        console.print(table)

    if to_keep:
        console.print("\n[bold green]To Keep:[/bold green]")
        table = Table(show_header=True)
        table.add_column("Domain")
        table.add_column("Emails")
        table.add_column("Open Rate")
        table.add_column("Reason")
        for sender, classification in to_keep[:10]:
            table.add_row(
                sender.domain,
                str(sender.total_emails),
                f"{sender.open_rate:.0f}%",
                classification.reasoning[:50],
            )
        console.print(table)


@main.command()
@click.option("--learning", is_flag=True, help="Show learning insights and preferences")
def status(learning: bool):
    """Show current nothx status."""
    config = Config.load()

    if not config.is_configured():
        console.print("[error]nothx is not configured. Run 'nothx init' first.[/error]")
        return

    db.init_db()

    # If --learning flag, show learning status instead
    if learning:
        _show_learning_status(config)
        return

    console.print("\n[header]nothx Status[/header]")
    console.print(Rule(style="dim"))

    # Stats summary as columns
    stats = db.get_stats()
    successful, failed = db.get_unsub_success_rate()
    total_unsub_attempts = successful + failed
    success_rate = (successful / total_unsub_attempts * 100) if total_unsub_attempts > 0 else 0

    panel_data = [
        (f"[count]{stats['total_senders']}[/count]", "Senders"),
        (f"[count]{stats['unsubscribed']}[/count]", "Unsubbed"),
        (f"[count]{stats['kept']}[/count]", "Kept"),
        (f"[count]{success_rate:.0f}%[/count]", "Success"),
    ]
    stat_panels = [
        Panel(f"{value}\n[muted]{label}[/muted]", expand=True, border_style="dim")
        for value, label in panel_data
    ]
    console.print(Columns(stat_panels, equal=True, expand=True))

    # Account info
    console.print("\n[header]Accounts[/header]")
    for name, acc in config.accounts.items():
        is_default = " [muted](default)[/muted]" if name == config.default_account else ""
        console.print(f"  {acc.email} ({acc.provider}){is_default}")

    # AI status
    console.print("\n[header]Configuration[/header]")
    if config.ai.enabled:
        console.print(f"  AI: [success]enabled[/success] ({config.ai.provider})")
    else:
        console.print("  AI: [warning]disabled[/warning] (heuristics only)")
    console.print(f"  Mode: {config.operation_mode}")
    console.print(f"  Scan days: {config.scan_days}")

    # Detailed stats
    console.print("\n[header]Details[/header]")
    if total_unsub_attempts > 0:
        console.print(
            f"  Unsubscribe results: [success]{successful} successful[/success], "
            f"[error]{failed} failed[/error]"
        )

    console.print(f"  Pending review: [count]{stats['pending_review']}[/count]")
    console.print(f"  Total runs: [count]{stats['total_runs']}[/count]")

    if stats["last_run"]:
        try:
            last_run_dt = datetime.fromisoformat(stats["last_run"])
            relative_time = humanize.naturaltime(last_run_dt)
            console.print(f"  Last run: {relative_time}")
        except (ValueError, TypeError):
            console.print(f"  Last run: {stats['last_run']}")

    # Schedule status
    schedule = get_schedule_status()
    if schedule:
        console.print("\n[header]Schedule[/header]")
        console.print(f"  Type: {schedule['type']}")
        console.print(f"  Frequency: {schedule['frequency']}")
    else:
        console.print("\n[warning]No automatic schedule configured[/warning]")
        console.print("Run [bold]nothx schedule --monthly[/bold] to set up")

    console.print()


@main.command()
@click.option("--all", "show_all", is_flag=True, help="Show all pending senders")
@click.option("--keep", "show_keep", is_flag=True, help="Review senders marked to keep")
@click.option("--unsub", "show_unsub", is_flag=True, help="Review senders marked to unsubscribe")
def review(show_all: bool, show_keep: bool, show_unsub: bool):
    """Review senders that need manual decision.

    By default, shows only senders that need review (uncertain classification).
    Use --all to see all pending senders, or --keep/--unsub to filter by classification.
    """
    config = Config.load()

    if not config.is_configured():
        console.print("[error]nothx is not configured. Run 'nothx init' first.[/error]")
        return

    db.init_db()

    # Determine which senders to show
    if show_keep:
        senders = db.get_senders_by_status(SenderStatus.KEEP)
        filter_label = "marked to keep"
    elif show_unsub:
        senders = db.get_senders_by_status(SenderStatus.UNSUBSCRIBED)
        filter_label = "marked to unsubscribe"
    elif show_all:
        senders = db.get_senders_by_status(SenderStatus.UNKNOWN)
        filter_label = "pending"
    else:
        # Default: only senders that need review (uncertain)
        senders = db.get_senders_for_review()
        filter_label = "needing review"

    if not senders:
        console.print(f"[success]No senders {filter_label}![/success]")
        return

    _select_header(f"{len(senders)} senders {filter_label}")

    for sender in senders:
        domain = sender["domain"]
        total = sender["total_emails"]
        subjects = sender.get("sample_subjects", "").split("|")[:3]

        console.print(f"[bold][{total} emails] [domain]{domain}[/domain][/bold]")
        if sender.get("ai_classification"):
            confidence = sender.get("ai_confidence", 0)
            console.print(
                f"  [muted]AI says: {sender['ai_classification']} ({confidence:.0%} confident)[/muted]"
            )
        if subjects and subjects[0]:
            console.print(f"  [muted]Subjects: {', '.join(s for s in subjects if s)}[/muted]")

        # Interactive selector with clear labels
        choice = questionary.select(
            f"What would you like to do with {domain}?",
            choices=[
                questionary.Choice("Unsubscribe - Stop receiving emails", value="unsub"),
                questionary.Choice("Keep - Continue receiving", value="keep"),
                questionary.Choice("Block - Block sender entirely", value="block"),
                questionary.Choice("Skip - Decide later", value="skip"),
            ],
            **Q_COMMON,
        ).ask()

        if choice is None:
            # User cancelled (Ctrl+C or ESC)
            console.print("  [muted]Cancelled[/muted]")
            break

        if choice == "unsub":
            db.set_user_override(domain, "unsub")
            db.update_sender_status(domain, SenderStatus.UNSUBSCRIBED)
            console.print("  [unsubscribe]→ Will unsubscribe[/unsubscribe]")
            user_action = Action.UNSUB
        elif choice == "keep":
            db.set_user_override(domain, "keep")
            db.update_sender_status(domain, SenderStatus.KEEP)
            console.print("  [keep]→ Will keep[/keep]")
            user_action = Action.KEEP
        elif choice == "block":
            db.set_user_override(domain, "block")
            db.update_sender_status(domain, SenderStatus.BLOCKED)
            console.print("  [block]→ Will block[/block]")
            user_action = Action.BLOCK
        else:
            console.print("  [review]→ Skipped[/review]")
            user_action = None

        # Log user action for learning (if not skipped)
        if user_action is not None:
            # Get AI recommendation if available
            ai_rec = None
            if ai_class_str := sender.get("ai_classification"):
                # Normalize 'unsubscribe' to 'unsub' for enum matching
                if ai_class_str == "unsubscribe":
                    ai_class_str = "unsub"
                try:
                    ai_rec = Action(ai_class_str)
                except ValueError:
                    pass  # ai_rec remains None for unknown values

            # Calculate open rate
            seen = sender.get("seen_emails", 0)
            open_rate = (seen / total * 100) if total > 0 else 0

            # Log the action
            action_record = UserAction(
                domain=domain,
                action=user_action,
                timestamp=datetime.now(),
                ai_recommendation=ai_rec,
                heuristic_score=None,  # Not available in review context
                open_rate=open_rate,
                email_count=total,
            )
            db.log_user_action(action_record)

            # Update learner with this action
            learner = get_learner()
            learner.update_from_action(action_record)

        console.print()


@main.command()
@click.argument("domain", required=False)
def undo(domain: str | None):
    """Undo recent unsubscribes."""
    db.init_db()

    if domain:
        # Undo specific domain - this is a correction (user changed their mind)
        db.set_user_override(domain, "keep")
        db.update_sender_status(domain, SenderStatus.KEEP)
        db.log_correction(domain, "unsub", "keep")

        # Get sender info for learning
        sender = db.get_sender(domain)
        if sender:
            seen = sender.get("seen_emails", 0)
            total = sender.get("total_emails", 0)
            open_rate = (seen / total * 100) if total > 0 else 0

            # Log the action for learning
            action_record = UserAction(
                domain=domain,
                action=Action.KEEP,
                timestamp=datetime.now(),
                ai_recommendation=Action.UNSUB,  # Undo means AI/system said unsub
                heuristic_score=None,
                open_rate=open_rate,
                email_count=total,
            )
            db.log_user_action(action_record)

            # Update learner
            learner = get_learner()
            learner.update_from_action(action_record)

        console.print(f"[success]✓ Marked {domain} as 'keep'[/success]")
        console.print("[muted]Learning from this correction.[/muted]")
        return

    # Show recent unsubscribes
    recent = db.get_recent_unsubscribes(days=30)

    if not recent:
        console.print("No recent unsubscribes to undo.")
        return

    console.print("\n[header]Recent unsubscribes (last 30 days):[/header]\n")

    for i, item in enumerate(recent[:20], 1):
        console.print(
            f"  {i}. {item['domain']} ({item['total_emails']} emails) - {item['attempted_at'][:10]}"
        )

    console.print("\nTo undo, run: [bold]nothx undo <domain>[/bold]")


@main.command()
@click.option("--monthly", is_flag=True, help="Schedule monthly runs")
@click.option("--weekly", is_flag=True, help="Schedule weekly runs")
@click.option("--off", is_flag=True, help="Disable scheduled runs")
@click.option("--status", "show_status", is_flag=True, help="Show current schedule")
def schedule(monthly: bool, weekly: bool, off: bool, show_status: bool):
    """Manage automatic scheduling."""
    if show_status or (not monthly and not weekly and not off):
        status = get_schedule_status()
        if status:
            console.print("\n[header]Current Schedule[/header]")
            console.print(f"  Type: {status['type']}")
            console.print(f"  Frequency: {status['frequency']}")
            console.print(f"  Path: {status['path']}")
        else:
            console.print("[yellow]No schedule configured[/yellow]")
        return

    if off:
        success, msg = uninstall_schedule()
        if success:
            console.print(f"[green]✓ {msg}[/green]")
        else:
            console.print(f"[red]{msg}[/red]")
        return

    frequency = "monthly" if monthly else "weekly"
    success, msg = install_schedule(frequency)

    if success:
        console.print(f"[green]✓ {msg}[/green]")
    else:
        console.print(f"[red]{msg}[/red]")


@main.command("config")
@click.option("--show", is_flag=True, help="Show current config")
@click.option("--ai", type=click.Choice(["on", "off"]), help="Enable/disable AI")
@click.option(
    "--mode", type=click.Choice(["hands_off", "notify", "confirm"]), help="Set operation mode"
)
def config_cmd(show: bool, ai: str | None, mode: str | None):
    """View or modify configuration."""
    config = Config.load()

    if ai:
        config.ai.enabled = ai == "on"
        config.save()
        console.print(f"AI: {'enabled' if config.ai.enabled else 'disabled'}")

    if mode:
        config.operation_mode = mode
        config.save()
        console.print(f"Mode: {mode}")

    if show or (not ai and not mode):
        console.print("\n[header]Current Configuration[/header]")
        console.print(f"  Config dir: {get_config_dir()}")
        console.print(f"  AI enabled: {config.ai.enabled}")
        console.print(f"  AI provider: {config.ai.provider}")
        console.print(f"  Operation mode: {config.operation_mode}")
        console.print(f"  Scan days: {config.scan_days}")
        console.print(f"  Unsub confidence: {config.thresholds.unsub_confidence}")
        console.print(f"  Keep confidence: {config.thresholds.keep_confidence}")


@main.command()
@click.argument("pattern")
@click.argument("action", type=click.Choice(["keep", "unsub", "block"]))
def rule(pattern: str, action: str):
    """Add a classification rule.

    Example: nothx rule "*.spam.com" unsub
    """
    db.init_db()
    db.add_rule(pattern, action)
    console.print(f"[green]✓ Added rule: {pattern} → {action}[/green]")


@main.command()
def rules():
    """List all classification rules."""
    db.init_db()
    rules_list = db.get_rules()

    if not rules_list:
        console.print("No rules configured.")
        console.print("Add rules with: [bold]nothx rule <pattern> <action>[/bold]")
        return

    table = Table(show_header=True)
    table.add_column("Pattern")
    table.add_column("Action")
    table.add_column("Created")

    for rule in rules_list:
        table.add_row(rule["pattern"], rule["action"], rule["created_at"][:10])

    console.print(table)


@main.command()
@click.option(
    "--status",
    type=click.Choice(["keep", "unsub", "blocked"]),
    help="Filter by status",
)
@click.option(
    "--sort",
    type=click.Choice(["emails", "domain", "date"]),
    default="date",
    help="Sort by field",
)
@click.option("--json", "as_json", is_flag=True, help="Output as JSON")
def senders(status: str | None, sort: str, as_json: bool):
    """List all tracked senders."""
    db.init_db()

    # Map CLI options to db function params
    status_map = {"unsub": "unsubscribed", "keep": "keep", "blocked": "blocked"}
    sort_map = {"emails": "emails", "domain": "domain", "date": "last_seen"}

    status_filter = status_map.get(status) if status else None
    all_senders = db.get_all_senders(status_filter=status_filter, sort_by=sort_map[sort])

    if not all_senders:
        console.print("[muted]No senders tracked yet. Run 'nothx run' to scan your inbox.[/muted]")
        return

    if as_json:
        click.echo(json.dumps(all_senders, indent=2, default=str))
        return

    status_label = f" ({status})" if status else ""
    console.print(f"\n[header]Tracked Senders{status_label} ({len(all_senders)} total)[/header]\n")

    table = Table(show_header=True)
    table.add_column("Domain", style="domain")
    table.add_column("Emails", style="count", justify="right")
    table.add_column("Status")
    table.add_column("Last Seen")

    status_styles = {
        "unsubscribed": "unsubscribe",
        "keep": "keep",
        "blocked": "block",
        "unknown": "review",
    }

    for sender in all_senders[:50]:  # Limit display to 50
        sender_status = sender.get("status", "unknown")
        style = status_styles.get(sender_status, "")
        status_display = f"[{style}]{sender_status.title()}[/{style}]"

        last_seen = sender.get("last_seen", "")
        if last_seen:
            try:
                last_dt = datetime.fromisoformat(last_seen)
                last_seen = humanize.naturaltime(last_dt)
            except (ValueError, TypeError):
                last_seen = last_seen[:10] if last_seen else "-"

        table.add_row(
            sender["domain"],
            str(sender.get("total_emails", 0)),
            status_display,
            last_seen or "-",
        )

    console.print(table)

    if len(all_senders) > 50:
        console.print(f"\n[muted]Showing first 50 of {len(all_senders)} senders[/muted]")


@main.command()
@click.argument("pattern")
@click.option("--json", "as_json", is_flag=True, help="Output as JSON")
def search(pattern: str, as_json: bool):
    """Search for a sender by domain pattern."""
    db.init_db()

    results = db.search_senders(pattern)

    if not results:
        console.print(f"[muted]No senders found matching '{pattern}'[/muted]")
        return

    if as_json:
        click.echo(json.dumps(results, indent=2, default=str))
        return

    console.print(f"\n[header]Found {len(results)} sender(s) matching '{pattern}':[/header]\n")

    for sender in results:
        domain = sender["domain"]
        status = sender.get("status", "unknown")
        total = sender.get("total_emails", 0)
        subjects = sender.get("sample_subjects", "").split("|")[:3]

        status_styles = {
            "unsubscribed": "unsubscribe",
            "keep": "keep",
            "blocked": "block",
            "unknown": "review",
        }
        style = status_styles.get(status, "")

        last_seen = sender.get("last_seen", "")
        if last_seen:
            try:
                last_dt = datetime.fromisoformat(last_seen)
                last_seen = humanize.naturaltime(last_dt)
            except (ValueError, TypeError):
                last_seen = last_seen[:10] if last_seen else ""

        console.print(f"  [domain]{domain}[/domain]")
        console.print(
            f"    Status: [{style}]{status.title()}[/{style}]"
            + (f" ({last_seen})" if last_seen else "")
        )
        console.print(f"    Emails: [count]{total}[/count] total")
        if subjects and subjects[0]:
            console.print(f"    Subjects: {', '.join(s for s in subjects[:3] if s)}")
        console.print()


@main.command()
@click.option("--limit", default=20, help="Number of entries to show")
@click.option("--failures", is_flag=True, help="Show only failures")
@click.option("--json", "as_json", is_flag=True, help="Output as JSON")
def history(limit: int, failures: bool, as_json: bool):
    """Show recent activity log."""
    db.init_db()

    activity = db.get_activity_log(limit=limit, failures_only=failures)

    if not activity:
        console.print("[muted]No activity recorded yet.[/muted]")
        return

    if as_json:
        click.echo(json.dumps(activity, indent=2, default=str))
        return

    label = " (failures only)" if failures else ""
    console.print(f"\n[header]Recent Activity{label}[/header]\n")

    for entry in activity:
        timestamp = entry.get("timestamp", "")
        try:
            ts_dt = datetime.fromisoformat(timestamp)
            date_str = ts_dt.strftime("%b %d, %I:%M %p")
        except (ValueError, TypeError):
            date_str = timestamp

        if entry["type"] == "run":
            scanned = entry.get("emails_scanned", 0)
            senders = entry.get("unique_senders", 0)
            unsubbed = entry.get("auto_unsubbed", 0)
            failed = entry.get("failed", 0)
            console.print(
                f"[muted]{date_str}[/muted]  ◉ Scan completed: {scanned} emails, {senders} senders, {unsubbed} unsubscribed"
                + (f", {failed} failed" if failed else "")
            )
        else:
            domain = entry.get("domain", "unknown")
            success = entry.get("success", False)
            if success:
                console.print(
                    f"[muted]{date_str}[/muted]  [success]✓[/success] Unsubscribed from [domain]{domain}[/domain]"
                )
            else:
                error = entry.get("error", "unknown error")
                console.print(
                    f"[muted]{date_str}[/muted]  [error]✗[/error] Failed to unsubscribe from [domain]{domain}[/domain] ({error[:30]})"
                )


@main.command()
@click.argument("type_", metavar="TYPE", type=click.Choice(["senders", "history"]))
@click.option("--output", "-o", required=True, help="Output file path")
def export(type_: str, output: str):
    """Export data to CSV.

    TYPE is either 'senders' or 'history'.
    """
    db.init_db()

    if type_ == "senders":
        data = db.get_all_senders()
        if not data:
            console.print("[warning]No senders to export.[/warning]")
            return
        fieldnames = [
            "domain",
            "total_emails",
            "seen_emails",
            "status",
            "first_seen",
            "last_seen",
            "has_unsubscribe",
            "sample_subjects",
        ]
    else:
        data = db.get_activity_log(limit=1000)
        if not data:
            console.print("[warning]No history to export.[/warning]")
            return
        fieldnames = [
            "type",
            "timestamp",
            "domain",
            "success",
            "method",
            "error",
            "emails_scanned",
            "unique_senders",
            "auto_unsubbed",
            "failed",
            "mode",
        ]

    try:
        with open(output, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
            writer.writeheader()
            writer.writerows(data)
        console.print(f"[success]✓ Exported {len(data)} records to {output}[/success]")
    except OSError as e:
        console.print(f"[error]Failed to write {output}: {e}[/error]")


@main.command("test")
def test_connection():
    """Test email connection."""
    config = Config.load()

    if not config.accounts:
        console.print("[error]No accounts configured. Run 'nothx init' first.[/error]")
        return

    for _name, account in config.accounts.items():
        console.print(f"\n[header]Testing connection to {account.email}...[/header]")

        with console.status("Connecting..."):
            success, msg = test_account(account)

        if success:
            console.print("[success]✓ IMAP connection successful[/success]")
            console.print("[success]✓ Authentication successful[/success]")
            console.print("[success]✓ Inbox accessible[/success]")
        else:
            console.print(f"[error]✗ Connection failed: {msg}[/error]")
            console.print("\n[muted]Suggestions:[/muted]")
            console.print("  • Check your internet connection")
            if tips := TROUBLESHOOTING_TIPS.get(account.provider):
                for tip in tips:
                    console.print(tip)
            console.print("  • Make sure IMAP is enabled in your email settings")


@main.command()
@click.option("--keep-config", is_flag=True, help="Keep accounts and API key, only clear data")
def reset(keep_config: bool):
    """Clear all data and start fresh."""
    from .config import get_config_path

    db.init_db()
    stats = db.get_stats()

    console.print("\n[warning]⚠️  This will delete all nothx data:[/warning]")
    console.print(f"  • {stats['total_senders']} tracked senders")
    console.print(f"  • {stats['unsubscribed']} unsubscribe records")
    console.print("  • All classification history")

    if not keep_config:
        console.print("  • All user rules")
        console.print("  • [warning]Configuration file (accounts, API key)[/warning]")

    console.print()

    # Require typing "reset" to confirm
    confirm = questionary.text('Type "reset" to confirm:').ask()

    if confirm != "reset":
        console.print("Cancelled.")
        return

    # Reset database
    senders_deleted, unsubs_deleted = db.reset_database(keep_config=keep_config)

    # Delete config file if not keeping
    if not keep_config:
        config_path = get_config_path()
        if config_path.exists():
            config_path.unlink()
            console.print("[success]✓ Configuration file deleted[/success]")

    console.print(
        f"[success]✓ Cleared {senders_deleted} senders and {unsubs_deleted} unsubscribe logs[/success]"
    )
    console.print("\nRun [bold]nothx init[/bold] to start fresh.")


@main.command()
@click.argument("shell", type=click.Choice(["bash", "zsh", "fish"]))
def completion(shell: str):
    """Generate shell completion script.

    To enable completions, add to your shell config:

    \b
    Bash: eval "$(nothx completion bash)"
    Zsh:  eval "$(nothx completion zsh)"
    Fish: nothx completion fish | source
    """

    # Click provides built-in completion support
    prog_name = "nothx"

    if shell == "bash":
        # Bash completion script
        script = f"""
_nothx_completion() {{
    local IFS=$'\\n'
    COMPREPLY=( $(env COMP_WORDS="${{COMP_WORDS[*]}}" \\
                     COMP_CWORD=$COMP_CWORD \\
                     _{prog_name.upper()}_COMPLETE=bash_complete $1) )
    return 0
}}
complete -o default -F _nothx_completion {prog_name}
"""
    elif shell == "zsh":
        # Zsh completion script
        script = f"""
#compdef {prog_name}

_nothx_completion() {{
    local -a completions
    local -a completions_with_descriptions
    local -a response
    (( ! $+commands[{prog_name}] )) && return 1

    response=("${{(@f)$(env COMP_WORDS="${{words[*]}}" \\
                            COMP_CWORD=$((CURRENT-1)) \\
                            _{prog_name.upper()}_COMPLETE=zsh_complete {prog_name})}}")

    for key descr in ${{(kv)response}}; do
      if [[ "$descr" == "_" ]]; then
          completions+=("$key")
      else
          completions_with_descriptions+=("$key":"$descr")
      fi
    done

    if [ -n "$completions_with_descriptions" ]; then
        _describe -V unsorted completions_with_descriptions -U
    fi

    if [ -n "$completions" ]; then
        compadd -U -V unsorted -a completions
    fi
}}

compdef _nothx_completion {prog_name}
"""
    else:  # fish
        # Fish completion script
        script = f"""
function _nothx_completion;
    set -l response (env _{prog_name.upper()}_COMPLETE=fish_complete COMP_WORDS=(commandline -cp) COMP_CWORD=(commandline -t) {prog_name});

    for completion in $response;
        set -l metadata (string split "," -- $completion);

        if [ $metadata[1] = "dir" ];
            __fish_complete_directories $metadata[2];
        else if [ $metadata[1] = "file" ];
            __fish_complete_path $metadata[2];
        else if [ $metadata[1] = "plain" ];
            echo $metadata[2];
        end;
    end;
end;

complete --no-files --command {prog_name} --arguments "(_nothx_completion)";
"""

    click.echo(script.strip())


@main.command()
@click.option("--check", is_flag=True, help="Only check for updates, don't install")
def update(check: bool):
    """Check for and install updates.

    Updates nothx to the latest version using pip.
    """
    import subprocess
    import sys
    import urllib.error
    import urllib.request

    console.print(f"\n[header]Current version:[/header] {__version__}")

    # Check for latest version on PyPI using the JSON API
    with console.status("Checking for updates..."):
        try:
            url = "https://pypi.org/pypi/nothx/json"
            with urllib.request.urlopen(url, timeout=10) as response:
                data = json.loads(response.read().decode("utf-8"))
                latest = data.get("info", {}).get("version")
        except (urllib.error.URLError, urllib.error.HTTPError, json.JSONDecodeError, OSError):
            latest = None

    if latest:
        console.print(f"[header]Latest version:[/header]  {latest}")

        if latest == __version__:
            console.print("\n[success]✓ You're already on the latest version![/success]")
            return

        if check:
            console.print(f"\n[info]Run 'nothx update' to upgrade to {latest}[/info]")
            return

        # Perform update
        console.print()
        if not questionary.confirm(f"Update to version {latest}?", default=True).ask():
            console.print("Cancelled.")
            return

        console.print("\n[header]Updating...[/header]")
        try:
            result = subprocess.run(
                [sys.executable, "-m", "pip", "install", "--upgrade", "nothx"],
                capture_output=True,
                text=True,
                timeout=120,
            )
            if result.returncode == 0:
                console.print(f"[success]✓ Updated to {latest}[/success]")
                console.print("\n[muted]Restart nothx to use the new version.[/muted]")
            else:
                console.print(f"[error]Update failed: {result.stderr}[/error]")
        except subprocess.TimeoutExpired:
            console.print("[error]Update timed out. Try running manually:[/error]")
            console.print("  pip install --upgrade nothx")
            return
    else:
        console.print("\n[warning]Could not check PyPI for updates.[/warning]")
        console.print("[muted]nothx may not be published yet, or you're offline.[/muted]")
        console.print("\nTo update manually:")
        console.print("  [info]pip install --upgrade nothx[/info]")
        console.print("  [muted]or from git:[/muted]")
        console.print("  [info]pip install --upgrade git+https://github.com/nothx/nothx.git[/info]")


# Command aliases for power users
main.add_command(run, name="r")
main.add_command(status, name="s")
main.add_command(review, name="rv")
main.add_command(history, name="h")


if __name__ == "__main__":
    main()
