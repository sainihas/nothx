"""Command-line interface for nothx."""

from datetime import datetime

import click
import questionary
from rich.progress import BarColumn, Progress, SpinnerColumn, TaskProgressColumn, TextColumn
from rich.prompt import Confirm
from rich.table import Table

from . import __version__, db
from .classifier import ClassificationEngine
from .classifier.ai import test_ai_connection
from .config import AccountConfig, Config, get_config_dir
from .imap import test_account
from .models import Action, RunStats, SenderStatus
from .scanner import scan_inbox
from .scheduler import get_schedule_status, install_schedule, uninstall_schedule
from .theme import console, print_banner
from .unsubscriber import unsubscribe


def _show_welcome_screen() -> None:
    """Show welcome screen with status and interactive command selector."""
    from .theme import BANNER

    config = Config.load()

    # Header: Brand + tagline
    console.print()
    console.print(BANNER)
    console.print("[logo]nothx[/logo]")
    console.print("AI-powered email unsubscribe tool")

    # Version + status in muted text
    status_parts = [f"v{__version__}"]

    account_count = len(config.accounts)
    if account_count > 0:
        status_parts.append(f"{account_count} account{'s' if account_count != 1 else ''}")
    else:
        status_parts.append("not configured")

    # Get last scan time if DB exists
    try:
        import humanize

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
    except Exception:
        pass

    console.print(f"[muted]{' · '.join(status_parts)}[/muted]")

    # Separator
    console.print("\n[muted]" + "─" * 50 + "[/muted]")

    # Get started section with interactive selector
    console.print("\n[header]Get started[/header]\n")

    # Build command choices based on configuration state
    if not config.accounts:
        # Not configured - prioritize init
        choices = [
            questionary.Choice("nothx init     Set up email accounts and API key", value="init"),
            questionary.Choice("nothx --help   View all commands", value="help"),
        ]
    else:
        # Configured - show main workflow commands
        choices = [
            questionary.Choice("nothx run      Scan inbox and unsubscribe", value="run"),
            questionary.Choice("nothx status   Show current stats", value="status"),
            questionary.Choice("nothx review   Review pending decisions", value="review"),
            questionary.Choice("nothx senders  List all tracked senders", value="senders"),
            questionary.Choice("nothx update   Check for updates", value="update"),
            questionary.Choice("nothx --help   View all commands", value="help"),
        ]

    selected = questionary.select(
        "",
        choices=choices,
        instruction="",
    ).ask()

    if selected is None:
        return

    # Execute the selected command
    ctx = click.get_current_context()
    if selected == "init":
        ctx.invoke(init)
    elif selected == "run":
        ctx.invoke(run, auto=False, dry_run=False, verbose=False)
    elif selected == "status":
        ctx.invoke(status)
    elif selected == "review":
        ctx.invoke(review, show_all=False, show_keep=False, show_unsub=False)
    elif selected == "senders":
        ctx.invoke(senders, status=None, sort="date", as_json=False)
    elif selected == "help":
        console.print(ctx.get_help())


@click.group(invoke_without_command=True)
@click.version_option(version=__version__)
@click.pass_context
def main(ctx):
    """nothx - AI-powered email unsubscribe tool.

    Set it up once. AI handles your inbox forever.
    """
    if ctx.invoked_subcommand is None:
        _show_welcome_screen()


def _add_email_account(config: Config) -> tuple[str, AccountConfig] | None:
    """Interactive flow to add an email account. Returns (name, account) or None if cancelled."""
    # Email provider selection
    provider = questionary.select(
        "Select your email provider:",
        choices=[
            questionary.Choice("Gmail", value="gmail"),
            questionary.Choice("Outlook", value="outlook"),
        ],
    ).ask()

    if provider is None:  # User cancelled
        return None

    # Email address
    email = questionary.text("Email address:").ask()
    if not email:
        return None

    # App password instructions
    if provider == "gmail":
        console.print("\n[warning]For Gmail, you need an App Password:[/warning]")
        console.print("  1. Go to myaccount.google.com/apppasswords")
        console.print("  2. Generate a new password for 'nothx'")
        console.print("  3. Copy the 16-character code\n")
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
def init():
    """Set up nothx with your email account and API key."""
    print_banner("Let's set up your inbox cleanup")

    config = Config.load()

    # Multi-account loop
    account_count = 0
    while True:
        result = _add_email_account(config)
        if result is None:
            if account_count == 0:
                console.print("[warning]No accounts configured. Run 'nothx init' to try again.[/warning]")
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

    # Anthropic API key
    console.print("\n[header]AI Classification Setup[/header]")
    console.print("nothx uses Claude AI to classify your emails.")
    console.print("Your email [bold]headers only[/bold] (never bodies) are sent to Anthropic.\n")

    api_key = questionary.text(
        "Anthropic API key (leave empty to skip):",
    ).ask()

    if api_key and api_key.strip():
        config.ai.api_key = api_key.strip()
        config.ai.enabled = True

        with console.status("Testing AI connection..."):
            success, msg = test_ai_connection(config)

        if success:
            console.print("[success]✓ AI working![/success]\n")
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


@main.group()
def account():
    """Manage email accounts."""
    pass


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

    account_name = questionary.select(
        "Select account to remove:",
        choices=choices,
    ).ask()

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
def run(auto: bool, dry_run: bool, verbose: bool):
    """Scan inbox and process marketing emails."""
    config = Config.load()

    if not config.is_configured():
        console.print("[red]nothx is not configured. Run 'nothx init' first.[/red]")
        return

    db.init_db()

    if dry_run:
        console.print("[yellow]DRY RUN - no changes will be made[/yellow]\n")

    _run_scan(config, verbose=verbose, dry_run=dry_run, auto=auto)


def _run_scan(config: Config, verbose: bool = False, dry_run: bool = False, auto: bool = False):
    """Run the main scan and classification process."""
    stats = RunStats(
        ran_at=datetime.now(),
        mode="auto" if auto else "interactive",
    )

    # Phase 1: Scan inbox
    console.print("\n[header]Phase 1/3: Scanning inbox[/header]")
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
        transient=True,
    ) as progress:
        task = progress.add_task("Connecting to mailbox...", total=None)
        scan_result = scan_inbox(config)
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

    # Summary
    console.print("[success]✓ Classification complete[/success]")
    console.print(f"  [unsubscribe]• {len(to_unsub)} to unsubscribe[/unsubscribe]")
    console.print(f"  [block]• {len(to_block)} to block[/block]")
    console.print(f"  [keep]• {len(to_keep)} to keep[/keep]")
    console.print(f"  [review]• {len(to_review)} need review[/review]")

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
            console.print("\n[header]Manual Review[/header]")
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
            console.print("\n[header]Updated decisions:[/header]")
            console.print(f"  [unsubscribe]• {len(to_unsub)} to unsubscribe[/unsubscribe]")
            console.print(f"  [keep]• {len(to_keep)} to keep[/keep]")
            console.print(f"  [review]• {len(to_review)} need review[/review]")

    # Phase 3: Execute unsubscribes (if not dry run)
    if not dry_run and (to_unsub or to_block):
        console.print()

        if auto or Confirm.ask(
            f"Unsubscribe from {len(to_unsub) + len(to_block)} senders?", default=True
        ):
            console.print("\n[header]Phase 3/3: Unsubscribing[/header]")
            account = config.get_account()

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
            console.print("\n[muted]⏱ Run `nothx undo` to restore if needed[/muted]")

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
def status():
    """Show current nothx status."""
    import humanize

    config = Config.load()

    if not config.is_configured():
        console.print("[error]nothx is not configured. Run 'nothx init' first.[/error]")
        return

    db.init_db()

    console.print("\n[header]nothx Status[/header]")
    console.print("=" * 40)

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

    # Stats
    stats = db.get_stats()
    successful, failed = db.get_unsub_success_rate()
    total_unsub_attempts = successful + failed

    console.print("\n[header]Statistics[/header]")
    console.print(f"  Total senders tracked: [count]{stats['total_senders']}[/count]")

    # Show unsubscribe breakdown with success rate
    if total_unsub_attempts > 0:
        success_rate = (successful / total_unsub_attempts) * 100
        console.print(
            f"  Unsubscribed: [count]{stats['unsubscribed']}[/count] "
            f"([success]{successful} successful[/success], [error]{failed} failed[/error])"
        )
        console.print(f"  Success rate: [count]{success_rate:.0f}%[/count]")
    else:
        console.print(f"  Unsubscribed: [count]{stats['unsubscribed']}[/count]")

    console.print(f"  Kept: [count]{stats['kept']}[/count]")
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

    console.print(f"\n[header]{len(senders)} senders {filter_label}:[/header]\n")

    for sender in senders:
        domain = sender["domain"]
        total = sender["total_emails"]
        subjects = sender.get("sample_subjects", "").split("|")[:3]

        console.print(f"[header][{total} emails] [domain]{domain}[/domain][/header]")
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
        ).ask()

        if choice is None:
            # User cancelled (Ctrl+C or ESC)
            console.print("  [muted]Cancelled[/muted]")
            break

        if choice == "unsub":
            db.set_user_override(domain, "unsub")
            db.update_sender_status(domain, SenderStatus.UNSUBSCRIBED)
            console.print("  [unsubscribe]→ Will unsubscribe[/unsubscribe]")
        elif choice == "keep":
            db.set_user_override(domain, "keep")
            db.update_sender_status(domain, SenderStatus.KEEP)
            console.print("  [keep]→ Will keep[/keep]")
        elif choice == "block":
            db.set_user_override(domain, "block")
            db.update_sender_status(domain, SenderStatus.BLOCKED)
            console.print("  [block]→ Will block[/block]")
        else:
            console.print("  [review]→ Skipped[/review]")

        console.print()


@main.command()
@click.argument("domain", required=False)
def undo(domain: str | None):
    """Undo recent unsubscribes."""
    db.init_db()

    if domain:
        # Undo specific domain
        db.set_user_override(domain, "keep")
        db.update_sender_status(domain, SenderStatus.KEEP)
        db.log_correction(domain, "unsub", "keep")
        console.print(f"[success]✓ Marked {domain} as 'keep'[/success]")
        console.print("[muted]AI will learn from this correction.[/muted]")
        return

    # Show recent unsubscribes
    recent = db.get_recent_unsubscribes(days=30)

    if not recent:
        console.print("No recent unsubscribes to undo.")
        return

    console.print("\n[bold]Recent unsubscribes (last 30 days):[/bold]\n")

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
            console.print("\n[bold]Current Schedule[/bold]")
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
        console.print("\n[bold]Current Configuration[/bold]")
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
    import json

    import humanize

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
    import json

    import humanize

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
        console.print(f"    Status: [{style}]{status.title()}[/{style}]" + (f" ({last_seen})" if last_seen else ""))
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
    import json

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
            console.print(f"[muted]{date_str}[/muted]  ◉ Scan completed: {scanned} emails, {senders} senders, {unsubbed} unsubscribed" + (f", {failed} failed" if failed else ""))
        else:
            domain = entry.get("domain", "unknown")
            success = entry.get("success", False)
            if success:
                console.print(f"[muted]{date_str}[/muted]  [success]✓[/success] Unsubscribed from [domain]{domain}[/domain]")
            else:
                error = entry.get("error", "unknown error")
                console.print(f"[muted]{date_str}[/muted]  [error]✗[/error] Failed to unsubscribe from [domain]{domain}[/domain] ({error[:30]})")


@main.command()
@click.argument("type_", metavar="TYPE", type=click.Choice(["senders", "history"]))
@click.option("--output", "-o", required=True, help="Output file path")
def export(type_: str, output: str):
    """Export data to CSV.

    TYPE is either 'senders' or 'history'.
    """
    import csv

    db.init_db()

    if type_ == "senders":
        data = db.get_all_senders()
        if not data:
            console.print("[warning]No senders to export.[/warning]")
            return
        fieldnames = ["domain", "total_emails", "seen_emails", "status", "first_seen", "last_seen", "has_unsubscribe", "sample_subjects"]
    else:
        data = db.get_activity_log(limit=1000)
        if not data:
            console.print("[warning]No history to export.[/warning]")
            return
        fieldnames = ["type", "timestamp", "domain", "success", "method", "error", "emails_scanned", "unique_senders", "auto_unsubbed", "failed", "mode"]

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
            if account.provider == "gmail":
                console.print("  • Verify your app password at myaccount.google.com/apppasswords")
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

    console.print(f"[success]✓ Cleared {senders_deleted} senders and {unsubs_deleted} unsubscribe logs[/success]")
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
        script = f'''
_nothx_completion() {{
    local IFS=$'\\n'
    COMPREPLY=( $(env COMP_WORDS="${{COMP_WORDS[*]}}" \\
                     COMP_CWORD=$COMP_CWORD \\
                     _{prog_name.upper()}_COMPLETE=bash_complete $1) )
    return 0
}}
complete -o default -F _nothx_completion {prog_name}
'''
    elif shell == "zsh":
        # Zsh completion script
        script = f'''
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
'''
    else:  # fish
        # Fish completion script
        script = f'''
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
'''

    click.echo(script.strip())


@main.command()
@click.option("--check", is_flag=True, help="Only check for updates, don't install")
def update(check: bool):
    """Check for and install updates.

    Updates nothx to the latest version using pip.
    """
    import subprocess
    import sys

    console.print(f"\n[header]Current version:[/header] {__version__}")

    # Check for latest version on PyPI
    with console.status("Checking for updates..."):
        try:
            result = subprocess.run(
                [sys.executable, "-m", "pip", "index", "versions", "nothx"],
                capture_output=True,
                text=True,
                timeout=30,
            )
            # Parse output to find latest version
            if result.returncode == 0 and "versions:" in result.stdout.lower():
                # pip index versions output format varies
                lines = result.stdout.strip().split("\n")
                for line in lines:
                    if "versions:" in line.lower():
                        versions = line.split(":")[-1].strip()
                        latest = versions.split(",")[0].strip()
                        break
                else:
                    latest = None
            else:
                latest = None
        except (subprocess.TimeoutExpired, FileNotFoundError):
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
