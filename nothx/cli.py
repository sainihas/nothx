"""Command-line interface for nothx."""

import sys
from datetime import datetime
from typing import Optional

import click
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.prompt import Prompt, Confirm

from . import __version__
from .config import Config, AccountConfig, get_config_dir
from .imap import test_account
from .classifier.ai import test_ai_connection
from .classifier import ClassificationEngine
from .scanner import scan_inbox
from .unsubscriber import unsubscribe
from .scheduler import install_schedule, uninstall_schedule, get_schedule_status
from .models import Action, SenderStatus, RunStats
from . import db

console = Console()


@click.group()
@click.version_option(version=__version__)
def main():
    """nothx - AI-powered email unsubscribe tool.

    Set it up once. AI handles your inbox forever.
    """
    pass


@main.command()
def init():
    """Set up nothx with your email account and API key."""
    console.print("\n[bold]Welcome to nothx![/bold]")
    console.print("Let's set you up.\n")

    config = Config.load()

    # Email provider
    provider = Prompt.ask(
        "Email provider",
        choices=["gmail", "outlook"],
        default="gmail"
    )

    # Email address
    email = Prompt.ask("Email address")

    # App password instructions
    if provider == "gmail":
        console.print("\n[yellow]For Gmail, you need an App Password:[/yellow]")
        console.print("  1. Go to myaccount.google.com/apppasswords")
        console.print("  2. Generate a new password for 'nothx'")
        console.print("  3. Copy the 16-character code\n")
    else:
        console.print("\n[yellow]Enter your email password or app password.[/yellow]\n")

    password = Prompt.ask("App Password", password=True)

    # Test connection
    account = AccountConfig(provider=provider, email=email, password=password)
    with console.status("Testing connection..."):
        success, msg = test_account(account)

    if not success:
        console.print(f"[red]Connection failed: {msg}[/red]")
        return

    console.print("[green]✓ Connected![/green]\n")

    # Save account
    config.accounts["default"] = account
    config.default_account = "default"

    # Anthropic API key
    console.print("[bold]AI Classification Setup[/bold]")
    console.print("nothx uses Claude AI to classify your emails.")
    console.print("Your email [bold]headers only[/bold] (never bodies) are sent to Anthropic.\n")

    api_key = Prompt.ask("Anthropic API key (or 'none' to skip)")

    if api_key.lower() != "none":
        config.ai.api_key = api_key
        config.ai.enabled = True

        with console.status("Testing AI connection..."):
            success, msg = test_ai_connection(config)

        if success:
            console.print("[green]✓ AI working![/green]\n")
        else:
            console.print(f"[yellow]AI test failed: {msg}[/yellow]")
            console.print("Continuing with heuristics-only mode.\n")
            config.ai.enabled = False
    else:
        config.ai.enabled = False
        console.print("Running in heuristics-only mode.\n")

    # Initialize database
    db.init_db()

    # Save config
    config.save()
    console.print(f"[green]✓ Configuration saved to {get_config_dir()}[/green]\n")

    # First scan
    if Confirm.ask("Run first scan now?", default=True):
        _run_scan(config, verbose=True, dry_run=True)

    # Schedule setup
    if Confirm.ask("\nAuto-schedule monthly runs?", default=True):
        success, msg = install_schedule("monthly")
        if success:
            console.print(f"[green]✓ {msg}[/green]")
        else:
            console.print(f"[yellow]{msg}[/yellow]")

    console.print("\n[bold green]Setup complete![/bold green]")
    console.print("Run [bold]nothx status[/bold] to see current state.")
    console.print("Run [bold]nothx run[/bold] to process emails.")


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

    # Scan inbox
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Scanning inbox...", total=None)
        scan_result = scan_inbox(config)
        sender_stats = scan_result.sender_stats
        progress.update(task, description=f"Found {len(sender_stats)} senders with marketing emails")

    if not sender_stats:
        console.print("No marketing emails found.")
        return

    stats.emails_scanned = sum(s.total_emails for s in sender_stats.values())
    stats.unique_senders = len(sender_stats)

    console.print(f"\nFound [bold]{stats.emails_scanned}[/bold] marketing emails from [bold]{stats.unique_senders}[/bold] senders.\n")

    # Classify senders
    engine = ClassificationEngine(config)

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Classifying senders...", total=None)
        classifications = engine.classify_batch(list(sender_stats.values()))

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
    console.print(f"AI classified:")
    console.print(f"  [red]• {len(to_unsub)} to unsubscribe[/red]")
    console.print(f"  [blue]• {len(to_block)} to block[/blue]")
    console.print(f"  [green]• {len(to_keep)} to keep[/green]")
    console.print(f"  [yellow]• {len(to_review)} need review[/yellow]")

    if verbose:
        _show_details(to_unsub, to_keep, to_review, to_block)

    # Execute unsubscribes (if not dry run)
    if not dry_run and (to_unsub or to_block):
        console.print()

        if auto or Confirm.ask(f"Unsubscribe from {len(to_unsub) + len(to_block)} senders?", default=True):
            account = config.get_account()

            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console,
            ) as progress:
                task = progress.add_task("Unsubscribing...", total=len(to_unsub) + len(to_block))

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

            console.print(f"\n[green]✓ Unsubscribed from {stats.auto_unsubbed} senders[/green]")
            if stats.failed:
                console.print(f"[yellow]! {stats.failed} failed (logged for retry)[/yellow]")

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
                classification.reasoning[:50]
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
                classification.reasoning[:50]
            )
        console.print(table)


@main.command()
def status():
    """Show current nothx status."""
    config = Config.load()

    if not config.is_configured():
        console.print("[red]nothx is not configured. Run 'nothx init' first.[/red]")
        return

    db.init_db()

    console.print("\n[bold]nothx Status[/bold]")
    console.print("=" * 40)

    # Account info
    account = config.get_account()
    if account:
        console.print(f"\nAccount: {account.email} ({account.provider})")

    # AI status
    if config.ai.enabled:
        console.print(f"AI: [green]enabled[/green] ({config.ai.provider})")
    else:
        console.print("AI: [yellow]disabled[/yellow] (heuristics only)")

    console.print(f"Mode: {config.operation_mode}")

    # Stats
    stats = db.get_stats()
    console.print(f"\n[bold]Statistics[/bold]")
    console.print(f"  Total senders tracked: {stats['total_senders']}")
    console.print(f"  Unsubscribed: {stats['unsubscribed']}")
    console.print(f"  Kept: {stats['kept']}")
    console.print(f"  Pending review: {stats['pending_review']}")
    console.print(f"  Total runs: {stats['total_runs']}")
    if stats['last_run']:
        console.print(f"  Last run: {stats['last_run']}")

    # Schedule status
    schedule = get_schedule_status()
    if schedule:
        console.print(f"\n[bold]Schedule[/bold]")
        console.print(f"  Type: {schedule['type']}")
        console.print(f"  Frequency: {schedule['frequency']}")
    else:
        console.print("\n[yellow]No automatic schedule configured[/yellow]")
        console.print("Run [bold]nothx schedule --monthly[/bold] to set up")

    console.print()


@main.command()
def review():
    """Review senders that need manual decision."""
    config = Config.load()

    if not config.is_configured():
        console.print("[red]nothx is not configured. Run 'nothx init' first.[/red]")
        return

    db.init_db()

    senders = db.get_senders_for_review()

    if not senders:
        console.print("[green]No senders need review![/green]")
        return

    console.print(f"\n[bold]{len(senders)} senders need your decision:[/bold]\n")

    for sender in senders:
        domain = sender['domain']
        total = sender['total_emails']
        subjects = sender.get('sample_subjects', '').split('|')[:3]

        console.print(f"[bold][{total} emails] {domain}[/bold]")
        if sender.get('ai_classification'):
            console.print(f"  AI says: {sender['ai_classification']} ({sender.get('ai_confidence', 0):.0%} confident)")
        if subjects:
            console.print(f"  Subjects: {', '.join(subjects)}")

        choice = Prompt.ask(
            "  Decision",
            choices=["u", "k", "b", "s"],
            default="s"
        )

        if choice == "u":
            db.set_user_override(domain, "unsub")
            db.update_sender_status(domain, SenderStatus.UNSUBSCRIBED)
            console.print(f"  [red]→ Will unsubscribe[/red]")
        elif choice == "k":
            db.set_user_override(domain, "keep")
            db.update_sender_status(domain, SenderStatus.KEEP)
            console.print(f"  [green]→ Will keep[/green]")
        elif choice == "b":
            db.set_user_override(domain, "block")
            db.update_sender_status(domain, SenderStatus.BLOCKED)
            console.print(f"  [blue]→ Will block[/blue]")
        else:
            console.print(f"  [yellow]→ Skipped[/yellow]")

        console.print()


@main.command()
@click.argument("domain", required=False)
def undo(domain: Optional[str]):
    """Undo recent unsubscribes."""
    config = Config.load()
    db.init_db()

    if domain:
        # Undo specific domain
        db.set_user_override(domain, "keep")
        db.update_sender_status(domain, SenderStatus.KEEP)
        db.log_correction(domain, "unsub", "keep")
        console.print(f"[green]✓ Marked {domain} as 'keep'[/green]")
        console.print("AI will learn from this correction.")
        return

    # Show recent unsubscribes
    recent = db.get_recent_unsubscribes(days=30)

    if not recent:
        console.print("No recent unsubscribes to undo.")
        return

    console.print("\n[bold]Recent unsubscribes (last 30 days):[/bold]\n")

    for i, item in enumerate(recent[:20], 1):
        console.print(f"  {i}. {item['domain']} ({item['total_emails']} emails) - {item['attempted_at'][:10]}")

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
            console.print(f"\n[bold]Current Schedule[/bold]")
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
@click.option("--mode", type=click.Choice(["hands_off", "notify", "confirm"]), help="Set operation mode")
def config_cmd(show: bool, ai: Optional[str], mode: Optional[str]):
    """View or modify configuration."""
    config = Config.load()

    if ai:
        config.ai.enabled = (ai == "on")
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
        table.add_row(rule['pattern'], rule['action'], rule['created_at'][:10])

    console.print(table)


if __name__ == "__main__":
    main()
