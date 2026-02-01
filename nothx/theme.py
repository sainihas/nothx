"""Theme system and shared console for nothx CLI."""

import os
import time

from rich.console import Console
from rich.live import Live
from rich.text import Text
from rich.theme import Theme

# Semantic color theme for consistent UI
NOTHX_THEME = Theme(
    {
        # Actions
        "success": "green",
        "error": "bold red",
        "warning": "yellow",
        "info": "cyan",
        # Email actions (grouped by meaning)
        "unsubscribe": "red",
        "keep": "green",
        "block": "bold red",
        "review": "yellow",
        # UI elements
        "header": "bright_white",
        "muted": "dim",
        "highlight": "bold cyan",
        "domain": "cyan",
        "count": "magenta",
        # Banner
        "logo": "orange1",
    }
)

# Shared console instance with theme applied
console = Console(theme=NOTHX_THEME)

# ASCII art banner lines (for animation)
BANNER_LINES = [
    " ███╗   ██╗ ██████╗ ████████╗██╗  ██╗██╗  ██╗",
    " ████╗  ██║██╔═══██╗╚══██╔══╝██║  ██║╚██╗██╔╝",
    " ██╔██╗ ██║██║   ██║   ██║   ███████║ ╚███╔╝",
    " ██║╚██╗██║██║   ██║   ██║   ██╔══██║ ██╔██╗",
    " ██║ ╚████║╚██████╔╝   ██║   ██║  ██║██╔╝ ██╗",
    " ╚═╝  ╚═══╝ ╚═════╝    ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝",
]

# Static banner with markup
BANNER = "[logo]\n" + "\n".join(BANNER_LINES) + "\n[/logo]"


def print_animated_banner(char_delay: float = 0.002) -> None:
    """Print banner with typewriter effect (characters appear left-to-right).

    Args:
        char_delay: Seconds between each column. Default 0.002 (2ms) for snappy feel.
    """
    # Skip animation if disabled or not a TTY
    if os.environ.get("NOTHX_NO_ANIMATION") or not console.is_terminal:
        console.print(BANNER)
        return

    max_len = max(len(line) for line in BANNER_LINES)

    with Live(console=console, refresh_per_second=60, transient=True) as live:
        for col in range(max_len + 1):
            frame = Text("\n".join(line[:col] for line in BANNER_LINES), style="logo")
            live.update(frame)
            time.sleep(char_delay)

    # Print final static version (so it persists after Live closes)
    console.print(BANNER)


def print_banner(subtitle: str = "Let's set up your inbox cleanup") -> None:
    """Print the nothx welcome banner with optional subtitle."""
    console.print("\n[info]📧 Welcome to nothx![/info]")
    print_animated_banner()
    if subtitle:
        console.print(f"\n[muted]✨ {subtitle}[/muted]\n")
