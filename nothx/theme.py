"""Theme system and shared console for nothx CLI."""

from rich.console import Console
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

# ASCII art banner (Claude Code style)
BANNER = """\
[logo]
 ███╗   ██╗ ██████╗ ████████╗██╗  ██╗██╗  ██╗
 ████╗  ██║██╔═══██╗╚══██╔══╝██║  ██║╚██╗██╔╝
 ██╔██╗ ██║██║   ██║   ██║   ███████║ ╚███╔╝
 ██║╚██╗██║██║   ██║   ██║   ██╔══██║ ██╔██╗
 ██║ ╚████║╚██████╔╝   ██║   ██║  ██║██╔╝ ██╗
 ╚═╝  ╚═══╝ ╚═════╝    ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝
[/logo]"""


def print_banner(subtitle: str = "Let's set up your inbox cleanup") -> None:
    """Print the nothx welcome banner with optional subtitle."""
    console.print("\n[info]📧 Welcome to nothx![/info]")
    console.print(BANNER)
    if subtitle:
        console.print(f"\n[muted]✨ {subtitle}[/muted]\n")
