"""Theme system and shared console for nothx CLI."""

import os
import time

from rich.box import ROUNDED
from rich.console import Console, Group
from rich.live import Live
from rich.panel import Panel
from rich.style import Style
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
        "header": "grey70",
        "muted": "grey50",
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
    "███╗   ██╗ ██████╗ ████████╗██╗  ██╗██╗  ██╗",
    "████╗  ██║██╔═══██╗╚══██╔══╝██║  ██║╚██╗██╔╝",
    "██╔██╗ ██║██║   ██║   ██║   ███████║ ╚███╔╝",
    "██║╚██╗██║██║   ██║   ██║   ██╔══██║ ██╔██╗",
    "██║ ╚████║╚██████╔╝   ██║   ██║  ██║██╔╝ ██╗",
    "╚═╝  ╚═══╝ ╚═════╝    ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝",
]

# Static banner with markup
BANNER = "[logo]\n" + "\n".join(BANNER_LINES) + "\n[/logo]"


def print_animated_banner(char_delay: float = 0.012) -> None:
    """Print banner with typewriter effect (characters appear left-to-right).

    Args:
        char_delay: Seconds between each column. Default 0.012 (~0.5s total).
    """
    # Skip animation if disabled or not a TTY
    if os.environ.get("NOTHX_NO_ANIMATION") or not console.is_terminal:
        console.print(BANNER)
        return

    max_len = max(len(line) for line in BANNER_LINES)

    with Live(console=console, refresh_per_second=60, transient=False) as live:
        for col in range(max_len + 1):
            frame = Text("\n".join(line[:col] for line in BANNER_LINES), style="logo")
            live.update(frame)
            time.sleep(char_delay)


def print_drop_down_banner(line_delay: float = 0.07) -> None:
    """Print banner with drop-down effect (line-by-line reveal from top).

    Args:
        line_delay: Seconds between each line. Default 0.07 (~0.4s total).
    """
    # Skip animation if disabled or not a TTY
    if os.environ.get("NOTHX_NO_ANIMATION") or not console.is_terminal:
        console.print(BANNER)
        return

    with Live(console=console, refresh_per_second=60, transient=False) as live:
        for num_lines in range(len(BANNER_LINES) + 1):
            frame = Text("\n".join(BANNER_LINES[:num_lines]), style="logo")
            live.update(frame)
            time.sleep(line_delay)


def print_banner(subtitle: str = "Let's set up your inbox cleanup") -> None:
    """Print the nothx welcome banner with optional subtitle."""
    console.print("\n[info]📧 Welcome to nothx![/info]")
    print_animated_banner()
    console.print()
    if subtitle:
        console.print(f"[muted]✨ {subtitle}[/muted]\n")


# --- Gradient + Panel welcome screen ---

# Pre-computed gradient: orange1 (#ffaf00) → deep orange (#ff5500)
# R stays 255, G goes 175→85, B stays 0 — 46 steps (one per banner column)
_BANNER_WIDTH = max(len(line) for line in BANNER_LINES)
GRADIENT_COLORS: list[str] = [
    f"#{255:02x}{175 - round(90 * i / max(_BANNER_WIDTH - 1, 1)):02x}{0:02x}"
    for i in range(_BANNER_WIDTH)
]


def apply_gradient(lines: list[str], visible_cols: int | None = None) -> Text:
    """Apply horizontal gradient coloring to ASCII art lines.

    Args:
        lines: List of banner text lines.
        visible_cols: If set, only color this many columns (rest filled with spaces).
            Used for typewriter animation.

    Returns:
        Rich Text object with per-character gradient styling.
    """
    max_len = max(len(line) for line in lines)
    cols = visible_cols if visible_cols is not None else max_len
    result = Text()

    for row_idx, line in enumerate(lines):
        if row_idx > 0:
            result.append("\n")
        # Pad line to full width so Panel stays constant size
        padded = line.ljust(max_len)
        for col_idx in range(max_len):
            char = padded[col_idx] if col_idx < cols else " "
            color = GRADIENT_COLORS[min(col_idx, len(GRADIENT_COLORS) - 1)]
            result.append(char, Style(color=color))

    return result


def build_welcome_panel(
    greeting: str, banner_text: Text, version_line: str
) -> Panel:
    """Build the welcome Panel with greeting title, gradient banner, and branding.

    Args:
        greeting: Greeting string for the panel title (e.g. "☀️  Good morning!").
        banner_text: Pre-rendered gradient Text for the ASCII art.
        version_line: Version/status string (e.g. "v0.1.2 · not configured").

    Returns:
        Rich Panel renderable.
    """
    content = Text()
    content.append_text(banner_text)
    content.append("\n\n")
    content.append("nothx", Style(color="orange1"))
    content.append("\n")
    content.append("Smart enough to say no.")
    content.append("\n")
    content.append(version_line, Style(color="grey50"))

    return Panel(
        content,
        title=greeting,
        title_align="left",
        box=ROUNDED,
        border_style="#ffaf00",
        padding=(1, 2),
        expand=True,
    )


def print_animated_welcome(
    greeting: str,
    version_line: str,
    char_delay: float = 0.012,
) -> None:
    """Print welcome Panel with typewriter-animated gradient banner.

    Args:
        greeting: Greeting string for the panel title.
        version_line: Version/status string.
        char_delay: Seconds between each column reveal. Default 0.012 (~0.5s total).
    """
    # Static fallback for non-TTY or disabled animation
    if os.environ.get("NOTHX_NO_ANIMATION") or not console.is_terminal:
        banner_text = apply_gradient(BANNER_LINES)
        panel = build_welcome_panel(greeting, banner_text, version_line)
        console.print()
        console.print(panel)
        return

    max_len = max(len(line) for line in BANNER_LINES)

    with Live(console=console, refresh_per_second=60, transient=False) as live:
        for col in range(max_len + 1):
            banner_text = apply_gradient(BANNER_LINES, visible_cols=col)
            panel = build_welcome_panel(greeting, banner_text, version_line)
            live.update(Group(Text(""), panel))
            time.sleep(char_delay)
