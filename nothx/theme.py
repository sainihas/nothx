"""Theme system and shared console for nothx CLI."""

import os
import random
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
        "warning": "#d4a017",
        "info": "cyan",
        # Email actions (grouped by meaning)
        "unsubscribe": "red",
        "keep": "green",
        "block": "bold red",
        "review": "#d4a017",
        # UI elements
        "header": "bold #a0a0a0",
        "muted": "#808080",
        "highlight": "bold cyan",
        "domain": "cyan",
        "count": "orange1",
        # Banner
        "logo": "orange1",
    }
)

# Shared console instance with theme applied
console = Console(theme=NOTHX_THEME)

# --- Dynamic gradient banner ---

_BANNER_HEIGHT = 9
_CHECK_ROW = 4  # middle row (0-indexed)
_CHECK_X_IDX = 1  # second x from left
_X_SPACING = 2  # chars per cell: 1 char + 1 space

_SCRAMBLE_CHARS = "!@#$%^&*+~<>|;:?"
_SCRAMBLE_FRAMES = 4  # random chars before locking in


def _make_banner_lines(width: int) -> list[str]:
    """Generate banner as rows of spaced x characters with a single check mark."""
    lines: list[str] = []
    for row in range(_BANNER_HEIGHT):
        chars: list[str] = []
        for col in range(width):
            if col % _X_SPACING == 0:
                x_idx = col // _X_SPACING
                if row == _CHECK_ROW and x_idx == _CHECK_X_IDX:
                    chars.append("✓")
                else:
                    chars.append("x")
            else:
                chars.append(" ")
        lines.append("".join(chars))
    return lines


def _make_gradient(width: int) -> list[str]:
    """Compute orange (#ffaf00) to deep-orange (#ff5500) gradient."""
    return [f"#{255:02x}{175 - round(90 * i / max(width - 1, 1)):02x}{0:02x}" for i in range(width)]


def apply_gradient(
    lines: list[str],
    colors: list[str],
    cell_states: dict[tuple[int, int], int] | None = None,
    check_style: str = "green",
) -> Text:
    """Apply horizontal gradient coloring to banner lines.

    Args:
        lines: List of banner text lines.
        colors: Per-column gradient color list.
        cell_states: If provided, maps (row, col) to age (frames since revealed).
            Cells not in dict are hidden. Age <= _SCRAMBLE_FRAMES shows random char.
            Age > _SCRAMBLE_FRAMES shows final char with gradient/green.
            If None, renders fully (static fallback).

    Returns:
        Rich Text object with per-character gradient styling.
    """
    max_len = max(len(line) for line in lines)
    result = Text()

    for row_idx, line in enumerate(lines):
        if row_idx > 0:
            result.append("\n")
        padded = line.ljust(max_len)
        for col_idx in range(max_len):
            final_char = padded[col_idx]

            if cell_states is not None:
                age = cell_states.get((row_idx, col_idx))
                if age is None:
                    # Not yet revealed
                    result.append(" ")
                    continue
                if age <= _SCRAMBLE_FRAMES:
                    # Cycling through random characters
                    scramble_char = random.choice(_SCRAMBLE_CHARS)
                    color = colors[min(col_idx, len(colors) - 1)]
                    result.append(scramble_char, Style(color=color, dim=True))
                    continue

            # Locked / static render
            if final_char == "✓":
                result.append(final_char, Style(color=check_style, bold=True))
            elif final_char == " ":
                result.append(" ")
            else:
                color = colors[min(col_idx, len(colors) - 1)]
                result.append(final_char, Style(color=color))

    return result


def build_welcome_panel(greeting: str, banner_text: Text, version_line: str) -> Panel:
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
    content.append("Your inbox, uncrowded.")
    content.append("\n")
    content.append(version_line, Style(color="#808080"))

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
    """Print welcome Panel with scramble + random-fill animated gradient banner.

    Args:
        greeting: Greeting string for the panel title.
        version_line: Version/status string.
        char_delay: Seconds per animation frame. Default 0.012.
    """
    # Compute banner width: console width minus panel border (2) and padding (4)
    banner_width = max(console.width - 6, 20)
    lines = _make_banner_lines(banner_width)
    colors = _make_gradient(banner_width)

    # Static fallback for non-TTY or disabled animation
    if os.environ.get("NOTHX_NO_ANIMATION") or not console.is_terminal:
        banner_text = apply_gradient(lines, colors)
        panel = build_welcome_panel(greeting, banner_text, version_line)
        console.print()
        console.print(panel)
        return

    # Collect all visible character positions (skip spaces)
    positions: list[tuple[int, int]] = []
    for row_idx, line in enumerate(lines):
        for col_idx, char in enumerate(line):
            if char != " ":
                positions.append((row_idx, col_idx))
    random.shuffle(positions)

    # Reveal in batches over ~25 frames, then wait for all to lock
    num_reveal_frames = 25
    batch_size = max(1, len(positions) // num_reveal_frames)
    reveal_frames = (len(positions) + batch_size - 1) // batch_size
    total_frames = reveal_frames + _SCRAMBLE_FRAMES + 1
    cell_states: dict[tuple[int, int], int] = {}

    with Live(console=console, refresh_per_second=60, transient=False) as live:
        for frame in range(total_frames):
            # Start new batch of positions
            start = frame * batch_size
            for pos in positions[start : start + batch_size]:
                if pos not in cell_states:
                    cell_states[pos] = 0

            # Age all active cells before render so final frame shows locked state
            for pos in cell_states:
                cell_states[pos] += 1

            # Render frame
            banner_text = apply_gradient(lines, colors, cell_states=cell_states)
            panel = build_welcome_panel(greeting, banner_text, version_line)
            live.update(Group(Text(""), panel))
            time.sleep(char_delay)

            # Stop early if all cells are locked
            if len(cell_states) == len(positions) and all(
                s > _SCRAMBLE_FRAMES for s in cell_states.values()
            ):
                break

        # Pause to let the reveal settle, then twinkle the check mark
        time.sleep(0.3)

        # Neon green flash → fade back to original green
        twinkle = [
            "#39ff14",  # neon green flash
            "#33ee12",
            "#2cdd10",
            "#26cc0e",
            "#20bb0c",
            "#1aaa0a",
            "#149908",
            "#0e8806",
            "#087704",
        ]
        for cs in twinkle:
            banner_text = apply_gradient(lines, colors, check_style=cs)
            panel = build_welcome_panel(greeting, banner_text, version_line)
            live.update(Group(Text(""), panel))
            time.sleep(0.06)

        # Final frame: original green
        banner_text = apply_gradient(lines, colors, check_style="green")
        panel = build_welcome_panel(greeting, banner_text, version_line)
        live.update(Group(Text(""), panel))
