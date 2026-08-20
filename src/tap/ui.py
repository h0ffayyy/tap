"""Console presentation for the interactive TAP installer.

All install-time output flows through one shared :class:`rich.console.Console`
so styled writes, spinners, and log records never fight over the terminal. The
module degrades cleanly on non-TTY streams and when ``NO_COLOR`` is set (rich
handles both automatically), so the same calls are safe under a pipe or CI.

Only the interactive ``install``/``uninstall`` flow uses this module; the
``run`` daemon keeps plain ``logging`` so journald output stays grep-friendly.
"""

from __future__ import annotations

import logging
import subprocess
from collections.abc import Sequence

from rich.console import Console
from rich.logging import RichHandler
from rich.panel import Panel
from rich.prompt import Confirm, Prompt
from rich.text import Text
from rich.theme import Theme

from tap import __version__

THEME = Theme(
    {
        "info": "cyan",
        "success": "bold green",
        "warning": "bold yellow",
        "error": "bold red",
        "prompt": "bold cyan",
        "step": "bold magenta",
        "dim": "dim",
    }
)

console = Console(theme=THEME, highlight=False)


# --------------------------------------------------------------------------
# Banner / structure
# --------------------------------------------------------------------------


def banner() -> None:
    """Render the boxed installer banner."""
    body = Text.assemble(
        ("Trusted Access Platform", "bold cyan"),
        ("\nremote reverse-SSH access dropbox", "dim"),
        (f"\nv{__version__}", "dim"),
        justify="center",
    )
    console.print(Panel(body, border_style="cyan", padding=(1, 6)))


def step(index: int, total: int, title: str) -> None:
    """Print a numbered stage header, e.g. ``▶ [3/8] Configuring sshd``."""
    console.print()
    console.print(f"[step]▶ [{index}/{total}][/] {title}")


# --------------------------------------------------------------------------
# Status lines
# --------------------------------------------------------------------------


def info(msg: str) -> None:
    console.print(f"[info]•[/] {msg}")


def success(msg: str) -> None:
    console.print(f"[success]✓[/] {msg}")


def warn(msg: str) -> None:
    console.print(f"[warning]![/] {msg}")


def error(msg: str) -> None:
    console.print(f"[error]✗[/] {msg}")


# --------------------------------------------------------------------------
# Command execution
# --------------------------------------------------------------------------


def run_step(
    description: str,
    cmd: Sequence[str],
    *,
    env: dict[str, str] | None = None,
    capture: bool = True,
) -> subprocess.CompletedProcess:
    """Run a *non-interactive* command with a spinner and a ✓/✗ result line.

    Do not use this for commands that read from the terminal (``ssh-keygen``,
    ``ssh-copy-id``): the captured/Live display would swallow their prompts.
    Run those directly instead.

    When ``capture`` is false or the console is not a TTY, output is streamed
    live and the spinner is skipped, so verbose runs and piped/CI runs still
    show progress without a corrupted Live region.
    """
    stream = not capture or not console.is_terminal
    if stream:
        info(f"{description}…")
        result = subprocess.run(list(cmd), check=False, env=env, text=True)
    else:
        with console.status(f"[info]{description}…[/]", spinner="dots"):
            result = subprocess.run(list(cmd), check=False, env=env, capture_output=True, text=True)

    if result.returncode == 0:
        success(description)
    else:
        warn(f"{description} (exit {result.returncode})")
        if not stream:
            output = (result.stdout or "") + (result.stderr or "")
            if output.strip():
                console.print(
                    Panel(output.strip(), title="output", border_style="red", padding=(0, 1))
                )
    return result


# --------------------------------------------------------------------------
# Prompts
# --------------------------------------------------------------------------


def ask(text: str, default: str = "") -> str:
    """Styled free-text prompt; returns the entered value or ``default``."""
    return Prompt.ask(f"[prompt]{text}[/]", default=default, console=console)


def confirm(text: str, default: bool = False) -> bool:
    """Styled yes/no prompt."""
    return Confirm.ask(f"[prompt]{text}[/]", default=default, console=console)


def ask_secret(text: str) -> str:
    """Styled masked prompt (no echo); returns ``""`` if left blank."""
    return Prompt.ask(f"[prompt]{text}[/]", password=True, default="", console=console)


# --------------------------------------------------------------------------
# Summary
# --------------------------------------------------------------------------


def summary(lines: Sequence[tuple[str, str]], *, title: str = "Installation complete") -> None:
    """Render a final recap panel from ``(label, value)`` rows."""
    body = Text()
    width = max((len(label) for label, _ in lines), default=0)
    for i, (label, value) in enumerate(lines):
        if i:
            body.append("\n")
        body.append(f"{label.rjust(width)}  ", style="dim")
        body.append(value)
    console.print()
    console.print(Panel(body, title=f"[success]{title}[/]", border_style="green", padding=(1, 2)))


# --------------------------------------------------------------------------
# Logging integration
# --------------------------------------------------------------------------


def configure_logging(verbose: bool) -> None:
    """Route the root logger through a :class:`RichHandler` on the shared console."""
    handler = RichHandler(
        console=console,
        show_path=False,
        show_time=verbose,
        show_level=verbose,
        markup=False,
        rich_tracebacks=True,
    )
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(message)s",
        handlers=[handler],
        force=True,
    )
