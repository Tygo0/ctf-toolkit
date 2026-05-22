"""
Logger utility — wraps Rich for consistent styled logging across all modules.
"""

from rich.console import Console
from rich.theme import Theme

_theme = Theme({
    "info":    "bold cyan",
    "success": "bold green",
    "warning": "bold yellow",
    "error":   "bold red",
    "debug":   "dim white",
    "section": "bold magenta",
})

console = Console(theme=_theme)


def info(msg: str) -> None:
    console.print(f"[info]  [*][/info] {msg}")

def success(msg: str) -> None:
    console.print(f"[success]  [+][/success] {msg}")

def warning(msg: str) -> None:
    console.print(f"[warning]  [!][/warning] {msg}")

def error(msg: str) -> None:
    console.print(f"[error]  [-][/error] {msg}")

def debug(msg: str) -> None:
    console.print(f"[debug]  [~][/debug] {msg}")

def section(title: str) -> None:
    console.rule(f"[section]{title}[/section]")
