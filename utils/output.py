"""
Output formatting utilities — Rich tables, panels, and key-value displays.
"""

from typing import Any
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

console = Console()


def kv_table(title: str, data: dict[str, Any], key_style: str = "bold cyan") -> None:
    """Render a two-column key-value table."""
    table = Table(
        title=title,
        box=box.ROUNDED,
        show_header=True,
        header_style="bold magenta",
        border_style="dim",
        expand=False,
    )
    table.add_column("Field", style=key_style, no_wrap=True)
    table.add_column("Value", style="white")

    for key, value in data.items():
        table.add_row(str(key), str(value) if value is not None else "[dim]N/A[/dim]")

    console.print(table)


def result_panel(content: str, title: str = "Result", style: str = "green") -> None:
    """Render a highlighted result panel."""
    console.print(Panel(content, title=f"[bold]{title}[/bold]", border_style=style, padding=(0, 2)))


def list_table(title: str, items: list[str], column: str = "Value") -> None:
    """Render a single-column list as a table."""
    table = Table(
        title=title,
        box=box.SIMPLE_HEAVY,
        header_style="bold magenta",
        border_style="dim",
        expand=False,
    )
    table.add_column(column, style="white")
    for item in items:
        table.add_row(str(item))
    console.print(table)


def multi_table(title: str, columns: list[str], rows: list[list[Any]]) -> None:
    """Render a multi-column table."""
    table = Table(
        title=title,
        box=box.ROUNDED,
        header_style="bold magenta",
        border_style="dim",
        expand=False,
    )
    for col in columns:
        table.add_column(col, style="white")
    for row in rows:
        table.add_row(*[str(c) if c is not None else "[dim]N/A[/dim]" for c in row])
    console.print(table)
