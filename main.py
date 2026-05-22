#!/usr/bin/env python3
"""
CTF Automation Toolkit
A modular CLI toolkit for CTF competitions, OSINT, and forensic analysis.
For educational use and authorized security testing only.
"""

import typer
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from modules.hashes import app as hash_app
from modules.encodings import app as encode_app
from modules.metadata import app as metadata_app
from modules.ziptools import app as zip_app
from modules.osint import app as osint_app

console = Console()

app = typer.Typer(
    name="ctf-toolkit",
    help="[bold cyan]CTF Automation Toolkit[/bold cyan] — Modular security & CTF utility suite.",
    rich_markup_mode="rich",
    no_args_is_help=True,
    add_completion=False,
)

# Register subcommand groups
app.add_typer(hash_app,     name="hash",     help="[yellow]Hash identification and cracking.[/yellow]")
app.add_typer(encode_app,   name="encode",   help="[yellow]Encode data (base64, hex, ROT13, etc).[/yellow]")
app.add_typer(metadata_app, name="metadata", help="[yellow]Extract metadata from files.[/yellow]")
app.add_typer(zip_app,      name="zip",      help="[yellow]Recursive archive extraction.[/yellow]")
app.add_typer(osint_app,    name="osint",    help="[yellow]OSINT utilities (WHOIS, DNS, subdomains).[/yellow]")


@app.callback(invoke_without_command=True)
def banner(ctx: typer.Context):
    """Show banner when no subcommand is given."""
    if ctx.invoked_subcommand is None:
        _print_banner()


def _print_banner():
    banner_text = Text()
    banner_text.append("  ██████╗████████╗███████╗    ████████╗ ██████╗  ██████╗ ██╗\n", style="bold cyan")
    banner_text.append("██╔════╝╚══██╔══╝██╔════╝    ╚══██╔══╝██╔═══██╗██╔═══██╗██║\n", style="bold cyan")
    banner_text.append("██║        ██║   █████╗          ██║   ██║   ██║██║   ██║██║\n", style="bold cyan")
    banner_text.append("██║        ██║   ██╔══╝          ██║   ██║   ██║██║   ██║██║\n", style="bold cyan")
    banner_text.append("╚██████╗   ██║   ██║             ██║   ╚██████╔╝╚██████╔╝███████╗\n", style="bold cyan")
    banner_text.append(" ╚═════╝   ╚═╝   ╚═╝             ╚═╝    ╚═════╝  ╚═════╝ ╚══════╝\n", style="bold cyan")
    banner_text.append("\n  CTF Automation Toolkit", style="bold white")
    banner_text.append("  v0.1.0", style="dim")
    banner_text.append("\n  For CTFs, educational labs & authorized security testing only.\n", style="italic dim")

    console.print(Panel(banner_text, border_style="cyan", padding=(0, 2)))
    console.print("  Run [bold cyan]ctf-toolkit --help[/bold cyan] to see available commands.\n")


if __name__ == "__main__":
    app()
