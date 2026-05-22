"""
Hash module — CLI commands for hash identification and dictionary cracking.

Commands:
    ctf-toolkit hash identify <hash>
    ctf-toolkit hash crack <hash> [--wordlist PATH] [--algo ALGO]
"""

import typer
from typing import Optional
from rich.console import Console
from rich.table import Table
from rich import box

from utils.logger import info, success, warning, error, section
from utils.output import result_panel

app = typer.Typer(
    name="hash",
    help="Hash identification and dictionary cracking.",
    no_args_is_help=True,
)

console = Console()


# ── identify ──────────────────────────────────────────────────────────────────

@app.command("identify")
def identify(
    hash_str: str = typer.Argument(..., help="The hash string to identify."),
):
    """
    Identify the type of a hash by its length and format.

    \b
    Examples:
      ctf-toolkit hash identify 5d41402abc4b2a76b9719d911017c592
      ctf-toolkit hash identify '$2a$12$...'
    """
    from modules.hashes.identifier import identify as _identify

    section("Hash Identifier")
    info(f"Analysing: [bold white]{hash_str}[/bold white]")
    info(f"Length:    [bold white]{len(hash_str.strip())} chars[/bold white]")
    console.print()

    matches = _identify(hash_str)

    if not matches:
        error("No matching hash types found.")
        console.print(
            "[dim]  The hash may be salted, non-standard, or not yet in the database.[/dim]\n"
        )
        raise typer.Exit(1)

    # Build results table
    table = Table(
        title=f"[bold]Possible Hash Types[/bold] — {len(matches)} match(es)",
        box=box.ROUNDED,
        header_style="bold magenta",
        border_style="cyan",
        show_lines=True,
    )
    table.add_column("Algorithm",    style="bold yellow",  no_wrap=True)
    table.add_column("Confidence",   style="white",        no_wrap=True)
    table.add_column("Hashcat Mode", style="bold cyan",    no_wrap=True)
    table.add_column("John Format",  style="bold cyan",    no_wrap=True)
    table.add_column("Notes",        style="dim white")

    confidence_styles = {
        "high":   "[bold green]HIGH[/bold green]",
        "medium": "[bold yellow]MEDIUM[/bold yellow]",
        "low":    "[bold red]LOW[/bold red]",
    }

    for m in matches:
        table.add_row(
            m.name,
            confidence_styles.get(m.confidence, m.confidence),
            str(m.hashcat_mode) if m.hashcat_mode is not None else "[dim]—[/dim]",
            m.john_format or "[dim]—[/dim]",
            m.description,
        )

    console.print(table)

    # Quick cracking tip
    best = matches[0]
    if best.hashcat_mode is not None:
        console.print(
            f"\n[dim]  → To crack:  [cyan]hashcat -m {best.hashcat_mode} {hash_str} wordlist.txt[/cyan][/dim]"
        )
    console.print(
        f"[dim]  → Use [cyan]ctf-toolkit hash crack {hash_str}[/cyan] to attempt dictionary cracking.[/dim]\n"
    )


# ── crack ─────────────────────────────────────────────────────────────────────

@app.command("crack")
def crack(
    hash_str: str = typer.Argument(..., help="The hash to crack."),
    wordlist: str = typer.Option(
        "wordlists/common.txt",
        "--wordlist", "-w",
        help="Path to the wordlist file.",
    ),
    algo: Optional[str] = typer.Option(
        None,
        "--algo", "-a",
        help="Force a specific algorithm: md5, sha1, sha256, sha512, ntlm. Auto-detected if omitted.",
    ),
):
    """
    Attempt to crack a hash using a dictionary attack.

    \b
    Examples:
      ctf-toolkit hash crack 5d41402abc4b2a76b9719d911017c592
      ctf-toolkit hash crack <hash> --wordlist /usr/share/wordlists/rockyou.txt
      ctf-toolkit hash crack <hash> --algo sha256 -w custom.txt
    """
    from modules.hashes.cracker import crack as _crack, ALGORITHMS

    section("Hash Cracker")
    info(f"Target:   [bold white]{hash_str}[/bold white]")
    info(f"Wordlist: [bold white]{wordlist}[/bold white]")
    info(f"Algo:     [bold white]{algo or 'auto-detect'}[/bold white]")
    console.print()

    # Validate manual algo
    if algo and algo not in ALGORITHMS:
        error(f"Unknown algorithm: [bold]{algo}[/bold]")
        info(f"Supported: {', '.join(ALGORITHMS.keys())}")
        raise typer.Exit(1)

    result = _crack(
        hash_str=hash_str,
        wordlist_path=wordlist,
        algorithms=[algo] if algo else None,
    )

    console.print()

    if result.found:
        success(f"Hash cracked after [bold]{result.attempts:,}[/bold] attempt(s)!")
        result_panel(
            f"[bold green]{result.plaintext}[/bold green]",
            title=f"Plaintext  ({result.algorithm.upper()})",
            style="green",
        )
    else:
        error(f"Hash not cracked. Tried [bold]{result.attempts:,}[/bold] combinations.")
        warning("Try a larger wordlist, e.g. rockyou.txt:")
        console.print(
            "  [dim]ctf-toolkit hash crack <hash> --wordlist /usr/share/wordlists/rockyou.txt[/dim]\n"
        )
