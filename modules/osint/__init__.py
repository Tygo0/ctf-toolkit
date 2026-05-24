"""
OSINT module — WHOIS, DNS, IP resolution, and subdomain enumeration.

Commands:
    ctf-toolkit osint whois <target>
    ctf-toolkit osint dns <target> [--type TYPE]
    ctf-toolkit osint resolve <ip>
    ctf-toolkit osint subdomains <domain>
"""

import typer
from typing import Optional
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich import box

from utils.logger import info, success, warning, error, section
from utils.output import kv_table, multi_table

app = typer.Typer(
    name="osint",
    help="OSINT utilities: WHOIS, DNS records, IP resolution, subdomain enumeration.",
    no_args_is_help=True,
)

console = Console()


# ── whois ─────────────────────────────────────────────────────────────────────

@app.command("whois")
def cmd_whois(
    target: str = typer.Argument(..., help="Domain name or IP address to query."),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Show raw WHOIS text."),
):
    """
    Perform a WHOIS lookup for a domain or IP address.

    \b
    Examples:
      ctf-toolkit osint whois example.com
      ctf-toolkit osint whois 93.184.216.34
      ctf-toolkit osint whois google.com --verbose
    """
    from modules.osint.whois_lookup import lookup

    section(f"WHOIS — {target}")

    info(f"Querying WHOIS for [bold white]{target}[/bold white]…")
    console.print()

    result = lookup(target)

    if result.warnings and not any(result.registrar or result.created or result.name_servers):
        for w in result.warnings:
            error(w)
        raise typer.Exit(1)

    # Registrar info
    registrar_data = {k: v for k, v in {
        "Registrar":     result.registrar,
        "Registrar URL": result.registrar_url,
        "WHOIS Server":  result.whois_server,
        "DNSSEC":        result.dnssec,
    }.items() if v}
    if registrar_data:
        kv_table("Registrar", registrar_data)
        console.print()

    # Dates
    date_data = {k: v for k, v in {
        "Created":  result.created,
        "Updated":  result.updated,
        "Expires":  result.expires,
    }.items() if v}
    if date_data:
        kv_table("Dates", date_data)
        console.print()

    # Registrant
    registrant_data = {k: v for k, v in {
        "Name":    result.registrant_name,
        "Org":     result.registrant_org,
        "Email":   result.registrant_email,
        "Country": result.registrant_country,
    }.items() if v}
    if registrant_data:
        kv_table("Registrant", registrant_data)
        console.print()

    # Name servers
    if result.name_servers:
        table = Table(title="Name Servers", box=box.SIMPLE_HEAVY,
                      header_style="bold magenta", border_style="dim")
        table.add_column("Nameserver", style="bold cyan")
        for ns in result.name_servers:
            table.add_row(ns)
        console.print(table)
        console.print()

    # Status flags
    if result.status:
        table = Table(title="Domain Status", box=box.SIMPLE_HEAVY,
                      header_style="bold magenta", border_style="dim")
        table.add_column("Status", style="white")
        for s in result.status:
            table.add_row(s)
        console.print(table)
        console.print()

    if result.warnings:
        for w in result.warnings:
            warning(w)
        console.print()

    if verbose and result.raw_text:
        section("Raw WHOIS Text")
        console.print(f"[dim]{result.raw_text}[/dim]")


# ── dns ───────────────────────────────────────────────────────────────────────

@app.command("dns")
def cmd_dns(
    target: str = typer.Argument(..., help="Domain name to query."),
    rtype: str  = typer.Option(
        "ALL", "--type", "-t",
        help="Record type: A, AAAA, MX, NS, TXT, CNAME, SOA, PTR, SRV, CAA — or ALL.",
    ),
    nameserver: Optional[str] = typer.Option(
        None, "--nameserver", "-n",
        help="Custom nameserver IP (e.g. 8.8.8.8 for Google DNS).",
    ),
):
    """
    Query DNS records for a domain.

    \b
    Examples:
      ctf-toolkit osint dns example.com
      ctf-toolkit osint dns example.com --type MX
      ctf-toolkit osint dns example.com --type TXT
      ctf-toolkit osint dns example.com --nameserver 1.1.1.1
    """
    from modules.osint.dns_lookup import lookup, lookup_all, ALL_RECORD_TYPES

    rtype_upper = rtype.upper()
    section(f"DNS — {target}  [{rtype_upper}]")
    ns_label = f" via [bold]{nameserver}[/bold]" if nameserver else ""
    info(f"Querying DNS for [bold white]{target}[/bold white]{ns_label}…")
    console.print()

    if rtype_upper == "ALL":
        results = lookup_all(target, nameserver)
        if not results:
            warning("No DNS records found for this domain.")
            raise typer.Exit(1)
        for r in results:
            _render_dns_result(r)
    else:
        if rtype_upper not in ALL_RECORD_TYPES:
            error(f"Unknown record type: [bold]{rtype}[/bold]")
            info(f"Valid types: {', '.join(ALL_RECORD_TYPES)}  or  ALL")
            raise typer.Exit(1)
        result = lookup(target, rtype_upper, nameserver)
        _render_dns_result(result)


def _render_dns_result(result) -> None:
    """Render a single DNSResult as a Rich table."""
    if result.warnings and not result.records:
        for w in result.warnings:
            warning(w)
        return

    has_priority = any(r.priority is not None for r in result.records)

    table = Table(
        title=f"[bold]{result.record_type}[/bold] records for [cyan]{result.query}[/cyan]",
        box=box.ROUNDED,
        header_style="bold magenta",
        border_style="dim",
        show_lines=False,
    )

    if has_priority:
        table.add_column("Priority", style="bold yellow", no_wrap=True, justify="right")
    table.add_column("Value", style="white")
    table.add_column("TTL",   style="dim",        no_wrap=True)

    for rec in sorted(result.records, key=lambda r: (r.priority or 0, r.value)):
        row = []
        if has_priority:
            row.append(str(rec.priority) if rec.priority is not None else "—")
        row += [rec.value, str(rec.ttl) if rec.ttl else "—"]
        table.add_row(*row)

    console.print(table)
    console.print()


# ── resolve ───────────────────────────────────────────────────────────────────

@app.command("resolve")
def cmd_resolve(
    target: str = typer.Argument(..., help="Domain name or IP address."),
    nameserver: Optional[str] = typer.Option(
        None, "--nameserver", "-n", help="Custom nameserver IP.",
    ),
):
    """
    Resolve a domain to IP addresses, or reverse-lookup an IP to hostname.
    Auto-detects whether the input is a domain or an IP.

    \b
    Examples:
      ctf-toolkit osint resolve example.com
      ctf-toolkit osint resolve 93.184.216.34
    """
    from modules.osint.dns_lookup import lookup, reverse_lookup
    import re

    section(f"Resolve — {target}")

    # Detect IP vs domain
    is_ip = bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", target) or
                 re.match(r"^[0-9a-fA-F:]+$", target))

    if is_ip:
        info(f"Reverse DNS lookup for [bold white]{target}[/bold white]…")
        console.print()
        result = reverse_lookup(target)
        if result.records:
            success(f"[bold white]{target}[/bold white] resolves to:")
            for rec in result.records:
                console.print(f"  [bold green]→[/bold green] [bold cyan]{rec.value}[/bold cyan]")
        else:
            warning("No PTR record found for this IP.")
    else:
        info(f"Resolving [bold white]{target}[/bold white]…")
        console.print()

        # A records
        a_result = lookup(target, "A", nameserver)
        # AAAA records
        aaaa_result = lookup(target, "AAAA", nameserver)

        if a_result.records:
            success(f"[bold white]{target}[/bold white] → IPv4:")
            for rec in a_result.records:
                console.print(f"  [bold green]→[/bold green] [bold cyan]{rec.value}[/bold cyan]  [dim](TTL {rec.ttl})[/dim]")
        if aaaa_result.records:
            console.print()
            success(f"[bold white]{target}[/bold white] → IPv6:")
            for rec in aaaa_result.records:
                console.print(f"  [bold green]→[/bold green] [bold cyan]{rec.value}[/bold cyan]  [dim](TTL {rec.ttl})[/dim]")

        if not a_result.records and not aaaa_result.records:
            for w in a_result.warnings + aaaa_result.warnings:
                warning(w)

    console.print()


# ── subdomains ────────────────────────────────────────────────────────────────

@app.command("subdomains")
def cmd_subdomains(
    domain: str = typer.Argument(..., help="Target domain to enumerate."),
    wordlist: Optional[str] = typer.Option(
        None, "--wordlist", "-w",
        help="Custom wordlist file (one subdomain per line). Uses built-in list if omitted.",
    ),
    threads: int = typer.Option(
        30, "--threads", "-t",
        help="Number of concurrent DNS threads (default: 30).",
    ),
    nameserver: Optional[str] = typer.Option(
        None, "--nameserver", "-n",
        help="Custom nameserver IP.",
    ),
):
    """
    Enumerate subdomains via DNS brute-force.
    Uses a built-in wordlist of common subdomains by default.

    \b
    Examples:
      ctf-toolkit osint subdomains example.com
      ctf-toolkit osint subdomains example.com --wordlist subdomains.txt
      ctf-toolkit osint subdomains example.com --threads 50 --nameserver 8.8.8.8
    """
    from modules.osint.subdomain import enumerate_subdomains, BUILTIN_WORDLIST
    from utils.helpers import read_wordlist

    section(f"Subdomain Enumeration — {domain}")

    # Load wordlist
    if wordlist:
        words = read_wordlist(wordlist)
        if not words:
            error(f"Could not load wordlist: [bold]{wordlist}[/bold]")
            raise typer.Exit(1)
        info(f"Loaded [bold]{len(words):,}[/bold] words from [bold white]{wordlist}[/bold white].")
    else:
        words = BUILTIN_WORDLIST
        info(f"Using built-in wordlist ([bold]{len(words):,}[/bold] subdomains).")

    info(f"Threads:    [bold white]{threads}[/bold white]")
    info(f"Nameserver: [bold white]{nameserver or 'system default'}[/bold white]")
    console.print()

    found_count = 0

    with Progress(
        SpinnerColumn(),
        TextColumn("[bold cyan]{task.description}"),
        BarColumn(),
        TextColumn("[dim]{task.completed}/{task.total}"),
        console=console,
    ) as progress:
        task = progress.add_task(f"Scanning {domain}…", total=len(words))

        def on_progress(sub: str):
            progress.advance(task)

        result = enumerate_subdomains(
            domain=domain,
            wordlist=words,
            threads=threads,
            nameserver=nameserver,
            progress_cb=on_progress,
        )
        found_count = len(result.hits)

    console.print()

    if not result.hits:
        warning("No subdomains found.")
        info("Try a larger wordlist or increase thread count.")
        raise typer.Exit(0)

    # Results table
    table = Table(
        title=f"[bold]Discovered Subdomains[/bold] — {found_count} found",
        box=box.ROUNDED,
        header_style="bold magenta",
        border_style="cyan",
        show_lines=False,
    )
    table.add_column("Subdomain",    style="bold yellow", no_wrap=True)
    table.add_column("FQDN",         style="bold cyan")
    table.add_column("IP Address(es)", style="white")
    table.add_column("CNAME",        style="dim white")

    for hit in result.hits:
        ips   = ", ".join(hit.ip_addresses) if hit.ip_addresses else "[dim]—[/dim]"
        cname = hit.cname or "[dim]—[/dim]"
        table.add_row(hit.subdomain, hit.fqdn, ips, cname)

    console.print(table)
    console.print()

    success(f"Found [bold]{found_count}[/bold] subdomain(s). "
            f"Checked [bold]{result.checked:,}[/bold], "
            f"errors: [bold]{result.errors}[/bold].")
    console.print()
