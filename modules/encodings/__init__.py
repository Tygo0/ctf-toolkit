"""
Encoding module — CLI commands for encoding and decoding data.

Commands:
    ctf-toolkit encode base64 "hello"
    ctf-toolkit encode base64 "aGVsbG8=" --decode
    ctf-toolkit encode hex "hello"
    ctf-toolkit encode rot13 "secret"
    ctf-toolkit encode binary "hi"
    ctf-toolkit encode url "hello world"
    ctf-toolkit encode morse "SOS"
    ctf-toolkit encode detect "aGVsbG8="
"""

import typer
from typing import Optional
from rich.console import Console
from rich.table import Table
from rich import box

from utils.logger import info, success, warning, error, section
from utils.output import result_panel, multi_table

app = typer.Typer(
    name="encode",
    help="Encode and decode data (base64, hex, ROT13, binary, morse, url…)",
    no_args_is_help=True,
)

console = Console()


# ── Shared display helper ─────────────────────────────────────────────────────

def _show(label: str, result: str, mode: str) -> None:
    title = f"{mode.upper()}  [{label}]"
    result_panel(f"[bold white]{result}[/bold white]", title=title, style="cyan")


# ── base64 ────────────────────────────────────────────────────────────────────

@app.command("base64")
def cmd_base64(
    text: str = typer.Argument(..., help="Text to encode or decode."),
    decode: bool = typer.Option(False, "--decode", "-d", help="Decode instead of encode."),
):
    """Encode or decode Base64.

    \b
    Examples:
      ctf-toolkit encode base64 "hello world"
      ctf-toolkit encode base64 "aGVsbG8gd29ybGQ=" --decode
    """
    from modules.encodings.codecs import base64_encode, base64_decode
    section("Base64")
    try:
        result = base64_decode(text) if decode else base64_encode(text)
        _show("base64", result, "DECODE" if decode else "ENCODE")
    except ValueError as e:
        error(str(e))
        raise typer.Exit(1)


# ── base32 ────────────────────────────────────────────────────────────────────

@app.command("base32")
def cmd_base32(
    text: str = typer.Argument(..., help="Text to encode or decode."),
    decode: bool = typer.Option(False, "--decode", "-d", help="Decode instead of encode."),
):
    """Encode or decode Base32.

    \b
    Examples:
      ctf-toolkit encode base32 "hello"
      ctf-toolkit encode base32 "NBSWY3DPEB3W64TMMQ======" --decode
    """
    from modules.encodings.codecs import base32_encode, base32_decode
    section("Base32")
    try:
        result = base32_decode(text) if decode else base32_encode(text)
        _show("base32", result, "DECODE" if decode else "ENCODE")
    except ValueError as e:
        error(str(e))
        raise typer.Exit(1)


# ── base58 ────────────────────────────────────────────────────────────────────

@app.command("base58")
def cmd_base58(
    text: str = typer.Argument(..., help="Text to encode or decode."),
    decode: bool = typer.Option(False, "--decode", "-d", help="Decode instead of encode."),
):
    """Encode or decode Base58 (Bitcoin-style alphabet).

    \b
    Examples:
      ctf-toolkit encode base58 "hello"
      ctf-toolkit encode base58 "Cn8eVZg" --decode
    """
    from modules.encodings.codecs import base58_encode, base58_decode
    section("Base58")
    try:
        result = base58_decode(text) if decode else base58_encode(text)
        _show("base58", result, "DECODE" if decode else "ENCODE")
    except ValueError as e:
        error(str(e))
        raise typer.Exit(1)


# ── hex ───────────────────────────────────────────────────────────────────────

@app.command("hex")
def cmd_hex(
    text: str = typer.Argument(..., help="Text to encode or decode."),
    decode: bool = typer.Option(False, "--decode", "-d", help="Decode instead of encode."),
):
    """Encode text to hex or decode a hex string.

    \b
    Examples:
      ctf-toolkit encode hex "hello"
      ctf-toolkit encode hex "68656c6c6f" --decode
      ctf-toolkit encode hex "0x68 0x65 0x6c" --decode
    """
    from modules.encodings.codecs import hex_encode, hex_decode
    section("Hex")
    try:
        result = hex_decode(text) if decode else hex_encode(text)
        _show("hex", result, "DECODE" if decode else "ENCODE")
    except ValueError as e:
        error(str(e))
        raise typer.Exit(1)


# ── rot13 ─────────────────────────────────────────────────────────────────────

@app.command("rot13")
def cmd_rot13(
    text: str = typer.Argument(..., help="Text to ROT13 transform."),
    n: int = typer.Option(13, "--n", help="Rotation amount (default 13). Use any 1-25 for Caesar cipher."),
):
    """Apply ROT-N cipher (default ROT13). ROT13 is self-inverse.

    \b
    Examples:
      ctf-toolkit encode rot13 "hello"
      ctf-toolkit encode rot13 "uryyb"            # decodes back to hello
      ctf-toolkit encode rot13 "hello" --n 3      # Caesar cipher shift 3
    """
    from modules.encodings.codecs import rot_n
    section(f"ROT{n}")
    if not 1 <= n <= 25:
        error("Rotation must be between 1 and 25.")
        raise typer.Exit(1)
    result = rot_n(text, n)
    _show(f"rot{n}", result, "TRANSFORM")

    # Brute-force all rotations if it looks like we're trying to decode
    if n == 13:
        console.print("\n[dim]  All ROT rotations (brute-force):[/dim]")
        table = Table(box=box.SIMPLE, header_style="bold magenta", border_style="dim")
        table.add_column("ROT", style="bold cyan", no_wrap=True)
        table.add_column("Result", style="white")
        for i in range(1, 26):
            table.add_row(f"ROT{i}", rot_n(text, i))
        console.print(table)


# ── url ───────────────────────────────────────────────────────────────────────

@app.command("url")
def cmd_url(
    text: str = typer.Argument(..., help="Text to URL-encode or decode."),
    decode: bool = typer.Option(False, "--decode", "-d", help="Decode instead of encode."),
):
    """URL-encode or decode a string.

    \b
    Examples:
      ctf-toolkit encode url "hello world & more"
      ctf-toolkit encode url "hello%20world%20%26%20more" --decode
    """
    from modules.encodings.codecs import url_encode, url_decode
    section("URL Encoding")
    try:
        result = url_decode(text) if decode else url_encode(text)
        _show("url", result, "DECODE" if decode else "ENCODE")
    except ValueError as e:
        error(str(e))
        raise typer.Exit(1)


# ── binary ────────────────────────────────────────────────────────────────────

@app.command("binary")
def cmd_binary(
    text: str = typer.Argument(..., help="Text to encode, or binary string to decode."),
    decode: bool = typer.Option(False, "--decode", "-d", help="Decode binary to text."),
):
    """Encode text to binary or decode a binary string.

    \b
    Examples:
      ctf-toolkit encode binary "hi"
      ctf-toolkit encode binary "01101000 01101001" --decode
    """
    from modules.encodings.codecs import binary_encode, binary_decode
    section("Binary")
    try:
        result = binary_decode(text) if decode else binary_encode(text)
        _show("binary", result, "DECODE" if decode else "ENCODE")
    except ValueError as e:
        error(str(e))
        raise typer.Exit(1)


# ── morse ─────────────────────────────────────────────────────────────────────

@app.command("morse")
def cmd_morse(
    text: str = typer.Argument(..., help="Text to encode or morse code to decode."),
    decode: bool = typer.Option(False, "--decode", "-d", help="Decode morse to text."),
):
    """Encode text to Morse code or decode Morse code to text.

    \b
    Examples:
      ctf-toolkit encode morse "SOS"
      ctf-toolkit encode morse "... --- ..." --decode
    """
    from modules.encodings.codecs import morse_encode, morse_decode
    section("Morse Code")
    result = morse_decode(text) if decode else morse_encode(text)
    _show("morse", result, "DECODE" if decode else "ENCODE")


# ── html ──────────────────────────────────────────────────────────────────────

@app.command("html")
def cmd_html(
    text: str = typer.Argument(..., help="Text to encode or HTML entities to decode."),
    decode: bool = typer.Option(False, "--decode", "-d", help="Decode HTML entities."),
):
    """Encode special characters to HTML entities or decode them.

    \b
    Examples:
      ctf-toolkit encode html "<script>alert('xss')</script>"
      ctf-toolkit encode html "&lt;script&gt;" --decode
    """
    from modules.encodings.codecs import html_encode, html_decode
    section("HTML Entities")
    result = html_decode(text) if decode else html_encode(text)
    _show("html", result, "DECODE" if decode else "ENCODE")


# ── detect ────────────────────────────────────────────────────────────────────

@app.command("detect")
def cmd_detect(
    text: str = typer.Argument(..., help="Encoded string to analyse."),
):
    """Auto-detect encoding and try all decoders on the input.

    \b
    Examples:
      ctf-toolkit encode detect "aGVsbG8="
      ctf-toolkit encode detect "68656c6c6f"
      ctf-toolkit encode detect "... --- ..."
    """
    from modules.encodings.codecs import detect_encoding
    section("Encoding Detector")
    info(f"Input: [bold white]{text}[/bold white]")
    console.print()

    results = detect_encoding(text)

    if not results:
        warning("No recognisable encoding found.")
        console.print("[dim]  The string may be plaintext, encrypted, or a custom encoding.[/dim]\n")
        return

    success(f"Found [bold]{len(results)}[/bold] possible decoding(s):\n")

    table = Table(
        title="Auto-Detect Results",
        box=box.ROUNDED,
        header_style="bold magenta",
        border_style="cyan",
        show_lines=True,
    )
    table.add_column("Codec",   style="bold yellow", no_wrap=True)
    table.add_column("Decoded Output", style="white")

    for r in results:
        table.add_row(r["codec"].upper(), r["result"])

    console.print(table)
    console.print()
