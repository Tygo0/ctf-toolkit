"""
ZIP / Archive tools module — recursive extraction, password cracking, safety checks.

Commands:
    ctf-toolkit zip extract <file>
    ctf-toolkit zip inspect <file>
"""

import typer
from pathlib import Path
from rich.console import Console
from rich.tree import Tree
from rich.table import Table
from rich import box

from utils.logger import info, success, warning, error, section
from utils.helpers import resolve_file, read_wordlist, file_size_str
from utils.output import kv_table

app = typer.Typer(
    name="zip",
    help="Recursive archive extraction with password cracking and safety checks.",
    no_args_is_help=True,
)

console = Console()


# ── Result tree renderer ──────────────────────────────────────────────────────

def _render_tree(result, tree=None):
    """Recursively build a Rich Tree from ExtractionResult."""
    from modules.ziptools.extractor import ExtractionResult

    label = f"[bold cyan]{result.archive_name}[/bold cyan]"
    if result.password_used is not None:
        label += f"  [bold green]🔓 password: '{result.password_used}'[/bold green]"
    if not result.success:
        label += f"  [bold red]✗ {result.error}[/bold red]"

    node = tree.add(label) if tree else Tree(label)

    if result.success:
        for f in result.files_extracted:
            is_child_archive = any(
                cr.archive_name == Path(f).name for cr in result.child_results
            )
            style = "bold yellow" if is_child_archive else "dim white"
            icon  = "📦" if is_child_archive else "📄"
            node.add(f"[{style}]{icon} {f}[/{style}]")

    for child in result.child_results:
        _render_tree(child, node)

    return node


def _count_results(result) -> tuple[int, int]:
    """Return (total_files, total_archives) from result tree."""
    files    = len(result.files_extracted)
    archives = len(result.child_results)
    for child in result.child_results:
        cf, ca = _count_results(child)
        files    += cf
        archives += ca
    return files, archives


# ── Surface helper ───────────────────────────────────────────────────────────

def _surface_final_files(out_dir: Path) -> list[str]:
    """
    Walk the entire output directory tree, collect every file that is NOT
    an archive, and copy it into out_dir/found/ — flat, deduplicated.
    Returns list of copied filenames.
    """
    import shutil
    from modules.ziptools.extractor import _is_archive

    found_dir = out_dir / "found"
    found_dir.mkdir(parents=True, exist_ok=True)

    surfaced = []
    seen_names: dict[str, int] = {}

    for p in sorted(out_dir.rglob("*")):
        # Skip the found/ dir itself and non-files
        if not p.is_file():
            continue
        if p.is_relative_to(found_dir):
            continue
        if _is_archive(p):
            continue

        # Deduplicate filenames (flag.txt from 3 layers → flag.txt, flag_1.txt …)
        name = p.name
        if name in seen_names:
            seen_names[name] += 1
            stem, suffix = Path(name).stem, Path(name).suffix
            name = f"{stem}_{seen_names[p.name]}{suffix}"
        else:
            seen_names[p.name] = 0

        dest = found_dir / name
        shutil.copy2(p, dest)
        surfaced.append(name)

    # Remove found/ if nothing ended up there
    if not surfaced:
        found_dir.rmdir()

    return surfaced


# ── extract ───────────────────────────────────────────────────────────────────

@app.command("extract")
def extract(
    archive: str = typer.Argument(..., help="Archive file to extract."),
    output: str = typer.Option(
        None, "--output", "-o",
        help="Output directory. Defaults to <archive_name>_out/ next to the archive.",
    ),
    wordlist: str = typer.Option(
        None, "--wordlist", "-w",
        help="Wordlist for password-protected ZIPs. Defaults to wordlists/common.txt.",
    ),
    no_recurse: bool = typer.Option(
        False, "--no-recurse",
        help="Disable recursive extraction of nested archives.",
    ),
    force: bool = typer.Option(
        False, "--force", "-f",
        help="Skip safety confirmation prompts.",
    ),
):
    """
    Extract an archive recursively, cracking passwords and diving into nested archives.

    \b
    Examples:
      ctf-toolkit zip extract challenge.zip
      ctf-toolkit zip extract nested.zip --output /tmp/out
      ctf-toolkit zip extract locked.zip --wordlist wordlists/common.txt
      ctf-toolkit zip extract single.zip --no-recurse
    """
    from modules.ziptools.extractor import (
        extract_recursive, _is_zip, _is_tar, flatten_results
    )
    from modules.ziptools.safety import check_zip, check_tar

    path = resolve_file(archive)
    section(f"Archive Extractor — {path.name}")

    # Determine output directory
    out_dir = Path(output) if output else path.parent / f"{path.stem}_out"
    info(f"Archive:    [bold white]{path}[/bold white]")
    info(f"Output dir: [bold white]{out_dir}[/bold white]")
    info(f"Recursive:  [bold white]{'No' if no_recurse else 'Yes'}[/bold white]")
    console.print()

    # Pre-flight safety check
    if _is_zip(path):
        report = check_zip(path)
    elif _is_tar(path):
        report = check_tar(path)
    else:
        error(f"Unrecognised archive format: [bold]{path.suffix}[/bold]")
        info("Supported formats: .zip  .tar  .tar.gz  .tgz  .tar.bz2")
        raise typer.Exit(1)

    # Display pre-flight info
    stats = {
        "Compressed Size":   file_size_str(path),
        "Uncompressed Size": f"{report.uncompressed_size / 1024:.1f} KB"
                             if report.uncompressed_size < 1024 * 1024
                             else f"{report.uncompressed_size / 1024 / 1024:.2f} MB",
        "File Count":        str(report.file_count),
        "Compression Ratio": f"{report.compression_ratio:.1f}:1",
        "Safety":            "[bold green]PASS[/bold green]" if report.safe
                             else f"[bold red]FAIL[/bold red] — {report.reason}",
    }
    kv_table("Pre-flight Inspection", stats)
    console.print()

    if not report.safe:
        error(f"Safety check failed: {report.reason}")
        if not force:
            warning("Use [bold]--force[/bold] to override safety checks (dangerous!).")
            raise typer.Exit(1)
        else:
            warning("Safety check overridden by --force. Proceeding anyway…")

    # Load wordlist
    wl = read_wordlist(wordlist) if wordlist else read_wordlist()
    if wl:
        info(f"Loaded [bold]{len(wl):,}[/bold] passwords from wordlist.")
        console.print()

    # Run extraction
    info("Extracting…")
    result = extract_recursive(
        path=path,
        output_root=out_dir,
        wordlist=wl if wl else None,
        depth=0,
    )

    console.print()

    # Render result tree
    tree = _render_tree(result)
    console.print(tree)
    console.print()

    if not result.success:
        error(f"Extraction failed: {result.error}")
        raise typer.Exit(1)

    total_files, total_archives = _count_results(result)
    success(
        f"Done! Extracted [bold]{total_files}[/bold] file(s) "
        f"across [bold]{total_archives + 1}[/bold] archive(s)."
    )

    # Surface all final (non-archive) files to out_dir/found/
    surfaced = _surface_final_files(out_dir)
    if surfaced:
        found_dir = out_dir / "found"
        console.print()
        success(f"Surfaced [bold]{len(surfaced)}[/bold] final file(s) → [bold cyan]{found_dir}[/bold cyan]")
        for name in surfaced:
            console.print(f"  [bold green]✓[/bold green] [white]{name}[/white]")
    else:
        info(f"Output: [bold cyan]{out_dir}[/bold cyan]")

    console.print()


# ── inspect ───────────────────────────────────────────────────────────────────

@app.command("inspect")
def inspect(
    archive: str = typer.Argument(..., help="Archive file to inspect."),
):
    """
    Inspect an archive's contents and safety profile without extracting.

    \b
    Examples:
      ctf-toolkit zip inspect challenge.zip
      ctf-toolkit zip inspect archive.tar.gz
    """
    from modules.ziptools.extractor import _is_zip, _is_tar
    from modules.ziptools.safety import check_zip, check_tar
    import zipfile, tarfile

    path = resolve_file(archive)
    section(f"Archive Inspector — {path.name}")

    if _is_zip(path):
        report = check_zip(path)
        is_zip = True
    elif _is_tar(path):
        report = check_tar(path)
        is_zip = False
    else:
        error(f"Unrecognised archive format: [bold]{path.suffix}[/bold]")
        raise typer.Exit(1)

    # Safety report
    safety_stats = {
        "Archive Size":      file_size_str(path),
        "Uncompressed Size": f"{report.uncompressed_size / 1024 / 1024:.2f} MB",
        "File Count":        str(report.file_count),
        "Compression Ratio": f"{report.compression_ratio:.1f}:1",
        "Safety Status":     "[bold green]SAFE[/bold green]" if report.safe
                             else f"[bold red]UNSAFE[/bold red] — {report.reason}",
    }
    kv_table("Safety Report", safety_stats)
    console.print()

    # File listing
    table = Table(
        title="Contents",
        box=box.ROUNDED,
        header_style="bold magenta",
        border_style="dim",
        show_lines=False,
    )
    table.add_column("File",              style="white",       max_width=60)
    table.add_column("Compressed",        style="cyan",        no_wrap=True)
    table.add_column("Uncompressed",      style="cyan",        no_wrap=True)
    table.add_column("Ratio",             style="dim",         no_wrap=True)
    table.add_column("Encrypted",         style="bold yellow", no_wrap=True)

    try:
        if is_zip:
            with zipfile.ZipFile(path, "r") as zf:
                for info in zf.infolist():
                    comp   = f"{info.compress_size / 1024:.1f} KB"
                    uncomp = f"{info.file_size / 1024:.1f} KB"
                    ratio  = (
                        f"{info.file_size / info.compress_size:.1f}:1"
                        if info.compress_size > 0 else "—"
                    )
                    encrypted = "[red]YES[/red]" if (info.flag_bits & 0x1) else "[green]No[/green]"
                    table.add_row(info.filename, comp, uncomp, ratio, encrypted)
        else:
            with tarfile.open(path, "r:*") as tf:
                for member in tf.getmembers():
                    if member.isfile():
                        size = f"{member.size / 1024:.1f} KB"
                        table.add_row(member.name, "—", size, "—", "[green]No[/green]")

        console.print(table)
    except Exception as e:
        error(f"Could not list contents: {e}")

    console.print()
