"""
Metadata module — extract and display metadata from images, PDFs, and Office files.

Commands:
    ctf-toolkit metadata analyze <file>
    ctf-toolkit metadata dump <file>       # full raw tag dump
"""

import typer
from pathlib import Path
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

from utils.logger import info, success, warning, error, section
from utils.helpers import resolve_file
from utils.output import kv_table

app = typer.Typer(
    name="metadata",
    help="Extract metadata from images, PDFs, and Office documents.",
    no_args_is_help=True,
)

console = Console()


# ── Shared renderers ──────────────────────────────────────────────────────────

def _render_image(meta, verbose: bool) -> None:
    from modules.metadata.image_extractor import ImageMetadata

    # File info
    file_info = {
        "File Name": meta.file_name,
        "File Size": meta.file_size,
        "File Type": meta.file_type,
    }

    # Camera / device
    camera = {k: v for k, v in {
        "Make":            meta.make,
        "Model":           meta.model,
        "Software":        meta.software,
        "Artist":          meta.artist,
        "Copyright":       meta.copyright,
        "Description":     meta.image_description,
    }.items() if v}

    # Timestamps
    timestamps = {k: v for k, v in {
        "Date/Time":          meta.datetime,
        "Date/Time Original": meta.datetime_original,
    }.items() if v}

    # Image properties
    image_props = {k: v for k, v in {
        "Width":       meta.width,
        "Height":      meta.height,
        "Orientation": meta.orientation,
        "Color Space": meta.color_space,
    }.items() if v}

    # Camera settings
    cam_settings = {k: v for k, v in {
        "Exposure Time": meta.exposure_time,
        "F-Number":      meta.f_number,
        "ISO":           meta.iso,
        "Focal Length":  meta.focal_length,
        "Flash":         meta.flash,
    }.items() if v}

    # GPS
    gps = {k: v for k, v in {
        "Latitude":  meta.gps_latitude,
        "Longitude": meta.gps_longitude,
        "Altitude":  meta.gps_altitude,
    }.items() if v}

    kv_table("File Info", file_info)

    if camera:
        console.print()
        kv_table("Device / Author", camera)

    if timestamps:
        console.print()
        kv_table("Timestamps", timestamps)

    if image_props:
        console.print()
        kv_table("Image Properties", image_props)

    if cam_settings:
        console.print()
        kv_table("Camera Settings", cam_settings)

    if gps:
        console.print()
        kv_table("GPS / Location", gps)
        lat = meta.gps_latitude.rstrip("°") if meta.gps_latitude else None
        lon = meta.gps_longitude.rstrip("°") if meta.gps_longitude else None
        if lat and lon:
            console.print(
                f"\n  [dim]→ Google Maps: [cyan]https://maps.google.com/?q={lat},{lon}[/cyan][/dim]"
            )

    if verbose and meta.raw_tags:
        console.print()
        _dump_raw(meta.raw_tags, "Raw EXIF Tags")

    if meta.warnings:
        console.print()
        for w in meta.warnings:
            warning(w)


def _render_pdf(meta, verbose: bool) -> None:
    file_info = {
        "File Name":   meta.file_name,
        "File Size":   meta.file_size,
        "PDF Version": meta.pdf_version or "Unknown",
        "Pages":       str(meta.page_count),
        "Encrypted":   "[bold red]YES[/bold red]" if meta.encrypted else "[green]No[/green]",
    }
    doc_info = {k: v for k, v in {
        "Title":    meta.title,
        "Author":   meta.author,
        "Subject":  meta.subject,
        "Keywords": meta.keywords,
        "Creator":  meta.creator,
        "Producer": meta.producer,
        "Created":  meta.created,
        "Modified": meta.modified,
    }.items() if v}

    kv_table("File Info", file_info)

    if doc_info:
        console.print()
        kv_table("Document Properties", doc_info)

    if verbose and meta.raw_info:
        console.print()
        _dump_raw(meta.raw_info, "Raw PDF Info Dict")

    if meta.warnings:
        console.print()
        for w in meta.warnings:
            warning(w)


def _render_office(meta, verbose: bool) -> None:
    file_info = {
        "File Name": meta.file_name,
        "File Size": meta.file_size,
        "Type":      meta.doc_type,
    }
    doc_info = {k: v for k, v in {
        "Title":            meta.title,
        "Subject":          meta.subject,
        "Author / Creator": meta.creator,
        "Last Modified By": meta.last_modified_by,
        "Keywords":         meta.keywords,
        "Description":      meta.description,
        "Created":          meta.created,
        "Modified":         meta.modified,
        "Revision":         meta.revision,
    }.items() if v}

    app_info = {k: v for k, v in {
        "Application": meta.application,
        "Version":     meta.app_version,
        "Company":     meta.company,
    }.items() if v}

    stats = {k: v for k, v in {
        "Pages":      meta.pages,
        "Words":      meta.words,
        "Characters": meta.characters,
        "Slides":     meta.slides,
        "Worksheets": meta.worksheets,
    }.items() if v}

    kv_table("File Info", file_info)

    if doc_info:
        console.print()
        kv_table("Document Properties", doc_info)

    if app_info:
        console.print()
        kv_table("Application Info", app_info)

    if stats:
        console.print()
        kv_table("Content Stats", stats)

    if verbose and (meta.raw_core or meta.raw_app):
        console.print()
        _dump_raw({**meta.raw_core, **meta.raw_app}, "Raw Properties")

    if meta.warnings:
        console.print()
        for w in meta.warnings:
            warning(w)


def _dump_raw(tags: dict, title: str) -> None:
    table = Table(
        title=title,
        box=box.SIMPLE_HEAVY,
        header_style="bold magenta",
        border_style="dim",
        expand=False,
        show_lines=False,
    )
    table.add_column("Tag",   style="bold cyan",  no_wrap=True, max_width=40)
    table.add_column("Value", style="white",       max_width=80)
    for k, v in sorted(tags.items()):
        table.add_row(str(k), str(v))
    console.print(table)


# ── analyze command ───────────────────────────────────────────────────────────

@app.command("analyze")
def analyze(
    file_path: str = typer.Argument(..., help="File to extract metadata from."),
    verbose: bool  = typer.Option(False, "--verbose", "-v", help="Show full raw tag dump."),
):
    """
    Extract and display metadata from an image, PDF, or Office document.
    File type is detected automatically from magic bytes.

    \b
    Examples:
      ctf-toolkit metadata analyze photo.jpg
      ctf-toolkit metadata analyze report.pdf
      ctf-toolkit metadata analyze document.docx
      ctf-toolkit metadata analyze spreadsheet.xlsx --verbose
    """
    from modules.metadata.detector import extract_metadata, FileKind

    path = resolve_file(file_path)
    section(f"Metadata — {path.name}")

    meta, kind = extract_metadata(path)

    if kind == FileKind.UNKNOWN or meta is None:
        error(f"Unsupported file type: [bold]{path.suffix}[/bold]")
        info("Supported: JPEG, PNG, TIFF, GIF, WebP  |  PDF  |  DOCX, XLSX, PPTX")
        raise typer.Exit(1)

    if kind == FileKind.IMAGE:
        _render_image(meta, verbose)
    elif kind == FileKind.PDF:
        _render_pdf(meta, verbose)
    elif kind == FileKind.OFFICE:
        _render_office(meta, verbose)

    console.print()
    success("Metadata extraction complete.")


# ── dump command ──────────────────────────────────────────────────────────────

@app.command("dump")
def dump(
    file_path: str = typer.Argument(..., help="File to dump all raw tags from."),
):
    """
    Dump every raw metadata tag/field found in the file.
    Useful for hunting hidden CTF flags in obscure EXIF fields.

    \b
    Examples:
      ctf-toolkit metadata dump suspicious.jpg
      ctf-toolkit metadata dump challenge.pdf
    """
    from modules.metadata.detector import extract_metadata, FileKind

    path = resolve_file(file_path)
    section(f"Raw Tag Dump — {path.name}")

    meta, kind = extract_metadata(path)

    if kind == FileKind.UNKNOWN or meta is None:
        error(f"Unsupported file type: [bold]{path.suffix}[/bold]")
        raise typer.Exit(1)

    if kind == FileKind.IMAGE:
        if meta.raw_tags:
            _dump_raw(meta.raw_tags, f"All Tags ({len(meta.raw_tags)})")
        else:
            warning("No EXIF tags found in this image.")

    elif kind == FileKind.PDF:
        all_raw = meta.raw_info
        if all_raw:
            _dump_raw(all_raw, f"PDF Info Dict ({len(all_raw)} fields)")
        else:
            warning("No metadata fields found in this PDF.")

    elif kind == FileKind.OFFICE:
        combined = {**meta.raw_core, **meta.raw_app}
        if combined:
            _dump_raw(combined, f"All Properties ({len(combined)} fields)")
        else:
            warning("No metadata properties found.")

    console.print()
