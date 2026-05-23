"""
File type dispatcher — detects the appropriate metadata extractor for a given file.
Uses both file extension and magic bytes for reliable detection.
"""

from pathlib import Path
from enum import Enum, auto


class FileKind(Enum):
    IMAGE  = auto()
    PDF    = auto()
    OFFICE = auto()
    UNKNOWN = auto()


# ── Magic byte signatures ─────────────────────────────────────────────────────

_MAGIC: list[tuple[bytes, FileKind]] = [
    (b"\xff\xd8\xff",            FileKind.IMAGE),   # JPEG
    (b"\x89PNG\r\n\x1a\n",      FileKind.IMAGE),   # PNG
    (b"GIF87a",                  FileKind.IMAGE),   # GIF87
    (b"GIF89a",                  FileKind.IMAGE),   # GIF89
    (b"II*\x00",                 FileKind.IMAGE),   # TIFF little-endian
    (b"MM\x00*",                 FileKind.IMAGE),   # TIFF big-endian
    (b"RIFF",                    FileKind.IMAGE),   # WebP (RIFF....WEBP)
    (b"%PDF",                    FileKind.PDF),
    (b"PK\x03\x04",              FileKind.OFFICE),  # ZIP → could be Office Open XML
]

_IMAGE_EXT  = {".jpg", ".jpeg", ".png", ".gif", ".tiff", ".tif", ".webp", ".bmp", ".heic"}
_OFFICE_EXT = {".docx", ".docm", ".xlsx", ".xlsm", ".pptx", ".pptm"}


def detect_kind(path: Path) -> FileKind:
    """Return the FileKind for a given path using magic bytes + extension."""
    suffix = path.suffix.lower()

    # Read magic bytes
    try:
        with open(path, "rb") as f:
            header = f.read(16)
    except Exception:
        header = b""

    for magic, kind in _MAGIC:
        if header.startswith(magic):
            # Disambiguate ZIP: could be Office or generic ZIP
            if kind == FileKind.OFFICE:
                if suffix in _OFFICE_EXT:
                    return FileKind.OFFICE
                # Fall through to extension check
                break
            return kind

    # Fall back to extension
    if suffix in _IMAGE_EXT:
        return FileKind.IMAGE
    if suffix == ".pdf":
        return FileKind.PDF
    if suffix in _OFFICE_EXT:
        return FileKind.OFFICE

    return FileKind.UNKNOWN


def extract_metadata(path: Path):
    """
    Dispatch to the correct extractor and return the metadata dataclass.
    Returns one of: ImageMetadata | PDFMetadata | OfficeMetadata | None
    """
    kind = detect_kind(path)

    if kind == FileKind.IMAGE:
        from modules.metadata.image_extractor import extract
        return extract(path), kind

    if kind == FileKind.PDF:
        from modules.metadata.pdf_extractor import extract
        return extract(path), kind

    if kind == FileKind.OFFICE:
        from modules.metadata.office_extractor import extract
        return extract(path), kind

    return None, kind
