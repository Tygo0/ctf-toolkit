"""
PDF metadata extractor — reads document info dict, XMP, and page data via PyPDF2.
"""

from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class PDFMetadata:
    file_name: str
    file_size: str
    page_count: int
    # Document info dict fields
    title: Optional[str]        = None
    author: Optional[str]       = None
    subject: Optional[str]      = None
    creator: Optional[str]      = None
    producer: Optional[str]     = None
    created: Optional[str]      = None
    modified: Optional[str]     = None
    keywords: Optional[str]     = None
    # Security
    encrypted: bool             = False
    # Extra
    pdf_version: Optional[str]  = None
    raw_info: dict              = field(default_factory=dict)
    warnings: list[str]         = field(default_factory=list)


def _clean(val) -> Optional[str]:
    """Strip PyPDF2 string wrappers and whitespace."""
    if val is None:
        return None
    s = str(val).strip()
    # Remove PDF date prefix: D:20231015120000
    if s.startswith("D:"):
        s = s[2:]
        # Try to pretty-print: YYYYMMDDHHMMSS
        try:
            from datetime import datetime
            dt = datetime.strptime(s[:14], "%Y%m%d%H%M%S")
            return dt.strftime("%Y-%m-%d %H:%M:%S")
        except Exception:
            return s
    return s or None


def extract(path: Path) -> PDFMetadata:
    """Extract metadata from a PDF file."""
    import PyPDF2
    from utils.helpers import file_size_str

    meta = PDFMetadata(
        file_name=path.name,
        file_size=file_size_str(path),
        page_count=0,
    )

    try:
        with open(path, "rb") as f:
            reader = PyPDF2.PdfReader(f)

            meta.encrypted  = reader.is_encrypted
            meta.page_count = len(reader.pages)

            # PDF version from raw stream
            try:
                f.seek(0)
                first_line = f.read(16).decode("latin-1", errors="replace")
                if first_line.startswith("%PDF-"):
                    meta.pdf_version = first_line[5:8].strip()
            except Exception:
                pass

            if reader.is_encrypted:
                meta.warnings.append("PDF is encrypted; metadata may be limited.")
                try:
                    reader.decrypt("")  # attempt blank password
                except Exception:
                    pass

            # Document info dictionary
            info = reader.metadata
            if info:
                raw = {}
                for k, v in info.items():
                    raw[str(k)] = str(v)
                meta.raw_info = raw

                meta.title    = _clean(info.get("/Title"))
                meta.author   = _clean(info.get("/Author"))
                meta.subject  = _clean(info.get("/Subject"))
                meta.creator  = _clean(info.get("/Creator"))
                meta.producer = _clean(info.get("/Producer"))
                meta.created  = _clean(info.get("/CreationDate"))
                meta.modified = _clean(info.get("/ModDate"))
                meta.keywords = _clean(info.get("/Keywords"))

    except Exception as e:
        meta.warnings.append(f"PDF read error: {e}")

    return meta
