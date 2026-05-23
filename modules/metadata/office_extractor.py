"""
Office document metadata extractor — parses .docx / .xlsx / .pptx core properties.
Office Open XML files are ZIP archives; we read docProps/core.xml and app.xml directly
without needing python-docx or openpyxl as hard dependencies.
"""

from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional
import zipfile
import xml.etree.ElementTree as ET


# ── XML namespace map ─────────────────────────────────────────────────────────

_NS = {
    "cp":  "http://schemas.openxmlformats.org/package/2006/metadata/core-properties",
    "dc":  "http://purl.org/dc/elements/1.1/",
    "dcterms": "http://purl.org/dc/terms/",
    "vt":  "http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes",
    "ep":  "http://schemas.openxmlformats.org/officeDocument/2006/extended-properties",
}


@dataclass
class OfficeMetadata:
    file_name: str
    file_size: str
    doc_type: str                   # Word / Excel / PowerPoint
    # Core properties
    title: Optional[str]            = None
    subject: Optional[str]          = None
    creator: Optional[str]          = None
    keywords: Optional[str]         = None
    description: Optional[str]      = None
    last_modified_by: Optional[str] = None
    created: Optional[str]          = None
    modified: Optional[str]         = None
    revision: Optional[str]         = None
    # Extended / app properties
    application: Optional[str]      = None
    app_version: Optional[str]      = None
    company: Optional[str]          = None
    # Content stats (Word)
    pages: Optional[str]            = None
    words: Optional[str]            = None
    characters: Optional[str]       = None
    # Content stats (Excel / PPT)
    slides: Optional[str]           = None
    worksheets: Optional[str]       = None
    # Raw
    raw_core: dict                   = field(default_factory=dict)
    raw_app: dict                    = field(default_factory=dict)
    warnings: list[str]              = field(default_factory=list)


def _xml_text(root: ET.Element, *tag_path: tuple) -> Optional[str]:
    """Walk a chain of namespaced tags and return the text content."""
    node = root
    for ns, tag in tag_path:
        node = node.find(f"{{{_NS[ns]}}}{tag}")
        if node is None:
            return None
    return (node.text or "").strip() or None


def _parse_core(xml_bytes: bytes) -> dict:
    """Parse docProps/core.xml into a flat dict."""
    out = {}
    try:
        root = ET.fromstring(xml_bytes)
        fields = [
            ("title",          ("dc",      "title")),
            ("subject",        ("dc",      "subject")),
            ("creator",        ("dc",      "creator")),
            ("keywords",       ("cp",      "keywords")),
            ("description",    ("dc",      "description")),
            ("lastModifiedBy", ("cp",      "lastModifiedBy")),
            ("created",        ("dcterms", "created")),
            ("modified",       ("dcterms", "modified")),
            ("revision",       ("cp",      "revision")),
        ]
        for key, (ns, tag) in fields:
            val = _xml_text(root, (ns, tag))
            if val:
                out[key] = val
    except Exception:
        pass
    return out


def _parse_app(xml_bytes: bytes) -> dict:
    """Parse docProps/app.xml into a flat dict."""
    out = {}
    try:
        root = ET.fromstring(xml_bytes)
        ns = "ep"
        simple_fields = [
            "Application", "AppVersion", "Company",
            "Pages", "Words", "Characters",
            "Slides", "Worksheets", "Notes",
            "TotalTime", "Template",
        ]
        for field_name in simple_fields:
            node = root.find(f"{{{_NS[ns]}}}{field_name}")
            if node is not None and node.text:
                out[field_name] = node.text.strip()
    except Exception:
        pass
    return out


def _doc_type(suffix: str) -> str:
    return {
        ".docx": "Word Document",
        ".docm": "Word Document (Macro-enabled)",
        ".xlsx": "Excel Workbook",
        ".xlsm": "Excel Workbook (Macro-enabled)",
        ".pptx": "PowerPoint Presentation",
        ".pptm": "PowerPoint Presentation (Macro-enabled)",
    }.get(suffix.lower(), "Office Document")


def extract(path: Path) -> OfficeMetadata:
    """Extract metadata from an Office Open XML file."""
    from utils.helpers import file_size_str

    meta = OfficeMetadata(
        file_name=path.name,
        file_size=file_size_str(path),
        doc_type=_doc_type(path.suffix),
    )

    if not zipfile.is_zipfile(path):
        meta.warnings.append("File does not appear to be a valid Office Open XML (ZIP) file.")
        return meta

    try:
        with zipfile.ZipFile(path, "r") as zf:
            names = zf.namelist()

            # ── Core properties ────────────────────────────────────────────────
            if "docProps/core.xml" in names:
                core = _parse_core(zf.read("docProps/core.xml"))
                meta.raw_core = core
                meta.title           = core.get("title")
                meta.subject         = core.get("subject")
                meta.creator         = core.get("creator")
                meta.keywords        = core.get("keywords")
                meta.description     = core.get("description")
                meta.last_modified_by = core.get("lastModifiedBy")
                meta.created         = core.get("created")
                meta.modified        = core.get("modified")
                meta.revision        = core.get("revision")
            else:
                meta.warnings.append("docProps/core.xml not found.")

            # ── App / extended properties ──────────────────────────────────────
            if "docProps/app.xml" in names:
                app = _parse_app(zf.read("docProps/app.xml"))
                meta.raw_app     = app
                meta.application = app.get("Application")
                meta.app_version = app.get("AppVersion")
                meta.company     = app.get("Company")
                meta.pages       = app.get("Pages")
                meta.words       = app.get("Words")
                meta.characters  = app.get("Characters")
                meta.slides      = app.get("Slides")
                meta.worksheets  = app.get("Worksheets")
            else:
                meta.warnings.append("docProps/app.xml not found.")

    except zipfile.BadZipFile:
        meta.warnings.append("Could not open as ZIP archive — file may be corrupted.")
    except Exception as e:
        meta.warnings.append(f"Office read error: {e}")

    return meta
