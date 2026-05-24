"""
Tests for modules/metadata — image, PDF, Office extractors, and file type detector.
Test files are generated programmatically so no binary assets need to be committed.
"""

import zipfile
import struct
import io
import tempfile
from pathlib import Path

import pytest

from modules.metadata.detector import detect_kind, extract_metadata, FileKind


# ── File factory helpers ──────────────────────────────────────────────────────

def make_jpeg(tmp_path: Path) -> Path:
    """Minimal valid JPEG (1x1 pixel, no EXIF)."""
    # SOI + APP0 JFIF + minimal SOF + EOI
    data = (
        b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00"
        b"\xff\xd9"
    )
    p = tmp_path / "test.jpg"
    p.write_bytes(data)
    return p


def make_png(tmp_path: Path, with_text: bool = False) -> Path:
    """Minimal valid PNG (1x1 black pixel), optionally with tEXt chunks."""

    def chunk(name: bytes, data: bytes) -> bytes:
        import zlib
        length = struct.pack(">I", len(data))
        crc = struct.pack(">I", zlib.crc32(name + data) & 0xFFFFFFFF)
        return length + name + data + crc

    sig    = b"\x89PNG\r\n\x1a\n"
    ihdr   = chunk(b"IHDR", struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0))
    # 1x1 black RGB pixel
    import zlib
    raw    = zlib.compress(b"\x00\x00\x00\x00")
    idat   = chunk(b"IDAT", raw)
    iend   = chunk(b"IEND", b"")

    data = sig + ihdr + idat + iend

    if with_text:
        text_chunk = chunk(b"tEXt", b"Software\x00TestApp 1.0")
        data = sig + ihdr + text_chunk + idat + iend

    p = tmp_path / "test.png"
    p.write_bytes(data)
    return p


def make_pdf(tmp_path: Path, with_meta: bool = True) -> Path:
    """Minimal valid PDF with optional metadata."""
    if with_meta:
        meta_line = (
            b"1 0 obj\n<< /Title (Test Document) /Author (CTF User) "
            b"/Producer (ctf-toolkit-test) /Creator (pytest) >>\nendobj\n"
        )
    else:
        meta_line = b""

    content = (
        b"%PDF-1.4\n"
        + meta_line
        + b"2 0 obj\n<< /Type /Catalog >>\nendobj\n"
        + b"xref\n0 1\n0000000000 65535 f\n"
        + b"trailer\n<< /Size 3 /Root 2 0 R"
    )
    if with_meta:
        content += b" /Info 1 0 R"
    content += b" >>\nstartxref\n9\n%%EOF\n"

    p = tmp_path / "test.pdf"
    p.write_bytes(content)
    return p


def make_docx(tmp_path: Path, with_meta: bool = True) -> Path:
    """Minimal .docx (Office Open XML) with optional core/app properties."""
    p = tmp_path / "test.docx"
    with zipfile.ZipFile(p, "w") as zf:
        zf.writestr("[Content_Types].xml",
            '<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org'
            '/package/2006/content-types"></Types>')
        if with_meta:
            zf.writestr("docProps/core.xml",
                '<?xml version="1.0"?>'
                '<cp:coreProperties '
                'xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" '
                'xmlns:dc="http://purl.org/dc/elements/1.1/" '
                'xmlns:dcterms="http://purl.org/dc/terms/">'
                '<dc:title>CTF Challenge</dc:title>'
                '<dc:creator>Alice</dc:creator>'
                '<cp:lastModifiedBy>Bob</cp:lastModifiedBy>'
                '<cp:revision>3</cp:revision>'
                '</cp:coreProperties>')
            zf.writestr("docProps/app.xml",
                '<?xml version="1.0"?>'
                '<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties">'
                '<Application>Microsoft Word</Application>'
                '<AppVersion>16.0</AppVersion>'
                '<Company>ACME Corp</Company>'
                '<Pages>2</Pages>'
                '<Words>150</Words>'
                '</Properties>')
    return p


# ── Detector tests ────────────────────────────────────────────────────────────

class TestDetector:
    def test_jpeg_detected(self, tmp_path):
        assert detect_kind(make_jpeg(tmp_path)) == FileKind.IMAGE

    def test_png_detected(self, tmp_path):
        assert detect_kind(make_png(tmp_path)) == FileKind.IMAGE

    def test_pdf_detected(self, tmp_path):
        assert detect_kind(make_pdf(tmp_path)) == FileKind.PDF

    def test_docx_detected(self, tmp_path):
        assert detect_kind(make_docx(tmp_path)) == FileKind.OFFICE

    def test_unknown_extension(self, tmp_path):
        p = tmp_path / "file.xyz"
        p.write_bytes(b"random data here")
        assert detect_kind(p) == FileKind.UNKNOWN

    def test_pdf_by_extension_fallback(self, tmp_path):
        p = tmp_path / "file.pdf"
        p.write_bytes(b"%PDF-1.4 minimal")
        assert detect_kind(p) == FileKind.PDF


# ── Image extractor tests ─────────────────────────────────────────────────────

class TestImageExtractor:
    def test_jpeg_returns_image_metadata(self, tmp_path):
        from modules.metadata.image_extractor import ImageMetadata
        meta, kind = extract_metadata(make_jpeg(tmp_path))
        assert kind == FileKind.IMAGE
        assert isinstance(meta, ImageMetadata)

    def test_jpeg_file_info_populated(self, tmp_path):
        meta, _ = extract_metadata(make_jpeg(tmp_path))
        assert meta.file_name == "test.jpg"
        assert meta.file_size != ""
        assert meta.file_type == "JPG"

    def test_png_returns_image_metadata(self, tmp_path):
        from modules.metadata.image_extractor import ImageMetadata
        meta, kind = extract_metadata(make_png(tmp_path))
        assert kind == FileKind.IMAGE
        assert isinstance(meta, ImageMetadata)

    def test_png_text_chunks_parsed(self, tmp_path):
        meta, _ = extract_metadata(make_png(tmp_path, with_text=True))
        assert meta.software == "TestApp 1.0"

    def test_jpeg_no_exif_no_crash(self, tmp_path):
        meta, _ = extract_metadata(make_jpeg(tmp_path))
        # No EXIF in this minimal JPEG — fields should be None, not crash
        assert meta.make is None
        assert meta.model is None


# ── PDF extractor tests ───────────────────────────────────────────────────────

class TestPDFExtractor:
    def test_pdf_returns_metadata(self, tmp_path):
        from modules.metadata.pdf_extractor import PDFMetadata
        meta, kind = extract_metadata(make_pdf(tmp_path))
        assert kind == FileKind.PDF
        assert isinstance(meta, PDFMetadata)

    def test_pdf_file_info(self, tmp_path):
        meta, _ = extract_metadata(make_pdf(tmp_path))
        assert meta.file_name == "test.pdf"
        assert meta.file_size != ""

    def test_pdf_no_meta_no_crash(self, tmp_path):
        meta, _ = extract_metadata(make_pdf(tmp_path, with_meta=False))
        assert meta.title is None
        assert meta.author is None


# ── Office extractor tests ────────────────────────────────────────────────────

class TestOfficeExtractor:
    def test_docx_returns_metadata(self, tmp_path):
        from modules.metadata.office_extractor import OfficeMetadata
        meta, kind = extract_metadata(make_docx(tmp_path))
        assert kind == FileKind.OFFICE
        assert isinstance(meta, OfficeMetadata)

    def test_docx_core_properties_parsed(self, tmp_path):
        meta, _ = extract_metadata(make_docx(tmp_path, with_meta=True))
        assert meta.title == "CTF Challenge"
        assert meta.creator == "Alice"
        assert meta.last_modified_by == "Bob"
        assert meta.revision == "3"

    def test_docx_app_properties_parsed(self, tmp_path):
        meta, _ = extract_metadata(make_docx(tmp_path, with_meta=True))
        assert meta.application == "Microsoft Word"
        assert meta.company == "ACME Corp"
        assert meta.pages == "2"
        assert meta.words == "150"

    def test_docx_no_meta_no_crash(self, tmp_path):
        meta, _ = extract_metadata(make_docx(tmp_path, with_meta=False))
        assert meta.title is None
        assert meta.creator is None
        assert "not found" in meta.warnings[0].lower()

    def test_non_zip_file_handled(self, tmp_path):
        from modules.metadata.office_extractor import extract
        p = tmp_path / "fake.docx"
        p.write_bytes(b"not a zip file at all")
        meta = extract(p)
        assert len(meta.warnings) > 0

    def test_doc_type_label_word(self, tmp_path):
        meta, _ = extract_metadata(make_docx(tmp_path))
        assert "Word" in meta.doc_type

    def test_raw_core_populated(self, tmp_path):
        meta, _ = extract_metadata(make_docx(tmp_path, with_meta=True))
        assert "title" in meta.raw_core or len(meta.raw_core) > 0

    def test_raw_app_populated(self, tmp_path):
        meta, _ = extract_metadata(make_docx(tmp_path, with_meta=True))
        assert len(meta.raw_app) > 0


# ── extract_metadata dispatcher tests ────────────────────────────────────────

class TestDispatcher:
    def test_unknown_returns_none(self, tmp_path):
        p = tmp_path / "random.bin"
        p.write_bytes(b"\x00\x01\x02\x03" * 20)
        meta, kind = extract_metadata(p)
        assert meta is None
        assert kind == FileKind.UNKNOWN

    def test_correct_type_returned_for_each(self, tmp_path):
        _, k1 = extract_metadata(make_jpeg(tmp_path))
        _, k2 = extract_metadata(make_pdf(tmp_path))
        _, k3 = extract_metadata(make_docx(tmp_path))
        assert k1 == FileKind.IMAGE
        assert k2 == FileKind.PDF
        assert k3 == FileKind.OFFICE
