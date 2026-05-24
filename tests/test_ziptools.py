"""
Tests for modules/ziptools — safety checks, extraction, recursion, and passwords.
All archives are built in-memory during the test run.
"""

import io
import zipfile
import tarfile
import struct
import zlib
from pathlib import Path

import pytest

from modules.ziptools.safety import (
    check_zip, check_tar, SafetyReport,
    MAX_UNCOMPRESSED_BYTES, MAX_FILE_COUNT, MIN_RATIO_THRESHOLD,
)
from modules.ziptools.extractor import (
    extract_recursive, flatten_results,
    _is_zip, _is_tar, _is_archive,
)


# ── Archive factory helpers ───────────────────────────────────────────────────

def make_zip(tmp_path: Path, files: dict[str, bytes], password: str = None) -> Path:
    """Create a ZIP with given {filename: content} mapping."""
    tmp_path.mkdir(parents=True, exist_ok=True)
    p = tmp_path / "test.zip"
    with zipfile.ZipFile(p, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in files.items():
            if password:
                zf.setpassword(password.encode())
                zf.writestr(zipfile.ZipInfo(name), data,
                            zipfile.ZIP_DEFLATED)
            else:
                zf.writestr(name, data)
    return p


def make_zip_encrypted(tmp_path: Path, files: dict[str, bytes], password: str) -> Path:
    """Create a password-protected ZIP (uses pyminizip-style workaround via ZipFile)."""
    p = tmp_path / "locked.zip"
    # Python's stdlib can write encrypted ZIPs
    with zipfile.ZipFile(p, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.setpassword(password.encode())
        for name, data in files.items():
            info = zipfile.ZipInfo(name)
            info.flag_bits |= 0x1  # encryption flag
            zf.writestr(info, data, zipfile.ZIP_DEFLATED)
    return p


def make_nested_zip(tmp_path: Path) -> Path:
    """Create a ZIP containing another ZIP."""
    tmp_path.mkdir(parents=True, exist_ok=True)
    inner = tmp_path / "inner.zip"
    with zipfile.ZipFile(inner, "w") as zf:
        zf.writestr("flag.txt", "CTF{nested_archive_flag}")

    outer = tmp_path / "outer.zip"
    with zipfile.ZipFile(outer, "w") as zf:
        zf.write(inner, "inner.zip")
        zf.writestr("readme.txt", "Extract the inner zip!")
    return outer


def make_tar_gz(tmp_path: Path, files: dict[str, bytes]) -> Path:
    """Create a .tar.gz archive."""
    tmp_path.mkdir(parents=True, exist_ok=True)
    p = tmp_path / "test.tar.gz"
    with tarfile.open(p, "w:gz") as tf:
        for name, data in files.items():
            info = tarfile.TarInfo(name=name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    return p


def make_zip_many_files(tmp_path: Path, count: int) -> Path:
    """Create a ZIP with many small files."""
    tmp_path.mkdir(parents=True, exist_ok=True)
    p = tmp_path / "manyfiles.zip"
    with zipfile.ZipFile(p, "w") as zf:
        for i in range(count):
            zf.writestr(f"file_{i:05d}.txt", f"content {i}")
    return p


# ── Safety check tests ────────────────────────────────────────────────────────

class TestSafetyChecks:

    def test_normal_zip_is_safe(self, tmp_path):
        p = make_zip(tmp_path, {"hello.txt": b"hello world"})
        report = check_zip(p)
        assert report.safe is True

    def test_report_has_file_count(self, tmp_path):
        p = make_zip(tmp_path, {"a.txt": b"a", "b.txt": b"b", "c.txt": b"c"})
        report = check_zip(p)
        assert report.file_count == 3

    def test_report_has_uncompressed_size(self, tmp_path):
        p = make_zip(tmp_path, {"test.txt": b"x" * 1000})
        report = check_zip(p)
        assert report.uncompressed_size >= 1000

    def test_too_many_files_flagged(self, tmp_path):
        p = make_zip_many_files(tmp_path, MAX_FILE_COUNT + 1)
        report = check_zip(p)
        assert report.safe is False
        assert "files" in report.reason.lower()

    def test_invalid_zip_flagged(self, tmp_path):
        p = tmp_path / "fake.zip"
        p.write_bytes(b"this is not a zip file")
        report = check_zip(p)
        assert report.safe is False

    def test_tar_gz_is_safe(self, tmp_path):
        p = make_tar_gz(tmp_path, {"hello.txt": b"hello"})
        report = check_tar(p)
        assert report.safe is True

    def test_tar_reports_file_count(self, tmp_path):
        p = make_tar_gz(tmp_path, {"a.txt": b"a", "b.txt": b"b"})
        report = check_tar(p)
        assert report.file_count == 2

    def test_safety_report_dataclass(self, tmp_path):
        p = make_zip(tmp_path, {"test.txt": b"test"})
        report = check_zip(p)
        assert isinstance(report, SafetyReport)
        assert hasattr(report, "safe")
        assert hasattr(report, "reason")
        assert hasattr(report, "file_count")
        assert hasattr(report, "compression_ratio")


# ── Archive detection tests ───────────────────────────────────────────────────

class TestArchiveDetection:

    def test_zip_detected(self, tmp_path):
        p = make_zip(tmp_path, {"f.txt": b"data"})
        assert _is_zip(p) is True
        assert _is_archive(p) is True

    def test_tar_gz_detected(self, tmp_path):
        p = make_tar_gz(tmp_path, {"f.txt": b"data"})
        assert _is_tar(p) is True
        assert _is_archive(p) is True

    def test_non_archive_not_detected(self, tmp_path):
        p = tmp_path / "plain.txt"
        p.write_bytes(b"just text here")
        assert _is_zip(p) is False
        assert _is_archive(p) is False

    def test_empty_file_not_archive(self, tmp_path):
        p = tmp_path / "empty.zip"
        p.write_bytes(b"")
        assert _is_archive(p) is False


# ── Extraction tests ──────────────────────────────────────────────────────────

class TestExtraction:

    def test_simple_zip_extracted(self, tmp_path):
        src = make_zip(tmp_path / "src", {"hello.txt": b"hello world"})
        result = extract_recursive(src, tmp_path / "out")
        assert result.success is True
        assert any("hello.txt" in f for f in result.files_extracted)

    def test_output_dir_created(self, tmp_path):
        src = make_zip(tmp_path / "src", {"f.txt": b"data"})
        out = tmp_path / "output"
        result = extract_recursive(src, out)
        assert result.success is True
        assert result.output_dir.exists()

    def test_multiple_files_extracted(self, tmp_path):
        src = make_zip(tmp_path / "src", {
            "a.txt": b"alpha",
            "b.txt": b"beta",
            "c.txt": b"gamma",
        })
        result = extract_recursive(src, tmp_path / "out")
        assert result.success is True
        assert len(result.files_extracted) == 3

    def test_file_contents_correct(self, tmp_path):
        src = make_zip(tmp_path / "src", {"secret.txt": b"FLAG{test}"})
        out = tmp_path / "out"
        result = extract_recursive(src, out)
        assert result.success is True
        extracted = result.output_dir / "test_extracted" / "secret.txt"
        # Find the actual extracted file
        extracted_files = list(result.output_dir.rglob("secret.txt"))
        assert len(extracted_files) == 1
        assert extracted_files[0].read_bytes() == b"FLAG{test}"

    def test_tar_gz_extracted(self, tmp_path):
        src = make_tar_gz(tmp_path / "src", {"note.txt": b"CTF note"})
        result = extract_recursive(src, tmp_path / "out")
        assert result.success is True
        assert any("note.txt" in f for f in result.files_extracted)

    def test_nonexistent_archive_fails_gracefully(self, tmp_path):
        fake = tmp_path / "nonexistent.zip"
        result = extract_recursive(fake, tmp_path / "out")
        assert result.success is False
        assert result.error is not None

    def test_corrupt_zip_fails_gracefully(self, tmp_path):
        p = tmp_path / "corrupt.zip"
        p.write_bytes(b"PK\x03\x04" + b"\x00" * 20)  # valid magic, garbage body
        result = extract_recursive(p, tmp_path / "out")
        assert result.success is False


# ── Recursive / nested archive tests ─────────────────────────────────────────

class TestRecursiveExtraction:

    def test_nested_zip_extracted(self, tmp_path):
        outer = make_nested_zip(tmp_path / "src")
        result = extract_recursive(outer, tmp_path / "out")
        assert result.success is True
        assert len(result.child_results) >= 1

    def test_nested_flag_reachable(self, tmp_path):
        outer = make_nested_zip(tmp_path / "src")
        out   = tmp_path / "out"
        result = extract_recursive(outer, out)
        assert result.success is True
        all_files = list(out.rglob("flag.txt"))
        assert len(all_files) >= 1
        assert b"CTF{nested_archive_flag}" in all_files[0].read_bytes()

    def test_depth_limit_respected(self, tmp_path):
        from modules.ziptools.safety import MAX_NESTING_DEPTH
        # Create a zip way past the depth limit
        p = make_zip(tmp_path / "src", {"file.txt": b"deep"})
        result = extract_recursive(p, tmp_path / "out", depth=MAX_NESTING_DEPTH + 1)
        assert result.success is False
        assert "depth" in result.error.lower()

    def test_flatten_results(self, tmp_path):
        outer = make_nested_zip(tmp_path / "src")
        result = extract_recursive(outer, tmp_path / "out")
        assert result.success is True
        flat = flatten_results(result)
        assert isinstance(flat, list)
        assert len(flat) >= 2  # outer files + inner files
        for depth, archive, filepath in flat:
            assert isinstance(depth, int)
            assert isinstance(archive, str)
            assert isinstance(filepath, str)


# ── Surfacing tests ───────────────────────────────────────────────────────────

class TestSurfacing:

    def test_final_files_surfaced_to_found(self, tmp_path):
        from modules.ziptools.__init__ import _surface_final_files
        # Create a nested structure manually
        deep = tmp_path / "a" / "b" / "c"
        deep.mkdir(parents=True)
        (deep / "flag.txt").write_bytes(b"CTF{flag}")
        (deep / "notes.txt").write_bytes(b"some notes")
        surfaced = _surface_final_files(tmp_path)
        assert "flag.txt" in surfaced
        assert "notes.txt" in surfaced
        assert (tmp_path / "found" / "flag.txt").exists()
        assert (tmp_path / "found" / "flag.txt").read_bytes() == b"CTF{flag}"

    def test_archives_not_surfaced(self, tmp_path):
        from modules.ziptools.__init__ import _surface_final_files
        sub = tmp_path / "sub"
        sub.mkdir()
        # Put a zip and a txt in sub/
        with zipfile.ZipFile(sub / "archive.zip", "w") as z:
            z.writestr("x.txt", "x")
        (sub / "flag.txt").write_bytes(b"flag")
        surfaced = _surface_final_files(tmp_path)
        assert "archive.zip" not in surfaced
        assert "flag.txt" in surfaced

    def test_duplicate_names_deduped(self, tmp_path):
        from modules.ziptools.__init__ import _surface_final_files
        for i, subdir in enumerate(["a", "b"]):
            d = tmp_path / subdir
            d.mkdir()
            (d / "flag.txt").write_bytes(f"flag{i}".encode())
        surfaced = _surface_final_files(tmp_path)
        assert len(surfaced) == 2
        names = set(surfaced)
        assert "flag.txt" in names
        assert "flag_1.txt" in names

    def test_end_to_end_nested_surfaces_flag(self, tmp_path):
        from modules.ziptools.__init__ import _surface_final_files
        # Build 3-layer zip
        inner = tmp_path / "src" / "inner.zip"
        inner.parent.mkdir(parents=True)
        with zipfile.ZipFile(inner, "w") as z:
            z.writestr("flag.txt", "CTF{deep_flag}")
        mid = tmp_path / "src" / "mid.zip"
        with zipfile.ZipFile(mid, "w") as z:
            z.write(inner, "inner.zip")
        out = tmp_path / "out"
        result = extract_recursive(mid, out)
        assert result.success
        surfaced = _surface_final_files(out)
        assert "flag.txt" in surfaced
        content = (out / "found" / "flag.txt").read_bytes()
        assert b"CTF{deep_flag}" in content

class TestPasswordHandling:

    def test_unprotected_zip_no_password(self, tmp_path):
        src = make_zip(tmp_path / "src", {"open.txt": b"no password needed"})
        result = extract_recursive(src, tmp_path / "out", wordlist=["wrong", "nope"])
        assert result.success is True
        assert result.password_used is None
