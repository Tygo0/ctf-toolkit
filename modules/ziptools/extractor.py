"""
Recursive archive extractor — handles ZIP, TAR, TAR.GZ, TAR.BZ2.
Supports password cracking, nested archive detection, and depth limiting.
"""

import zipfile
import tarfile
import shutil
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional

from modules.ziptools.safety import (
    check_zip, check_tar, MAX_NESTING_DEPTH, SafetyReport
)


# ── Result types ──────────────────────────────────────────────────────────────

@dataclass
class ExtractionResult:
    success: bool
    archive_name: str
    output_dir: Path
    files_extracted: list[str]  = field(default_factory=list)
    password_used: Optional[str]= None
    depth: int                  = 0
    child_results: list         = field(default_factory=list)  # list[ExtractionResult]
    warnings: list[str]         = field(default_factory=list)
    error: Optional[str]        = None


# ── Archive type detection ────────────────────────────────────────────────────

def _is_zip(path: Path) -> bool:
    return zipfile.is_zipfile(path)

def _is_tar(path: Path) -> bool:
    try:
        if not path.exists():
            return False
        return tarfile.is_tarfile(str(path))
    except Exception:
        return False

def _is_archive(path: Path) -> bool:
    try:
        return _is_zip(path) or _is_tar(path)
    except Exception:
        return False

def _archive_label(path: Path) -> str:
    s = path.suffix.lower()
    if s in (".zip",):
        return "ZIP"
    if s in (".tar",):
        return "TAR"
    if path.name.lower().endswith((".tar.gz", ".tgz")):
        return "TAR.GZ"
    if path.name.lower().endswith((".tar.bz2", ".tbz2")):
        return "TAR.BZ2"
    if _is_zip(path):
        return "ZIP"
    if _is_tar(path):
        return "TAR"
    return "ARCHIVE"


# ── Password cracking for ZIP ─────────────────────────────────────────────────

def _try_zip_passwords(
    path: Path,
    dest: Path,
    wordlist: Optional[list[str]] = None,
    progress_cb=None,
) -> tuple[bool, Optional[str]]:
    """
    Try to extract a password-protected ZIP using a wordlist.
    Returns (success, password_used).
    """
    passwords = [""] + (wordlist or [])  # always try blank first

    for pw in passwords:
        try:
            with zipfile.ZipFile(path, "r") as zf:
                zf.extractall(path=dest, pwd=pw.encode() if pw else None)
            return True, pw or None
        except RuntimeError:
            # Wrong password
            pass
        except Exception:
            pass
        if progress_cb:
            progress_cb()

    return False, None


# ── ZIP extraction ────────────────────────────────────────────────────────────

def _extract_zip(
    path: Path,
    dest: Path,
    wordlist: Optional[list[str]],
    depth: int,
    progress_cb=None,
) -> ExtractionResult:
    dest.mkdir(parents=True, exist_ok=True)
    result = ExtractionResult(
        success=False,
        archive_name=path.name,
        output_dir=dest,
        depth=depth,
    )

    # Safety check
    report = check_zip(path)
    if not report.safe:
        result.error = f"Safety check failed: {report.reason}"
        return result

    # Try extraction (with optional password cracking)
    try:
        with zipfile.ZipFile(path, "r") as zf:
            needs_password = any(info.flag_bits & 0x1 for info in zf.infolist())

        if needs_password:
            success, pw = _try_zip_passwords(path, dest, wordlist, progress_cb)
            if not success:
                result.error = "Password-protected ZIP — no matching password found in wordlist."
                return result
            result.password_used = pw
        else:
            with zipfile.ZipFile(path, "r") as zf:
                zf.extractall(path=dest)

    except zipfile.BadZipFile as e:
        result.error = f"Corrupt ZIP file: {e}"
        return result
    except Exception as e:
        result.error = f"Extraction error: {e}"
        return result

    # Collect extracted files
    result.files_extracted = [
        str(p.relative_to(dest)) for p in dest.rglob("*") if p.is_file()
    ]
    result.success = True
    return result


# ── TAR extraction ────────────────────────────────────────────────────────────

def _extract_tar(
    path: Path,
    dest: Path,
    depth: int,
) -> ExtractionResult:
    dest.mkdir(parents=True, exist_ok=True)
    result = ExtractionResult(
        success=False,
        archive_name=path.name,
        output_dir=dest,
        depth=depth,
    )

    report = check_tar(path)
    if not report.safe:
        result.error = f"Safety check failed: {report.reason}"
        return result

    try:
        with tarfile.open(path, "r:*") as tf:
            # Filter out path traversal attempts
            safe_members = []
            for member in tf.getmembers():
                if ".." in member.name or member.name.startswith("/"):
                    result.warnings.append(f"Skipped unsafe path: {member.name}")
                    continue
                safe_members.append(member)
            tf.extractall(path=dest, members=safe_members)
    except Exception as e:
        result.error = f"TAR extraction error: {e}"
        return result

    result.files_extracted = [
        str(p.relative_to(dest)) for p in dest.rglob("*") if p.is_file()
    ]
    result.success = True
    return result


# ── Recursive engine ──────────────────────────────────────────────────────────

def extract_recursive(
    path: Path,
    output_root: Path,
    wordlist: Optional[list[str]] = None,
    depth: int = 0,
    progress_cb=None,
) -> ExtractionResult:
    """
    Extract an archive recursively, diving into any nested archives found.

    Args:
        path:        Archive file to extract.
        output_root: Base output directory.
        wordlist:    Passwords to try on encrypted ZIPs.
        depth:       Current nesting depth (internal, starts at 0).
        progress_cb: Optional callable called on each password attempt.

    Returns:
        ExtractionResult tree.
    """
    if depth > MAX_NESTING_DEPTH:
        return ExtractionResult(
            success=False,
            archive_name=path.name,
            output_dir=output_root,
            depth=depth,
            error=f"Maximum nesting depth ({MAX_NESTING_DEPTH}) reached.",
        )

    if not path.exists():
        return ExtractionResult(
            success=False,
            archive_name=path.name,
            output_dir=output_root,
            depth=depth,
            error=f"File not found: {path}",
        )

    # Choose destination dir: <output_root>/<archive_stem>_extracted/
    dest = output_root / f"{path.stem}_extracted"
    # Avoid collisions if the same name appears at different depths
    if dest.exists():
        dest = output_root / f"{path.stem}_extracted_d{depth}"

    # Extract based on type
    if _is_zip(path):
        result = _extract_zip(path, dest, wordlist, depth, progress_cb)
    elif _is_tar(path):
        result = _extract_tar(path, dest, depth)
    else:
        return ExtractionResult(
            success=False,
            archive_name=path.name,
            output_dir=output_root,
            depth=depth,
            error=f"Unrecognised archive format: {path.name}",
        )

    if not result.success:
        return result

    # Recurse into any nested archives found
    for extracted_file in list(result.files_extracted):
        child_path = dest / extracted_file
        if child_path.exists() and _is_archive(child_path):
            child_result = extract_recursive(
                path=child_path,
                output_root=dest,
                wordlist=wordlist,
                depth=depth + 1,
                progress_cb=progress_cb,
            )
            result.child_results.append(child_result)

    return result


# ── Flat file list (for reporting) ────────────────────────────────────────────

def flatten_results(result: ExtractionResult) -> list[tuple[int, str, str]]:
    """
    Recursively collect all extracted files.
    Returns list of (depth, archive_name, relative_file_path).
    """
    rows = [(result.depth, result.archive_name, f) for f in result.files_extracted]
    for child in result.child_results:
        rows.extend(flatten_results(child))
    return rows
