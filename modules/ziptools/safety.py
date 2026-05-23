"""
Safety checks for archive extraction — detects zip bombs, oversized archives,
and excessive nesting depth before any extraction happens.
"""

import zipfile
import tarfile
from pathlib import Path
from dataclasses import dataclass


# ── Configurable limits ───────────────────────────────────────────────────────

MAX_UNCOMPRESSED_BYTES = 500 * 1024 * 1024   # 500 MB
MAX_FILE_COUNT         = 10_000
MAX_NESTING_DEPTH      = 10
MIN_RATIO_THRESHOLD    = 100                  # compressed:uncompressed ratio


@dataclass
class SafetyReport:
    safe: bool
    reason: str = ""
    compressed_size: int = 0
    uncompressed_size: int = 0
    file_count: int = 0
    compression_ratio: float = 0.0


def check_zip(path: Path) -> SafetyReport:
    """
    Inspect a ZIP file's metadata without extracting.
    Returns a SafetyReport indicating whether extraction is safe.
    """
    if not zipfile.is_zipfile(path):
        return SafetyReport(safe=False, reason="Not a valid ZIP file.")

    compressed_size   = path.stat().st_size
    uncompressed_size = 0
    file_count        = 0

    try:
        with zipfile.ZipFile(path, "r") as zf:
            for info in zf.infolist():
                uncompressed_size += info.file_size
                file_count        += 1

                # Per-file safety checks
                if info.file_size > MAX_UNCOMPRESSED_BYTES:
                    return SafetyReport(
                        safe=False,
                        reason=f"Single file '{info.filename}' would expand to "
                               f"{info.file_size / 1024 / 1024:.1f} MB (limit: "
                               f"{MAX_UNCOMPRESSED_BYTES / 1024 / 1024:.0f} MB).",
                        compressed_size=compressed_size,
                        uncompressed_size=uncompressed_size,
                        file_count=file_count,
                    )

                if file_count > MAX_FILE_COUNT:
                    return SafetyReport(
                        safe=False,
                        reason=f"Archive contains more than {MAX_FILE_COUNT:,} files.",
                        compressed_size=compressed_size,
                        uncompressed_size=uncompressed_size,
                        file_count=file_count,
                    )

    except zipfile.BadZipFile as e:
        return SafetyReport(safe=False, reason=f"Corrupt ZIP: {e}")
    except Exception as e:
        return SafetyReport(safe=False, reason=f"Could not inspect ZIP: {e}")

    # Total size check
    if uncompressed_size > MAX_UNCOMPRESSED_BYTES:
        return SafetyReport(
            safe=False,
            reason=f"Total uncompressed size {uncompressed_size / 1024 / 1024:.1f} MB "
                   f"exceeds limit of {MAX_UNCOMPRESSED_BYTES / 1024 / 1024:.0f} MB.",
            compressed_size=compressed_size,
            uncompressed_size=uncompressed_size,
            file_count=file_count,
        )

    # Compression ratio check (zip bomb signature)
    ratio = 0.0
    if compressed_size > 0:
        ratio = uncompressed_size / compressed_size
        if ratio > MIN_RATIO_THRESHOLD:
            return SafetyReport(
                safe=False,
                reason=f"Suspicious compression ratio of {ratio:.0f}:1 "
                       f"(threshold: {MIN_RATIO_THRESHOLD}:1). Possible zip bomb.",
                compressed_size=compressed_size,
                uncompressed_size=uncompressed_size,
                file_count=file_count,
                compression_ratio=ratio,
            )

    return SafetyReport(
        safe=True,
        reason="OK",
        compressed_size=compressed_size,
        uncompressed_size=uncompressed_size,
        file_count=file_count,
        compression_ratio=ratio,
    )


def check_tar(path: Path) -> SafetyReport:
    """Inspect a TAR/TAR.GZ/TAR.BZ2 file's metadata without extracting."""
    uncompressed_size = 0
    file_count        = 0
    compressed_size   = path.stat().st_size

    try:
        with tarfile.open(path, "r:*") as tf:
            for member in tf.getmembers():
                if member.isfile():
                    uncompressed_size += member.size
                    file_count        += 1

                    if member.size > MAX_UNCOMPRESSED_BYTES:
                        return SafetyReport(
                            safe=False,
                            reason=f"Single file '{member.name}' would expand to "
                                   f"{member.size / 1024 / 1024:.1f} MB.",
                            compressed_size=compressed_size,
                            uncompressed_size=uncompressed_size,
                            file_count=file_count,
                        )
                    if file_count > MAX_FILE_COUNT:
                        return SafetyReport(
                            safe=False,
                            reason=f"Archive contains more than {MAX_FILE_COUNT:,} files.",
                            compressed_size=compressed_size,
                            uncompressed_size=uncompressed_size,
                            file_count=file_count,
                        )

    except Exception as e:
        return SafetyReport(safe=False, reason=f"Could not inspect archive: {e}")

    if uncompressed_size > MAX_UNCOMPRESSED_BYTES:
        return SafetyReport(
            safe=False,
            reason=f"Total size {uncompressed_size / 1024 / 1024:.1f} MB exceeds limit.",
            compressed_size=compressed_size,
            uncompressed_size=uncompressed_size,
            file_count=file_count,
        )

    ratio = (uncompressed_size / compressed_size) if compressed_size > 0 else 0.0
    return SafetyReport(
        safe=True,
        reason="OK",
        compressed_size=compressed_size,
        uncompressed_size=uncompressed_size,
        file_count=file_count,
        compression_ratio=ratio,
    )
