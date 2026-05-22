"""
Shared helper utilities used across modules.
"""

import os
import sys
from pathlib import Path
from typing import Optional


def resolve_file(path: str) -> Path:
    """Resolve a file path and exit with error if it doesn't exist."""
    from utils.logger import error
    p = Path(path)
    if not p.exists():
        error(f"File not found: [bold]{path}[/bold]")
        sys.exit(1)
    if not p.is_file():
        error(f"Path is not a file: [bold]{path}[/bold]")
        sys.exit(1)
    return p


def file_size_str(path: Path) -> str:
    """Return a human-readable file size string."""
    size = path.stat().st_size
    for unit in ["B", "KB", "MB", "GB"]:
        if size < 1024:
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} TB"


def read_wordlist(path: Optional[str] = None) -> list[str]:
    """
    Read passwords from a wordlist file.
    Falls back to the bundled default wordlist if no path given.
    """
    from utils.logger import warning

    default = Path(__file__).parent.parent / "wordlists" / "common.txt"
    target = Path(path) if path else default

    if not target.exists():
        warning(f"Wordlist not found: {target}")
        return []

    with open(target, "r", errors="ignore") as f:
        return [line.strip() for line in f if line.strip()]


def truncate(s: str, max_len: int = 80) -> str:
    """Truncate a string with an ellipsis if over max_len."""
    return s if len(s) <= max_len else s[:max_len - 3] + "..."


def is_printable(data: bytes, threshold: float = 0.75) -> bool:
    """Return True if the majority of bytes are printable ASCII."""
    if not data:
        return False
    printable = sum(32 <= b < 127 for b in data)
    return (printable / len(data)) >= threshold
