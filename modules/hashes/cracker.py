"""
Hash cracker — dictionary attack supporting MD5, SHA-1, SHA-256, SHA-512, NTLM.
"""

import hashlib
from pathlib import Path
from typing import Optional, Callable

from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn


# ── Supported algorithms ──────────────────────────────────────────────────────

def _md5(word: str) -> str:
    return hashlib.md5(word.encode()).hexdigest()

def _sha1(word: str) -> str:
    return hashlib.sha1(word.encode()).hexdigest()

def _sha256(word: str) -> str:
    return hashlib.sha256(word.encode()).hexdigest()

def _sha512(word: str) -> str:
    return hashlib.sha512(word.encode()).hexdigest()

def _ntlm(word: str) -> str:
    import hashlib
    return hashlib.new("md4", word.encode("utf-16-le")).hexdigest()


ALGORITHMS: dict[str, Callable[[str], str]] = {
    "md5":    _md5,
    "sha1":   _sha1,
    "sha256": _sha256,
    "sha512": _sha512,
    "ntlm":   _ntlm,
}


# ── Auto-detect algorithm by hash length ─────────────────────────────────────

_LENGTH_MAP: dict[int, list[str]] = {
    32:  ["md5", "ntlm"],
    40:  ["sha1"],
    64:  ["sha256"],
    128: ["sha512"],
}

def detect_algorithms(hash_str: str) -> list[str]:
    """Return likely algorithm names based on hash length."""
    return _LENGTH_MAP.get(len(hash_str.strip()), [])


# ── Core cracker ─────────────────────────────────────────────────────────────

class CrackResult:
    def __init__(
        self,
        found: bool,
        plaintext: Optional[str] = None,
        algorithm: Optional[str] = None,
        attempts: int = 0,
    ):
        self.found = found
        self.plaintext = plaintext
        self.algorithm = algorithm
        self.attempts = attempts


def crack(
    hash_str: str,
    wordlist_path: str,
    algorithms: Optional[list[str]] = None,
) -> CrackResult:
    """
    Run a dictionary attack against hash_str.

    Args:
        hash_str:      The target hash (hex string).
        wordlist_path: Path to the wordlist file.
        algorithms:    List of algorithm names to try. Auto-detected if None.

    Returns:
        CrackResult with found status, plaintext, and attempt count.
    """
    from utils.logger import warning

    h = hash_str.strip().lower()

    # Determine which algorithms to attempt
    algos = algorithms or detect_algorithms(h)
    if not algos:
        algos = list(ALGORITHMS.keys())  # try all if unknown length

    # Validate
    unknown = [a for a in algos if a not in ALGORITHMS]
    if unknown:
        warning(f"Unknown algorithm(s) skipped: {', '.join(unknown)}")
        algos = [a for a in algos if a in ALGORITHMS]

    if not algos:
        return CrackResult(found=False, attempts=0)

    # Load wordlist
    wl = Path(wordlist_path)
    if not wl.exists():
        warning(f"Wordlist not found: {wordlist_path}")
        return CrackResult(found=False, attempts=0)

    with open(wl, "r", errors="ignore") as f:
        words = [line.strip() for line in f if line.strip()]

    attempts = 0

    with Progress(
        SpinnerColumn(),
        TextColumn("[bold cyan]{task.description}"),
        BarColumn(),
        TextColumn("[dim]{task.completed}/{task.total}"),
        TimeElapsedColumn(),
    ) as progress:
        task = progress.add_task(
            f"Trying {len(words)} words × {len(algos)} algo(s)…",
            total=len(words) * len(algos),
        )

        for word in words:
            for algo in algos:
                attempts += 1
                fn = ALGORITHMS[algo]
                try:
                    digest = fn(word)
                except Exception:
                    progress.advance(task)
                    continue

                if digest == h:
                    progress.stop()
                    return CrackResult(
                        found=True,
                        plaintext=word,
                        algorithm=algo,
                        attempts=attempts,
                    )
                progress.advance(task)

    return CrackResult(found=False, attempts=attempts)
