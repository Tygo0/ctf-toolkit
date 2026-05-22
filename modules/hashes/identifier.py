"""
Hash identifier — detects hash types by length, character set, and known prefixes.
"""

import re
from dataclasses import dataclass


@dataclass
class HashMatch:
    name: str
    hashcat_mode: int | None
    john_format: str | None
    description: str
    confidence: str  # "high" | "medium" | "low"


# ── Pattern definitions ────────────────────────────────────────────────────────

_HEX = r"^[a-fA-F0-9]+$"
_B64 = r"^[a-zA-Z0-9+/=]+$"

_PATTERNS: list[tuple[re.Pattern, HashMatch]] = [
    # ── Fixed-length hex hashes ────────────────────────────────────────────────
    (re.compile(r"^[a-fA-F0-9]{32}$"), HashMatch(
        name="MD5",
        hashcat_mode=0,
        john_format="raw-md5",
        description="MD5 — 128-bit, extremely common in CTFs",
        confidence="high",
    )),
    (re.compile(r"^[a-fA-F0-9]{32}$"), HashMatch(
        name="NTLM",
        hashcat_mode=1000,
        john_format="nt",
        description="NTLM — Windows password hash, same length as MD5",
        confidence="medium",
    )),
    (re.compile(r"^[a-fA-F0-9]{40}$"), HashMatch(
        name="SHA-1",
        hashcat_mode=100,
        john_format="raw-sha1",
        description="SHA-1 — 160-bit, deprecated but still seen in CTFs",
        confidence="high",
    )),
    (re.compile(r"^[a-fA-F0-9]{56}$"), HashMatch(
        name="SHA-224",
        hashcat_mode=1300,
        john_format="raw-sha224",
        description="SHA-224 — 224-bit truncated SHA-2",
        confidence="high",
    )),
    (re.compile(r"^[a-fA-F0-9]{64}$"), HashMatch(
        name="SHA-256",
        hashcat_mode=1400,
        john_format="raw-sha256",
        description="SHA-256 — 256-bit, very common",
        confidence="high",
    )),
    (re.compile(r"^[a-fA-F0-9]{96}$"), HashMatch(
        name="SHA-384",
        hashcat_mode=10800,
        john_format="raw-sha384",
        description="SHA-384 — 384-bit SHA-2 variant",
        confidence="high",
    )),
    (re.compile(r"^[a-fA-F0-9]{128}$"), HashMatch(
        name="SHA-512",
        hashcat_mode=1700,
        john_format="raw-sha512",
        description="SHA-512 — 512-bit, strongest common SHA-2",
        confidence="high",
    )),

    # ── Prefixed / structured hashes ──────────────────────────────────────────
    (re.compile(r"^\$2[ayb]\$\d{2}\$.{53}$"), HashMatch(
        name="bcrypt",
        hashcat_mode=3200,
        john_format="bcrypt",
        description="bcrypt — adaptive hash, very slow to crack",
        confidence="high",
    )),
    (re.compile(r"^\$6\$.{8,16}\$.{86}$"), HashMatch(
        name="SHA-512 Crypt",
        hashcat_mode=1800,
        john_format="sha512crypt",
        description="sha512crypt — Linux /etc/shadow format",
        confidence="high",
    )),
    (re.compile(r"^\$5\$.{8,16}\$.{43}$"), HashMatch(
        name="SHA-256 Crypt",
        hashcat_mode=7400,
        john_format="sha256crypt",
        description="sha256crypt — Linux /etc/shadow format",
        confidence="high",
    )),
    (re.compile(r"^\$1\$.{0,8}\$.{22}$"), HashMatch(
        name="MD5 Crypt",
        hashcat_mode=500,
        john_format="md5crypt",
        description="md5crypt — legacy Linux hash ($1$...)",
        confidence="high",
    )),
    (re.compile(r"^\$apr1\$.{0,8}\$.{22}$"), HashMatch(
        name="MD5 Apache",
        hashcat_mode=1600,
        john_format="md5crypt",
        description="Apache MD5 crypt ($apr1$...)",
        confidence="high",
    )),

    # ── MySQL ──────────────────────────────────────────────────────────────────
    (re.compile(r"^\*[a-fA-F0-9]{40}$"), HashMatch(
        name="MySQL4.1+",
        hashcat_mode=300,
        john_format="mysql-sha1",
        description="MySQL 4.1+ password hash (*...)",
        confidence="high",
    )),
    (re.compile(r"^[a-fA-F0-9]{16}$"), HashMatch(
        name="MySQL3.x",
        hashcat_mode=200,
        john_format="mysql",
        description="MySQL < 4.1 password hash (16 hex chars)",
        confidence="medium",
    )),

    # ── CRC / short ───────────────────────────────────────────────────────────
    (re.compile(r"^[a-fA-F0-9]{8}$"), HashMatch(
        name="CRC-32",
        hashcat_mode=None,
        john_format=None,
        description="CRC-32 or Adler-32 checksum (8 hex chars)",
        confidence="medium",
    )),
]


def identify(hash_str: str) -> list[HashMatch]:
    """
    Return all HashMatch candidates for the given hash string.
    Results are ordered: high confidence first.
    """
    h = hash_str.strip()
    matches: list[HashMatch] = []
    seen: set[str] = set()

    for pattern, candidate in _PATTERNS:
        if pattern.match(h) and candidate.name not in seen:
            matches.append(candidate)
            seen.add(candidate.name)

    # Sort: high > medium > low
    order = {"high": 0, "medium": 1, "low": 2}
    matches.sort(key=lambda m: order.get(m.confidence, 9))
    return matches
