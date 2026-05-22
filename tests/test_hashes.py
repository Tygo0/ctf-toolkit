"""
Tests for modules/hashes — identifier and cracker.
"""

import hashlib
import tempfile
from pathlib import Path

import pytest

from modules.hashes.identifier import identify, HashMatch
from modules.hashes.cracker import crack, detect_algorithms, ALGORITHMS


# ── Identifier tests ──────────────────────────────────────────────────────────

class TestHashIdentifier:

    def test_md5_identified(self):
        h = hashlib.md5(b"hello").hexdigest()   # 5d41402abc4b2a76b9719d911017c592
        matches = identify(h)
        names = [m.name for m in matches]
        assert "MD5" in names

    def test_sha1_identified(self):
        h = hashlib.sha1(b"hello").hexdigest()
        matches = identify(h)
        names = [m.name for m in matches]
        assert "SHA-1" in names

    def test_sha256_identified(self):
        h = hashlib.sha256(b"hello").hexdigest()
        matches = identify(h)
        names = [m.name for m in matches]
        assert "SHA-256" in names

    def test_sha512_identified(self):
        h = hashlib.sha512(b"hello").hexdigest()
        matches = identify(h)
        names = [m.name for m in matches]
        assert "SHA-512" in names

    def test_bcrypt_identified(self):
        h = "$2a$12$ABCDEFGHIJKLMNOPQRSTUUABCDEFGHIJKLMNOPQRSTUVWXYZ01234"
        matches = identify(h)
        names = [m.name for m in matches]
        assert "bcrypt" in names

    def test_unknown_returns_empty(self):
        matches = identify("notahash!!!")
        assert matches == []

    def test_high_confidence_sorted_first(self):
        h = hashlib.md5(b"test").hexdigest()
        matches = identify(h)
        assert matches[0].confidence == "high"

    def test_whitespace_stripped(self):
        h = "  " + hashlib.sha256(b"hello").hexdigest() + "  "
        matches = identify(h)
        assert len(matches) > 0

    def test_returns_list_of_hashmatches(self):
        h = hashlib.sha1(b"abc").hexdigest()
        matches = identify(h)
        for m in matches:
            assert isinstance(m, HashMatch)


# ── Algorithm detection tests ─────────────────────────────────────────────────

class TestAlgorithmDetection:

    def test_md5_length_detected(self):
        algos = detect_algorithms("a" * 32)
        assert "md5" in algos

    def test_sha1_length_detected(self):
        algos = detect_algorithms("a" * 40)
        assert "sha1" in algos

    def test_sha256_length_detected(self):
        algos = detect_algorithms("a" * 64)
        assert "sha256" in algos

    def test_sha512_length_detected(self):
        algos = detect_algorithms("a" * 128)
        assert "sha512" in algos

    def test_unknown_length_returns_empty(self):
        algos = detect_algorithms("a" * 99)
        assert algos == []


# ── Cracker tests ─────────────────────────────────────────────────────────────

class TestHashCracker:

    def _make_wordlist(self, words: list[str]) -> str:
        tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False)
        tmp.write("\n".join(words))
        tmp.close()
        return tmp.name

    def test_crack_md5_success(self):
        wl = self._make_wordlist(["wrong1", "hello", "wrong2"])
        h = hashlib.md5(b"hello").hexdigest()
        result = crack(h, wl, algorithms=["md5"])
        assert result.found is True
        assert result.plaintext == "hello"
        assert result.algorithm == "md5"

    def test_crack_sha256_success(self):
        wl = self._make_wordlist(["nope", "password123", "other"])
        h = hashlib.sha256(b"password123").hexdigest()
        result = crack(h, wl, algorithms=["sha256"])
        assert result.found is True
        assert result.plaintext == "password123"

    def test_crack_sha1_success(self):
        wl = self._make_wordlist(["abc", "secret", "xyz"])
        h = hashlib.sha1(b"secret").hexdigest()
        result = crack(h, wl, algorithms=["sha1"])
        assert result.found is True
        assert result.plaintext == "secret"

    def test_crack_not_found(self):
        wl = self._make_wordlist(["wrong1", "wrong2"])
        h = hashlib.md5(b"notinlist").hexdigest()
        result = crack(h, wl, algorithms=["md5"])
        assert result.found is False
        assert result.plaintext is None

    def test_crack_missing_wordlist(self):
        result = crack("abc123", "/nonexistent/wordlist.txt", algorithms=["md5"])
        assert result.found is False
        assert result.attempts == 0

    def test_crack_attempts_counted(self):
        words = ["a", "b", "c", "d", "e"]
        wl = self._make_wordlist(words)
        h = hashlib.md5(b"nothere").hexdigest()
        result = crack(h, wl, algorithms=["md5"])
        assert result.attempts == len(words)

    def test_all_algorithms_present(self):
        expected = {"md5", "sha1", "sha256", "sha512", "ntlm"}
        assert expected.issubset(set(ALGORITHMS.keys()))
