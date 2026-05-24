"""
Tests for modules/encodings — all codecs, round-trips, and edge cases.
"""

import pytest
from modules.encodings.codecs import (
    base64_encode, base64_decode,
    base32_encode, base32_decode,
    base58_encode, base58_decode,
    hex_encode, hex_decode,
    rot13, rot_n,
    url_encode, url_decode,
    binary_encode, binary_decode,
    morse_encode, morse_decode,
    html_encode, html_decode,
    detect_encoding,
)


# ── Helpers ───────────────────────────────────────────────────────────────────

ROUND_TRIP_TEXTS = ["hello", "CTF{flag_here}", "Hello World!", "abc123"]


# ── Base64 ────────────────────────────────────────────────────────────────────

class TestBase64:
    def test_encode(self):
        assert base64_encode("hello") == "aGVsbG8="

    def test_decode(self):
        assert base64_decode("aGVsbG8=") == "hello"

    def test_decode_no_padding(self):
        assert base64_decode("aGVsbG8") == "hello"

    def test_round_trip(self):
        for t in ROUND_TRIP_TEXTS:
            assert base64_decode(base64_encode(t)) == t

    def test_invalid_raises(self):
        with pytest.raises(ValueError):
            base64_decode("!!!not_valid_base64!!!")


# ── Base32 ────────────────────────────────────────────────────────────────────

class TestBase32:
    def test_encode(self):
        assert base32_encode("hello") == "NBSWY3DP"

    def test_decode(self):
        assert base32_decode("NBSWY3DP") == "hello"

    def test_round_trip(self):
        for t in ROUND_TRIP_TEXTS:
            assert base32_decode(base32_encode(t)) == t

    def test_lowercase_input(self):
        assert base32_decode("nbswy3dp") == "hello"


# ── Base58 ────────────────────────────────────────────────────────────────────

class TestBase58:
    def test_encode_decode(self):
        assert base58_decode(base58_encode("hello")) == "hello"

    def test_encode_produces_no_zeros_or_Os(self):
        result = base58_encode("hello world")
        assert "0" not in result
        assert "O" not in result
        assert "I" not in result
        assert "l" not in result

    def test_invalid_character_raises(self):
        with pytest.raises(ValueError):
            base58_decode("0OIl")  # all invalid in base58


# ── Hex ───────────────────────────────────────────────────────────────────────

class TestHex:
    def test_encode(self):
        assert hex_encode("hello") == "68656c6c6f"

    def test_decode(self):
        assert hex_decode("68656c6c6f") == "hello"

    def test_decode_with_0x_prefix(self):
        assert hex_decode("0x68656c6c6f") == "hello"

    def test_decode_with_spaces(self):
        assert hex_decode("68 65 6c 6c 6f") == "hello"

    def test_decode_with_backslash_x(self):
        assert hex_decode("\\x68\\x65\\x6c\\x6c\\x6f") == "hello"

    def test_round_trip(self):
        for t in ROUND_TRIP_TEXTS:
            assert hex_decode(hex_encode(t)) == t

    def test_invalid_raises(self):
        with pytest.raises(ValueError):
            hex_decode("zzzzzz")


# ── ROT13 / ROT-N ─────────────────────────────────────────────────────────────

class TestRot:
    def test_rot13_encode(self):
        assert rot13("hello") == "uryyb"

    def test_rot13_self_inverse(self):
        assert rot13(rot13("hello world")) == "hello world"

    def test_rot13_preserves_non_alpha(self):
        assert rot13("Hello, World! 123") == "Uryyb, Jbeyq! 123"

    def test_rot_n_shift_1(self):
        assert rot_n("abc", 1) == "bcd"

    def test_rot_n_shift_25(self):
        assert rot_n("bcd", 25) == "abc"

    def test_rot_n_wraps(self):
        assert rot_n("z", 1) == "a"
        assert rot_n("Z", 1) == "A"

    def test_rot_n_preserves_case(self):
        result = rot_n("Hello", 13)
        assert result[0].isupper()

    def test_rot_n_full_round_trip(self):
        for t in ["hello", "WORLD", "MixedCase"]:
            assert rot_n(rot_n(t, 13), 13) == t


# ── URL ───────────────────────────────────────────────────────────────────────

class TestUrl:
    def test_encode_spaces(self):
        assert url_encode("hello world") == "hello%20world"

    def test_encode_special_chars(self):
        encoded = url_encode("a&b=c")
        assert "&" not in encoded
        assert "=" not in encoded

    def test_decode(self):
        assert url_decode("hello%20world") == "hello world"

    def test_round_trip(self):
        for t in ["hello world", "a&b=c", "flag{test}"]:
            assert url_decode(url_encode(t)) == t

    def test_decode_plus_sign(self):
        # %2B should decode to '+'
        assert url_decode("%2B") == "+"


# ── Binary ────────────────────────────────────────────────────────────────────

class TestBinary:
    def test_encode(self):
        assert binary_encode("A") == "01000001"

    def test_decode(self):
        assert binary_decode("01000001") == "A"

    def test_encode_multiple_chars(self):
        result = binary_encode("hi")
        assert result == "01101000 01101001"

    def test_decode_with_spaces(self):
        assert binary_decode("01101000 01101001") == "hi"

    def test_round_trip(self):
        for t in ROUND_TRIP_TEXTS:
            assert binary_decode(binary_encode(t)) == t

    def test_invalid_raises(self):
        with pytest.raises(ValueError):
            binary_decode("99999999")


# ── Morse ─────────────────────────────────────────────────────────────────────

class TestMorse:
    def test_encode_sos(self):
        assert morse_encode("SOS") == "... --- ..."

    def test_decode_sos(self):
        assert morse_decode("... --- ...") == "SOS"

    def test_encode_space(self):
        result = morse_encode("A B")
        assert "/" in result

    def test_decode_space(self):
        result = morse_decode(".- / -...")
        assert " " in result

    def test_round_trip_letters(self):
        original = "HELLO"
        assert morse_decode(morse_encode(original)) == original

    def test_unknown_char_marked(self):
        result = morse_encode("@")
        assert "?" in result


# ── HTML entities ─────────────────────────────────────────────────────────────

class TestHtml:
    def test_encode_lt_gt(self):
        assert "&lt;" in html_encode("<")
        assert "&gt;" in html_encode(">")

    def test_encode_ampersand(self):
        assert "&amp;" in html_encode("&")

    def test_decode(self):
        assert html_decode("&lt;script&gt;") == "<script>"

    def test_round_trip(self):
        for t in ["<hello>", "a & b", "\"quoted\""]:
            assert html_decode(html_encode(t)) == t


# ── Auto-detect ───────────────────────────────────────────────────────────────

class TestDetect:
    def test_detects_base64(self):
        results = detect_encoding(base64_encode("hello"))
        codecs_found = [r["codec"] for r in results]
        assert "base64" in codecs_found

    def test_detects_hex(self):
        results = detect_encoding(hex_encode("hello"))
        codecs_found = [r["codec"] for r in results]
        assert "hex" in codecs_found

    def test_detects_morse(self):
        results = detect_encoding("... --- ...")
        codecs_found = [r["codec"] for r in results]
        assert "morse" in codecs_found

    def test_detect_returns_list(self):
        results = detect_encoding("aGVsbG8=")
        assert isinstance(results, list)

    def test_detect_result_has_codec_and_result_keys(self):
        results = detect_encoding(base64_encode("hello"))
        for r in results:
            assert "codec" in r
            assert "result" in r

    def test_detect_excludes_identical_output(self):
        # Plaintext passed through ROT13 gives different result
        # but plaintext through URL decode should be same — excluded
        results = detect_encoding("hello")
        for r in results:
            assert r["result"] != "hello"
