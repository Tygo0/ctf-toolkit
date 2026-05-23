"""
Encoding/decoding engine — pure functions for every supported codec.
Each function raises ValueError on invalid input so the CLI can handle errors cleanly.
"""

import base64
import binascii
import codecs
import urllib.parse
from typing import Optional


# ── Base64 ────────────────────────────────────────────────────────────────────

def base64_encode(text: str) -> str:
    return base64.b64encode(text.encode()).decode()

def base64_decode(text: str) -> str:
    # Pad if needed
    padded = text.strip() + "=" * (-len(text.strip()) % 4)
    try:
        return base64.b64decode(padded).decode()
    except Exception as e:
        raise ValueError(f"Invalid base64: {e}")


# ── Base32 ────────────────────────────────────────────────────────────────────

def base32_encode(text: str) -> str:
    return base64.b32encode(text.encode()).decode()

def base32_decode(text: str) -> str:
    padded = text.strip().upper() + "=" * (-len(text.strip()) % 8)
    try:
        return base64.b32decode(padded).decode()
    except Exception as e:
        raise ValueError(f"Invalid base32: {e}")


# ── Base58 ────────────────────────────────────────────────────────────────────

_B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

def base58_encode(text: str) -> str:
    data = text.encode()
    n = int.from_bytes(data, "big")
    result = ""
    while n:
        n, r = divmod(n, 58)
        result = _B58_ALPHABET[r] + result
    # leading zero bytes
    for byte in data:
        if byte == 0:
            result = _B58_ALPHABET[0] + result
        else:
            break
    return result

def base58_decode(text: str) -> str:
    text = text.strip()
    n = 0
    for char in text:
        if char not in _B58_ALPHABET:
            raise ValueError(f"Invalid base58 character: {char!r}")
        n = n * 58 + _B58_ALPHABET.index(char)
    # count leading '1's (zero bytes)
    pad = len(text) - len(text.lstrip(_B58_ALPHABET[0]))
    result = n.to_bytes((n.bit_length() + 7) // 8 or 1, "big")
    return (b"\x00" * pad + result).decode(errors="replace")


# ── Hex ───────────────────────────────────────────────────────────────────────

def hex_encode(text: str) -> str:
    return text.encode().hex()

def hex_decode(text: str) -> str:
    clean = text.strip().replace(" ", "").replace("0x", "").replace("\\x", "")
    try:
        return bytes.fromhex(clean).decode()
    except Exception as e:
        raise ValueError(f"Invalid hex string: {e}")


# ── ROT13 ─────────────────────────────────────────────────────────────────────

def rot13(text: str) -> str:
    """ROT13 is its own inverse."""
    return codecs.encode(text, "rot_13")

def rot_n(text: str, n: int) -> str:
    """ROT-N cipher for any rotation (letters only)."""
    result = []
    for ch in text:
        if ch.isalpha():
            base = ord("A") if ch.isupper() else ord("a")
            result.append(chr((ord(ch) - base + n) % 26 + base))
        else:
            result.append(ch)
    return "".join(result)


# ── URL encoding ──────────────────────────────────────────────────────────────

def url_encode(text: str) -> str:
    return urllib.parse.quote(text, safe="")

def url_decode(text: str) -> str:
    try:
        return urllib.parse.unquote(text)
    except Exception as e:
        raise ValueError(f"Invalid URL encoding: {e}")


# ── Binary ────────────────────────────────────────────────────────────────────

def binary_encode(text: str) -> str:
    return " ".join(format(ord(c), "08b") for c in text)

def binary_decode(text: str) -> str:
    parts = text.strip().split()
    try:
        return "".join(chr(int(p, 2)) for p in parts)
    except Exception as e:
        raise ValueError(f"Invalid binary string: {e}")


# ── Morse code ────────────────────────────────────────────────────────────────

_MORSE_ENC = {
    "A": ".-",   "B": "-...", "C": "-.-.", "D": "-..",  "E": ".",
    "F": "..-.", "G": "--.",  "H": "....", "I": "..",   "J": ".---",
    "K": "-.-",  "L": ".-..", "M": "--",   "N": "-.",   "O": "---",
    "P": ".--.", "Q": "--.-", "R": ".-.",  "S": "...",  "T": "-",
    "U": "..-",  "V": "...-", "W": ".--",  "X": "-..-", "Y": "-.--",
    "Z": "--..",
    "0": "-----", "1": ".----", "2": "..---", "3": "...--", "4": "....-",
    "5": ".....", "6": "-....", "7": "--...", "8": "---..", "9": "----.",
    " ": "/",
}
_MORSE_DEC = {v: k for k, v in _MORSE_ENC.items()}

def morse_encode(text: str) -> str:
    result = []
    for ch in text.upper():
        if ch in _MORSE_ENC:
            result.append(_MORSE_ENC[ch])
        else:
            result.append("?")
    return " ".join(result)

def morse_decode(text: str) -> str:
    tokens = text.strip().split(" ")
    result = []
    for token in tokens:
        if token == "/":
            result.append(" ")
        elif token in _MORSE_DEC:
            result.append(_MORSE_DEC[token])
        else:
            result.append(f"[?{token}]")
    return "".join(result)


# ── HTML entities ─────────────────────────────────────────────────────────────

def html_encode(text: str) -> str:
    import html
    return html.escape(text)

def html_decode(text: str) -> str:
    import html
    return html.unescape(text)


# ── Auto-detect: try all decoders ─────────────────────────────────────────────

def detect_encoding(text: str) -> list[dict]:
    """
    Attempt every decoder and return successes as a list of dicts:
    {"codec": name, "result": decoded_string}
    """
    candidates = []

    attempts = [
        ("base64",  base64_decode),
        ("base32",  base32_decode),
        ("hex",     hex_decode),
        ("binary",  binary_decode),
        ("url",     url_decode),
        ("morse",   morse_decode),
        ("html",    html_decode),
        ("rot13",   rot13),
    ]

    for name, fn in attempts:
        try:
            result = fn(text)
            # Only include if result is different and reasonably printable
            if result and result != text and result.isprintable():
                candidates.append({"codec": name, "result": result})
        except Exception:
            pass

    return candidates
