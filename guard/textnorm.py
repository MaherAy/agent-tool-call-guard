"""Bounded text normalization and decoding.

The leak checks compare text under the same transformations the benchmark declares as supported encodings
(case/spacing, URL, base64, hex, ROT13, reversal). Decoding is depth-limited and size-capped so a hostile
payload cannot turn the monitor into a denial-of-service vector.
"""

from __future__ import annotations

import base64
import binascii
import codecs
import re
import unicodedata
from urllib.parse import unquote

MAX_SCAN_CHARS = 200_000
MAX_EXPANDED_CHARS = 50_000

_ZERO_WIDTH = {ord(c): None for c in "​‌‍⁠﻿­"}
_NON_ALNUM = re.compile(r"[^a-z0-9]")
_B64 = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")
_HEX = re.compile(r"(?:[0-9a-fA-F]{2}){8,}")


def clean(text: str) -> str:
    """NFKC-normalize, drop zero-width and control characters (keeps newlines and tabs)."""
    text = unicodedata.normalize("NFKC", text).translate(_ZERO_WIDTH)
    return "".join(ch for ch in text if ch in "\n\t" or unicodedata.category(ch)[0] != "C")


def squash(text: str) -> str:
    return " ".join(text.split()).lower()


def alnum(text: str) -> str:
    return _NON_ALNUM.sub("", text.lower())


def decode_b64_token(token: str) -> str:
    padded = token + "=" * (-len(token) % 4)
    try:
        return base64.b64decode(padded, validate=True).decode("utf-8", "ignore")
    except (binascii.Error, ValueError):
        return ""


def decode_hex_token(token: str) -> str:
    try:
        return bytes.fromhex(token).decode("utf-8", "ignore")
    except ValueError:
        return ""


def printable_ratio(text: str) -> float:
    if not text:
        return 0.0
    return sum(1 for ch in text if ch.isprintable() or ch in "\n\t") / len(text)


def b64_pieces(text: str) -> list[str]:
    return [d for d in (decode_b64_token(t) for t in _B64.findall(text)) if d]


def hex_pieces(text: str) -> list[str]:
    return [d for d in (decode_hex_token(t) for t in _HEX.findall(text)) if d]


def variants(text: str) -> list[tuple[str, str]]:
    """Six readings of a string: plain, url, base64, hex, rot13, reversed."""
    text = text[:MAX_SCAN_CHARS]
    return [
        ("plain", text),
        ("url", unquote(text)),
        ("base64", "\n".join(b64_pieces(text))),
        ("hex", "\n".join(hex_pieces(text))),
        ("rot13", codecs.decode(text, "rot13")),
        ("reversed", text[::-1]),
    ]


def expand(text: str, rounds: int = 2) -> str:
    """The text plus every printable decoded piece found inside it (base64, hex, URL), depth-limited.

    Used on untrusted content so an encoded or fragmented instruction becomes visible to the
    instruction-reconstruction check.
    """
    text = clean(text)[:MAX_SCAN_CHARS]
    parts = [text]
    frontier = [text]
    for _ in range(rounds):
        found: list[str] = []
        for chunk in frontier:
            for piece in b64_pieces(chunk) + hex_pieces(chunk):
                if printable_ratio(piece) >= 0.9:
                    found.append(piece)
            unquoted = unquote(chunk)
            if unquoted != chunk:
                found.append(unquoted)
        parts.extend(found)
        frontier = found
        if not found or sum(len(p) for p in parts) > MAX_EXPANDED_CHARS:
            break
    return "\n".join(parts)[:MAX_EXPANDED_CHARS]
