"""Text variants for the firewall: the only place where normalized, de-obfuscated
and decoded versions of a text are produced (CLAUDE.md architecture rule).

Detectors run on every variant and the scorer keeps the maximum per detector,
so an attack hidden behind zero-width characters, homoglyphs, fullwidth forms
or an encoding is scored as if it were written in plain text.
"""

from __future__ import annotations

import unicodedata
from collections.abc import Sequence

from pydantic import BaseModel

# Invisible characters commonly used to split keywords ("ig​nore").
ZERO_WIDTH_CHARS = frozenset(
    {
        "­",  # soft hyphen
        "᠎",  # Mongolian vowel separator
        "​",  # zero-width space
        "‌",  # zero-width non-joiner
        "‍",  # zero-width joiner
        "⁠",  # word joiner
        "﻿",  # zero-width no-break space / BOM
    }
)
_ZERO_WIDTH_TABLE = {ord(c): None for c in ZERO_WIDTH_CHARS}

# Cyrillic and Greek letters that render like Latin ones. NFKC does not fold
# these, so they need an explicit map. Accented Latin letters (é, è, à, ç...)
# are deliberately absent: French text must survive unchanged.
_HOMOGLYPHS = {
    # Cyrillic lowercase
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "у": "y",
    "і": "i", "ј": "j", "ѕ": "s", "ԁ": "d", "һ": "h", "ԛ": "q", "ԝ": "w",
    # Cyrillic uppercase
    "А": "A", "В": "B", "Е": "E", "К": "K", "М": "M", "Н": "H", "О": "O",
    "Р": "P", "С": "C", "Т": "T", "Х": "X", "І": "I", "Ј": "J", "Ѕ": "S",
    # Greek lowercase
    "α": "a", "ο": "o", "ι": "i", "κ": "k", "ν": "v", "ρ": "p", "υ": "u",
    # Greek uppercase
    "Α": "A", "Β": "B", "Ε": "E", "Ζ": "Z", "Η": "H", "Ι": "I", "Κ": "K",
    "Μ": "M", "Ν": "N", "Ο": "O", "Ρ": "P", "Τ": "T", "Υ": "Y", "Χ": "X",
}
_HOMOGLYPH_TABLE = str.maketrans(_HOMOGLYPHS)


class TextVariant(BaseModel):
    """One version of the scanned text. `name` tells the scorer where a finding came from."""

    name: str
    text: str


def strip_zero_width(text: str) -> str:
    return text.translate(_ZERO_WIDTH_TABLE)


def nfkc_lower(text: str) -> str:
    """NFKC folds fullwidth/compatibility forms (ｉｇｎｏｒｅ -> ignore); casefold lowercases."""
    return unicodedata.normalize("NFKC", text).casefold()


def deobfuscate(text: str) -> str:
    """Remove zero-width characters, apply NFKC, then map homoglyphs to Latin."""
    return unicodedata.normalize("NFKC", strip_zero_width(text)).translate(_HOMOGLYPH_TABLE)


def build_variants(text: str, decoded_payloads: Sequence[str] = ()) -> list[TextVariant]:
    """Return the variants to scan, `original` first, without duplicate texts.

    Order: original, nfkc_lower, no_zero_width, deobfuscated, decoded_0..n.
    Decoding itself lives in EncodingDetector; the pipeline passes its
    decoded_payloads here so that every variant is assembled in this module.
    """
    candidates = [
        ("original", text),
        ("nfkc_lower", nfkc_lower(text)),
        ("no_zero_width", strip_zero_width(text)),
        ("deobfuscated", deobfuscate(text)),
    ]
    candidates += [(f"decoded_{i}", payload) for i, payload in enumerate(decoded_payloads)]

    variants: list[TextVariant] = []
    seen: set[str] = set()
    for name, variant_text in candidates:
        if variant_text in seen:
            continue
        seen.add(variant_text)
        variants.append(TextVariant(name=name, text=variant_text))
    return variants
