"""Text variants for the firewall: the only place where normalized, de-obfuscated
and decoded versions of a text are produced (CLAUDE.md architecture rule).

Detectors run on every variant and the scorer keeps the maximum per detector,
so an attack hidden behind zero-width or bidi characters, Unicode tag characters,
homoglyphs, fullwidth forms, letters split by spaces or an encoding is scored as
if it were written in plain text. The original text is never modified.
"""

from __future__ import annotations

import re
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

# Bidirectional controls: they reorder how text is displayed ("ig\u202enore") without
# being visible. Stripped from variants only: unlike ZERO_WIDTH_CHARS they are not
# reported by IndirectDetector, because U+200E/U+200F occur in legitimate RTL text.
BIDI_CONTROL_CHARS = frozenset(
    {
        "\u200e", "\u200f",                      # left-to-right / right-to-left mark
        "\u202a", "\u202b", "\u202c", "\u202d", "\u202e",  # embeddings, overrides, pop
        "\u2066", "\u2067", "\u2068", "\u2069",  # isolates
    }
)

# Unicode tag characters (U+E0000-U+E007F) are invisible. U+E0020-U+E007E mirror
# printable ASCII, so they can carry a hidden instruction ("ASCII smuggling").
TAG_BLOCK = range(0xE0000, 0xE0080)
_TAG_ASCII = range(0xE0020, 0xE007F)
TAG_OFFSET = 0xE0000

_INVISIBLE_TABLE = {ord(c): None for c in ZERO_WIDTH_CHARS | BIDI_CONTROL_CHARS}
_INVISIBLE_TABLE.update({cp: None for cp in TAG_BLOCK})

# Three or more single letters separated by spaces: "i g n o r e". Letters only
# ([^\W\d_]), so "chapitre 3 a 2" stays as it is. Two or more spaces between
# letters mark a word gap and are kept as one space.
_SPACED_LETTERS = re.compile(r"(?<!\w)[^\W\d_](?: {1,3}[^\W\d_](?!\w)){2,}")
_WORD_GAP = re.compile(r" {2,}")

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
    """Remove every invisible character: zero-width, bidi controls and tag characters."""
    return text.translate(_INVISIBLE_TABLE)


def nfkc_lower(text: str) -> str:
    """NFKC folds fullwidth/compatibility forms (ｉｇｎｏｒｅ -> ignore); casefold lowercases."""
    return unicodedata.normalize("NFKC", text).casefold()


def deobfuscate(text: str) -> str:
    """Remove invisible characters, apply NFKC, then map homoglyphs to Latin."""
    return unicodedata.normalize("NFKC", strip_zero_width(text)).translate(_HOMOGLYPH_TABLE)


def decode_tag_chars(text: str) -> str:
    """Return the ASCII hidden in Unicode tag characters (U+E0041 -> "A"), "" if none."""
    return "".join(chr(ord(c) - TAG_OFFSET) for c in text if ord(c) in _TAG_ASCII)


def collapse_spaced_letters(text: str) -> str:
    """Join letters split by spaces: "i g n o r e  a l l" -> "ignore all".

    Only runs of three or more single characters change, so ordinary words and
    "a b" stay as they are. A run split by single spaces only becomes one word:
    without a dictionary its word boundaries cannot be recovered.
    """

    def join(match: re.Match[str]) -> str:
        return " ".join(word.replace(" ", "") for word in _WORD_GAP.split(match.group(0)))

    return _SPACED_LETTERS.sub(join, text)


def build_variants(text: str, decoded_payloads: Sequence[str] = ()) -> list[TextVariant]:
    """Return the variants to scan, `original` first, without duplicate texts.

    Order: original, nfkc_lower, no_zero_width, deobfuscated, collapsed,
    tag_payload, then decoded_i and decoded_i_deobfuscated for each payload.
    Decoding itself lives in EncodingDetector; the pipeline passes its
    decoded_payloads here so that every variant is assembled in this module.
    Decoded names keep the "decoded_" prefix: the scorer relies on it.
    """
    clean = deobfuscate(text)
    candidates = [
        ("original", text),
        ("nfkc_lower", nfkc_lower(text)),
        ("no_zero_width", strip_zero_width(text)),
        ("deobfuscated", clean),
        ("collapsed", collapse_spaced_letters(clean)),
        ("tag_payload", deobfuscate(decode_tag_chars(text))),
    ]
    for i, payload in enumerate(decoded_payloads):
        candidates.append((f"decoded_{i}", payload))
        candidates.append((f"decoded_{i}_deobfuscated", collapse_spaced_letters(deobfuscate(payload))))

    variants: list[TextVariant] = []
    seen: set[str] = set()
    for name, variant_text in candidates:
        if variant_text in seen or (not variant_text and name != "original"):
            continue
        seen.add(variant_text)
        variants.append(TextVariant(name=name, text=variant_text))
    return variants
