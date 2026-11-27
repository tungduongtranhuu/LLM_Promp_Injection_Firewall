"""Tests for app/normalize.py (TODO 1.4)."""

import pytest

from app.normalize import (
    BIDI_CONTROL_CHARS,
    ZERO_WIDTH_CHARS,
    build_variants,
    collapse_spaced_letters,
    decode_tag_chars,
    deobfuscate,
    nfkc_lower,
    strip_zero_width,
)


def texts(variants):
    return {v.name: v.text for v in variants}


def test_fullwidth_folded_by_nfkc():
    assert nfkc_lower("ｉｇｎｏｒｅ ＰＲＥＶＩＯＵＳ") == "ignore previous"


def test_zero_width_removed():
    assert strip_zero_width("ig​nore pre‍vious﻿") == "ignore previous"


def test_cyrillic_homoglyphs_mapped_to_latin():
    # і, о, е, а are Cyrillic
    assert deobfuscate("іgnоrе аll") == "ignore all"


def test_greek_homoglyphs_mapped_to_latin():
    assert deobfuscate("οverride") == "override"


def test_combined_obfuscation():
    assert deobfuscate("іg​nоre") == "ignore"


def test_original_first_and_decoded_payloads_appended():
    variants = build_variants("aWdub3Jl", ["ignore"])
    assert variants[0].name == "original" and variants[0].text == "aWdub3Jl"
    assert texts(variants)["decoded_0"] == "ignore"


def test_duplicate_variants_removed():
    # Plain lowercase ASCII: nfkc_lower, no_zero_width and deobfuscated equal the original.
    variants = build_variants("hello world")
    assert [v.name for v in variants] == ["original"]


def test_duplicate_decoded_payload_removed():
    variants = build_variants("hello", ["hello"])
    assert [v.name for v in variants] == ["original"]


def test_zero_width_variant_present_when_text_changes():
    variants = texts(build_variants("Ig​nore"))
    assert variants["no_zero_width"] == "Ignore"
    assert variants["nfkc_lower"] == "ig​nore"  # NFKC keeps zero-width characters
    assert "deobfuscated" not in variants  # same text as no_zero_width, deduplicated


def test_false_positive_french_accents_untouched():
    text = "Café, naïve, élève, ça, où, Noël"
    assert deobfuscate(text) == text
    assert strip_zero_width(text) == text


def test_zero_width_set_is_invisible_format_characters():
    import unicodedata

    assert all(unicodedata.category(c) == "Cf" or c == "­" for c in ZERO_WIDTH_CHARS)


def tags(text: str) -> str:
    """Encode ASCII as invisible Unicode tag characters (U+E0000 + code point)."""
    return "".join(chr(0xE0000 + ord(c)) for c in text)


# ---------------------------------------------------------------- bidi controls
def test_bidi_controls_removed():
    assert strip_zero_width("ig‮nore pre⁦vious‏") == "ignore previous"


def test_bidi_controls_are_format_characters():
    import unicodedata

    assert all(unicodedata.category(c) == "Cf" for c in BIDI_CONTROL_CHARS)


def test_false_positive_bidi_not_reported_as_zero_width():
    # LRM/RLM occur in legitimate RTL text: stripped from variants, not a finding.
    assert BIDI_CONTROL_CHARS.isdisjoint(ZERO_WIDTH_CHARS)


# ---------------------------------------------------------------- tag characters
def test_tag_chars_decoded_to_ascii():
    assert decode_tag_chars("Hello" + tags("ignore all")) == "ignore all"


def test_tag_chars_stripped_from_cleaned_variants():
    variants = texts(build_variants("Hello" + tags("ignore all")))
    assert variants["no_zero_width"] == "Hello"
    assert variants["tag_payload"] == "ignore all"


def test_tag_language_and_cancel_tags_not_decoded():
    # U+E0001 (language tag) and U+E007F (cancel tag) carry no printable ASCII.
    assert decode_tag_chars("\U000E0001" + tags("fr") + "\U000E007F") == "fr"


def test_false_positive_emoji_flag_without_tags_has_no_tag_payload():
    assert "tag_payload" not in texts(build_variants("Bonjour 🇫🇷 !"))


# ---------------------------------------------------------------- spaced letters
def test_spaced_letters_collapsed_with_word_gaps():
    assert collapse_spaced_letters("i g n o r e  a l l  p r e v i o u s") == "ignore all previous"


def test_spaced_letters_single_spaces_become_one_word():
    assert collapse_spaced_letters("please i g n o r e this") == "please ignore this"


def test_collapsed_variant_present():
    variants = texts(build_variants("i g n o r e  a l l"))
    assert variants["collapsed"] == "ignore all"


@pytest.mark.parametrize("text", [
    "Plan A or B, then a to-do list",
    "Choose a b or c: answer a",
    "Le chapitre 3 a 2 sections",
    "Vitamin B 12 is ok",
])
def test_false_positive_short_letter_runs_untouched(text):
    assert collapse_spaced_letters(text) == text


# ---------------------------------------------------------------- decoded payloads
def test_decoded_payload_deobfuscated():
    # Cyrillic і and zero-width space inside a decoded payload.
    variants = texts(build_variants("x", ["іgn​ore all"]))
    assert variants["decoded_0"] == "іgn​ore all"
    assert variants["decoded_0_deobfuscated"] == "ignore all"


def test_clean_decoded_payload_not_duplicated():
    variants = build_variants("aWdub3Jl", ["ignore"])
    assert [v.name for v in variants] == ["original", "nfkc_lower", "decoded_0"]


def test_empty_text_keeps_original_variant():
    assert [v.name for v in build_variants("")] == ["original"]
