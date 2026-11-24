"""Tests for app/normalize.py (TODO 1.4)."""

from app.normalize import ZERO_WIDTH_CHARS, build_variants, deobfuscate, nfkc_lower, strip_zero_width


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
