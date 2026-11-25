"""URL helpers shared by detectors. Pure functions, no network access."""

from __future__ import annotations

import re
from collections.abc import Iterable, Sequence

# Host part of a URL (userinfo and port included), as a whitelist: Unicode letters
# (homoglyph hosts must still match), digits, "-", ".", ":", "@", "%", ending on a
# letter or digit. A blacklist kept the punctuation around the URL in the host:
# "https://moncompte.acme.fr," or Markdown bold "**https://moncompte.acme.fr**".
HOST_CHARS = r"[\w\-.:@%]*[^\W_]"

URL_RE = re.compile(rf"\bhttps?://({HOST_CHARS})", re.IGNORECASE)


def url_host(netloc: str) -> str:
    """Hostname from a URL netloc: drops userinfo, port and a trailing dot, lowercases."""
    host = netloc.rsplit("@", 1)[-1]
    host = host.split(":", 1)[0]
    return host.rstrip(".").lower()


def extract_url_hosts(text: str) -> list[str]:
    return [url_host(m.group(1)) for m in URL_RE.finditer(text)]


def host_allowed(host: str, allowlist: Iterable[str]) -> bool:
    """True if host is an allowlisted domain or one of its subdomains.

    Suffix matching is on label boundaries: with "acme.fr" allowed,
    "intranet.acme.fr" is allowed but "acme.fr.evil.example" and "evilacme.fr" are not.
    """
    host = host.lower()
    for domain in allowlist:
        domain = domain.lower().lstrip(".")
        if host == domain or host.endswith("." + domain):
            return True
    return False


def unapproved_hosts(hosts: Sequence[str], allowlist: Iterable[str]) -> list[str]:
    allowlist = tuple(allowlist)
    return [h for h in hosts if not host_allowed(h, allowlist)]


# Whole URL: scheme, host (group 1), then an optional path that does not end
# on sentence punctuation, so "see https://x.example/a." keeps its final dot.
URL_FULL_RE = re.compile(
    rf"\bhttps?://({HOST_CHARS})(?:[/?#][^\s<>\"'()\[\]]*[^\s<>\"'()\[\].,;:!?])?",
    re.IGNORECASE,
)


def redact_unapproved_urls(
    text: str, allowlist: Iterable[str], placeholder: str
) -> tuple[str, list[str]]:
    """Replace every URL whose host is not allowlisted. Returns (new_text, redacted_hosts)."""
    allowlist = tuple(allowlist)
    redacted: list[str] = []

    def _replace(match: re.Match[str]) -> str:
        host = url_host(match.group(1))
        if host_allowed(host, allowlist):
            return match.group(0)
        redacted.append(host)
        return placeholder

    return URL_FULL_RE.sub(_replace, text), redacted
