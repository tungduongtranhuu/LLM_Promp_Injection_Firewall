"""URL helpers shared by detectors. Pure functions, no network access."""

from __future__ import annotations

import re
from collections.abc import Iterable, Sequence

URL_RE = re.compile(r"\bhttps?://([^\s/?#<>\"'()\[\]]+)", re.IGNORECASE)


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
