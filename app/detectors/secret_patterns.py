"""Secret patterns shared by OutputDetector (detection) and the audit log (redaction).

Pure regexes and helpers, no I/O. Test strings matching these formats must be
built at runtime (GitHub Push Protection), e.g. "sk_" + "live_" + "0fake" * 8.
"""

from __future__ import annotations

import re

# Well-known credential formats: essentially no benign use in an assistant answer.
KNOWN_SECRET_PATTERNS: dict[str, re.Pattern[str]] = {
    "stripe_key": re.compile(r"\b[rs]k_(?:live|test)_[0-9A-Za-z]{16,}\b"),
    "aws_access_key_id": re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    "github_token": re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{40,})\b"),
    "slack_token": re.compile(r"\bxox[abposr]-[A-Za-z0-9-]{10,}"),
    "google_api_key": re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"),
    "private_key": re.compile(r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----"),
    "jwt": re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}"),
}

# "mot de passe : X", "le mot de passe temporaire est X", "password is X", "api_key=X".
# The value is only a credential if looks_like_credential() says so.
CREDENTIAL_ASSIGNMENT = re.compile(
    r"\b(?:mots?\s+de\s+passe|mdp|password|passwd|pwd|passphrase|api[_\s-]?key"
    r"|cl[ée]\s+(?:d['’]\s*API|secr[èe]te)|secret|token|jeton)\b"
    r"(?:\s+(?:temporaire|provisoire|actuel|initial|par\s+d[ée]faut|du\s+wi-?fi|wi-?fi|temporary|default|new|nouveau))*"
    r"\s*(?:[:=]|\b(?:is|est|sera|will\s+be|reste)\b)\s*"
    r"[«\"'`]?\s*(?P<value>[^\s\"'`»,;]+)",
    re.IGNORECASE,
)

_STRONG_SYMBOL = re.compile(r"[!@#$%^&*+?~=|<>]")
_URL_OR_MAIL = re.compile(r"^(?:https?://|www\.)|@[\w-]+\.\w", re.IGNORECASE)


def looks_like_credential(value: str) -> bool:
    """A password-like value: 6+ chars, a letter, and a digit or a strong symbol.

    Rejects plain words ("personnel", "confidentiel"), numbers ("14"),
    identifiers like "prenom.nom", URLs and e-mail addresses.
    """
    value = value.rstrip(".:!?)")
    if len(value) < 6 or _URL_OR_MAIL.search(value):
        return False
    has_letter = any(c.isalpha() for c in value)
    has_digit = any(c.isdigit() for c in value)
    return has_letter and (has_digit or bool(_STRONG_SYMBOL.search(value)))


def credential_disclosures(text: str) -> list[str]:
    """Values disclosed after a credential keyword (used for detection only, never logged)."""
    return [m.group("value") for m in CREDENTIAL_ASSIGNMENT.finditer(text) if looks_like_credential(m.group("value"))]


def known_secret_kinds(text: str) -> list[str]:
    return sorted(kind for kind, pattern in KNOWN_SECRET_PATTERNS.items() if pattern.search(text))
