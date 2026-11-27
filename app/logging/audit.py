"""Audit log: one JSON object per line in logs/firewall.jsonl (ARCHITECTURE.md §3.3).

This file is the contract with the SIEM (Wazuh `localfile` in json format):
do not rename fields without updating siem/wazuh/local_rules.xml.

Every event has: ts (UTC ISO-8601 with milliseconds, "Z"), source, event_type,
request_id, decision, score. Scanned text is never logged in full: only a
redacted excerpt (<= 200 chars) and the sha256 of the full text.
"""

from __future__ import annotations

import hashlib
import json
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from app import config
from app.detectors.secret_patterns import KNOWN_SECRET_PATTERNS
from app.models import ScanResult

SOURCE = "llm_firewall"
EXCERPT_MAX_CHARS = 200
REDACTED = "[REDACTED]"
RESERVED_FIELDS = frozenset({"ts", "source", "event_type", "request_id", "decision", "score", "excerpt", "text_sha256"})

# "password: hunter2", "the reset password is hunter2", "mot de passe = x", "api_key=..."
_SECRET_ASSIGNMENT = re.compile(
    r"\b(password|passwd|pwd|passphrase|mot\s+de\s+passe|api[_-]?key|access[_-]?key|token|secret)"
    r"(\s*(?:[:=]|\bis\b|\best\b)\s*)"
    r"([\"']?)([^\s\"',;]+)",
    re.IGNORECASE,
)
# Long key-like strings: API keys, bearer tokens, private-key material.
_KEY_LIKE = re.compile(r"\b(?=[A-Za-z0-9_\-]*\d)(?=[A-Za-z0-9_\-]*[A-Za-z])[A-Za-z0-9_\-]{32,}\b")


def utc_timestamp(now: Optional[datetime] = None) -> str:
    """UTC ISO-8601 with milliseconds and a Z suffix, e.g. 2026-11-25T09:14:03.512Z."""
    now = now or datetime.now(timezone.utc)
    return now.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def redact(text: str) -> str:
    # Known formats first: an AWS key id (20 chars) or a JWT is shorter than _KEY_LIKE.
    for pattern in KNOWN_SECRET_PATTERNS.values():
        text = pattern.sub(REDACTED, text)
    text = _SECRET_ASSIGNMENT.sub(lambda m: f"{m.group(1)}{m.group(2)}{m.group(3)}{REDACTED}", text)
    return _KEY_LIKE.sub(REDACTED, text)


def make_excerpt(text: str, limit: int = EXCERPT_MAX_CHARS) -> str:
    """Redact first, then collapse whitespace and truncate, so a secret is never cut in half and kept."""
    flat = " ".join(redact(text).split())
    return flat if len(flat) <= limit else flat[: limit - 1] + "…"


def sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def log_event(
    event_type: str,
    *,
    request_id: Optional[str] = None,
    decision: Optional[str] = None,
    score: Optional[float] = None,
    text: Optional[str] = None,
    path: Optional[Path | str] = None,
    **fields: Any,
) -> dict[str, Any]:
    """Append exactly one JSON line to the audit log and return the event."""
    clash = RESERVED_FIELDS.intersection(fields)
    if clash:
        raise ValueError(f"reserved audit fields passed as extra fields: {sorted(clash)}")

    event: dict[str, Any] = {
        "ts": utc_timestamp(),
        "source": SOURCE,
        "event_type": event_type,
        "request_id": request_id or uuid.uuid4().hex,
        "decision": decision,
        "score": score,
    }
    if text is not None:
        event["excerpt"] = make_excerpt(text)
        event["text_sha256"] = sha256_hex(text)
    event.update(fields)

    log_path = Path(path or config.audit_log_path)
    log_path.parent.mkdir(parents=True, exist_ok=True)
    line = json.dumps(event, ensure_ascii=False, separators=(",", ":"), default=str)
    with log_path.open("a", encoding="utf-8") as handle:
        handle.write(line + "\n")
    return event


def log_scan(
    event_type: str,
    result: ScanResult,
    text: str,
    *,
    request_id: Optional[str] = None,
    path: Optional[Path | str] = None,
    **fields: Any,
) -> dict[str, Any]:
    """Log a scan result: decision, score, context, detectors, OWASP/ATLAS taxonomy from the findings."""
    return log_event(
        event_type,
        request_id=request_id,
        decision=result.decision,
        score=result.score,
        text=text,
        path=path,
        context=result.context,
        detectors=result.detectors,
        techniques=sorted({f.technique for f in result.findings if f.points > 0}),
        labels=result.labels,
        owasp=result.owasp,
        atlas=result.atlas,
        **fields,
    )
