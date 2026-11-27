"""Turn a scan decision into what the caller does with the text.

The policy (which action for which decision and context) lives in
ScoringRules.WARN_POLICY / BLOCK_POLICY. This module only applies it.
Pure: no I/O. `log=True` tells the caller to write an audit event.
Used by app/rag/ingest.py [0], app/rag/retriever.py [3] and app/rag/chain.py [1][4].
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Literal

from pydantic import BaseModel, Field

from app.detectors.url_utils import redact_unapproved_urls
from app.models import ScanResult
from app.pipeline import scan
from app.scoring.rules import ScoringRules

Action = Literal["allow", "allow_and_log", "quarantine", "drop_chunk", "redact_urls", "block"]
ScanFn = Callable[[str, str], ScanResult]


class Enforcement(BaseModel):
    action: Action
    allowed: bool                      # may the text continue down the chain
    text: str | None                   # text to pass on (redacted if needed); None if not allowed
    log: bool                          # caller must write an audit event
    redacted_hosts: list[str] = Field(default_factory=list)
    reason: str


def enforce(result: ScanResult, text: str, *, scan_fn: ScanFn = scan) -> Enforcement:
    """Apply the context policy to `result`, the scan of `text`."""
    action = ScoringRules.enforcement_action(result.decision, result.context)
    if action is None:
        return Enforcement(action="allow", allowed=True, text=text, log=False, reason="ALLOW")
    if action == "allow_and_log":
        return Enforcement(action=action, allowed=True, text=text, log=True, reason=result.decision)
    if action == "redact_urls":
        return _redact_or_block(result, text, scan_fn)
    return Enforcement(action=action, allowed=False, text=None, log=True, reason=result.decision)


def _redact_or_block(result: ScanResult, text: str, scan_fn: ScanFn) -> Enforcement:
    """Redact unapproved URLs; block unless the redacted text scans as ALLOW."""
    redacted, hosts = redact_unapproved_urls(
        text, ScoringRules.URL_ALLOWLIST, ScoringRules.URL_REDACTION
    )
    if not hosts:
        return Enforcement(
            action="block", allowed=False, text=None, log=True,
            reason=f"{result.decision}: no unapproved URL to redact",
        )
    rescan = scan_fn(redacted, result.context)
    if rescan.decision != "ALLOW":
        return Enforcement(
            action="block", allowed=False, text=None, log=True, redacted_hosts=hosts,
            reason=f"{result.decision}: still {rescan.decision} after redaction",
        )
    return Enforcement(
        action="redact_urls", allowed=True, text=redacted, log=True, redacted_hosts=hosts,
        reason=f"{result.decision}: unapproved URLs redacted",
    )
