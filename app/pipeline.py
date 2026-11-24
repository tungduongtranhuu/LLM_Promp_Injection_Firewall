"""The firewall pipeline: every scan goes through scan(text, context).

encoding (original) -> build_variants -> heuristic (original)
-> regex / jailbreak / indirect / output (every variant) -> scorer -> decision

scan() is pure: it does not log. Callers decide which audit event to write,
so evaluations and re-scans do not flood the SIEM log.
"""

from __future__ import annotations

from app import config
from app.detectors.encoding_detector import EncodingDetector
from app.detectors.heuristic_detector import HeuristicDetector
from app.detectors.indirect_detector import IndirectDetector
from app.detectors.jailbreak_detector import JailbreakDetector
from app.detectors.output_detector import OutputDetector
from app.detectors.regex_detector import RegexDetector
from app.models import Finding, ScanResult
from app.normalize import build_variants
from app.scoring.rules import ScoringRules
from app.scoring.scorer import RiskScorer

_encoding = EncodingDetector()
_heuristic = HeuristicDetector()
_regex = RegexDetector()
_jailbreak = JailbreakDetector()
_indirect = IndirectDetector(ScoringRules.URL_ALLOWLIST)
_output = OutputDetector(ScoringRules.URL_ALLOWLIST)
_scorer = RiskScorer()


def scan(text: str, context: str = "user_prompt") -> ScanResult:
    """Scan one text in a given context and return the score, decision and findings."""
    enabled = ScoringRules.context_rules(context)["enabled_detectors"]  # ValueError on unknown context

    encoding_result = _encoding.detect(text)
    # Sorted: EncodingDetector de-duplicates through a set, so its order is not stable.
    variants = build_variants(text, sorted(encoding_result["decoded_payloads"]))
    texts = [v.text for v in variants]

    total, details = _scorer.score_all(
        encoding_result,
        _heuristic.detect(text),
        [_regex.detect(t) for t in texts],
        [_jailbreak.detect(t) for t in texts],
        [_indirect.detect(t) for t in texts],
        [_output.detect(t) for t in texts] if "output" in enabled else None,
        context=context,
        variant_names=[v.name for v in variants],
        warn=config.warn_threshold,
        block=config.block_threshold,
    )

    findings = [Finding(**f) for f in details["findings"]]
    scoring = [f for f in findings if f.points > 0]
    primary = next((f for f in scoring if f.owasp), None)
    risk = details["risk_level"]
    return ScanResult(
        score=total,
        decision=risk["action"],
        level=risk["level"],
        context=context,
        detectors=sorted({f.detector for f in scoring}),
        findings=findings,
        labels=sorted({f.label for f in scoring}),
        owasp=primary.owasp if primary else None,
        atlas=primary.atlas if primary else None,
        details={
            "detector_scores": details["detector_scores"],
            "best_variant": details["best_variant"],
            "variants": [v.name for v in variants],
        },
    )
