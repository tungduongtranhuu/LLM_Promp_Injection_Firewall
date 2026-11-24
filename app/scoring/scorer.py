"""Turn detector findings into a risk score. Every number comes from rules.py."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any, Dict, List, Optional, Tuple

from app.scoring.rules import ScoringRules

# Result key holding the technique ids, for each detector that runs on every variant.
VARIANT_DETECTOR_KEYS = {
    "regex": "matches",
    "jailbreak": "jailbreak_types",
    "indirect": "findings",
    "output": "findings",
}


class RiskScorer:
    def __init__(self) -> None:
        self.rules = ScoringRules()

    # ------------------------------------------------------------------ public API
    def score_all(
        self,
        encoding_result: Dict,
        heuristic_result: Dict,
        regex_results: List[Dict],
        jailbreak_results: List[Dict],
        indirect_results: Optional[List[Dict]] = None,
        output_results: Optional[List[Dict]] = None,
        *,
        context: str = "user_prompt",
        variant_names: Optional[Sequence[str]] = None,
        warn: Optional[float] = None,
        block: Optional[float] = None,
    ) -> Tuple[float, Dict]:
        """
        Score all detection results for one scanned text.

        Args:
            encoding_result: EncodingDetector.detect() on the original text
            heuristic_result: HeuristicDetector.detect() on the original text
            regex_results, jailbreak_results, indirect_results, output_results:
                one result per text variant, in the order of `variant_names`
            context: user_prompt | document | retrieved_chunk | llm_output
            variant_names: names from app.normalize.build_variants ("original", "decoded_0"...)
            warn, block: threshold overrides (app.config), default to rules.py

        Return: (total_score, details) with details = {
            "context", "total", "risk_level",
            "detector_scores": {"regex": 50.0, ...},
            "best_variant": {"regex": "decoded_0", ...},
            "findings": [{"technique", "detector", "variant", "points", "label", "owasp", "atlas"}, ...],
        }
        """
        rules = self.rules
        ctx = rules.context_rules(context)  # ValueError on an unknown context
        enabled = set(ctx["enabled_detectors"])
        per_variant = {
            "regex": regex_results or [],
            "jailbreak": jailbreak_results or [],
            "indirect": indirect_results or [],
            "output": output_results or [],
        }
        n_variants = max((len(r) for r in per_variant.values()), default=0)
        names = list(variant_names) if variant_names is not None else [f"variant_{i}" for i in range(n_variants)]

        # 1. Techniques per detector: best variant for variant detectors, original for heuristic.
        selected: Dict[str, Tuple[str, List[str]]] = {}
        for detector, results in per_variant.items():
            if detector not in enabled or not results:
                continue
            candidates = [self._techniques(detector, r, context) for r in results]
            best = max(range(len(candidates)), key=lambda i: (self._points(detector, candidates[i], True), -i))
            selected[detector] = (names[best], candidates[best])
        if "heuristic" in enabled:
            anomalies = self._filter(heuristic_result.get("anomalies", []), "heuristic", context)
            selected["heuristic"] = ("original", anomalies)

        # 2. Weak signals count only next to a non-weak finding.
        has_strong = any(t not in rules.WEAK_SIGNALS for _, techs in selected.values() for t in techs)

        findings: List[Dict[str, Any]] = []
        detector_scores: Dict[str, float] = {}
        for detector, (variant, techniques) in selected.items():
            weight = rules.detector_weight(context, detector)
            total = 0.0
            for technique in techniques:
                points = rules.technique_weight(detector, technique) * weight
                if technique in rules.WEAK_SIGNALS and not has_strong:
                    points = 0.0
                total += points
                findings.append(self._finding(technique, detector, variant, points, context))
            detector_scores[detector] = total

        # 3. Encoding: only readable decodes count, and mostly when the decoded text is malicious.
        if "encoding" in enabled:
            decoded_hit = self._decoded_variant_hit(per_variant, names, context, enabled)
            encoding_score = self.score_encoding(encoding_result, decoded_hit) * rules.detector_weight(context, "encoding")
            detector_scores["encoding"] = encoding_score
            if encoding_score > 0:
                findings.append(self._finding("encoded_payload", "encoding", "original", encoding_score, context))

        total_score = min(sum(detector_scores.values()), rules.MAX_SCORE)
        risk_level = rules.get_risk_level(total_score, warn=warn, block=block)
        findings.sort(key=lambda f: f["points"], reverse=True)
        details = {
            "context": context,
            "total": total_score,
            "risk_level": risk_level,
            "detector_scores": detector_scores,
            "best_variant": {d: v for d, (v, _) in selected.items()},
            "findings": findings,
        }
        return total_score, details

    def score_encoding(self, detection_result: Dict, decoded_hit: bool = False) -> float:
        """Encoding is an evasion technique: small signal unless decoded content is malicious.

        A ROT13-only decode is ignored unless it triggered a detector, because ROT13
        of any letter string ("deadbeefcafebabe") still looks like letters.
        """
        enc = self.rules.ENCODING_RULES
        decoded = detection_result.get("encodings_detected") or []
        readable = [e for e in decoded if e != "rot13"]
        score = 0.0
        if readable or decoded_hit:
            score += enc["encoding_present"]
        if decoded_hit:
            score += enc["decoded_triggers_detector"]
        if detection_result.get("entropy_score", 0.0) > enc["high_entropy"]["threshold"]:
            score += enc["high_entropy"]["score"]
        if not decoded:
            score += len(detection_result.get("encoding_patterns") or []) * enc["pattern_detected"]
        return score

    # ------------------------------------------------------------------ helpers
    def _filter(self, techniques: Sequence[str], detector: str, context: str) -> List[str]:
        disabled = self.rules.context_rules(context)["disabled_findings"].get(detector, ())
        return [t for t in techniques if t not in disabled]

    def _techniques(self, detector: str, result: Dict, context: str) -> List[str]:
        return self._filter(result.get(VARIANT_DETECTOR_KEYS[detector], []), detector, context)

    def _points(self, detector: str, techniques: Sequence[str], strong_only: bool) -> float:
        return sum(
            self.rules.technique_weight(detector, t)
            for t in techniques
            if not (strong_only and t in self.rules.WEAK_SIGNALS)
        )

    def _decoded_variant_hit(
        self, per_variant: Dict[str, List[Dict]], names: Sequence[str], context: str, enabled: set
    ) -> bool:
        for detector, results in per_variant.items():
            if detector not in enabled:
                continue
            for name, result in zip(names, results):
                if name.startswith("decoded_") and self._points(detector, self._techniques(detector, result, context), True) > 0:
                    return True
        return False

    def _finding(self, technique: str, detector: str, variant: str, points: float, context: str) -> Dict[str, Any]:
        label = self.rules.label_for(technique, context)
        return {
            "technique": technique,
            "detector": detector,
            "variant": variant,
            "points": points,
            "label": label,
            **self.rules.taxonomy_for(label),
        }
