from typing import Dict, List, Tuple
from app.scoring.rules import ScoringRules


class RiskScorer:
    def __init__(self):
        self.rules = ScoringRules()


    def score_encoding(self, detection_result: Dict) -> float:
        """Score encoding detection result"""
        score = 0.0
        
        # Score for detected encodings
        if detection_result.get("encodings_detected"):
            for encoding in detection_result["encodings_detected"]:
                score += self.rules.ENCODING_RULES["encoding_detected"]["base_score"]
        
        # Score for each decoded payload
        if detection_result.get("decoded_payloads"):
            score += len(detection_result["decoded_payloads"]) * self.rules.ENCODING_RULES["decoded_payload"]["score"]
        
        # Score for high entropy
        entropy = detection_result.get("entropy_score", 0.0)
        if entropy > self.rules.ENCODING_RULES["high_entropy"]["threshold"]:
            score += self.rules.ENCODING_RULES["high_entropy"]["score"]
        
        # Score for patterns (only if no actual encodings detected)
        if not detection_result.get("encodings_detected") and detection_result.get("encoding_patterns"):
            score += len(detection_result["encoding_patterns"]) * self.rules.ENCODING_RULES["pattern_detected"]["score"]
        
        return score
    
    def score_heuristic(self, detection_result: Dict) -> float:
        """Score heuristic detection result"""
        anomalies = detection_result.get("anomalies", [])
        score = len(anomalies) * self.rules.HEURISTIC_RULES["anomaly"]["score_per_anomaly"]
        return score
    
    def score_regex(self, detection_result: Dict) -> float:
        """Score regex detection result"""
        matches = detection_result.get("matches", [])
        
        # Use weights if available, otherwise use default
        score = 0.0
        for match in matches:
            weight = self.rules.REGEX_RULES["pattern_weights"].get(match, self.rules.REGEX_RULES["pattern_match"]["score_per_match"])
            score += weight
        
        return score
    
    def score_jailbreak(self, detection_result: Dict) -> float:
        """Score jailbreak detection result"""
        jailbreak_types = detection_result.get("jailbreak_types", [])
        
        # Use weights if available, otherwise use default
        score = 0.0
        for jb_type in jailbreak_types:
            weight = self.rules.JAILBREAK_RULES["type_weights"].get(jb_type, self.rules.JAILBREAK_RULES["jailbreak_type"]["score_per_type"])
            score += weight
        
        return score
    
    
    def score_all(
        self,
        encoding_result: Dict,
        heuristic_result: Dict,
        regex_results: List[Dict],
        jailbreak_results: List[Dict]
    ) -> Tuple[float, Dict]:
        """
        Score all detection results and calculate final risk.
        
        Args:
            encoding_result: Output from EncodingDetector.detect()
            heuristic_result: Output from HeuristicDetector.detect()
            regex_results: List of outputs from RegexDetector.detect() (one per text variant)
            jailbreak_results: List of outputs from JailbreakDetector.detect() (one per text variant)
        
        Return:
            (total_score, scoring_details)
            
            total_score: 0-100
            scoring_details: {
                "encoding": {"score": 20, "result": {...}},
                "heuristic": {"score": 10, "result": {...}},
                "regex": {"score": 20, "max_from_variants": "variant_1", "variants": [...]},
                "jailbreak": {"score": 30, "max_from_variants": "variant_0", "variants": [...]},
                "total": 80,
                "risk_level": {"level": "HIGH", "action": "BLOCK", "score": 80}
            }
        """
        
        encoding_score = self.score_encoding(encoding_result)
        
        heuristic_score = self.score_heuristic(heuristic_result)
        
        regex_scores = [self.score_regex(r) for r in regex_results]
        regex_score = max(regex_scores) if regex_scores else 0.0
        regex_max_variant = self._find_max_variant(regex_results, regex_scores)
        
        jailbreak_scores = [self.score_jailbreak(r) for r in jailbreak_results]
        jailbreak_score = max(jailbreak_scores) if jailbreak_scores else 0.0
        jailbreak_max_variant = self._find_max_variant(jailbreak_results, jailbreak_scores)
        
        aggregation_method = self.rules.AGGREGATION_RULES["method"]
        
        if aggregation_method == "sum":
            total_score = encoding_score + heuristic_score + regex_score + jailbreak_score
        elif aggregation_method == "weighted_sum":
            weights = self.rules.AGGREGATION_RULES["detector_weights"]
            total_score = (
                encoding_score * weights["encoding"] +
                heuristic_score * weights["heuristic"] +
                regex_score * weights["regex"] +
                jailbreak_score * weights["jailbreak"]
            )
        else:
            total_score = encoding_score + heuristic_score + regex_score + jailbreak_score
        
        max_score = self.rules.AGGREGATION_RULES["max_score_cap"]
        total_score = min(total_score, max_score)
        
        risk_level = self.rules.get_risk_level(total_score)
        
        details = {
            "encoding": {
                "score": encoding_score,
                "result": encoding_result
            },
            "heuristic": {
                "score": heuristic_score,
                "result": heuristic_result
            },
            "regex": {
                "score": regex_score,
                "max_from_variant": regex_max_variant,
                "variants": [
                    {"variant": i, "score": regex_scores[i], "result": regex_results[i]}
                    for i in range(len(regex_results))
                ]
            },
            "jailbreak": {
                "score": jailbreak_score,
                "max_from_variant": jailbreak_max_variant,
                "variants": [
                    {"variant": i, "score": jailbreak_scores[i], "result": jailbreak_results[i]}
                    for i in range(len(jailbreak_results))
                ]
            },
            "total": total_score,
            "risk_level": risk_level
        }
        
        return total_score, details
    
    @staticmethod
    def _find_max_variant(results: List[Dict], scores: List[float]) -> str:
        """Find which variant had the maximum score"""
        if not scores:
            return "N/A"
        
        max_idx = scores.index(max(scores))
        return f"variant_{max_idx}"

