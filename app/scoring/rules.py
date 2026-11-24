from typing import Dict


class ScoringRules:
    """
    Centralized scoring rules for all detectors.
    
    Philosophy: Detectors only detect, Scorer only scores.
    Rules define HOW MUCH each detection contributes to risk.
    """
    
    ENCODING_RULES = {
        "encoding_detected": {
            "description": "Points per encoding type discovered",
            "base_score": 20,
            "applies_to": ["base64", "hex", "rot13", "url_encoded", "unicode_escaped"]
        },
        "decoded_payload": {
            "description": "Points per successfully decoded payload",
            "score": 15
        },
        "high_entropy": {
            "description": "Points when text entropy is suspiciously high (>4.5)",
            "threshold": 4.5,
            "score": 10
        },
        "pattern_detected": {
            "description": "Points when encoding pattern detected but not yet decoded",
            "score": 5,
            "applies_to": ["base64_pattern", "hex_pattern", "url_encoded_pattern", "unicode_escaped_pattern"]
        }
    }
    

    HEURISTIC_RULES = {
        "entropy": {
            "description": "Entropy analysis - flagged in ENCODING_RULES",
            "high_entropy_threshold": 4.5,
            "score": 10
        },
        
        "excessive_length": {
            "description": "Prompt longer than 2000 characters",
            "threshold": 2000,
            "score": 8
        },
        
        "repeated_chars": {
            "description": "Excessive character repetition (8+ in 10-char window)",
            "threshold": 8,
            "score": 5
        },
        
        "nested_formatting": {
            "description": "Suspicious nested formatting (markdown, XML, JSON)",
            "score": 12,
            "types": {
                "markdown_code_fence": 6,    
                "markdown_formatting": 4,       
                "xml_nesting": 8,             
                "json_nesting": 10,            
                "deep_nesting": 12            
            }
        },
        
        "language_switching": {
            "description": "Suspicious language/script switching (normal + encoding + commands)",
            "score": 15,
            "patterns": {
                "normal_plus_encoding": 10,     
                "normal_plus_command": 12,     
                "unnatural_script_mixing": 8   
            }
        },
        
        "unicode_mixing": {
            "description": "PURE multi-script mixing (2+ non-Latin scripts, >70% non-ASCII, no normal text)",
            "examples": ["Привет世界", "العربیةไทย"],
            "score": 6,
            "note": "Different from language_switching - this is PURE script mixing without normal English text"
        },
        
        "anomaly": {
            "description": "Points per detected anomaly (backward compatibility)",
            "score_per_anomaly": 10,
            "applies_to": ["unicode_mixing", "excessive_length", "repeated_chars", 
                          "nested_formatting", "language_switching"]
        }
    }
    
    REGEX_RULES = {
        "pattern_match": {
            "description": "Points per prompt injection pattern detected",
            "score_per_match": 20,
            "applies_to": ["prompt_override", "extraction", "role_switching"]
        },
        "pattern_weights": {
            "description": "Optional: Different weights per pattern type (can be used for fine-tuning)",
            "prompt_override": 20,
            "extraction": 20,
            "role_switching": 20
        }
    }
    
    JAILBREAK_RULES = {
        "jailbreak_type": {
            "description": "Points per jailbreak type detected",
            "score_per_type": 30,
            "applies_to": ["DAN", "developer_mode", "unrestricted", "evil_assistant"]
        },
        "type_weights": {
            "description": "Optional: Different weights per jailbreak type",
            "DAN": 30,
            "developer_mode": 30,
            "unrestricted": 30,
            "evil_assistant": 30
        }
    }
    
    # Decision thresholds: the single source of truth. app/config.py may override
    # them from env vars (WARN_THRESHOLD / BLOCK_THRESHOLD) but never redefines them.
    WARN_THRESHOLD = 31   # score >= 31 -> WARN
    BLOCK_THRESHOLD = 50  # score >= 50 -> BLOCK

    RISK_THRESHOLDS = {
        "low": {"min": 0, "level": "LOW", "action": "ALLOW"},
        "medium": {"min": WARN_THRESHOLD, "level": "MEDIUM", "action": "WARN"},
        "high": {"min": BLOCK_THRESHOLD, "level": "HIGH", "action": "BLOCK"},
    }

    AGGREGATION_RULES = {
        "description": "How to combine scores from different detectors",
        "method": "sum",  
        "detector_weights": {
            "encoding": 1.0,     
            "heuristic": 1.0,    
            "regex": 1.0,        
            "jailbreak": 1.0     
        },
        "multi_variant_rule": "take_maximum", 
        "max_score_cap": 100     
    }
    
    @classmethod
    def get_risk_level(
        cls, score: float, warn: float | None = None, block: float | None = None
    ) -> Dict:
        """
        Map a score to a risk level and action.

        BLOCK if score >= block, WARN if score >= warn, ALLOW otherwise.
        `warn` / `block` default to the class thresholds; callers pass the
        env-overridden values from app.config.

        Return: {"level": "LOW"|"MEDIUM"|"HIGH", "action": "ALLOW"|"WARN"|"BLOCK", "score": score}
        """
        warn = cls.WARN_THRESHOLD if warn is None else warn
        block = cls.BLOCK_THRESHOLD if block is None else block
        if score >= block:
            tier = cls.RISK_THRESHOLDS["high"]
        elif score >= warn:
            tier = cls.RISK_THRESHOLDS["medium"]
        else:
            tier = cls.RISK_THRESHOLDS["low"]
        return {"level": tier["level"], "action": tier["action"], "score": score}
