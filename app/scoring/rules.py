"""Scoring rules: the single source of truth for every weight, threshold and label.

Philosophy: detectors only detect, the scorer only scores, rules hold the numbers.
Detectors emit *technique* ids; this module says how many points each one is
worth, which ones count in which context, and which OWASP / MITRE ATLAS
category each one belongs to.

Weight tiers (justified by the eval in eval/RESULTS.md, not by target inputs):
- Tier A, 50 = BLOCK on its own: phrasing with essentially no benign use.
- Tier B, 35 = WARN on its own: usually malicious, plausible benign uses.
- Weak signals, 10: only count when another non-weak finding is present.
"""

from typing import Dict, Optional


class ScoringRules:
    # ------------------------------------------------------------------ thresholds
    # Decision thresholds: the single source of truth. app/config.py may override
    # them from env vars (WARN_THRESHOLD / BLOCK_THRESHOLD) but never redefines them.
    WARN_THRESHOLD = 31   # score >= 31 -> WARN
    BLOCK_THRESHOLD = 50  # score >= 50 -> BLOCK

    RISK_THRESHOLDS = {
        "low": {"min": 0, "level": "LOW", "action": "ALLOW"},
        "medium": {"min": WARN_THRESHOLD, "level": "MEDIUM", "action": "WARN"},
        "high": {"min": BLOCK_THRESHOLD, "level": "HIGH", "action": "BLOCK"},
    }

    MAX_SCORE = 100

    # ------------------------------------------------------------------ technique weights
    REGEX_RULES = {
        "pattern_weights": {
            "prompt_override": 50,  # tier A
            "extraction": 35,       # tier B
            "role_switching": 10,   # weak signal ("act as a translator" is normal)
        }
    }

    JAILBREAK_RULES = {
        "type_weights": {
            "DAN": 50,              # tier A
            "developer_mode": 50,   # tier A
            "unrestricted": 35,     # tier B: "no restrictions" also appears in policy text (W2)
            "evil_assistant": 50,   # tier A
        }
    }

    INDIRECT_RULES = {
        "weights": {
            "fake_delimiter": 50,           # tier A
            "ai_addressing": 35,            # tier B
            "conditional_instruction": 35,  # tier B
            "hidden_html_comment": 35,      # tier B
            "zero_width_chars": 35,         # tier B
            "unapproved_url": 35,           # tier B
            "relay_instruction": 10,        # weak signal ("indiquez à l'utilisateur de redémarrer")
        }
    }

    OUTPUT_RULES = {
        "weights": {
            "markdown_image_exfil": 50,  # tier A
        }
    }

    # Heuristic anomalies: points per anomaly, keyed by HeuristicDetector.ANOMALIES.
    HEURISTIC_RULES = {
        "excessive_length": 8,     # > 2000 characters
        "repeated_chars": 5,       # 8+ identical characters in a 10-character window
        "nested_formatting": 12,   # Markdown fences/formatting, XML tags, deep JSON
        "unicode_mixing": 6,       # pure multi-script text, e.g. "Привет世界"
        "language_switching": 15,  # normal text + encoding hints / code syntax / other script
    }

    # Encoding is an evasion technique, not an attack (TODO 1.5a): the payload
    # itself is scored through the decoded_* variants. Encoding alone is a small signal.
    ENCODING_RULES = {
        "encoding_present": 5,            # once, if a readable payload was decoded
        "decoded_triggers_detector": 15,  # a decoded_* variant produced a non-weak finding
        "high_entropy": {"threshold": 4.5, "score": 5},
        "pattern_detected": 5,            # per encoding-like pattern, only when nothing was decoded
    }

    # Techniques that only count when another non-weak finding is present.
    WEAK_SIGNALS = frozenset({"role_switching", "relay_instruction"})

    # Domains whose URLs are legitimate (subdomains included).
    URL_ALLOWLIST = ("acme.fr",)

    # ------------------------------------------------------------------ contexts
    CONTEXTS = ("user_prompt", "document", "retrieved_chunk", "llm_output")

    DETECTORS = ("encoding", "heuristic", "regex", "jailbreak", "indirect", "output")
    _INPUT_DETECTORS = ("encoding", "heuristic", "regex", "jailbreak", "indirect")
    # Markdown and long text are normal in documents and model answers.
    _DOCUMENT_HEURISTICS_OFF = ("nested_formatting", "excessive_length")

    CONTEXT_RULES = {
        "user_prompt": {
            "enabled_detectors": _INPUT_DETECTORS,
            # A user pasting a link is not an injection.
            "disabled_findings": {"indirect": ("unapproved_url",)},
            "detector_weights": {},
        },
        "document": {
            "enabled_detectors": _INPUT_DETECTORS,
            "disabled_findings": {"heuristic": _DOCUMENT_HEURISTICS_OFF},
            "detector_weights": {},
        },
        "retrieved_chunk": {
            "enabled_detectors": _INPUT_DETECTORS,
            "disabled_findings": {"heuristic": _DOCUMENT_HEURISTICS_OFF},
            "detector_weights": {},
        },
        "llm_output": {
            "enabled_detectors": _INPUT_DETECTORS + ("output",),
            "disabled_findings": {"heuristic": _DOCUMENT_HEURISTICS_OFF},
            "detector_weights": {},
        },
    }
    DEFAULT_DETECTOR_WEIGHT = 1.0

    # ------------------------------------------------------------------ taxonomy
    # Technique -> label. "injection" is resolved by context: OWASP calls the same
    # phrase a direct injection in a user prompt and an indirect one in a document.
    TECHNIQUE_LABELS = {
        "prompt_override": "injection",
        "ai_addressing": "injection",
        "conditional_instruction": "injection",
        "hidden_html_comment": "injection",
        "zero_width_chars": "injection",
        "fake_delimiter": "injection",
        "unapproved_url": "injection",
        "DAN": "injection.jailbreak",
        "developer_mode": "injection.jailbreak",
        "unrestricted": "injection.jailbreak",
        "evil_assistant": "injection.jailbreak",
        "extraction": "system_prompt_leakage",
        "markdown_image_exfil": "sensitive_info_disclosure",
        "encoded_payload": "evasion.encoding",
        "role_switching": "signal",
        "relay_instruction": "signal",
        "excessive_length": "signal",
        "repeated_chars": "signal",
        "nested_formatting": "signal",
        "unicode_mixing": "signal",
        "language_switching": "signal",
    }

    INJECTION_LABEL_BY_CONTEXT = {
        "user_prompt": "injection.direct",
        "document": "injection.indirect",
        "retrieved_chunk": "injection.indirect",
        "llm_output": "injection.indirect",
    }

    # OWASP Top 10 for LLM Applications 2025 and MITRE ATLAS.
    # ATLAS ids to verify on atlas.mitre.org (see docs/ARCHITECTURE.md).
    LABEL_TAXONOMY: Dict[str, Dict[str, Optional[str]]] = {
        "injection.direct": {"owasp": "LLM01", "atlas": "AML.T0051.000"},
        "injection.indirect": {"owasp": "LLM01", "atlas": "AML.T0051.001"},
        "injection.jailbreak": {"owasp": "LLM01", "atlas": "AML.T0054"},
        "system_prompt_leakage": {"owasp": "LLM07", "atlas": "AML.T0056"},
        "sensitive_info_disclosure": {"owasp": "LLM02", "atlas": "AML.T0057"},
        "evasion.encoding": {"owasp": None, "atlas": None},
        "signal": {"owasp": None, "atlas": None},
    }

    # ------------------------------------------------------------------ helpers
    @classmethod
    def context_rules(cls, context: str) -> Dict:
        if context not in cls.CONTEXT_RULES:
            raise ValueError(f"unknown context {context!r}; expected one of {cls.CONTEXTS}")
        return cls.CONTEXT_RULES[context]

    @classmethod
    def detector_weight(cls, context: str, detector: str) -> float:
        return cls.context_rules(context)["detector_weights"].get(detector, cls.DEFAULT_DETECTOR_WEIGHT)

    @classmethod
    def technique_weight(cls, detector: str, technique: str) -> float:
        tables = {
            "regex": cls.REGEX_RULES["pattern_weights"],
            "jailbreak": cls.JAILBREAK_RULES["type_weights"],
            "indirect": cls.INDIRECT_RULES["weights"],
            "output": cls.OUTPUT_RULES["weights"],
            "heuristic": cls.HEURISTIC_RULES,
        }
        return tables[detector][technique]  # KeyError on purpose: every technique needs a weight

    @classmethod
    def label_for(cls, technique: str, context: str) -> str:
        label = cls.TECHNIQUE_LABELS[technique]
        if label == "injection":
            label = cls.INJECTION_LABEL_BY_CONTEXT[context]
        return label

    @classmethod
    def taxonomy_for(cls, label: str) -> Dict[str, Optional[str]]:
        return cls.LABEL_TAXONOMY[label]

    @classmethod
    def get_risk_level(
        cls, score: float, warn: Optional[float] = None, block: Optional[float] = None
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
