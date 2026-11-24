import re
from typing import Dict, List


class JailbreakDetector:
    """Detect jailbreak phrasing (attempts to switch off the model's safety).

    Per OWASP LLM 2025, a jailbreak is a form of prompt injection: rules.py
    labels every technique below as injection.jailbreak (LLM01).
    """

    _FLAGS = re.IGNORECASE

    JAILBREAK_PATTERNS: Dict[str, List[re.Pattern]] = {
        "DAN": [
            # Case-sensitive on purpose: "DAN" the persona, not "Dan" from IT.
            re.compile(r"\bDAN\b"),
            re.compile(r"\bdan\s+(?:mode|jailbreak|prompt)\b", _FLAGS),
            re.compile(r"\bdo\s+anything\s+now\b", _FLAGS),
        ],
        "developer_mode": [
            # Requires an activation verb or state: "is there a developer mode in the API?" is benign.
            re.compile(
                r"\b(?:enable|activate|enter|turn\s+on|switch\s+to|unlock)\b[^.\n]{0,30}?\bdev(?:eloper)?\s+mode\b",
                _FLAGS,
            ),
            re.compile(r"\bdev(?:eloper)?\s+mode\s+(?:on|enabled|activated|unlocked)\b", _FLAGS),
        ],
        "unrestricted": [
            re.compile(r"\bunrestricted\s+(?:ai|mode|assistant|model)\b", _FLAGS),
            re.compile(r"\bno\s+restrictions\b", _FLAGS),
            # "remove restrictions now", but not "remove restrictions on my bike"
            re.compile(
                r"\b(?:remove|disable|lift|bypass)\s+(?:(?:all|any|your|the)\s+)*"
                r"(?:safety\s+|content\s+)?(?:restrictions|filters?|guardrails)\b"
                r"(?!\s+on\s+(?:my|the|a|an|his|her|this|our)\b)",
                _FLAGS,
            ),
        ],
        "evil_assistant": [
            # A role verb is required: "that was a bad AI answer" is benign.
            re.compile(
                r"\b(?:be|become|act\s+as|you\s+are|play)\s+(?:an?\s+|the\s+)?"
                r"(?:evil|bad|unethical|malicious)\s+(?:ai|assistant|bot|chatbot)\b",
                _FLAGS,
            ),
            re.compile(r"\b(?:evil|bad|unethical|malicious)\s+(?:ai|assistant)\s+mode\b", _FLAGS),
        ],
    }

    def detect(self, text: str) -> Dict:
        """
        Detect jailbreak attempts.

        Return: {"jailbreak_types": ["DAN", "developer_mode"]}
        """
        jailbreak_types = [
            jailbreak_type
            for jailbreak_type, patterns in self.JAILBREAK_PATTERNS.items()
            if any(pattern.search(text) for pattern in patterns)
        ]
        return {"jailbreak_types": jailbreak_types}
