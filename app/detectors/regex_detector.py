import re
from typing import Dict, List


class RegexDetector:
    """Detect prompt-injection phrasing with regular expressions (EN + FR).

    Emits technique ids; app/scoring/rules.py maps them to OWASP labels:
    - prompt_override : instruction override ("ignore previous instructions")
    - extraction      : system prompt leakage attempts (OWASP LLM07)
    - role_switching  : weak signal only ("act as", "you are now"), scored only
                        when another finding is present (see rules.WEAK_SIGNALS)
    """

    _FLAGS = re.IGNORECASE

    _EN_TARGETS = r"(?:instructions?|rules|directions|prompts?|messages?|guidelines|commands?)"
    _FR_TARGETS = r"(?:instructions|consignes|r[èe]gles|directives)"

    PATTERNS: Dict[str, List[re.Pattern]] = {
        "prompt_override": [
            re.compile(
                r"\b(?:ignore|disregard|forget|skip|override)\s+"
                r"(?:(?:all|the|any|your|of|my|these|those)\s+)*"
                r"(?:previous|prior|above|earlier|preceding|former|original)\s+" + _EN_TARGETS + r"\b",
                _FLAGS,
            ),
            re.compile(r"\bdisregard\s+(?:the\s+)?(?:above|previous)\b", _FLAGS),
            re.compile(r"\bforget\s+(?:(?:about|the)\s+)+above\b", _FLAGS),
            re.compile(r"\bforget\s+everything\s+(?:you\s+(?:were|know|have\s+been)|above|before)\b", _FLAGS),
            # FR: "Ignorez les instructions précédentes", "Ignore les règles ci-dessus"
            re.compile(
                r"\bignor(?:e|es|ez|er)\s+(?:(?:toutes|tous|les|tes|vos|mes|ces)\s+)*" + _FR_TARGETS +
                r"\s+(?:pr[ée]c[ée]dentes|ant[ée]rieures|ci-dessus|d'avant)",
                _FLAGS,
            ),
            # FR: "Oublie toutes tes consignes" (but not "N'oubliez pas les consignes")
            re.compile(r"\boubli(?:e|es|ez|er)\s+(?:(?:toutes|tous|les|tes|vos)\s+)*" + _FR_TARGETS + r"\b", _FLAGS),
        ],
        "extraction": [
            re.compile(
                r"\b(?:reveal|show|tell|print|display|output|repeat|give)(?:\s+me)?\s+"
                r"(?:(?:the|your|full|entire|exact|complete|original)\s+)*"
                r"(?:system\s+prompt|hidden\s+(?:prompt|instructions)|initial\s+instructions)\b",
                _FLAGS,
            ),
            re.compile(r"\bwhat\s+was\s+i\s+instructed\b", _FLAGS),
            re.compile(r"\bwhat\s+are\s+your\s+(?:instructions|rules|guidelines)\b", _FLAGS),
            re.compile(r"\bhidden\s+prompt\b", _FLAGS),
            # FR: "Montre-moi ton prompt système", "Affiche le prompt système"
            re.compile(
                r"\b(?:montre|affiche|r[ée]v[èée]le|donne|r[ée]p[èée]te)(?:s|z)?(?:-moi|\s+moi)?\s+"
                r"(?:(?:ton|votre|le|tes|vos|les)\s+)?"
                r"(?:prompt\s+syst[èe]me|instructions\s+(?:cach[ée]es|syst[èe]me|initiales))",
                _FLAGS,
            ),
        ],
        "role_switching": [
            re.compile(r"\byou\s+are\s+now\b", _FLAGS),
            re.compile(r"\bpretend\s+(?:that\s+)?you\s+are\b", _FLAGS),
            re.compile(r"\bact\s+as\b", _FLAGS),
            re.compile(r"\bfrom\s+now\s+on\b", _FLAGS),
            re.compile(r"\btu\s+es\s+maintenant\b", _FLAGS),
            re.compile(r"\bfais\s+comme\s+si\s+tu\s+[ée]tais\b", _FLAGS),
            re.compile(r"\b[àa]\s+partir\s+de\s+maintenant\b", _FLAGS),
        ],
    }

    def detect(self, text: str) -> Dict[str, List[str]]:
        """
        Scan text for patterns.

        Return: {"matches": ["prompt_override", "extraction"]}
        """
        matches = [
            technique
            for technique, patterns in self.PATTERNS.items()
            if any(pattern.search(text) for pattern in patterns)
        ]
        return {"matches": matches}
