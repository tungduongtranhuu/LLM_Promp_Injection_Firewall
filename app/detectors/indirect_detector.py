import re
from collections.abc import Sequence
from typing import Dict, List

from app.detectors.url_utils import extract_url_hosts, unapproved_hosts
from app.normalize import ZERO_WIDTH_CHARS


class IndirectDetector:
    """Detect instructions planted in content the model reads (documents, retrieved chunks).

    Emits technique ids; app/scoring/rules.py maps them to OWASP labels and
    weights, and decides per context which ones count:
    - ai_addressing           : text addressed to the AI ("Note to AI:", "À l'attention de l'assistant")
    - conditional_instruction : "when answering/summarizing ... the user/this document"
    - relay_instruction       : "tell the user ..." (weak signal: normal in helpdesk docs)
    - hidden_html_comment     : <!-- ... --> (invisible once rendered)
    - zero_width_chars        : invisible characters used to split keywords
    - fake_delimiter          : chat-template tokens or fake turns (<|system|>, [INST], ### System:)
    - unapproved_url          : http(s) URL whose host is not in the allowlist
    """

    _I = re.IGNORECASE
    _IM = re.IGNORECASE | re.MULTILINE

    PATTERNS: Dict[str, List[re.Pattern]] = {
        "ai_addressing": [
            re.compile(r"\bnote\s+to\s+(?:the\s+)?(?:ai|assistant|llm|model|chatbot)\b", _I),
            re.compile(r"(?<!\w)[àa]\s+l['’]attention\s+de\s+l['’](?:ia|assistant|intelligence\s+artificielle)\b", _I),
            re.compile(r"\b(?:note|message)\s+(?:pour|à)\s+l['’](?:ia|assistant)\b", _I),
            re.compile(r"^\s*(?:ai\s+)?assistant\s*:", _IM),
            re.compile(r"\b(?:ai|llm|assistant)\s+instructions?\s*:", _I),
        ],
        "conditional_instruction": [
            re.compile(
                r"\bwhen\s+(?:you\s+)?(?:answer(?:ing)?|respond(?:ing)?|summari[sz](?:e|ing)|repl(?:y|ying))\b"
                r"[^.\n]{0,40}?"
                r"\b(?:the\s+user|users?|questions?|quer(?:y|ies)|prompts?|this\s+(?:document|page|text|file|content))\b",
                _I,
            ),
            # FR uses the informal "tu" that a document addresses to the AI;
            # human procedures say "Lorsque vous répondez".
            re.compile(r"\b(?:lorsque|quand)\s+tu\s+(?:r[ée]ponds|r[ée]sumes|r[ée]diges)\b", _I),
        ],
        "relay_instruction": [
            re.compile(r"\b(?:tell|inform|instruct|remind)\s+(?:the\s+)?users?\b", _I),
            re.compile(r"\bindiqu(?:e|ez|er)(?:-lui|\s+[àa]\s+l['’]utilisateur)\b", _I),
        ],
        "hidden_html_comment": [
            re.compile(r"<!--[\s\S]*?-->"),
        ],
        "fake_delimiter": [
            re.compile(r"<\|\s*(?:system|user|assistant|im_start|im_end|endoftext|end)\s*\|>", _I),
            re.compile(r"\[/?INST\]"),
            re.compile(r"<</?SYS>>"),
            re.compile(r"^\s*#{1,6}\s*(?:system|assistant|developer)\s*:", _IM),
            re.compile(r"</\s*(?:context|system|instructions?|document|user_input|retrieved)\s*>", _I),
            # A fake conversation: a "User:" turn followed later by an "Assistant:" turn.
            re.compile(r"^\s*(?:user|human)\s*:[\s\S]*?^\s*(?:assistant|ai|bot)\s*:", _IM),
        ],
    }

    def __init__(self, url_allowlist: Sequence[str] = ()) -> None:
        self.url_allowlist = tuple(url_allowlist)

    def detect(self, text: str) -> Dict[str, List[str]]:
        """
        Return: {"findings": ["ai_addressing", "unapproved_url"], "unapproved_hosts": ["evil.example"]}
        """
        findings = [
            technique
            for technique, patterns in self.PATTERNS.items()
            if any(pattern.search(text) for pattern in patterns)
        ]
        if any(c in ZERO_WIDTH_CHARS for c in text):
            findings.append("zero_width_chars")
        bad_hosts = unapproved_hosts(extract_url_hosts(text), self.url_allowlist)
        if bad_hosts:
            findings.append("unapproved_url")
        return {"findings": findings, "unapproved_hosts": sorted(set(bad_hosts))}
