import re
from typing import Dict, List

class JailbreakDetector:
    """Detect jailbreak patterns"""
    
    JAILBREAK_PATTERNS = {
        "DAN": [
            r"\bDAN\b",
            r"do anything now",
            r"DAN jailbreak",
        ],
        "developer_mode": [
            r"developer mode",
            r"dev mode",
            r"enable developer mode",
            r"activate developer mode",
        ],
        "unrestricted": [
            r"unrestricted AI",
            r"no restrictions",
            r"remove restrictions",
            r"bypass filter",
        ],
        "evil_assistant": [
            r"evil assistant",
            r"bad ai",
            r"unethical ai",
        ]
    }
    
    def detect(self, text: str) -> Dict:
        """
        Detect jailbreak attempts
        
        Return:
        {
            "jailbreak_types": ["DAN", "developer_mode"]
        }
        
        """
        jailbreak_types = []
        text_lower = text.lower()
        
        for jailbreak_type, patterns in self.JAILBREAK_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, text_lower, re.IGNORECASE):
                    jailbreak_types.append(jailbreak_type)
                    break
        
        return {
            "jailbreak_types": jailbreak_types
        }