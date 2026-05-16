import re
from typing import List, Dict

class RegexDetector:
    """Detector that uses regular expressions to identify risky content in messages."""
    # Attack patterns's dictionnary
    PATTERN = {
        "prompt_override" : [
            r"ignore\s+previous\s+instructions",
            r"forget\s+(about|the)\s+above",
            r"disregard\s+(the\s+)?(above|previous)",
            r"forget\s+everything\s+you\s+(were|know)",
        ],
        "extraction": [
            r"(reveal|show|tell\s+me|print)(\s+me)?\s+(the\s+)?system\s+prompt",
            r"what\s+was\s+i\s+instructed",
            r"what\s+are\s+your\s+instructions",
            r"hidden\s+prompt",
        ],
        "role_switching": [
            r"you\s+are\s+now",
            r"pretend\s+you\s+are",
            r"act\s+as",
            r"from\s+now\s+on",
        ]
    }

    def detect(self, text: str) -> Dict[str, List[str]]:
        """
        Scan text for patterns
        
        Return:
        {
            "matches": ["prompt_override", "extraction"]
        }
        
        """
        matches = []
        text_lower = text.lower()
        for attack_type, patterns in self.PATTERN.items():
            for pattern in patterns:
                if re.search(pattern, text_lower):
                    matches.append(attack_type)
                    break  # No need to check other patterns of the same type
        
        return {
            "matches": matches
        }
