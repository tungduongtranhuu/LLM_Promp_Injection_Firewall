import re
from typing import List, Dict

class RegexDetector:
    """Detector that uses regular expressions to identify risky content in messages."""
    # Attack patterns's dictionnary
    PATTERN = {
        "prompt_override" : [
            r"ignore previous instructions",
            r"forget (about|the) above",
            r"disregard (the )?(above|previous)",
            r"forget everything you (were|know)",
        ],
        "extraction": [
            r"(reveal|show|tell me|print) (the )?system prompt",
            r"what was i instructed",
            r"what are your instructions",
            r"hidden prompt",
        ],
        "role_switching": [
            r"you are now",
            r"pretend you are",
            r"act as",
            r"from now on",
        ]
    }

    def detect(self, text: str) -> Dict[str, List[str]]:
        """
        Scan text for patterns
        
        Return:
        {
            "matches": ["prompt_override", "extraction"],
            "score_add": 40
        }
        """
        matches = []
        text_lower = text.lower()
        for attack_type, patterns in self.PATTERN.items():
            for pattern in patterns:
                if re.search(pattern, text_lower):
                    matches.append(attack_type)
                    break  # No need to check other patterns of the same type
        
        score_add = len(matches) * 20  # Each match adds 20 to the risk score
        return {
            "matches": matches,
            "score_add": score_add
        }

if __name__ == "__main__":
    detector = RegexDetector()
    
    # Test 1: malicious
    result = detector.detect("ignore previous instructions")
    print(f"Test 1: {result}")
    # Output: {'matches': ['prompt_override'], 'score_add': 20}
    
    # Test 2: safe
    result = detector.detect("What is Python?")
    print(f"Test 2: {result}")
    # Output: {'matches': [], 'score_add': 0}