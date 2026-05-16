import unicodedata
import re
from typing import Dict, List

class HeuristicDetector:
    """
    Detect structural anomalies:
    - Abnormal length (>2000 chars) 
    - Repeated characters (>8 in 10-char window)
    - Nested formatting (markdown, XML, JSON) 
    - Unicode mixing (PURE multi-script only)
    - Language switching (normal + encoding patterns/commands/scripts)
    """
    
    def detect(self, text: str) -> Dict:
        """
        Detect heuristic anomalies
        
        Return:
        {
            "anomalies": ["unicode_mixing", "excessive_length", "repeated_chars", 
                         "nested_formatting", "language_switching"]
        }
        
        """
        anomalies = []
 
        if len(text) > 2000:
            anomalies.append("excessive_length")
        
        # 2. Repeated characters (>8 in 10-char window)
        if self._has_excessive_repetition(text):
            anomalies.append("repeated_chars")
        
        # Task 3.3: Nested formatting detection
        # 3. Markdown fences, XML tags, JSON nesting
        if self._has_suspicious_nesting(text):
            anomalies.append("nested_formatting")
        
        # 4. Unicode mixing (Latin + Cyrillic, etc.)
        if self._has_suspicious_unicode(text):
            anomalies.append("unicode_mixing")
        
        # Task 3.4: Language switching detection
        # 5. Suspicious language/script switching
        if self._has_language_switching(text):
            anomalies.append("language_switching")
        
        return {
            "anomalies": list(set(anomalies))  
        }
    
    def _has_suspicious_unicode(self, text: str) -> bool:
        """
        Check if there's PURE suspicious unicode mixing (multiple non-Latin scripts).
         
        Examples:
        - "Привет世界" (Russian + Chinese, no English) → TRUE (unicode_mixing)
        - "Hello привет" (English + Russian) → FALSE (this is language_switching, not pure unicode_mixing)
        """
        scripts = set()
        non_ascii_chars = 0
        total_chars = len(text)
        
        for char in text:
            if ord(char) < 128:  # ASCII
                continue
            
            non_ascii_chars += 1
            name = unicodedata.name(char, "UNKNOWN")
            
            # Detect script types (non-Latin)
            if "CYRILLIC" in name:
                scripts.add("CYRILLIC")
            elif "GREEK" in name:
                scripts.add("GREEK")
            elif "ARABIC" in name:
                scripts.add("ARABIC")
            elif "HEBREW" in name:
                scripts.add("HEBREW")
            elif "CJK" in name or "HIRAGANA" in name or "KATAKANA" in name:
                scripts.add("CJK")
        
  
        non_ascii_ratio = non_ascii_chars / max(total_chars, 1)
        
        return len(scripts) >= 2 and non_ascii_ratio > 0.7
    
    def _has_excessive_repetition(self, text: str) -> bool:
        """Check if there are excessive repeated characters"""
        for i in range(len(text) - 10):
            char = text[i]
            if text[i:i+10].count(char) >= 8:  
                return True
        return False
    
    def _has_suspicious_nesting(self, text: str) -> List[str]:
        """
        Detect nested formatting that could hide malicious content
        - Markdown fences (```code```)
        - XML/HTML tags (<tag>)
        - JSON nesting ({...})
        - Deep nesting levels
        """
        nesting_indicators = []
        
        # 1. Markdown code fences (``` ``` or ~~strikethrough~~)
        if re.search(r'```[^`]*```', text, re.DOTALL):
            nesting_indicators.append("markdown_code_fence")
        
        # 2. Markdown with special formatting (**, __, [], ())
        if re.search(r'\*{2,}|_{2,}|\[.+?\]\(.+?\)', text):
            nesting_indicators.append("markdown_formatting")
        
        # 3. XML/HTML tags
        if re.search(r'<[^>]+>[^<]*</[^>]+>', text):
            nesting_indicators.append("xml_nesting")
        
        # 4. JSON-like nesting (curly braces with content)
        if self._has_json_nesting(text):
            nesting_indicators.append("json_nesting")
        
        # 5. Deep parenthesis nesting (more than 3 levels)
        if self._has_deep_parenthesis_nesting(text):
            nesting_indicators.append("deep_nesting")
        
        return len(nesting_indicators) > 0
    
    def _has_json_nesting(self, text: str) -> bool:
        """Check if text has JSON-like nesting patterns"""
        # Simple heuristic: count open/close braces
        # If balanced and >3 levels, suspicious
        max_depth = 0
        current_depth = 0
        
        for char in text:
            if char == '{' or char == '[':
                current_depth += 1
                max_depth = max(max_depth, current_depth)
            elif char == '}' or char == ']':
                current_depth -= 1
        
        # Suspicious if deep nesting (>3 levels) with balanced braces
        return max_depth >= 3 and current_depth == 0
    
    def _has_deep_parenthesis_nesting(self, text: str) -> bool:
        """Check for deep parenthesis nesting (3+ levels)"""
        max_depth = 0
        current_depth = 0
        
        for char in text:
            if char == '(' or char == '[' or char == '{':
                current_depth += 1
                max_depth = max(max_depth, current_depth)
            elif char == ')' or char == ']' or char == '}':
                current_depth -= 1
        
        return max_depth >= 3
    
    def _has_language_switching(self, text: str) -> bool:
        """
        Task 3.4: Detect suspicious language/script switching.
        
        FIX for overlap: This detects mixing of (normal text + suspicious patterns).
        Examples of suspicious patterns:
        1. Encoding hints (Base64, Hex, URL-encoded)
        2. Command syntax (Python, SQL, Shell)
        3. Script mixing with normal text (English + non-Latin scripts)
        
        Examples:
        - "Hello world aWdub3JlIA==" → TRUE (normal + encoding)
        - "Execute: import sys" → TRUE (normal + command)
        - "Hello привет" → TRUE (normal + Cyrillic)
        - "Привет世界" → FALSE (pure multi-script, not language_switching)
        - "What is Python?" → FALSE (pure normal text)
        """
        # Check for suspicious mixing patterns
        
        # 1. Normal text + suspicious patterns in same message
        has_normal_text = self._has_normal_language(text)
        has_encoding_patterns = self._check_for_encoding_patterns(text)
        has_command_syntax = self._has_command_syntax(text)
        has_script_mixing = self._has_script_mixing_with_normal(text)  # Checks: normal + non-Latin scripts
        
        # Suspicious if mixing normal + ANY of the above
        if has_normal_text:
            if has_encoding_patterns or has_command_syntax or has_script_mixing:
                return True
        
        return False
    
    def _check_for_encoding_patterns(self, text: str) -> bool:
        """
        Check if text has encoding-like PATTERNS (hints, not actual decoding)
        
        NOTE: Actual encoding detection & decoding is in encoding_detector.py
        This just checks if text LOOKS LIKE it might be encoded
        """
        # Base64-like pattern
        if re.search(r'[A-Za-z0-9+/]{20,}={0,2}', text):
            return True
        
        # Hex pattern (0x prefix or long hex strings)
        if re.search(r'0x[0-9a-fA-F]{8,}|[0-9a-fA-F]{20,}', text):
            return True
        
        # URL encoding pattern
        if re.search(r'%[0-9A-Fa-f]{2}', text):
            return True
        
        # Unicode escape sequences
        if re.search(r'\\[ux][0-9a-fA-F]{2,4}', text):
            return True
        
        return False
    
    def _has_script_mixing_with_normal(self, text: str) -> bool:
        """
        Check if text has mixing of normal (ASCII/Latin) + non-Latin scripts.
        
        This is different from pure unicode_mixing:
        - "Hello привет" → TRUE (normal + Cyrillic)
        - "Привет世界" → FALSE (pure non-Latin, no normal text)
        """
        has_ascii_text = False
        has_non_latin_script = False
        
        for char in text:
            if ord(char) < 128:  # ASCII
                has_ascii_text = True
                continue
            
            name = unicodedata.name(char, "UNKNOWN")
            
            # Check for non-Latin scripts
            if "CYRILLIC" in name or "GREEK" in name or "ARABIC" in name or \
               "HEBREW" in name or "CJK" in name or "HIRAGANA" in name or "KATAKANA" in name:
                has_non_latin_script = True
        
        # Suspicious if mixing normal text + non-Latin scripts
        return has_ascii_text and has_non_latin_script
    
    def _has_normal_language(self, text: str) -> bool:
        """Check if text contains normal language words"""
        # Simple heuristic: contains spaces + letters + some length
        if len(text) < 10:
            return False
        
        # Check for word patterns (letter sequences separated by spaces)
        words = text.split()
        normal_words = [w for w in words if len(w) > 2 and w.isalpha()]
        
        return len(normal_words) > 0
    
    def _has_command_syntax(self, text: str) -> bool:
        """Check for command/code syntax patterns"""
        # Shell commands
        if re.search(r'(bash|sh|cmd|exec|system|eval|import|execute)\s*\(', text, re.IGNORECASE):
            return True
        
        # Python-like syntax
        if re.search(r'(import|from|def|class|lambda|exec|eval)\s+', text, re.IGNORECASE):
            return True
        
        # SQL-like syntax
        if re.search(r'(SELECT|INSERT|DELETE|UPDATE|DROP)\s+', text, re.IGNORECASE):
            return True
        
        # Common injection markers
        if re.search(r"('\s*OR\s*'|;\s*(DROP|DELETE|INSERT))", text, re.IGNORECASE):
            return True
        
        return False
