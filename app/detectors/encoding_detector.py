import re
import base64
import codecs
import math
from typing import Dict, List, Tuple

class EncodingDetector:
    """
    Expert detector cho encoding patterns + payload analysis
    - Detect encoding patterns: Base64, Hex, ROT13, URL encoding, Unicode escapes
    - Multi-layer decoding
    - Entropy analysis (Task 3.1)
    - Pattern hints (Base64-like, Hex-like, URL-like, Unicode-like)
    
    Consolidation: ALL encoding-related pattern detection in 1 place
        """
    
    def detect(self, text: str) -> Dict:
        """
        Detect encoding types + patterns + entropy
        
        Tasks:
        - Task 3.1: Entropy analysis - Flag obfuscated/encoded payloads
        - Pattern detection: Identify encoding-like patterns
        
        Return:
        {
            "encodings_detected": ["base64"],           # Successfully decoded encodings
            "decoded_payloads": ["ignore previous instructions"],
            "encoding_patterns": ["base64_pattern", "hex_pattern"],  # Pattern hints
            "entropy_score": 4.2,                       # Shannon entropy
            "suspicious": True
        }
        """
        encodings_detected = []      # Only successful decodings
        decoded_payloads = []
        encoding_patterns = []       # Pattern hints
        max_entropy = 0.0
        
        # 1. Multi-layer decoding attempts (ACTUAL decodings)
        decode_attempts = self._multi_layer_decode(text)
        
        for encoding_type, decoded_text in decode_attempts:
            if decoded_text and decoded_text != text:
                encodings_detected.append(encoding_type)
                decoded_payloads.append(decoded_text)
        
        # 2. Detect encoding patterns (hints, not actual decoding)
        encoding_patterns = self._detect_encoding_patterns(text)
        
        # 3. Entropy analysis (Task 3.1)
        entropy = self._calculate_entropy(text)
        max_entropy = entropy  # Always track entropy
        
        # Remove duplicates
        encodings_detected = list(set(encodings_detected))
        decoded_payloads = list(set(decoded_payloads))
        encoding_patterns = list(set(encoding_patterns))
        
        return {
            "encodings_detected": encodings_detected,
            "decoded_payloads": decoded_payloads,
            "encoding_patterns": encoding_patterns,
            "entropy_score": round(max_entropy, 2),
            "suspicious": len(encodings_detected) > 0 or len(encoding_patterns) > 0 or max_entropy > 4.5
        }
    
    
    def _multi_layer_decode(self, text: str) -> List[Tuple[str, str]]:
        """
        Try decode text with single-pass decoders (no recursion)
        
        Return: [("base64", decoded_text), ("hex", decoded_text), ...]
        """
        results = []
        
        # 1. Try Base64 (1 time only)
        decoded_b64 = self._try_base64_decode(text)
        if decoded_b64 and decoded_b64 != text and self._is_valid_decoded(decoded_b64):
            results.append(("base64", decoded_b64))
        
        # 2. Try Hex
        decoded_hex = self._try_hex_decode(text)
        if decoded_hex and decoded_hex != text and self._is_valid_decoded(decoded_hex):
            results.append(("hex", decoded_hex))
        
        # 3. Try ROT13 (only if text looks like ROT13)
        if self._might_be_rot13(text):
            decoded_rot13 = self._try_rot13_decode(text)
            if decoded_rot13 and decoded_rot13 != text and self._is_valid_decoded(decoded_rot13):
                results.append(("rot13", decoded_rot13))
        
        # 4. Try URL encoding
        if re.search(r'%[0-9A-Fa-f]{2}', text):
            decoded_url = self._try_url_decode(text)
            if decoded_url and decoded_url != text and self._is_valid_decoded(decoded_url):
                results.append(("url_encoded", decoded_url))
        
        # 5. Try Unicode escapes
        if re.search(r'\\u[0-9a-fA-F]{4}|\\x[0-9a-fA-F]{2}', text):
            decoded_unicode = self._try_unicode_decode(text)
            if decoded_unicode and decoded_unicode != text and self._is_valid_decoded(decoded_unicode):
                results.append(("unicode_escaped", decoded_unicode))
        
        return results
    
    def _is_valid_decoded(self, text: str) -> bool:
        """
        Check if decoded text is valid (not gibberish)
        Used for Hex, URL, Unicode decodings
        """
        if not text or len(text) < 3:
            return False
        
        printable_count = sum(1 for c in text if c.isprintable())
        printable_ratio = printable_count / len(text)
        
        if printable_ratio < 0.7:
            return False
        
        digit_ratio = sum(1 for c in text if c.isdigit()) / len(text)
        if digit_ratio > 0.6:
            return False
        
        return True
    
    def _might_be_rot13(self, text: str) -> bool:
        """
        Heuristic: check if text might be ROT13 encoded
        
        ROT13 is only useful if:
        - Input contains mostly letters (>60%)
        - NOT already looks like base64/hex
        - Does NOT contain spaces/punctuation (normal text indicator)
        """
        # Skip if already looks like base64 or hex
        if self._looks_like_base64(text) or self._looks_like_hex(text):
            return False
        
        # Skip if contains spaces or punctuation - indicates normal text
        if ' ' in text or any(c in text for c in ',.!?;:'):
            return False
        
        # Check if mostly letters (ROT13 only affects letters)
        letter_ratio = sum(1 for c in text if c.isalpha()) / max(len(text), 1)
        
        return letter_ratio > 0.6  # At least 60% letters
    
    def _looks_like_base64(self, text: str) -> bool:
        """Check if text looks like Base64 encoding"""
        return bool(re.search(r'[A-Za-z0-9+/]{20,}={0,2}', text))
    
    def _looks_like_hex(self, text: str) -> bool:
        """Check if text looks like Hex encoding"""
        return bool(re.search(r'0x[0-9a-fA-F]{8,}|[0-9a-fA-F]{30,}', text))
    
    
    def _try_base64_decode(self, text: str) -> str:
        """Try decode base64"""
        try:
            # Filter out non-base64 chars and check length
            if not re.search(r'^[A-Za-z0-9+/]*={0,2}$', text.strip()):
                return None
            
            decoded = base64.b64decode(text.strip()).decode('utf-8', errors='ignore')
            
            # Validate: decoded should be printable
            if len(decoded) > 0 and decoded.isprintable():
                return decoded
        except Exception:
            pass
        
        return None
    
    def _try_hex_decode(self, text: str) -> str:
        """Try decode hex"""
        try:
            # Remove spaces
            hex_str = text.replace(" ", "").replace("0x", "")
            
            # Check if valid hex
            if not re.match(r'^[0-9a-fA-F]+$', hex_str):
                return None
            
            # Decode
            decoded = bytes.fromhex(hex_str).decode('utf-8', errors='ignore')
            
            if len(decoded) > 0 and decoded.isprintable():
                return decoded
        except Exception:
            pass
        
        return None
    
    def _try_rot13_decode(self, text: str) -> str:
        """Try decode ROT13"""
        try:
            decoded = codecs.decode(text, 'rot_13')
            
            # Check if actually changed
            if decoded != text and decoded.isprintable():
                return decoded
        except Exception:
            pass
        
        return None
    
    def _try_url_decode(self, text: str) -> str:
        """Try decode URL encoding (%20, %2F, etc.)"""
        try:
            from urllib.parse import unquote
            
            decoded = unquote(text)
            
            if decoded != text and decoded.isprintable():
                return decoded
        except Exception:
            pass
        
        return None
    
    def _try_unicode_decode(self, text: str) -> str:
        """Try decode Unicode escapes (\\u0000, \\x00)"""
        try:
            # Pattern: \u0000 hoặc \x00
            decoded = text.encode().decode('unicode-escape')
            
            if decoded != text and decoded.isprintable():
                return decoded
        except Exception:
            pass
        
        return None

    def _detect_encoding_patterns(self, text: str) -> List[str]:
        """
        Detect encoding-like PATTERNS (hints, not actual decoding)
        
        Used by downstream detectors to identify: normal text + encoding patterns
        
        Returns list of detected patterns:
        - "base64_pattern": Text looks like Base64
        - "hex_pattern": Text looks like Hex
        - "url_encoded_pattern": Text looks like URL-encoded
        - "unicode_escaped_pattern": Text has Unicode escapes
        """
        patterns = []
        
        # 1. Base64-like pattern (long alphanumeric + / + =)
        if re.search(r'[A-Za-z0-9+/]{20,}={0,2}', text):
            patterns.append("base64_pattern")
        
        # 2. Hex pattern (0x prefix or long hex strings - 30+ to avoid false positives)
        if re.search(r'0x[0-9a-fA-F]{8,}|[0-9a-fA-F]{30,}', text):
            patterns.append("hex_pattern")
        
        # 3. URL encoding pattern (%2F, %20, etc.)
        if re.search(r'%[0-9A-Fa-f]{2}', text):
            patterns.append("url_encoded_pattern")
        
        # 4. Unicode escape pattern (\u or \x)
        if re.search(r'\\[ux][0-9a-fA-F]{2,4}', text):
            patterns.append("unicode_escaped_pattern")
        
        return patterns

    def _calculate_entropy(self, text: str) -> float:
        if not text:
            return 0.0
        
        # Count character frequencies
        freq = {}
        for char in text:
            freq[char] = freq.get(char, 0) + 1
        
        # Calculate entropy
        entropy = 0.0
        text_len = len(text)
        
        for count in freq.values():
            p = count / text_len
            entropy -= p * math.log2(p)
        
        return entropy

