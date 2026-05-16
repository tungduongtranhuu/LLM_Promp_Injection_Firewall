"""
Configuration Management

Loads environment variables for API keys, security thresholds, and logging.
Uses python-dotenv for local development, environment variables for production.
"""

import os
from dotenv import load_dotenv

# Load environment variables from .env file (if exists)
load_dotenv()

# ========== LLM API Configuration ==========
api_key = os.getenv("GEMINI_API_KEY", "")
llm_model = os.getenv("LLM_MODEL", "gemini-pro")

# ========== Security Thresholds ==========
# Risk Score Ranges:
#   0-30: LOW (ALLOW)
#   31-49: MEDIUM (WARN)
#   50-100: HIGH (BLOCK)

block_threshold = int(os.getenv("BLOCK_THRESHOLD", 50))    # Block if score >= 50
warn_threshold = int(os.getenv("WARN_THRESHOLD", 31))      # Warn if score >= 31

# ========== Logging Configuration ==========
log_level = os.getenv("LOG_LEVEL", "INFO")
log_file = os.getenv("LOG_FILE", "logs/firewall.log")

# ========== Optional: Custom Scoring Weights ==========
# These can be used to customize scoring behavior per environment
custom_encoding_weight = float(os.getenv("ENCODING_WEIGHT", 1.0))
custom_heuristic_weight = float(os.getenv("HEURISTIC_WEIGHT", 1.0))
custom_regex_weight = float(os.getenv("REGEX_WEIGHT", 1.0))
custom_jailbreak_weight = float(os.getenv("JAILBREAK_WEIGHT", 1.0))


# ========== Helper Functions ==========
def is_secure_api_key() -> bool:
    """Check if API key is configured"""
    return len(api_key) > 0


def get_risk_action(score: float) -> str:
    """Get security action based on risk score"""
    if score >= block_threshold:
        return "BLOCK"
    elif score >= warn_threshold:
        return "WARN"
    else:
        return "ALLOW"


