"""
Configuration Management

Loads environment variables for API keys, threshold overrides and logging.
Uses python-dotenv for local development, environment variables for production.

Scoring numbers (weights, thresholds) are defined only in app/scoring/rules.py.
This module may override thresholds from the environment, but its defaults
always come from ScoringRules so there is never a second copy of the numbers.
"""

import os

from dotenv import load_dotenv

from app.scoring.rules import ScoringRules

# Load environment variables from .env file (if exists)
load_dotenv()

# ========== LLM API Configuration ==========
api_key = os.getenv("GEMINI_API_KEY", "")
llm_model = os.getenv("LLM_MODEL", "gemini-pro")

# ========== Security Thresholds (env overrides of ScoringRules) ==========
block_threshold = int(os.getenv("BLOCK_THRESHOLD", ScoringRules.BLOCK_THRESHOLD))
warn_threshold = int(os.getenv("WARN_THRESHOLD", ScoringRules.WARN_THRESHOLD))

# ========== Logging Configuration ==========
log_level = os.getenv("LOG_LEVEL", "INFO")
log_file = os.getenv("LOG_FILE", "logs/firewall.log")
audit_log_path = os.getenv("AUDIT_LOG_PATH", "logs/firewall.jsonl")  # JSONL contract with the SIEM


# ========== Helper Functions ==========
def is_secure_api_key() -> bool:
    """Check if API key is configured"""
    return len(api_key) > 0
