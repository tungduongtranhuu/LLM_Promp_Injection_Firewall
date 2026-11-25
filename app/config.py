"""
Configuration Management

Loads environment variables for the LLM provider, RAG paths, threshold overrides
and logging. Uses python-dotenv for local development, environment variables otherwise.

Scoring numbers (weights, thresholds) are defined only in app/scoring/rules.py.
This module may override thresholds from the environment, but its defaults
always come from ScoringRules so there is never a second copy of the numbers.
"""

import os

from dotenv import load_dotenv

from app.scoring.rules import ScoringRules

# Load environment variables from .env file (if exists)
load_dotenv()

# ========== LLM provider: Ollama on the host (WSL), never in docker-compose ==========
ollama_url = os.getenv("OLLAMA_URL", "http://localhost:11434").rstrip("/")
ollama_model = os.getenv("OLLAMA_MODEL", "qwen2.5:3b")
ollama_embed_model = os.getenv("OLLAMA_EMBED_MODEL", "nomic-embed-text")
llm_timeout = float(os.getenv("LLM_TIMEOUT", "120"))

# ========== RAG ==========
RAG_MODES = ("normal", "degraded", "maintenance")
rag_mode = os.getenv("RAG_MODE", "normal")
rag_top_k = int(os.getenv("RAG_TOP_K", "4"))
corpus_path = os.getenv("CORPUS_PATH", "data/corpus")
chroma_path = os.getenv("CHROMA_PATH", "data/chroma")
chroma_collection = os.getenv("CHROMA_COLLECTION", "acme_kb")
quarantine_path = os.getenv("QUARANTINE_PATH", "quarantine")

# ========== Security Thresholds (env overrides of ScoringRules) ==========
block_threshold = int(os.getenv("BLOCK_THRESHOLD", ScoringRules.BLOCK_THRESHOLD))
warn_threshold = int(os.getenv("WARN_THRESHOLD", ScoringRules.WARN_THRESHOLD))

# ========== Logging Configuration ==========
log_level = os.getenv("LOG_LEVEL", "INFO")
audit_log_path = os.getenv("AUDIT_LOG_PATH", "logs/firewall.jsonl")  # JSONL contract with the SIEM
