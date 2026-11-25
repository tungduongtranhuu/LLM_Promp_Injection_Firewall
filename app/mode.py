"""RAG_MODE: the running mode of the assistant, switchable at runtime.

- normal      : full chain [1] -> [2][3] -> LLM -> [4].
- degraded    : no retrieval (knowledge base not trusted or being restored);
                the LLM gives general advice only, [1] and [4] still apply.
- maintenance : /chat answers 503 without calling the LLM; prompts are still scanned and logged.

The initial value comes from the RAG_MODE env var (config.rag_mode).
resilience/contain.py and /admin/mode (P4) switch it with set_mode().
"""

from __future__ import annotations

from typing import cast, get_args

from app import config
from app.models import RagMode

MODES: tuple[str, ...] = get_args(RagMode)  # ("normal", "degraded", "maintenance")


def validate(mode: str) -> RagMode:
    if mode not in MODES:
        raise ValueError(f"unknown RAG_MODE {mode!r}; expected one of {MODES}")
    return cast(RagMode, mode)


_current: RagMode = validate(config.rag_mode)


def get_mode() -> RagMode:
    return _current


def set_mode(mode: str) -> RagMode:
    """Switch the mode and return the previous one. ValueError on an unknown mode."""
    global _current
    previous, _current = _current, validate(mode)
    return previous
