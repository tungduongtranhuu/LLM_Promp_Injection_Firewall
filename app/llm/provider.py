"""LLM provider: chat completion and embeddings.

The RAG code depends only on the LLMProvider protocol, so tests use a fake
provider and never need Ollama. OllamaProvider talks to the Ollama HTTP API
on the host (OLLAMA_URL, default http://localhost:11434) with plain httpx.
"""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path
from typing import Literal, Protocol, TypedDict

import httpx

from app import config

SYSTEM_PROMPT_PATH = Path(__file__).resolve().parent / "system_prompt.md"


class Message(TypedDict):
    role: Literal["system", "user", "assistant"]
    content: str


class LLMUnavailableError(RuntimeError):
    """The LLM backend cannot be reached or returned an unusable answer."""


class LLMProvider(Protocol):
    def chat(self, messages: Sequence[Message]) -> str: ...

    def embed_documents(self, texts: Sequence[str]) -> list[list[float]]: ...

    def embed_query(self, text: str) -> list[float]: ...

    def ping(self) -> bool: ...


def load_system_prompt(path: Path = SYSTEM_PROMPT_PATH) -> str:
    """The system prompt lives in a file so resilience/backup.py can snapshot it."""
    return path.read_text(encoding="utf-8").strip()


class OllamaProvider:
    """Ollama HTTP API: POST /api/chat and POST /api/embed.

    nomic-embed-text was trained with task prefixes: documents are embedded
    as "search_document: ..." and questions as "search_query: ...".
    """

    DOCUMENT_PREFIX = "search_document: "
    QUERY_PREFIX = "search_query: "

    def __init__(
        self,
        base_url: str | None = None,
        model: str | None = None,
        embed_model: str | None = None,
        timeout: float | None = None,
        client: httpx.Client | None = None,
    ) -> None:
        self.base_url = (base_url or config.ollama_url).rstrip("/")
        self.model = model or config.ollama_model
        self.embed_model = embed_model or config.ollama_embed_model
        self.client = client or httpx.Client(
            base_url=self.base_url, timeout=timeout or config.llm_timeout
        )

    def _post(self, path: str, payload: dict) -> dict:
        try:
            response = self.client.post(path, json=payload)
            response.raise_for_status()
            return response.json()
        except (httpx.HTTPError, ValueError) as exc:
            raise LLMUnavailableError(f"Ollama {path} failed: {exc}") from exc

    def chat(self, messages: Sequence[Message]) -> str:
        data = self._post(
            "/api/chat",
            {
                "model": self.model,
                "messages": list(messages),
                "stream": False,
                "options": {"temperature": 0},  # reproducible answers for the golden set
            },
        )
        content = (data.get("message") or {}).get("content")
        if not isinstance(content, str):
            raise LLMUnavailableError("Ollama /api/chat returned no message content")
        return content

    def _embed(self, texts: Sequence[str]) -> list[list[float]]:
        if not texts:
            return []
        data = self._post("/api/embed", {"model": self.embed_model, "input": list(texts)})
        embeddings = data.get("embeddings")
        if not isinstance(embeddings, list) or len(embeddings) != len(texts):
            raise LLMUnavailableError("Ollama /api/embed returned an unexpected number of embeddings")
        return embeddings

    def embed_documents(self, texts: Sequence[str]) -> list[list[float]]:
        return self._embed([self.DOCUMENT_PREFIX + t for t in texts])

    def embed_query(self, text: str) -> list[float]:
        return self._embed([self.QUERY_PREFIX + text])[0]

    def ping(self) -> bool:
        try:
            return self.client.get("/api/tags", timeout=3).status_code == 200
        except httpx.HTTPError:
            return False
