"""Shared fixtures for the RAG tests: no Ollama, no real data/ directories.

FakeProvider stands in for OllamaProvider: deterministic bag-of-words
embeddings (so similar texts are close) and a scripted chat answer.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
from collections.abc import Callable, Sequence
from pathlib import Path

import pytest

from app import config
from app.llm.provider import LLMUnavailableError, Message
from app.rag.store import VectorStore

DIM = 256
_WORD = re.compile(r"\w+")


def bag_of_words(text: str) -> list[float]:
    vector = [0.0] * DIM
    for word in _WORD.findall(text.lower()):
        if len(word) > 2:
            vector[int(hashlib.md5(word.encode()).hexdigest(), 16) % DIM] += 1.0
    norm = math.sqrt(sum(v * v for v in vector)) or 1.0
    return [v / norm for v in vector] if any(vector) else [1.0 / math.sqrt(DIM)] * DIM


class FakeProvider:
    """Records every chat call; `answer` is a string or a function of the messages."""

    def __init__(self, answer: str | Callable[[Sequence[Message]], str] = "Réponse de test.") -> None:
        self.answer = answer
        self.calls: list[list[Message]] = []
        self.fail = False

    def chat(self, messages: Sequence[Message]) -> str:
        if self.fail:
            raise LLMUnavailableError("fake outage")
        self.calls.append(list(messages))
        return self.answer(messages) if callable(self.answer) else self.answer

    def embed_documents(self, texts: Sequence[str]) -> list[list[float]]:
        if self.fail:
            raise LLMUnavailableError("fake outage")
        return [bag_of_words(t) for t in texts]

    def embed_query(self, text: str) -> list[float]:
        if self.fail:
            raise LLMUnavailableError("fake outage")
        return bag_of_words(text)

    def ping(self) -> bool:
        return not self.fail

    def prompt_text(self) -> str:
        """Everything sent to the LLM in the last call."""
        return "\n".join(m["content"] for m in self.calls[-1])


@pytest.fixture
def provider() -> FakeProvider:
    return FakeProvider()


@pytest.fixture
def store(tmp_path: Path, provider: FakeProvider) -> VectorStore:
    return VectorStore(provider, path=tmp_path / "chroma", collection="test_kb")


@pytest.fixture
def audit_log(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    path = tmp_path / "logs" / "firewall.jsonl"
    monkeypatch.setattr(config, "audit_log_path", str(path))
    return path


@pytest.fixture
def corpus(tmp_path: Path) -> Path:
    """A copy of the real Acme corpus, safe to modify."""
    source = Path(__file__).resolve().parent.parent / "data" / "corpus"
    target = tmp_path / "corpus"
    target.mkdir()
    for doc in source.glob("*.md"):
        (target / doc.name).write_bytes(doc.read_bytes())
    return target


@pytest.fixture
def client(provider: FakeProvider, store: VectorStore, audit_log: Path):
    """TestClient wired to the fake provider and the tmp_path store (never Ollama, never data/)."""
    from fastapi.testclient import TestClient

    from app.api.routes import get_provider, get_store
    from app.main import app

    app.dependency_overrides[get_provider] = lambda: provider
    app.dependency_overrides[get_store] = lambda: store
    try:
        yield TestClient(app)
    finally:
        app.dependency_overrides.clear()


@pytest.fixture
def events(audit_log: Path) -> Callable[..., list[dict]]:
    """events() -> every audit event; events("x.y") -> only that event_type."""

    def read(event_type: str | None = None) -> list[dict]:
        if not audit_log.exists():
            return []
        lines = [json.loads(line) for line in audit_log.read_text(encoding="utf-8").splitlines()]
        return [e for e in lines if event_type is None or e["event_type"] == event_type]

    return read
