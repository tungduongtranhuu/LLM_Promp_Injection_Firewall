"""Ingestion: data/corpus/*.md -> scan [0] -> chunks -> vector store.

    python -m app.rag.ingest [--corpus data/corpus] [--chroma data/chroma] [--quarantine quarantine]

Each document is scanned whole in the "document" context and the decision goes
through enforce(). A quarantined document is moved to quarantine/<ts>/ (kept as
evidence, never deleted) and none of its chunks are indexed. Idempotent: a file
whose sha256 is already indexed is skipped.

Audit events: ingest.document_indexed, ingest.document_quarantined.
"""

from __future__ import annotations

import argparse
import hashlib
import re
import shutil
import uuid
from collections.abc import Callable, Sequence
from datetime import datetime, timezone
from pathlib import Path

from pydantic import BaseModel, Field

from app import config
from app.enforcement import enforce
from app.logging.audit import log_scan, utc_timestamp
from app.models import ScanResult
from app.pipeline import scan
from app.rag.store import VectorStore

ScanFn = Callable[[str, str], ScanResult]

MAX_CHUNK_CHARS = 1200
_SECTION = re.compile(r"^(?=##\s)", re.MULTILINE)  # split before each "## " heading
_TITLE = re.compile(r"^#\s+.+$", re.MULTILINE)


class IngestReport(BaseModel):
    indexed: list[str] = Field(default_factory=list)
    unchanged: list[str] = Field(default_factory=list)
    quarantined: list[str] = Field(default_factory=list)
    quarantine_dir: str | None = None
    chunks: int = 0

    def summary(self) -> str:
        line = (
            f"Ingestion : {len(self.indexed)} indexé(s) ({self.chunks} chunks), "
            f"{len(self.unchanged)} inchangé(s), {len(self.quarantined)} en quarantaine"
        )
        if self.quarantined:
            line += f" -> {self.quarantine_dir} : {', '.join(self.quarantined)}"
        return line


def split_markdown(text: str, max_chars: int = MAX_CHUNK_CHARS) -> list[str]:
    """One chunk per "## " section, prefixed with the document title for retrieval.

    The text before the first section (title and introduction) is a chunk too,
    so nothing in the document escapes the retrieval scan. A section longer
    than max_chars is split on blank lines.
    """
    title_match = _TITLE.search(text)
    title = title_match.group(0).strip() if title_match else ""
    chunks: list[str] = []
    for section in _SECTION.split(text):
        section = section.strip()
        if not section:
            continue
        for part in _split_long(section, max_chars):
            if title and not part.startswith(title):
                part = f"{title}\n\n{part}"
            chunks.append(part)
    return chunks


def _split_long(section: str, max_chars: int) -> list[str]:
    if len(section) <= max_chars:
        return [section]
    parts: list[str] = []
    current = ""
    for paragraph in re.split(r"\n\s*\n", section):
        candidate = f"{current}\n\n{paragraph}" if current else paragraph
        if current and len(candidate) > max_chars:
            parts.append(current)
            current = paragraph
        else:
            current = candidate
    if current:
        parts.append(current)
    return parts


def _quarantine_stamp(now: datetime | None = None) -> str:
    return (now or datetime.now(timezone.utc)).strftime("%Y%m%dT%H%M%S%fZ")


def ingest_corpus(
    store: VectorStore,
    corpus_dir: Path | str | None = None,
    quarantine_root: Path | str | None = None,
    *,
    scan_fn: ScanFn = scan,
    request_id: str | None = None,
) -> IngestReport:
    corpus = Path(corpus_dir or config.corpus_path)
    quarantine_dir = Path(quarantine_root or config.quarantine_path) / _quarantine_stamp()
    request_id = request_id or uuid.uuid4().hex
    report = IngestReport()

    for path in sorted(corpus.glob("*.md")):
        doc_id = path.name
        raw = path.read_bytes()
        doc_sha256 = hashlib.sha256(raw).hexdigest()
        if store.document_sha256(doc_id) == doc_sha256:
            report.unchanged.append(doc_id)
            continue

        text = raw.decode("utf-8")
        result = scan_fn(text, "document")
        decision = enforce(result, text, scan_fn=scan_fn)
        if not decision.allowed:
            quarantine_dir.mkdir(parents=True, exist_ok=True)
            target = quarantine_dir / doc_id
            shutil.move(str(path), target)
            # The store mirrors the corpus: an older indexed version leaves with the file.
            store.delete_document(doc_id)
            log_scan(
                "ingest.document_quarantined", result, text, request_id=request_id,
                doc_id=doc_id, doc_sha256=doc_sha256, action=decision.action,
                quarantine_path=str(target),
            )
            report.quarantined.append(doc_id)
            report.quarantine_dir = str(quarantine_dir)
            continue

        chunks = split_markdown(text)
        store.upsert_document(doc_id, doc_sha256, chunks, ingested_at=utc_timestamp())
        log_scan(
            "ingest.document_indexed", result, text, request_id=request_id,
            doc_id=doc_id, doc_sha256=doc_sha256, chunks=len(chunks),
        )
        report.indexed.append(doc_id)
        report.chunks += len(chunks)
    return report


def main(argv: Sequence[str] | None = None) -> int:
    from app.llm.provider import LLMUnavailableError, OllamaProvider

    parser = argparse.ArgumentParser(description="Ingest data/corpus/ into ChromaDB (scan [0]).")
    parser.add_argument("--corpus", default=config.corpus_path)
    parser.add_argument("--chroma", default=config.chroma_path)
    parser.add_argument("--quarantine", default=config.quarantine_path)
    args = parser.parse_args(argv)

    try:
        store = VectorStore(OllamaProvider(), path=args.chroma)
        report = ingest_corpus(store, args.corpus, args.quarantine)
    except LLMUnavailableError as exc:
        print(f"Ollama injoignable ({config.ollama_url}) : {exc}")
        return 1
    print(report.summary())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
