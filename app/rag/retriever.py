"""Retriever: top-k chunks from the store, then scan [3] on each chunk.

Chunks are scanned again at query time even if their document passed the
ingestion scan: an attacker with write access to the corpus or to ChromaDB
(resilience/attack.py --direct) never goes through scan [0].
A chunk that is not ALLOW is dropped from the LLM context (drop_chunk policy)
and logged as retrieval.chunk_flagged; the other chunks are kept.
"""

from __future__ import annotations

from collections.abc import Callable

from pydantic import BaseModel, Field

from app.enforcement import enforce
from app.logging.audit import log_scan
from app.models import ScanResult, StoredChunk
from app.pipeline import scan
from app.rag.store import VectorStore

ScanFn = Callable[[str, str], ScanResult]


class Retrieval(BaseModel):
    kept: list[StoredChunk] = Field(default_factory=list)
    dropped: list[StoredChunk] = Field(default_factory=list)

    @property
    def sources(self) -> list[str]:
        """Distinct doc_ids of the kept chunks, in retrieval order."""
        return list(dict.fromkeys(c.doc_id for c in self.kept))


def retrieve(
    query: str,
    store: VectorStore,
    k: int,
    *,
    request_id: str,
    scan_fn: ScanFn = scan,
) -> Retrieval:
    retrieval = Retrieval()
    for chunk in store.query(query, k):
        result = scan_fn(chunk.text, "retrieved_chunk")
        decision = enforce(result, chunk.text, scan_fn=scan_fn)
        if decision.allowed:
            retrieval.kept.append(chunk)
            continue
        retrieval.dropped.append(chunk)
        log_scan(
            "retrieval.chunk_flagged", result, chunk.text, request_id=request_id,
            doc_id=chunk.doc_id, doc_sha256=chunk.doc_sha256, chunk_id=chunk.chunk_id,
            chunk_index=chunk.chunk_index, chunk_sha256=chunk.chunk_sha256,
            ingested_at=chunk.ingested_at, action=decision.action,
        )
    return retrieval
