"""Vector store: ChromaDB on disk (data/chroma/) with our own embeddings.

Embeddings come from an Embedder (OllamaProvider in production, a fake in
tests), so Chroma never downloads its default ONNX model. Every chunk carries
doc_id, doc_sha256 (sha256 of the whole source file), chunk_index,
chunk_sha256 and ingested_at, which the investigation (P4) relies on.
"""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path
from typing import Any, Protocol

import chromadb

from app import config
from app.logging.audit import sha256_hex, utc_timestamp
from app.models import StoredChunk


class Embedder(Protocol):
    def embed_documents(self, texts: Sequence[str]) -> list[list[float]]: ...

    def embed_query(self, text: str) -> list[float]: ...


def chunk_id(doc_id: str, index: int) -> str:
    return f"{doc_id}#{index}"


def _to_chunk(chunk_id_: str, text: str, meta: dict[str, Any], distance: float | None = None) -> StoredChunk:
    return StoredChunk(
        chunk_id=chunk_id_,
        doc_id=meta["doc_id"],
        doc_sha256=meta["doc_sha256"],
        chunk_index=meta["chunk_index"],
        chunk_sha256=meta["chunk_sha256"],
        ingested_at=meta["ingested_at"],
        text=text,
        distance=distance,
    )


class VectorStore:
    def __init__(
        self,
        embedder: Embedder,
        path: Path | str | None = None,
        collection: str | None = None,
    ) -> None:
        self.embedder = embedder
        self.path = Path(path or config.chroma_path)
        self.path.mkdir(parents=True, exist_ok=True)
        client = chromadb.PersistentClient(
            path=str(self.path), settings=chromadb.Settings(anonymized_telemetry=False)
        )
        self._collection = client.get_or_create_collection(
            collection or config.chroma_collection,
            embedding_function=None,
            metadata={"hnsw:space": "cosine"},
        )

    # ------------------------------------------------------------------ writes
    def upsert_document(
        self,
        doc_id: str,
        doc_sha256: str,
        chunks: Sequence[str],
        ingested_at: str | None = None,
    ) -> list[str]:
        """Replace every chunk of doc_id with `chunks`. Returns the chunk ids.

        Embeddings are computed first: if the embedder fails, the indexed
        version of the document is left untouched.
        """
        embeddings = self.embedder.embed_documents(chunks) if chunks else []
        self.delete_document(doc_id)
        if not chunks:
            return []
        ingested_at = ingested_at or utc_timestamp()
        ids = [chunk_id(doc_id, i) for i in range(len(chunks))]
        self._collection.add(
            ids=ids,
            documents=list(chunks),
            embeddings=embeddings,
            metadatas=[
                {
                    "doc_id": doc_id,
                    "doc_sha256": doc_sha256,
                    "chunk_index": i,
                    "chunk_sha256": sha256_hex(text),
                    "ingested_at": ingested_at,
                }
                for i, text in enumerate(chunks)
            ],
        )
        return ids

    def delete_document(self, doc_id: str) -> None:
        self._collection.delete(where={"doc_id": doc_id})

    # ------------------------------------------------------------------ reads
    def count(self) -> int:
        return self._collection.count()

    def document_sha256(self, doc_id: str) -> str | None:
        """sha256 of the indexed version of doc_id, or None if it is not indexed."""
        got = self._collection.get(where={"doc_id": doc_id}, limit=1, include=["metadatas"])
        return got["metadatas"][0]["doc_sha256"] if got["ids"] else None

    def doc_ids(self) -> list[str]:
        got = self._collection.get(include=["metadatas"])
        return sorted({m["doc_id"] for m in got["metadatas"]})

    def all_chunks(self) -> list[StoredChunk]:
        got = self._collection.get(include=["documents", "metadatas"])
        chunks = [_to_chunk(i, d, m) for i, d, m in zip(got["ids"], got["documents"], got["metadatas"])]
        return sorted(chunks, key=lambda c: (c.doc_id, c.chunk_index))

    def query(self, text: str, k: int) -> list[StoredChunk]:
        """The k chunks closest to `text`, nearest first."""
        n = min(k, self.count())
        if n <= 0:
            return []
        got = self._collection.query(
            query_embeddings=[self.embedder.embed_query(text)],
            n_results=n,
            include=["documents", "metadatas", "distances"],
        )
        return [
            _to_chunk(i, d, m, dist)
            for i, d, m, dist in zip(got["ids"][0], got["documents"][0], got["metadatas"][0], got["distances"][0])
        ]
