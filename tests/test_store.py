"""Tests for app/rag/store.py (ChromaDB in tmp_path, fake embeddings)."""

import hashlib

import pytest

from app.llm.provider import LLMUnavailableError


def test_upsert_stores_metadata(store):
    ids = store.upsert_document("vpn.md", "abc123", ["VPN passerelle", "MFA notification"], ingested_at="2026-11-25T09:00:00.000Z")
    assert ids == ["vpn.md#0", "vpn.md#1"]
    chunks = store.all_chunks()
    assert [c.chunk_id for c in chunks] == ids
    first = chunks[0]
    assert first.doc_id == "vpn.md" and first.doc_sha256 == "abc123" and first.chunk_index == 0
    assert first.chunk_sha256 == hashlib.sha256(b"VPN passerelle").hexdigest()
    assert first.ingested_at == "2026-11-25T09:00:00.000Z"


def test_upsert_replaces_previous_version(store):
    store.upsert_document("doc.md", "v1", ["a b c", "d e f", "g h i"])
    store.upsert_document("doc.md", "v2", ["nouvelle version"])
    assert store.count() == 1
    assert store.document_sha256("doc.md") == "v2"


def test_delete_and_unknown_document(store):
    store.upsert_document("doc.md", "v1", ["texte"])
    store.delete_document("doc.md")
    assert store.count() == 0 and store.document_sha256("doc.md") is None


def test_query_returns_nearest_first(store):
    store.upsert_document("vpn.md", "s1", ["connexion VPN passerelle Acme"])
    store.upsert_document("imprimantes.md", "s2", ["imprimante badge copieur impression"])
    hits = store.query("comment imprimer avec mon badge sur le copieur", k=2)
    assert [h.doc_id for h in hits] == ["imprimantes.md", "vpn.md"]
    assert hits[0].distance is not None and hits[0].distance <= hits[1].distance


def test_query_on_empty_store(store):
    assert store.query("vpn", k=4) == []


def test_query_k_larger_than_store(store):
    store.upsert_document("vpn.md", "s1", ["VPN"])
    assert len(store.query("VPN", k=10)) == 1


def test_embedding_failure_keeps_indexed_version(store, provider):
    store.upsert_document("doc.md", "v1", ["version saine"])
    provider.fail = True
    with pytest.raises(LLMUnavailableError):
        store.upsert_document("doc.md", "v2", ["nouvelle version"])
    assert store.document_sha256("doc.md") == "v1"


def test_store_persists_on_disk(tmp_path, provider):
    from app.rag.store import VectorStore

    VectorStore(provider, path=tmp_path / "c", collection="kb_persist").upsert_document("d.md", "s", ["x y z"])
    assert VectorStore(provider, path=tmp_path / "c", collection="kb_persist").doc_ids() == ["d.md"]
