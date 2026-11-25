"""Tests for app/rag/retriever.py: scan [3] on every retrieved chunk."""

import hashlib
from pathlib import Path

from app.rag.ingest import ingest_corpus, split_markdown
from app.rag.retriever import retrieve

POISONED = Path(__file__).resolve().parent.parent / "eval" / "chunks" / "attack" / "reset_mdp_v2_html_comment.md"
QUESTION = "Comment réinitialiser mon mot de passe sur le portail libre-service ?"


def inject_directly(store, doc_id="procedure_reset_mdp_v2.md"):
    """Simulate attack.py --direct: index into the store without scan [0]."""
    raw = POISONED.read_bytes()
    store.upsert_document(doc_id, hashlib.sha256(raw).hexdigest(), split_markdown(raw.decode("utf-8")))
    return hashlib.sha256(raw).hexdigest()


def test_clean_chunks_are_kept_and_not_logged(store, corpus, tmp_path, events):
    ingest_corpus(store, corpus, tmp_path / "q")
    before = len(events())
    result = retrieve(QUESTION, store, k=4, request_id="r1")
    assert len(result.kept) == 4 and result.dropped == []
    assert "reinitialisation_mot_de_passe.md" in result.sources
    assert len(events()) == before  # ALLOW chunks are not alerts


def test_poisoned_chunk_bypassing_ingestion_is_dropped(store, corpus, tmp_path, events):
    ingest_corpus(store, corpus, tmp_path / "q")
    ioc = inject_directly(store)
    result = retrieve(QUESTION, store, k=4, request_id="r1")

    assert [c.doc_id for c in result.dropped] == ["procedure_reset_mdp_v2.md"]
    assert all("acme-support-reset.example" not in c.text for c in result.kept)
    assert "reinitialisation_mot_de_passe.md" in result.sources  # legit procedure still answers

    [event] = events("retrieval.chunk_flagged")
    assert event["request_id"] == "r1" and event["context"] == "retrieved_chunk"
    assert event["doc_id"] == "procedure_reset_mdp_v2.md" and event["doc_sha256"] == ioc
    assert event["action"] == "drop_chunk" and event["decision"] in ("WARN", "BLOCK")
    assert event["owasp"] == "LLM01" and event["atlas"] == "AML.T0051.001"
    assert {"chunk_id", "chunk_index", "chunk_sha256", "ingested_at"} <= event.keys()


def test_every_chunk_dropped(store, events):
    inject_directly(store)
    result = retrieve(QUESTION, store, k=4, request_id="r2")
    assert result.kept == [] and result.sources == []
    assert len(events("retrieval.chunk_flagged")) == len(result.dropped) >= 1


def test_empty_store(store):
    result = retrieve(QUESTION, store, k=4, request_id="r3")
    assert result.kept == [] and result.dropped == []
