"""Tests for app/rag/ingest.py: scan [0], quarantine, idempotence, chunking."""

import hashlib
from pathlib import Path

from app.rag.ingest import ingest_corpus, main, split_markdown

POISONED = Path(__file__).resolve().parent.parent / "eval" / "chunks" / "attack" / "reset_mdp_v2_html_comment.md"


def test_clean_corpus_is_indexed(store, corpus, tmp_path, events):
    report = ingest_corpus(store, corpus, tmp_path / "quarantine")
    assert len(report.indexed) == 10 and report.quarantined == []
    assert store.doc_ids() == sorted(p.name for p in corpus.glob("*.md"))
    assert store.count() == report.chunks
    indexed = events("ingest.document_indexed")
    assert len(indexed) == 10
    vpn = next(e for e in indexed if e["doc_id"] == "vpn_connexion.md")
    assert vpn["doc_sha256"] == hashlib.sha256((corpus / "vpn_connexion.md").read_bytes()).hexdigest()
    assert vpn["decision"] == "ALLOW" and vpn["context"] == "document"
    assert len({e["request_id"] for e in indexed}) == 1  # one id per ingestion run


def test_poisoned_document_is_quarantined(store, corpus, tmp_path, events):
    (corpus / "procedure_reset_mdp_v2.md").write_bytes(POISONED.read_bytes())
    report = ingest_corpus(store, corpus, tmp_path / "quarantine")

    assert report.quarantined == ["procedure_reset_mdp_v2.md"]
    assert "procedure_reset_mdp_v2.md" not in store.doc_ids()
    assert not (corpus / "procedure_reset_mdp_v2.md").exists()
    moved = Path(report.quarantine_dir) / "procedure_reset_mdp_v2.md"
    assert moved.read_bytes() == POISONED.read_bytes()  # evidence kept, byte for byte

    [event] = events("ingest.document_quarantined")
    assert event["doc_id"] == "procedure_reset_mdp_v2.md" and event["decision"] in ("WARN", "BLOCK")
    assert event["doc_sha256"] == hashlib.sha256(POISONED.read_bytes()).hexdigest()
    assert event["owasp"] == "LLM01" and event["quarantine_path"] == str(moved)
    assert "acme-support-reset.example" not in str(store.all_chunks())


def test_reingest_is_idempotent(store, corpus, tmp_path, events):
    ingest_corpus(store, corpus, tmp_path / "q")
    before = store.all_chunks()
    report = ingest_corpus(store, corpus, tmp_path / "q")
    assert report.indexed == [] and len(report.unchanged) == 10
    assert store.all_chunks() == before
    assert len(events("ingest.document_indexed")) == 10  # no new events


def test_modified_document_is_reindexed(store, corpus, tmp_path):
    ingest_corpus(store, corpus, tmp_path / "q")
    doc = corpus / "teams.md"
    doc.write_text(doc.read_text(encoding="utf-8") + "\n## Nouveauté\n\nLes sondages sont disponibles.\n", encoding="utf-8")
    report = ingest_corpus(store, corpus, tmp_path / "q")
    assert report.indexed == ["teams.md"]
    assert store.document_sha256("teams.md") == hashlib.sha256(doc.read_bytes()).hexdigest()


def test_indexed_document_turned_malicious_leaves_the_store(store, corpus, tmp_path):
    ingest_corpus(store, corpus, tmp_path / "q")
    (corpus / "teams.md").write_bytes(POISONED.read_bytes())
    report = ingest_corpus(store, corpus, tmp_path / "q")
    assert report.quarantined == ["teams.md"]
    assert "teams.md" not in store.doc_ids()


def test_split_markdown_one_chunk_per_section_with_title():
    text = "# Titre\n\nIntro.\n\n## A\n\nTexte A.\n\n## B\n\nTexte B.\n"
    assert split_markdown(text) == ["# Titre\n\nIntro.", "# Titre\n\n## A\n\nTexte A.", "# Titre\n\n## B\n\nTexte B."]


def test_split_markdown_keeps_text_before_first_section():
    # A hidden instruction placed before the first heading must still be indexed and scanned.
    text = "<!-- note -->\n# Titre\n\n## A\n\nTexte."
    assert "<!-- note -->" in split_markdown(text)[0]


def test_split_markdown_long_section():
    paragraphs = [f"Paragraphe {i} " + "mot " * 60 for i in range(10)]
    chunks = split_markdown("# T\n\n## Long\n\n" + "\n\n".join(paragraphs), max_chars=600)
    assert len(chunks) > 1
    assert all(c.startswith("# T") for c in chunks)
    assert "".join(chunks).count("Paragraphe") == 10


def test_cli_reports_ollama_down(tmp_path, monkeypatch, capsys):
    from app.llm import provider as provider_module

    class Down(provider_module.OllamaProvider):
        def embed_documents(self, texts):
            raise provider_module.LLMUnavailableError("down")

    monkeypatch.setattr(provider_module, "OllamaProvider", Down)
    corpus = tmp_path / "corpus"
    corpus.mkdir()
    (corpus / "a.md").write_text("# A\n\n## B\n\nTexte.", encoding="utf-8")
    code = main(["--corpus", str(corpus), "--chroma", str(tmp_path / "c"), "--quarantine", str(tmp_path / "q")])
    assert code == 1 and "Ollama injoignable" in capsys.readouterr().out
