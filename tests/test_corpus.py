"""The Acme corpus (data/corpus/) is the clean baseline: it must pass the firewall."""

from pathlib import Path

import pytest

from app.detectors.url_utils import extract_url_hosts, host_allowed
from app.pipeline import scan
from app.scoring.rules import ScoringRules

CORPUS = Path(__file__).resolve().parent.parent / "data" / "corpus"
DOCS = sorted(CORPUS.glob("*.md"))


def test_corpus_size():
    assert 8 <= len(DOCS) <= 10


@pytest.mark.parametrize("context", ["document", "retrieved_chunk"])
@pytest.mark.parametrize("doc", DOCS, ids=lambda p: p.name)
def test_corpus_document_is_allowed(doc, context):
    result = scan(doc.read_text(encoding="utf-8"), context)
    assert result.decision == "ALLOW", [f.technique for f in result.findings]


@pytest.mark.parametrize("doc", DOCS, ids=lambda p: p.name)
def test_corpus_links_only_to_acme(doc):
    hosts = extract_url_hosts(doc.read_text(encoding="utf-8"))
    assert all(host_allowed(h, ScoringRules.URL_ALLOWLIST) for h in hosts), hosts


def test_official_reset_portal_is_documented():
    text = (CORPUS / "reinitialisation_mot_de_passe.md").read_text(encoding="utf-8")
    assert "https://moncompte.acme.fr" in text
