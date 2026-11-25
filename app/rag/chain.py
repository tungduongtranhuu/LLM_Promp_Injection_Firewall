"""The /chat chain: [1] input scan -> [2] retrieve + [3] chunk scan -> LLM -> [4] output scan.

Every decision goes through enforce() (per-context policy in rules.py);
this module never branches on a scan decision itself. All the audit events
of one request share its request_id.
"""

from __future__ import annotations

from collections.abc import Sequence

from app import config
from app.enforcement import enforce
from app.llm.provider import LLMProvider, LLMUnavailableError, Message, load_system_prompt
from app.logging.audit import log_scan
from app.models import ChatResponse, StoredChunk
from app.pipeline import scan
from app.rag.retriever import retrieve
from app.rag.store import VectorStore

BLOCKED_MESSAGE = "Votre message a été bloqué par le pare-feu de l'assistant."
BLOCKED_OUTPUT_MESSAGE = (
    "La réponse de l'assistant a été bloquée par le pare-feu. "
    "Contactez le support : https://support.acme.fr ou poste 4242."
)
NO_CONTEXT_MESSAGE = (
    "Je n'ai pas trouvé d'information fiable sur ce sujet dans la base documentaire. "
    "Contactez le support : https://support.acme.fr ou poste 4242."
)
UNAVAILABLE_MESSAGE = "L'assistant est momentanément indisponible. Réessayez dans quelques minutes."


def build_messages(question: str, chunks: Sequence[StoredChunk]) -> list[Message]:
    excerpts = "\n\n".join(f"### Source : [{c.doc_id}]\n{c.text}" for c in chunks)
    return [
        {"role": "system", "content": load_system_prompt()},
        {"role": "user", "content": f"<extraits>\n{excerpts}\n</extraits>\n\nQuestion : {question}"},
    ]


def answer(
    message: str,
    *,
    provider: LLMProvider,
    store: VectorStore,
    request_id: str,
    top_k: int | None = None,
) -> ChatResponse:
    # [1] input scan: the prompt is always logged (prompt.scanned), whatever the decision.
    prompt_result = scan(message, "user_prompt")
    log_scan("prompt.scanned", prompt_result, message, request_id=request_id)
    base = {"score": prompt_result.score, "decision": prompt_result.decision, "request_id": request_id}
    if not enforce(prompt_result, message).allowed:
        return ChatResponse(response=BLOCKED_MESSAGE, status="blocked", **base)

    try:
        # [2] retrieve + [3] per-chunk scan
        retrieval = retrieve(message, store, top_k or config.rag_top_k, request_id=request_id)
        common = {**base, "sources": retrieval.sources, "dropped_chunks": len(retrieval.dropped)}
        if not retrieval.kept:
            # Nothing trustworthy to ground the answer on: do not let the LLM improvise.
            return ChatResponse(response=NO_CONTEXT_MESSAGE, status="no_context", **common)
        raw_answer = provider.chat(build_messages(message, retrieval.kept))
    except LLMUnavailableError:
        return ChatResponse(response=UNAVAILABLE_MESSAGE, status="unavailable", **base)

    return _scan_output(raw_answer, request_id, common)


def _scan_output(raw_answer: str, request_id: str, common: dict) -> ChatResponse:
    """[4] output scan: pass, redact unapproved URLs, or block (enforce() decides)."""
    result = scan(raw_answer, "llm_output")
    decision = enforce(result, raw_answer)
    if decision.log:
        log_scan(
            "output.flagged", result, raw_answer, request_id=request_id,
            action=decision.action, redacted_hosts=decision.redacted_hosts,
            sources=common.get("sources", []),
        )
    if not decision.allowed:
        return ChatResponse(response=BLOCKED_OUTPUT_MESSAGE, status="blocked", output_decision=result.decision, **common)
    status = "filtered" if decision.redacted_hosts else "safe"
    return ChatResponse(response=decision.text or "", status=status, output_decision=result.decision, **common)
