import uuid

from fastapi import APIRouter

from app.logging.audit import log_scan
from app.models import ChatRequest, ChatResponse
from app.pipeline import scan

router = APIRouter()

BLOCKED_MESSAGE = "Votre message a été bloqué par le pare-feu de l'assistant."


@router.post("/chat", response_model=ChatResponse)
async def chat(request: ChatRequest) -> ChatResponse:
    """Scan the user prompt and log the result. The LLM call arrives in P2."""
    request_id = uuid.uuid4().hex
    result = scan(request.message, "user_prompt")
    log_scan("prompt.scanned", result, request.message, request_id=request_id)

    blocked = result.decision == "BLOCK"
    return ChatResponse(
        response=BLOCKED_MESSAGE if blocked else "received",
        status="blocked" if blocked else "safe",
        score=result.score,
        decision=result.decision,
        request_id=request_id,
    )
