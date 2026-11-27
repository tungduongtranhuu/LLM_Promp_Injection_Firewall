import uuid
from functools import lru_cache

from fastapi import APIRouter, Depends, Response

from app.llm.provider import LLMProvider, OllamaProvider
from app.mode import get_mode
from app.models import ChatRequest, ChatResponse
from app.rag.chain import answer
from app.rag.store import VectorStore

router = APIRouter()

UNAVAILABLE_STATUSES = frozenset({"unavailable", "maintenance"})


@lru_cache(maxsize=1)
def get_provider() -> LLMProvider:
    return OllamaProvider()


@lru_cache(maxsize=1)
def get_store() -> VectorStore:
    return VectorStore(get_provider())


# Sync handlers: FastAPI runs them in a thread pool (httpx and ChromaDB calls are blocking).
@router.post("/chat", response_model=ChatResponse)
def chat(
    request: ChatRequest,
    response: Response,
    provider: LLMProvider = Depends(get_provider),
    store: VectorStore = Depends(get_store),
) -> ChatResponse:
    """[1] input scan -> [2][3] retrieval + chunk scan -> LLM -> [4] output scan."""
    result = answer(
        request.message, provider=provider, store=store, request_id=uuid.uuid4().hex, mode=get_mode()
    )
    if result.status in UNAVAILABLE_STATUSES:
        response.status_code = 503
    return result


@router.get("/health")
def health(
    provider: LLMProvider = Depends(get_provider),
    store: VectorStore = Depends(get_store),
) -> dict:
    return {"status": "ok", "mode": get_mode(), "ollama": provider.ping(), "chunks": store.count()}
