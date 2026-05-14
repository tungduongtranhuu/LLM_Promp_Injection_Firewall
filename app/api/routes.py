from fastapi import APIRouter
from app.models import ChatRequest, ChatResponse

router = APIRouter()


@router.post("/chat", response_model=ChatResponse)
async def chat(request: ChatRequest) -> ChatResponse:
    return ChatResponse(
        response = "received",
        status = "safe",
        score = 0.0
    )
