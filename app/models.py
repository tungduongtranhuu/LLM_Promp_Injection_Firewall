from pydantic import BaseModel
from typing import Optional


class ChatRequest(BaseModel):
    """Request model for /chat endpoint"""
    message: str


class ChatResponse(BaseModel):
    """Response model for /chat endpoint"""
    response: str
    status: Optional[str] = "safe"  # "safe" hoặc "blocked"
    score: Optional[float] = None  # điểm risk (0-100)
