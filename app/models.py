from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, Field

Decision = Literal["ALLOW", "WARN", "BLOCK"]
ScanContext = Literal["user_prompt", "document", "retrieved_chunk", "llm_output"]


class ChatRequest(BaseModel):
    """Request model for /chat endpoint"""
    message: str


class ChatResponse(BaseModel):
    """Response model for /chat endpoint"""
    response: str
    status: Optional[str] = "safe"  # "safe" or "blocked"
    score: Optional[float] = None  # risk score (0-100)
    decision: Optional[Decision] = None
    request_id: Optional[str] = None


class Finding(BaseModel):
    """One technique detected in the scanned text, with its points and taxonomy."""
    technique: str  # e.g. "prompt_override", "ai_addressing"
    detector: str  # regex | jailbreak | indirect | output | heuristic | encoding
    variant: str  # text variant the technique was found in ("original", "decoded_0"...)
    points: float  # contribution to the score (0 for a weak signal without companion)
    label: str  # injection.direct | injection.indirect | injection.jailbreak | system_prompt_leakage ...
    owasp: Optional[str] = None  # OWASP Top 10 for LLM 2025, e.g. "LLM01"
    atlas: Optional[str] = None  # MITRE ATLAS technique id


class ScanResult(BaseModel):
    """Output of app.pipeline.scan()."""
    score: float
    decision: Decision
    level: Literal["LOW", "MEDIUM", "HIGH"]
    context: ScanContext
    detectors: List[str] = Field(default_factory=list)  # detectors that contributed points
    findings: List[Finding] = Field(default_factory=list)  # sorted by points, highest first
    labels: List[str] = Field(default_factory=list)  # distinct labels of scoring findings
    owasp: Optional[str] = None  # taxonomy of the top-scoring categorized finding
    atlas: Optional[str] = None
    details: Dict[str, Any] = Field(default_factory=dict)
