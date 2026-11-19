"""AegisAI Copilot retrieval endpoints."""
from __future__ import annotations

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field, field_validator

from agents.response.response_engine import engine
from backend.auth import get_current_admin, get_current_user
from rag.knowledge_base import knowledge_base

router = APIRouter(prefix="/api/v1/copilot", tags=["copilot"])


class CopilotQuery(BaseModel):
    query: str = Field(min_length=2, max_length=1000)
    limit: int = Field(default=3, ge=1, le=10)


class SuggestedAction(BaseModel):
    ip: str = Field(min_length=1, max_length=45)
    action: str = Field(pattern=r"^(log|rate_limit|block)$")


class KnowledgeDocumentRequest(BaseModel):
    document_id: str = Field(min_length=1, max_length=128)
    title: str = Field(min_length=1, max_length=200)
    text: str = Field(min_length=1, max_length=100000)
    source: str = Field(min_length=1, max_length=200)
    chunk_size: int = Field(default=800, ge=100, le=10000)

    @field_validator("document_id", "title", "text", "source")
    @classmethod
    def reject_blank_values(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("must not be blank")
        return value


@router.post("/query", summary="Ask the offline security knowledge assistant")
def query_copilot(request: CopilotQuery, _user: dict = Depends(get_current_user)):
    return knowledge_base.answer(request.query, request.limit)


@router.post("/actions/execute", summary="Execute a suggested safe response action")
def execute_suggested_action(request: SuggestedAction, _admin: dict = Depends(get_current_admin)):
    return engine.apply_action(request.ip, request.action)


@router.post("/documents", summary="Ingest a local security document")
def ingest_document(request: KnowledgeDocumentRequest, _admin: dict = Depends(get_current_admin)):
    chunks = knowledge_base.ingest(**request.model_dump())
    return {"document_id": request.document_id, "chunks_added": chunks}