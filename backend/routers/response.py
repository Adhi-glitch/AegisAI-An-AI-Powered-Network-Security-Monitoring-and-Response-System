"""Response Center endpoints for policy preview and active dry-run blocks."""
from __future__ import annotations

from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from agents.response.response_engine import engine
from backend.auth import get_current_admin, get_current_user
from database import models
from database.init_db import SessionLocal

router = APIRouter(prefix="/api/v1/response", tags=["response"])


class PolicyPreviewRequest(BaseModel):
    attack_type: str | None = Field(default=None, max_length=64)
    confidence: float = Field(ge=0.0, le=1.0)
    severity: str | None = Field(default=None, max_length=32)
    asset_criticality: str | None = Field(default=None, max_length=32)
    mode: Literal["dry-run", "approval-required", "auto-live"] = "dry-run"


class PolicyRuleRequest(BaseModel):
    name: str = Field(min_length=1, max_length=96)
    attack_types: list[str] = Field(default_factory=list, max_length=20)
    min_confidence: float | None = Field(default=None, ge=0.0, le=1.0)
    min_severity: str | None = Field(default=None, max_length=32)
    min_asset_criticality: str | None = Field(default=None, max_length=32)
    action: Literal["log", "alert", "rate_limit", "block", "isolate", "quarantine", "notify"]
    mode: Literal["dry-run", "approval-required", "auto-live"] = "dry-run"
    priority: int = Field(default=100, ge=0, le=10000)


class ExecuteRequest(BaseModel):
    ip: str = Field(min_length=3, max_length=45)
    action: Literal["log", "alert", "rate_limit", "block", "isolate", "quarantine", "notify"]
    mode: Literal["dry-run", "approval-required", "auto-live"] = "dry-run"
    reason: str | None = Field(default=None, max_length=255)


@router.post("/policy/preview", summary="Preview a response policy decision")
def preview_policy(
    request: PolicyPreviewRequest,
    _user: dict = Depends(get_current_user),
):
    """Return an explainable decision without executing an action."""
    decision = engine.evaluate_policy(
        request.confidence,
        attack_type=request.attack_type,
        severity=request.severity,
        asset_criticality=request.asset_criticality,
        mode=request.mode,
    )
    return {
        "action": decision.action,
        "rule_id": decision.rule_id,
        "reason": decision.reason,
        "requires_approval": decision.requires_approval,
        "mode": request.mode,
    }


@router.get("/blocks", summary="List active response blocks")
def list_blocks(_user: dict = Depends(get_current_user)):
    """Return in-memory blocks; dry-run blocks are visible for demonstrations."""
    with engine.lock:
        engine._prune_expired_locked()
        return {
            "items": [
                {"ip": ip, "unblock_at": unblock_at}
                for ip, unblock_at in engine.blocked.items()
            ]
        }


@router.post("/unblock", summary="Rollback a block")
def rollback_block(ip: str, _admin: dict = Depends(get_current_admin)):
    return engine.manual_unblock(ip)


@router.get("/policies", summary="List configurable response policies")
def list_policies(_user: dict = Depends(get_current_user)):
    db = SessionLocal()
    try:
        rows = db.query(models.PolicyRule).order_by(models.PolicyRule.priority, models.PolicyRule.id).all()
        return {"items": [{"id": row.id, "name": row.name, "attack_types": row.attack_types or [], "min_confidence": row.min_confidence, "min_severity": row.min_severity, "min_asset_criticality": row.min_asset_criticality, "action": row.action, "mode": row.mode, "priority": row.priority, "enabled": row.enabled} for row in rows]}
    finally:
        db.close()


@router.post("/policies", summary="Create a response policy", status_code=201)
def create_policy(request: PolicyRuleRequest, _admin: dict = Depends(get_current_admin)):
    db = SessionLocal()
    try:
        if db.query(models.PolicyRule).filter(models.PolicyRule.name == request.name).first():
            raise HTTPException(status_code=409, detail="Policy name already exists")
        row = models.PolicyRule(**request.model_dump())
        db.add(row)
        db.commit()
        db.refresh(row)
        return {"id": row.id, "name": row.name, "action": row.action, "mode": row.mode}
    finally:
        db.close()


@router.get("/approvals", summary="List pending response approvals")
def list_approvals(_admin: dict = Depends(get_current_admin)):
    db = SessionLocal()
    try:
        rows = db.query(models.ResponseApproval).filter(models.ResponseApproval.status == "pending").order_by(models.ResponseApproval.created_at).all()
        return {"items": [{"id": row.id, "ip": row.ip, "action": row.action, "requested_by": row.requested_by, "created_at": row.created_at.isoformat() if row.created_at else None} for row in rows]}
    finally:
        db.close()


@router.post("/execute", summary="Execute or queue a response action")
def execute(request: ExecuteRequest, user: dict = Depends(get_current_user)):
    if request.mode == "auto-live":
        if user.get("role") != "admin":
            raise HTTPException(status_code=403, detail="Admin access required to execute actions")
        raise HTTPException(
            status_code=409,
            detail="Live response execution is disabled; use dry-run or approval-required mode.",
        )
    db = SessionLocal()
    try:
        if request.mode == "approval-required":
            approval = models.ResponseApproval(ip=request.ip, action=request.action, requested_by=user.get("username"))
            db.add(approval)
            db.add(models.ResponseAudit(ip=request.ip, action=request.action, mode=request.mode, status="pending", actor=user.get("username"), reason=request.reason))
            db.commit()
            db.refresh(approval)
            return {"status": "pending_approval", "approval_id": approval.id, "ip": request.ip, "action": request.action}
        if user.get("role") != "admin":
            raise HTTPException(status_code=403, detail="Admin access required to execute actions")
        result = engine.apply_action(request.ip, request.action)
        db.add(models.ResponseAudit(ip=request.ip, action=request.action, mode=request.mode, status=str(result.get("status")), actor=user.get("username"), reason=request.reason, metadata_json=result))
        db.commit()
        return result
    finally:
        db.close()


@router.post("/approvals/{approval_id}/decision", summary="Approve or reject a response action")
def decide_approval(approval_id: int, approved: bool, reason: str = "", admin: dict = Depends(get_current_admin)):
    db = SessionLocal()
    try:
        approval = db.query(models.ResponseApproval).filter(models.ResponseApproval.id == approval_id).first()
        if not approval or approval.status != "pending":
            raise HTTPException(status_code=404, detail="Pending approval not found")
        approval.status = "approved" if approved else "rejected"
        approval.decision_by = admin.get("username")
        approval.decision_reason = reason
        approval.decided_at = models.utc_now()
        result: dict[str, Any] = {"status": approval.status, "approval_id": approval.id}
        if approved:
            action_result = engine.apply_action(approval.ip, approval.action)
            result = action_result | result
            result["action_status"] = action_result.get("status")
        db.add(models.ResponseAudit(ip=approval.ip, action=approval.action, mode="approval-required", status=approval.status, actor=admin.get("username"), reason=reason, metadata_json=result))
        db.commit()
        return result
    finally:
        db.close()


@router.get("/audit", summary="List durable response audit records")
def list_audit(_admin: dict = Depends(get_current_admin)):
    db = SessionLocal()
    try:
        rows = db.query(models.ResponseAudit).order_by(models.ResponseAudit.id.desc()).limit(200).all()
        return {"items": [{"id": row.id, "ip": row.ip, "action": row.action, "mode": row.mode, "status": row.status, "actor": row.actor, "reason": row.reason, "created_at": row.created_at.isoformat() if row.created_at else None} for row in rows]}
    finally:
        db.close()