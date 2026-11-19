"""Safe, admin-only AegisAI toolbox commands.

This is intentionally not an arbitrary shell. Every command is a named,
validated application operation so the console cannot become a remote command
execution endpoint.
"""
from __future__ import annotations

from typing import Any, Callable

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field
from sqlalchemy import inspect

from agents.analytics.features import posture_digest
from agents.coordinator.coordinator import load_runtime
from agents.response.response_engine import engine
from backend.auth import get_current_admin
from database import models
from database.init_db import SessionLocal, engine as database_engine

router = APIRouter(prefix="/api/v1/admin-tools", tags=["admin-tools"])


class ToolRequest(BaseModel):
    command_key: str = Field(min_length=1, max_length=96)
    arguments: dict[str, Any] = Field(default_factory=dict)


def _health(_: dict[str, Any]) -> dict[str, Any]:
    try:
        load_runtime()
        model_loaded = True
    except Exception:
        model_loaded = False
    return {"status": "ok", "model_loaded": model_loaded}


def _stats(_: dict[str, Any]) -> dict[str, Any]:
    db = SessionLocal()
    try:
        return {"alerts": db.query(models.Alert).count(), "detections": db.query(models.Detection).count(), "actions": db.query(models.Action).count(), "incidents": db.query(models.Incident).count()}
    finally:
        db.close()


def _blocks(_: dict[str, Any]) -> dict[str, Any]:
    with engine.lock:
        engine._prune_expired_locked()
        return {"items": [{"ip": ip, "unblock_at": value} for ip, value in engine.blocked.items()]}


def _audit(_: dict[str, Any]) -> dict[str, Any]:
    db = SessionLocal()
    try:
        rows = db.query(models.AdminToolAudit).order_by(models.AdminToolAudit.id.desc()).limit(50).all()
        return {"items": [{"id": row.id, "command_key": row.command_key, "actor": row.actor, "success": row.success, "created_at": row.created_at.isoformat() if row.created_at else None} for row in rows]}
    finally:
        db.close()


def _tables(_: dict[str, Any]) -> dict[str, Any]:
    return {"tables": inspect(database_engine).get_table_names()}


def _posture(_: dict[str, Any]) -> dict[str, Any]:
    stats = _stats({})
    return posture_digest(attack_volume=stats["alerts"], blocked=len(engine.blocked), unresolved_incidents=stats["incidents"], model_health=1.0)


COMMANDS: dict[str, tuple[str, Callable[[dict[str, Any]], dict[str, Any]]]] = {
    "system.health": ("Check API and model health", _health),
    "system.stats": ("Read aggregate AegisAI counts", _stats),
    "response.blocks": ("List active dry-run blocks", _blocks),
    "response.audit": ("Read admin toolbox audit history", _audit),
    "database.tables": ("List initialized database tables", _tables),
    "security.posture": ("Calculate the current posture score", _posture),
}


@router.get("/commands", summary="List available safe admin commands")
def list_commands(_admin: dict = Depends(get_current_admin)):
    return {"items": [{"key": key, "description": description} for key, (description, _) in COMMANDS.items()]}


@router.post("/execute", summary="Execute one safe admin command")
def execute_command(request: ToolRequest, admin: dict = Depends(get_current_admin)):
    command = COMMANDS.get(request.command_key)
    if command is None:
        return {"success": False, "error": "Unknown command key", "available": sorted(COMMANDS)}
    description, handler = command
    try:
        output = handler(request.arguments)
        success = True
    except Exception as exc:
        output = {"error": str(exc)}
        success = False
    db = SessionLocal()
    try:
        db.add(models.AdminToolAudit(command_key=request.command_key, actor=admin.get("username"), success=success, arguments=request.arguments, output=output))
        db.commit()
    finally:
        db.close()
    return {"success": success, "command_key": request.command_key, "description": description, "output": output}