"""
Actions v1 router — paginated list and authenticated manual unblock.
GET  /api/v1/actions           — paginated
POST /api/v1/actions/unblock   — manual IP unblock (auth required)
"""
from __future__ import annotations

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from backend.auth import get_current_admin
from database import models
from database.init_db import SessionLocal

router = APIRouter(prefix="/api/v1/actions", tags=["actions"])


class UnblockRequest(BaseModel):
    ip: str


def _action_to_dict(a: models.Action) -> dict:
    return {
        "id": a.id,
        "detection_id": a.detection_id,
        "action_type": a.action_type,
        "timestamp": a.timestamp.isoformat() if a.timestamp else None,
        "reversed_at": a.reversed_at.isoformat() if a.reversed_at else None,
    }


@router.get("", summary="List response actions (paginated)")
def list_actions(page: int = 1, limit: int = 50):
    """Return all response actions newest-first with pagination."""
    page = max(1, page)
    limit = min(limit, 200)
    db = SessionLocal()
    try:
        total = db.query(models.Action).count()
        items = (
            db.query(models.Action)
            .order_by(models.Action.id.desc())
            .offset((page - 1) * limit)
            .limit(limit)
            .all()
        )
        return {
            "items": [_action_to_dict(a) for a in items],
            "total": total,
            "page": page,
            "pages": max(1, -(-total // limit)),
        }
    finally:
        db.close()


@router.post("/unblock", summary="Manually unblock an IP (admin only)")
def manual_unblock(
    req: UnblockRequest,
    _admin: dict = Depends(get_current_admin),
):
    """
    Request an immediate unblock for the given IP.
    Requires admin role.  Response engine decides how to act (dry-run by default).
    """
    from agents.response.response_engine import engine

    res = engine.manual_unblock(req.ip)
    return res
