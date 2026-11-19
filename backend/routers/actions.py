"""
Actions v1 router — paginated list and authenticated manual unblock.
GET  /api/v1/actions           — paginated
POST /api/v1/actions/unblock   — manual IP unblock (auth required)
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel

from backend.auth import get_current_admin, get_current_user
from backend.threat_policy import harmful_detection_filters
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
def list_actions(
    page: int = Query(default=1, ge=1),
    limit: int = Query(default=50, ge=1, le=200),
    _user: dict = Depends(get_current_user),
):
    """Return all response actions newest-first with pagination."""
    db = SessionLocal()
    try:
        query = (
            db.query(models.Action)
            .join(models.Detection, models.Action.detection_id == models.Detection.id)
            .filter(*harmful_detection_filters())
        )
        total = query.count()
        items = (
            query
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
