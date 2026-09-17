"""
Stats and health router.
GET /api/v1/stats   — aggregated detection statistics
GET /api/v1/health  — liveness + model loaded flag
"""
from __future__ import annotations

from fastapi import APIRouter

from agents.coordinator.coordinator import load_runtime
from database import models
from database.init_db import SessionLocal

router = APIRouter(prefix="/api/v1", tags=["stats"])


@router.get("/stats", summary="Aggregated detection statistics")
def stats():
    """
    Return total counts for alerts, detections and actions,
    plus breakdowns by predicted class and action type.
    """
    db = SessionLocal()
    try:
        alerts_n = db.query(models.Alert).count()
        dets = db.query(models.Detection).all()
        actions = db.query(models.Action).all()

        by_class: dict[str, int] = {}
        for d in dets:
            by_class[d.predicted_class] = by_class.get(d.predicted_class, 0) + 1

        by_action: dict[str, int] = {}
        for a in actions:
            by_action[a.action_type] = by_action.get(a.action_type, 0) + 1

        return {
            "alerts": alerts_n,
            "detections": len(dets),
            "actions": len(actions),
            "by_class": by_class,
            "by_action": by_action,
        }
    finally:
        db.close()


@router.get("/health", summary="Liveness and model health")
async def health():
    """Return API liveness status and whether the ML model bundle is loaded."""
    model_ok = False
    try:
        load_runtime()
        model_ok = True
    except FileNotFoundError:
        model_ok = False
    return {"status": "ok", "model_loaded": model_ok}
