"""
Stats and health router.
GET /api/v1/stats   — aggregated detection statistics
GET /api/v1/health  — liveness + model loaded flag
"""
from __future__ import annotations

import logging

from fastapi import APIRouter, Depends
from sqlalchemy import func

from agents.coordinator.coordinator import load_runtime
from backend.auth import get_current_user
from database import models
from database.init_db import SessionLocal
from backend.threat_policy import harmful_detection_filters

router = APIRouter(prefix="/api/v1", tags=["stats"])
_LOGGER = logging.getLogger(__name__)


@router.get("/stats", summary="Aggregated detection statistics")
def stats(_user: dict = Depends(get_current_user)):
    """
    Return total counts for alerts, detections and actions,
    plus breakdowns by predicted class and action type.
    """
    db = SessionLocal()
    try:
        detections_query = db.query(models.Detection).filter(*harmful_detection_filters())
        detections_n = detections_query.count()
        alerts_n = (
            db.query(models.Alert)
            .join(models.Detection, models.Detection.alert_id == models.Alert.id)
            .filter(*harmful_detection_filters())
            .distinct()
            .count()
        )
        by_class = dict(
            db.query(models.Detection.predicted_class, func.count(models.Detection.id))
            .filter(*harmful_detection_filters())
            .group_by(models.Detection.predicted_class)
            .all()
        )
        by_action = dict(
            db.query(models.Action.action_type, func.count(models.Action.id))
            .join(models.Detection, models.Action.detection_id == models.Detection.id)
            .filter(*harmful_detection_filters())
            .group_by(models.Action.action_type)
            .all()
        )

        return {
            "alerts": alerts_n,
            "detections": detections_n,
            "actions": sum(by_action.values()),
            "by_class": by_class,
            "by_action": by_action,
        }
    finally:
        db.close()


@router.get("/health", summary="Liveness and model health")
async def health():
    """Return API liveness status and whether the ML model bundle is loaded."""
    try:
        load_runtime()
        return {"status": "ok", "model_loaded": True}
    except Exception:
        _LOGGER.exception("Health check could not load model")
        return {
            "status": "ok",
            "model_loaded": False,
            "model_error": "Model bundle unavailable; see backend logs.",
        }
