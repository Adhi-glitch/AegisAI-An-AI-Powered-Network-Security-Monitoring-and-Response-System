"""
Alerts v1 router — paginated CRUD with live WebSocket broadcast.
GET  /api/v1/alerts              — paginated list
GET  /api/v1/alerts/{alert_id}   — single alert detail
POST /api/v1/alerts              — ingest alert + run detection (auth required)
"""
from __future__ import annotations

from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from agents.coordinator.coordinator import (
    ModelUnavailableError,
    get_recorded_action,
    process_features,
)
from agents.detection.live_rules import is_rule_detection
from agents.detection.threat_policy import threat_severity
from backend.auth import get_current_admin, get_current_user
from backend.threat_policy import harmful_detection_filters
from backend.routers.ws import manager as ws_manager
from database import models
from database.init_db import SessionLocal

router = APIRouter(prefix="/api/v1/alerts", tags=["alerts"])


# ── Schemas ───────────────────────────────────────────────────────────────────
class AlertIn(BaseModel):
    source_ip: str = "unknown"
    dest_ip: str = "unknown"
    protocol: Optional[str] = None
    raw_features: Dict[str, Any] = Field(default_factory=dict)
    run_detection: bool = True


class AlertOut(BaseModel):
    id: int
    timestamp: Optional[str]
    source_ip: str
    dest_ip: str
    protocol: Optional[str]
    severity: Optional[str] = None


class PaginatedAlerts(BaseModel):
    items: list[AlertOut]
    total: int
    page: int
    pages: int


# ── Helpers ───────────────────────────────────────────────────────────────────
def _alert_to_dict(a: models.Alert) -> dict:
    severity = next(
        (
            threat_severity(d.predicted_class, d.confidence)
            for d in a.detections or []
            if threat_severity(d.predicted_class, d.confidence) is not None
        ),
        None,
    )
    return {
        "id": a.id,
        "timestamp": a.timestamp.isoformat() if a.timestamp else None,
        "source_ip": a.source_ip,
        "dest_ip": a.dest_ip,
        "protocol": a.protocol,
        "severity": severity or getattr(a, "severity", None),
    }


# ── Endpoints ─────────────────────────────────────────────────────────────────
@router.get("", summary="List alerts (paginated)")
def list_alerts(
    page: int = Query(default=1, ge=1),
    limit: int = Query(default=50, ge=1, le=200),
    _user: dict = Depends(get_current_user),
):
    """Return a paginated list of alerts, newest first."""
    db = SessionLocal()
    try:
        query = (
            db.query(models.Alert)
            .join(models.Detection, models.Detection.alert_id == models.Alert.id)
            .filter(*harmful_detection_filters())
            .distinct()
        )
        total = query.count()
        items = (
            query
            .order_by(models.Alert.timestamp.desc())
            .offset((page - 1) * limit)
            .limit(limit)
            .all()
        )
        return {
            "items": [_alert_to_dict(a) for a in items],
            "total": total,
            "page": page,
            "pages": max(1, -(-total // limit)),  # ceiling division
        }
    finally:
        db.close()


@router.get("/{alert_id}", summary="Single alert detail")
def get_alert(
    alert_id: int,
    _user: dict = Depends(get_current_user),
):
    """Return full detail for a single alert including raw features."""
    db = SessionLocal()
    try:
        a = (
            db.query(models.Alert)
            .join(models.Detection, models.Detection.alert_id == models.Alert.id)
            .filter(models.Alert.id == alert_id, *harmful_detection_filters())
            .first()
        )
        if not a:
            raise HTTPException(status_code=404, detail="Alert not found")
        result = _alert_to_dict(a)
        result["raw_features"] = a.raw_features
        # Attach associated detections
        result["detections"] = [
            {
                "id": d.id,
                "predicted_class": d.predicted_class,
                "confidence": d.confidence,
                "model_version": d.model_version,
                "detection_source": d.detection_source,
                "severity": a.severity,
            }
            for d in (a.detections or [])
            if (
                threat_severity(d.predicted_class, d.confidence) is not None
                or is_rule_detection(d.detection_source, d.predicted_class)
            )
        ]
        return result
    finally:
        db.close()


@router.post("", summary="Ingest alert and run detection")
async def ingest_alert(
    alert: AlertIn,
    _admin: dict = Depends(get_current_admin),
):
    """
    Persist and broadcast only a supported threat classification.
    Requires administrator access; benign and low-confidence flows are not stored.
    """
    db = SessionLocal()
    try:
        features = dict(alert.raw_features or {})
        features.setdefault("source_ip", alert.source_ip)
        features.setdefault("dest_ip", alert.dest_ip)
        if alert.protocol:
            features.setdefault("protocol", alert.protocol)

        try:
            result = process_features(features) if alert.run_detection else None
        except ModelUnavailableError as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc
        severity = (
            threat_severity(result.get("predicted"), result.get("confidence"))
            if result is not None
            else None
        )
        if result is None or severity is None:
            return {
                "id": None,
                "detection_id": None,
                "action_id": None,
                "recorded": False,
                "result": result,
            }

        a = models.Alert(
            source_ip=alert.source_ip,
            dest_ip=alert.dest_ip,
            protocol=alert.protocol,
            raw_features=features,
            severity=severity,
        )
        db.add(a)
        db.flush()

        det = models.Detection(
            alert_id=a.id,
            predicted_class=str(result["predicted"]),
            confidence=str(result["confidence"]),
            model_version="active_bundle",
            detection_source="model",
        )
        db.add(det)
        db.flush()
        detection_id = det.id

        act = models.Action(
            detection_id=det.id,
            action_type=get_recorded_action(result),
        )
        db.add(act)
        db.commit()
        db.refresh(a)
        db.refresh(act)
        action_id = act.id

        broadcast_payload = {
            "id": detection_id,
            "alert_id": a.id,
            "predicted_class": result["predicted"],
            "confidence": result["confidence"],
            "severity": severity,
            "source_ip": alert.source_ip,
            "action": get_recorded_action(result),
            "timestamp": a.timestamp.isoformat() if a.timestamp else None,
        }
        await ws_manager.broadcast(broadcast_payload)

        return {
            "id": a.id,
            "detection_id": detection_id,
            "action_id": action_id,
            "recorded": True,
            "severity": severity,
            "result": result,
        }
    finally:
        db.close()
