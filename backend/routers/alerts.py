"""
Alerts v1 router — paginated CRUD with live WebSocket broadcast.
GET  /api/v1/alerts              — paginated list
GET  /api/v1/alerts/{alert_id}   — single alert detail
POST /api/v1/alerts              — ingest alert + run detection (auth required)
"""
from __future__ import annotations

import asyncio
from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from agents.coordinator.coordinator import load_runtime, process_features
from agents.feature_extraction.csv_extractor import extract_from_row
from backend.auth import get_current_user
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
    return {
        "id": a.id,
        "timestamp": a.timestamp.isoformat() if a.timestamp else None,
        "source_ip": a.source_ip,
        "dest_ip": a.dest_ip,
        "protocol": a.protocol,
        "severity": getattr(a, "severity", None),
    }


# ── Endpoints ─────────────────────────────────────────────────────────────────
@router.get("", summary="List alerts (paginated)")
def list_alerts(page: int = 1, limit: int = 50):
    """Return a paginated list of alerts, newest first."""
    page = max(1, page)
    limit = min(limit, 200)
    db = SessionLocal()
    try:
        total = db.query(models.Alert).count()
        items = (
            db.query(models.Alert)
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
def get_alert(alert_id: int):
    """Return full detail for a single alert including raw features."""
    db = SessionLocal()
    try:
        a = db.query(models.Alert).filter(models.Alert.id == alert_id).first()
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
            }
            for d in (a.detections or [])
        ]
        return result
    finally:
        db.close()


@router.post("", summary="Ingest alert and run detection")
async def ingest_alert(
    alert: AlertIn,
    current_user: dict = Depends(get_current_user),
):
    """
    Store an alert, optionally run detection, persist Detection + Action,
    and broadcast the result to all WebSocket clients.
    Requires authentication.
    """
    db = SessionLocal()
    try:
        features = dict(alert.raw_features or {})
        features.setdefault("source_ip", alert.source_ip)
        features.setdefault("dest_ip", alert.dest_ip)
        if alert.protocol:
            features.setdefault("protocol", alert.protocol)

        a = models.Alert(
            source_ip=alert.source_ip,
            dest_ip=alert.dest_ip,
            protocol=alert.protocol,
            raw_features=features,
        )
        db.add(a)
        db.commit()
        db.refresh(a)

        result = None
        detection_id = None
        action_id = None

        if alert.run_detection:
            result = process_features(features)

            det = models.Detection(
                alert_id=a.id,
                predicted_class=str(result["predicted"]),
                confidence=str(result["confidence"]),
                model_version="baseline_rf",
            )
            db.add(det)
            db.commit()
            db.refresh(det)
            detection_id = det.id

            act = models.Action(
                detection_id=det.id,
                action_type=str(
                    result.get("action")
                    or result.get("response", {}).get("status", "log")
                ),
            )
            db.add(act)
            db.commit()
            db.refresh(act)
            action_id = act.id

            # Broadcast to live WebSocket feed
            broadcast_payload = {
                "id": detection_id,
                "alert_id": a.id,
                "predicted_class": result["predicted"],
                "confidence": result["confidence"],
                "source_ip": alert.source_ip,
                "action": result.get("action"),
                "timestamp": a.timestamp.isoformat() if a.timestamp else None,
            }
            try:
                await ws_manager.broadcast(broadcast_payload)
            except Exception:
                pass

        return {
            "id": a.id,
            "detection_id": detection_id,
            "action_id": action_id,
            "result": result,
        }
    finally:
        db.close()
