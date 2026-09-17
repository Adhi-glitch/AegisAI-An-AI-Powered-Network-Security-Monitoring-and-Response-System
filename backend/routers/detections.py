"""
Detections v1 router — paginated list, single detail, 24h timeline.
GET /api/v1/detections               — paginated
GET /api/v1/detections/timeline      — hourly counts for last 24h
GET /api/v1/detections/{det_id}      — single detection with explanation
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, HTTPException

from database import models
from database.init_db import SessionLocal

router = APIRouter(prefix="/api/v1/detections", tags=["detections"])


def _det_to_dict(d: models.Detection) -> dict:
    conf = d.confidence
    # Normalise: stored as string, return as float when possible
    try:
        conf = float(conf)
    except (TypeError, ValueError):
        pass
    return {
        "id": d.id,
        "alert_id": d.alert_id,
        "predicted_class": d.predicted_class,
        "confidence": conf,
        "model_version": d.model_version,
    }


@router.get("", summary="List detections (paginated)")
def list_detections(page: int = 1, limit: int = 50):
    """Return detections newest-first with pagination metadata."""
    page = max(1, page)
    limit = min(limit, 200)
    db = SessionLocal()
    try:
        total = db.query(models.Detection).count()
        items = (
            db.query(models.Detection)
            .order_by(models.Detection.id.desc())
            .offset((page - 1) * limit)
            .limit(limit)
            .all()
        )
        return {
            "items": [_det_to_dict(d) for d in items],
            "total": total,
            "page": page,
            "pages": max(1, -(-total // limit)),
        }
    finally:
        db.close()


@router.get("/timeline", summary="Hourly detection counts for last 24h")
def detections_timeline():
    """
    Return a list of {hour, count} dicts for the last 24 hours.
    Used to render the area chart on the dashboard.
    """
    db = SessionLocal()
    try:
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        since = now - timedelta(hours=24)

        detections = (
            db.query(models.Detection)
            .join(models.Alert, models.Detection.alert_id == models.Alert.id)
            .filter(models.Alert.timestamp >= since)
            .all()
        )

        # Build hourly buckets (last 24 hours)
        buckets: dict[str, int] = {}
        for h in range(24):
            bucket_time = since + timedelta(hours=h)
            label = bucket_time.strftime("%H:00")
            buckets[label] = 0

        for d in detections:
            # Get timestamp from the joined alert (via relationship)
            try:
                alert = d.alert
                if alert and alert.timestamp:
                    label = alert.timestamp.strftime("%H:00")
                    if label in buckets:
                        buckets[label] += 1
            except Exception:
                pass

        return [{"hour": h, "count": c} for h, c in buckets.items()]
    finally:
        db.close()


@router.get("/{det_id}", summary="Single detection detail")
def get_detection(det_id: int):
    """Return a single detection with its confidence and associated alert info."""
    db = SessionLocal()
    try:
        d = db.query(models.Detection).filter(models.Detection.id == det_id).first()
        if not d:
            raise HTTPException(status_code=404, detail="Detection not found")
        result = _det_to_dict(d)
        # Include basic alert info
        if d.alert:
            result["alert"] = {
                "source_ip": d.alert.source_ip,
                "dest_ip": d.alert.dest_ip,
                "protocol": d.alert.protocol,
                "timestamp": d.alert.timestamp.isoformat() if d.alert.timestamp else None,
            }
        return result
    finally:
        db.close()
