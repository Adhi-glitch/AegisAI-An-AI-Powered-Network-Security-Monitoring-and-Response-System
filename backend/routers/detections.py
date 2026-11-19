"""
Detections v1 router — paginated list, single detail, 24h timeline.
GET /api/v1/detections               — paginated
GET /api/v1/detections/timeline      — hourly counts for last 24h
GET /api/v1/detections/{det_id}      — single detection with explanation
"""
from __future__ import annotations

import csv
from datetime import datetime, timedelta
from io import StringIO

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import StreamingResponse

from backend.auth import get_current_user, get_current_viewer
from agents.detection.threat_policy import threat_severity
from database import models
from database.init_db import SessionLocal
from backend.threat_policy import harmful_detection_filters

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
        "detection_source": d.detection_source,
        "severity": (
            threat_severity(d.predicted_class, conf)
            or (d.alert.severity if d.alert else None)
        ),
    }


@router.get("", summary="List detections (paginated)")
def list_detections(
    page: int = Query(default=1, ge=1),
    limit: int = Query(default=50, ge=1, le=200),
    _user: dict = Depends(get_current_user),
):
    """Return detections newest-first with pagination metadata."""
    db = SessionLocal()
    try:
        query = db.query(models.Detection).filter(*harmful_detection_filters())
        total = query.count()
        items = (
            query
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
def detections_timeline(_user: dict = Depends(get_current_user)):
    """
    Return a list of {hour, count} dicts for the last 24 hours.
    Used to render the area chart on the dashboard.
    """
    db = SessionLocal()
    try:
        now = datetime.now()
        since = now - timedelta(hours=24)

        detections = (
            db.query(models.Detection)
            .join(models.Alert, models.Detection.alert_id == models.Alert.id)
            .filter(*harmful_detection_filters())
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
            alert = d.alert
            if alert and alert.timestamp:
                label = alert.timestamp.strftime("%H:00")
                if label in buckets:
                    buckets[label] += 1

        return [{"hour": h, "count": c} for h, c in buckets.items()]
    finally:
        db.close()


@router.get("/export.csv", summary="Export a viewer threat report")
def export_threat_report(_viewer: dict = Depends(get_current_viewer)):
    """Stream persisted Phase 1 threats as a CSV for viewer review."""
    def rows():
        db = SessionLocal()
        try:
            output = StringIO(newline="")
            writer = csv.writer(output)
            writer.writerow(
                ["detection_id", "alert_id", "timestamp", "threat", "severity",
                 "confidence", "detection_source", "source_ip", "dest_ip", "protocol"]
            )
            yield output.getvalue()

            query = (
                db.query(models.Detection, models.Alert)
                .join(models.Alert, models.Detection.alert_id == models.Alert.id)
                .filter(*harmful_detection_filters())
                .order_by(models.Detection.id.desc())
                .yield_per(500)
            )
            for detection, alert in query:
                output = StringIO(newline="")
                writer = csv.writer(output)
                writer.writerow(
                    [
                        detection.id,
                        alert.id,
                        alert.timestamp.isoformat() if alert.timestamp else "",
                        detection.predicted_class,
                        threat_severity(detection.predicted_class, detection.confidence)
                        or alert.severity
                        or "",
                        detection.confidence,
                        detection.detection_source,
                        alert.source_ip,
                        alert.dest_ip,
                        alert.protocol,
                    ]
                )
                yield output.getvalue()
        finally:
            db.close()

    return StreamingResponse(
        rows(),
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": 'attachment; filename="aegisai-threat-report.csv"'},
    )


@router.get("/{det_id}", summary="Single detection detail")
def get_detection(
    det_id: int,
    _user: dict = Depends(get_current_user),
):
    """Return a single detection with its confidence and associated alert info."""
    db = SessionLocal()
    try:
        d = (
            db.query(models.Detection)
            .filter(models.Detection.id == det_id, *harmful_detection_filters())
            .first()
        )
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
