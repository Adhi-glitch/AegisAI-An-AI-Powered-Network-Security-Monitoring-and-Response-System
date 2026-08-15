"""
AegisAI FastAPI backend: alert ingest with live detection, listings, stats, dashboard.
"""
from __future__ import annotations

from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, Dict, Optional

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field

from agents.coordinator.coordinator import load_runtime, process_features
from agents.feature_extraction.csv_extractor import extract_from_row
from database import models
from database.init_db import SessionLocal, init_db

@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    try:
        load_runtime()
        print("Loaded detection model bundle")
    except FileNotFoundError as exc:
        print(f"WARNING: model bundle not loaded ({exc}). /alerts will store only.")
    yield


app = FastAPI(title="AegisAI API", version="0.3.0", lifespan=lifespan)

BASE_DIR = Path(__file__).resolve().parent
TEMPLATES_DIR = BASE_DIR / "templates"
STATIC_DIR = BASE_DIR / "static"
TEMPLATES_DIR.mkdir(parents=True, exist_ok=True)
STATIC_DIR.mkdir(parents=True, exist_ok=True)

templates = Jinja2Templates(directory=str(TEMPLATES_DIR))
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


class AlertIn(BaseModel):
    source_ip: str = "unknown"
    dest_ip: str = "unknown"
    protocol: Optional[str] = None
    raw_features: Dict[str, Any] = Field(default_factory=dict)
    run_detection: bool = True


class ActionUnblock(BaseModel):
    ip: str


class ReplayRow(BaseModel):
    """Optional helper body: a flat feature map (CSV-like)."""
    features: Dict[str, Any]
    source_ip: str = "unknown"
    dest_ip: str = "unknown"
    protocol: Optional[str] = None


@app.get("/", response_class=HTMLResponse)
def dashboard(request: Request):
    return templates.TemplateResponse(request, "dashboard.html")


@app.post("/alerts")
async def ingest_alert(alert: AlertIn):
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
                action_type=str(result.get("action") or result.get("response", {}).get("status")),
            )
            db.add(act)
            db.commit()
            db.refresh(act)
            action_id = act.id

        return {
            "id": a.id,
            "detection_id": detection_id,
            "action_id": action_id,
            "result": result,
        }
    finally:
        db.close()


@app.post("/detect")
async def detect_row(row: ReplayRow):
    """Run detection on a flat feature map without requiring a prior alert id."""
    features = extract_from_row(row.features)
    features["source_ip"] = row.source_ip
    features["dest_ip"] = row.dest_ip
    if row.protocol:
        features["protocol"] = row.protocol
    result = process_features(features)
    return result


@app.get("/alerts")
def list_alerts(limit: int = 100):
    db = SessionLocal()
    try:
        items = (
            db.query(models.Alert)
            .order_by(models.Alert.timestamp.desc())
            .limit(limit)
            .all()
        )
        return [
            {
                "id": a.id,
                "timestamp": a.timestamp.isoformat() if a.timestamp else None,
                "source_ip": a.source_ip,
                "dest_ip": a.dest_ip,
                "protocol": a.protocol,
            }
            for a in items
        ]
    finally:
        db.close()


@app.get("/detections")
def list_detections(limit: int = 100):
    db = SessionLocal()
    try:
        items = (
            db.query(models.Detection)
            .order_by(models.Detection.id.desc())
            .limit(limit)
            .all()
        )
        return [
            {
                "id": d.id,
                "alert_id": d.alert_id,
                "predicted_class": d.predicted_class,
                "confidence": d.confidence,
                "model_version": d.model_version,
            }
            for d in items
        ]
    finally:
        db.close()


@app.get("/actions")
def list_actions(limit: int = 100):
    db = SessionLocal()
    try:
        items = (
            db.query(models.Action)
            .order_by(models.Action.id.desc())
            .limit(limit)
            .all()
        )
        return [
            {
                "id": a.id,
                "detection_id": a.detection_id,
                "action_type": a.action_type,
                "timestamp": a.timestamp.isoformat() if a.timestamp else None,
                "reversed_at": a.reversed_at.isoformat() if a.reversed_at else None,
            }
            for a in items
        ]
    finally:
        db.close()


@app.get("/stats")
def stats():
    db = SessionLocal()
    try:
        alerts_n = db.query(models.Alert).count()
        dets = db.query(models.Detection).all()
        actions = db.query(models.Action).all()
        by_class: Dict[str, int] = {}
        for d in dets:
            by_class[d.predicted_class] = by_class.get(d.predicted_class, 0) + 1
        by_action: Dict[str, int] = {}
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


@app.post("/actions/unblock")
def manual_unblock(req: ActionUnblock):
    from agents.response.response_engine import engine

    res = engine.manual_unblock(req.ip)
    return res


@app.get("/health")
async def health():
    model_ok = False
    try:
        load_runtime()
        model_ok = True
    except FileNotFoundError:
        model_ok = False
    return {"status": "ok", "model_loaded": model_ok}
