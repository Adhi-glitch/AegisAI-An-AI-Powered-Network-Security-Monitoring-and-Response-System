"""
AegisAI FastAPI application — v0.4.0

New in this version:
- JWT authentication (POST /api/v1/auth/token)
- Versioned API routers under /api/v1/
- Real-time WebSocket feed at /ws/feed
- Security headers + request logging middleware
- CORS configured for React SPA at localhost:5173 and localhost:3000
- Prometheus metrics at /metrics (via prometheus-fastapi-instrumentator)
- All legacy endpoints preserved for backward compatibility
"""
from __future__ import annotations

from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, Dict, Optional

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field

from agents.coordinator.coordinator import load_runtime, process_features
from agents.feature_extraction.csv_extractor import extract_from_row
from backend.middleware import RequestLoggingMiddleware, SecurityHeadersMiddleware
from backend.routers import alerts as alerts_router
from backend.routers import actions as actions_router
from backend.routers import auth as auth_router
from backend.routers import detections as detections_router
from backend.routers import stats as stats_router
from backend.routers import ws as ws_router
from database import models
from database.init_db import SessionLocal, init_db


# ── Lifespan ──────────────────────────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialise DB and load ML model bundle on startup."""
    init_db()
    try:
        load_runtime()
        print("[OK] Detection model bundle loaded")
    except FileNotFoundError as exc:
        print(f"[WARN] Model bundle not loaded ({exc}). /alerts will store-only.")
    yield


# ── App factory ───────────────────────────────────────────────────────────────
app = FastAPI(
    title="AegisAI API",
    version="0.4.0",
    description="AI-powered Network Intrusion Detection and Response System",
    lifespan=lifespan,
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json",
)

# ── CORS ──────────────────────────────────────────────────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://127.0.0.1:3000",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Custom middleware (order matters — outermost applied last) ─────────────────
app.add_middleware(RequestLoggingMiddleware)
app.add_middleware(SecurityHeadersMiddleware)

# ── Prometheus metrics (optional — graceful skip if not installed) ─────────────
try:
    from prometheus_fastapi_instrumentator import Instrumentator
    Instrumentator().instrument(app).expose(app, endpoint="/metrics")
except ImportError:
    pass  # prometheus-fastapi-instrumentator not installed, metrics disabled

# ── Versioned API routers ──────────────────────────────────────────────────────
app.include_router(auth_router.router)
app.include_router(alerts_router.router)
app.include_router(detections_router.router)
app.include_router(actions_router.router)
app.include_router(stats_router.router)
app.include_router(ws_router.router)

# ── Static assets & Jinja2 dashboard (legacy) ─────────────────────────────────
BASE_DIR = Path(__file__).resolve().parent
TEMPLATES_DIR = BASE_DIR / "templates"
STATIC_DIR = BASE_DIR / "static"
TEMPLATES_DIR.mkdir(parents=True, exist_ok=True)
STATIC_DIR.mkdir(parents=True, exist_ok=True)

templates = Jinja2Templates(directory=str(TEMPLATES_DIR))
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


# ═══════════════════════════════════════════════════════════════════════════════
# Legacy endpoints (v0.3 backward compatibility — kept for existing tooling)
# ═══════════════════════════════════════════════════════════════════════════════

class AlertIn(BaseModel):
    source_ip: str = "unknown"
    dest_ip: str = "unknown"
    protocol: Optional[str] = None
    raw_features: Dict[str, Any] = Field(default_factory=dict)
    run_detection: bool = True


class ActionUnblock(BaseModel):
    ip: str


class ReplayRow(BaseModel):
    """Flat feature map (CSV-like) for the /detect endpoint."""
    features: Dict[str, Any]
    source_ip: str = "unknown"
    dest_ip: str = "unknown"
    protocol: Optional[str] = None


@app.get("/", response_class=HTMLResponse, include_in_schema=False)
def dashboard(request: Request):
    """Legacy Jinja2 dashboard (still served at root for backward compat)."""
    return templates.TemplateResponse(request, "dashboard.html")


@app.post("/alerts", include_in_schema=False)
async def ingest_alert_legacy(alert: AlertIn):
    """Legacy alert ingest — no auth required (backward compat)."""
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

            # Also broadcast via WS
            from backend.routers.ws import manager as ws_manager
            try:
                await ws_manager.broadcast({
                    "id": detection_id,
                    "alert_id": a.id,
                    "predicted_class": result["predicted"],
                    "confidence": result["confidence"],
                    "source_ip": alert.source_ip,
                    "action": result.get("action"),
                    "timestamp": a.timestamp.isoformat() if a.timestamp else None,
                })
            except Exception:
                pass

        return {"id": a.id, "detection_id": detection_id, "action_id": action_id, "result": result}
    finally:
        db.close()


@app.post("/detect", include_in_schema=False)
async def detect_row_legacy(row: ReplayRow):
    """Legacy detect endpoint — no DB write."""
    features = extract_from_row(row.features)
    features["source_ip"] = row.source_ip
    features["dest_ip"] = row.dest_ip
    if row.protocol:
        features["protocol"] = row.protocol
    return process_features(features)


@app.get("/alerts", include_in_schema=False)
def list_alerts_legacy(limit: int = 100):
    """Legacy alerts list — no pagination."""
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


@app.get("/detections", include_in_schema=False)
def list_detections_legacy(limit: int = 100):
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


@app.get("/actions", include_in_schema=False)
def list_actions_legacy(limit: int = 100):
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


@app.get("/stats", include_in_schema=False)
def stats_legacy():
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


@app.get("/health", include_in_schema=False)
async def health_legacy():
    model_ok = False
    try:
        load_runtime()
        model_ok = True
    except FileNotFoundError:
        model_ok = False
    return {"status": "ok", "model_loaded": model_ok}


@app.post("/actions/unblock", include_in_schema=False)
def manual_unblock_legacy(req: ActionUnblock):
    from agents.response.response_engine import engine
    return engine.manual_unblock(req.ip)
