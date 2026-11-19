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
import logging
from pathlib import Path
from typing import Any, Dict, Optional

from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from sqlalchemy import func

from agents.coordinator.coordinator import (
    ModelUnavailableError,
    get_recorded_action,
    load_runtime,
    process_features,
)
from agents.detection.threat_policy import threat_severity
from agents.feature_extraction.csv_extractor import extract_from_row
from backend.auth import (
    ensure_bootstrap_users,
    get_current_admin,
    get_current_user,
    validate_security_config,
)
from backend.middleware import RequestLoggingMiddleware, SecurityHeadersMiddleware
from backend.routers import alerts as alerts_router
from backend.routers import actions as actions_router
from backend.routers import response as response_router
from backend.routers import copilot as copilot_router
from backend.routers import incidents as incidents_router
from backend.routers import operations as operations_router
from backend.routers import admin_tools as admin_tools_router
from backend.routers import auth as auth_router
from backend.routers import capture as capture_router
from backend.routers import detections as detections_router
from backend.routers import demo as demo_router
from backend.routers import stats as stats_router
from backend.routers import ws as ws_router
from backend.threat_policy import harmful_detection_filters
from database import models
from database.init_db import SessionLocal, init_db

_LOGGER = logging.getLogger(__name__)

# ── Lifespan ──────────────────────────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialise DB and load ML model bundle on startup."""
    validate_security_config()
    init_db()
    ensure_bootstrap_users()
    try:
        load_runtime()
        print("[OK] Detection model bundle loaded")
    except Exception:
        _LOGGER.exception("Model bundle unavailable at startup; API will run in degraded mode")
    yield
    try:
        from network_capture import stop_capture
        stop_capture()
    except Exception:
        pass  # Always shut down cleanly


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
        "http://localhost:8000",
        "http://127.0.0.1:8000",
    ],
    allow_origin_regex=r"^https?://(localhost|127\.0\.0\.1)(:\d+)?$",
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
app.include_router(capture_router.router)
app.include_router(demo_router.router)
app.include_router(alerts_router.router)
app.include_router(detections_router.router)
app.include_router(actions_router.router)
app.include_router(response_router.router)
app.include_router(copilot_router.router)
app.include_router(incidents_router.router)
app.include_router(operations_router.router)
app.include_router(admin_tools_router.router)
app.include_router(stats_router.router)
app.include_router(ws_router.router)

# ── Static assets & Frontends ──────────────────────────────────────────────────
BASE_DIR = Path(__file__).resolve().parent
ROOT_DIR = BASE_DIR.parent
FRONTEND_DIST = ROOT_DIR / "frontend" / "dist"
FRONTEND_ASSETS = FRONTEND_DIST / "assets"
FRONTEND_INDEX = FRONTEND_DIST / "index.html"

TEMPLATES_DIR = BASE_DIR / "templates"
STATIC_DIR = BASE_DIR / "static"
TEMPLATES_DIR.mkdir(parents=True, exist_ok=True)
STATIC_DIR.mkdir(parents=True, exist_ok=True)

templates = Jinja2Templates(directory=str(TEMPLATES_DIR))
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

if FRONTEND_ASSETS.exists():
    app.mount("/assets", StaticFiles(directory=str(FRONTEND_ASSETS)), name="assets")


class ReplayRow(BaseModel):
    """Flat feature map (CSV-like) for the legacy /detect endpoint."""
    features: Dict[str, Any]
    source_ip: str = "unknown"
    dest_ip: str = "unknown"
    protocol: Optional[str] = None


# ═══════════════════════════════════════════════════════════════════════════════
# Frontend routes
# ═══════════════════════════════════════════════════════════════════════════════

@app.get("/", include_in_schema=False)
def home_page(request: Request):
    """Serve the public AegisAI project homepage."""
    return templates.TemplateResponse(request, "home.html")


def serve_console():
    """Serve the React/Vite operator console."""
    if not FRONTEND_INDEX.is_file():
        raise HTTPException(
            status_code=503,
            detail="The React application has not been built. Run npm run build in frontend/.",
        )
    return FileResponse(str(FRONTEND_INDEX))


@app.get("/signin", include_in_schema=False)
def sign_in_page(request: Request):
    return templates.TemplateResponse(request, "signin.html")


@app.get("/dashboard", include_in_schema=False)
def dashboard_page(request: Request):
    return templates.TemplateResponse(request, "dashboard.html")


@app.get("/console", include_in_schema=False)
def console_page():
    return serve_console()


@app.get("/legacy", response_class=HTMLResponse, include_in_schema=False)
def legacy_dashboard(request: Request):
    """Serve the temporary Jinja dashboard during the React migration."""
    return templates.TemplateResponse(request, "dashboard.html")


@app.get("/favicon.svg", include_in_schema=False)
def serve_favicon():
    fav = FRONTEND_DIST / "favicon.svg"
    if fav.exists():
        return FileResponse(str(fav))
    raise HTTPException(status_code=404)


@app.get("/icons.svg", include_in_schema=False)
def serve_icons():
    ic = FRONTEND_DIST / "icons.svg"
    if ic.exists():
        return FileResponse(str(ic))
    raise HTTPException(status_code=404)


@app.post("/alerts", include_in_schema=False)
async def ingest_alert_legacy(
    alert: alerts_router.AlertIn,
    _admin: dict = Depends(get_current_admin),
):
    """Legacy alert ingest; administrator-only and harmful-threats-only."""
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

        from backend.routers.ws import manager as ws_manager
        await ws_manager.broadcast({
            "id": detection_id,
            "alert_id": a.id,
            "predicted_class": result["predicted"],
            "confidence": result["confidence"],
            "severity": severity,
            "source_ip": alert.source_ip,
            "action": get_recorded_action(result),
            "timestamp": a.timestamp.isoformat() if a.timestamp else None,
        })
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


@app.post("/detect", include_in_schema=False)
async def detect_row_legacy(
    row: ReplayRow,
    _admin: dict = Depends(get_current_admin),
):
    """Legacy detection endpoint; admin-only because inference can trigger a response."""
    features = extract_from_row(row.features)
    features["source_ip"] = row.source_ip
    features["dest_ip"] = row.dest_ip
    if row.protocol:
        features["protocol"] = row.protocol
    try:
        return process_features(features)
    except ModelUnavailableError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


@app.get("/alerts", include_in_schema=False)
def list_alerts_legacy(
    limit: int = Query(default=100, ge=1, le=200),
    _user: dict = Depends(get_current_user),
):
    """Legacy alerts list — no pagination."""
    db = SessionLocal()
    try:
        items = (
            db.query(models.Alert)
            .join(models.Detection, models.Detection.alert_id == models.Alert.id)
            .filter(*harmful_detection_filters())
            .distinct()
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
                "severity": next(
                    (
                        threat_severity(d.predicted_class, d.confidence)
                        for d in a.detections or []
                        if threat_severity(d.predicted_class, d.confidence) is not None
                    ),
                    a.severity,
                ),
            }
            for a in items
        ]
    finally:
        db.close()


@app.get("/detections", include_in_schema=False)
def list_detections_legacy(
    limit: int = Query(default=100, ge=1, le=200),
    _user: dict = Depends(get_current_user),
):
    db = SessionLocal()
    try:
        items = (
            db.query(models.Detection)
            .filter(*harmful_detection_filters())
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
                "detection_source": d.detection_source,
                "severity": (
                    threat_severity(d.predicted_class, d.confidence)
                    or (d.alert.severity if d.alert else None)
                ),
            }
            for d in items
        ]
    finally:
        db.close()


@app.get("/actions", include_in_schema=False)
def list_actions_legacy(
    limit: int = Query(default=100, ge=1, le=200),
    _user: dict = Depends(get_current_user),
):
    db = SessionLocal()
    try:
        items = (
            db.query(models.Action)
            .join(models.Detection, models.Action.detection_id == models.Detection.id)
            .filter(*harmful_detection_filters())
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
def stats_legacy(_user: dict = Depends(get_current_user)):
    db = SessionLocal()
    try:
        detection_query = db.query(models.Detection).filter(*harmful_detection_filters())
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
            "detections": detection_query.count(),
            "actions": sum(by_action.values()),
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
    except Exception:
        _LOGGER.exception("Legacy health check could not load model")
        return {
            "status": "ok",
            "model_loaded": model_ok,
            "model_error": "Model bundle unavailable; see backend logs.",
        }
    return {"status": "ok", "model_loaded": model_ok}


@app.post("/actions/unblock", include_in_schema=False)
def manual_unblock_legacy(
    req: actions_router.UnblockRequest,
    _admin: dict = Depends(get_current_admin),
):
    from agents.response.response_engine import engine
    return engine.manual_unblock(req.ip)


# ── Unknown routes ────────────────────────────────────────────────────────────
@app.get("/{full_path:path}", include_in_schema=False)
def unknown_route(full_path: str):
    if full_path.startswith(("api/", "ws/", "static/", "assets/", "metrics", "legacy")):
        raise HTTPException(status_code=404, detail="Not found")
    raise HTTPException(status_code=404, detail="Not found")
