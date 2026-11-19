"""Operational APIs for analyst feedback, intel, health, search, and posture."""
from __future__ import annotations

from datetime import datetime, timedelta
import ipaddress
from pathlib import Path
import re
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field, field_validator

from agents.coordinator.coordinator import load_runtime
from backend.auth import get_current_admin, get_current_user
from database import models
from database.init_db import SessionLocal
from agents.analytics.features import feedback_queue, network_graph, posture_digest, psi, simulate_scenario
from agents.explainability.explain import explain_prediction_2

router = APIRouter(prefix="/api/v1", tags=["operations"])


class FeedbackRequest(BaseModel):
    label: Literal["true_positive", "false_positive", "unsure"]
    notes: str | None = Field(default=None, max_length=1000)


class AssetRequest(BaseModel):
    ip: str = Field(min_length=3, max_length=45)
    hostname: str | None = Field(default=None, max_length=255)
    criticality: Literal["low", "medium", "high", "critical"] = "low"
    tags: list[str] = Field(default_factory=list, max_length=20)


class SimulationRequest(BaseModel):
    stages: list[str] = Field(min_length=1, max_length=50)
    speed: float = Field(default=1.0, gt=0.0, le=100.0)
    false_positive_count: int = Field(default=0, ge=0, le=100000)


class DriftRequest(BaseModel):
    baseline: list[float] = Field(min_length=1, max_length=100000)
    current: list[float] = Field(min_length=1, max_length=100000)


class SavedSearchRequest(BaseModel):
    name: str = Field(min_length=1, max_length=96)
    query: str = Field(min_length=2, max_length=500)


class WatchlistRequest(BaseModel):
    name: str = Field(min_length=1, max_length=96)
    ip: str = Field(min_length=3, max_length=45)


class FeedItem(BaseModel):
    ip: str = Field(min_length=3, max_length=45)
    threat_type: str = Field(min_length=1, max_length=64)
    source: str = Field(min_length=1, max_length=64)
    severity: Literal["low", "medium", "high", "critical"] = "medium"
    abuse_score: float | None = Field(default=None, ge=0.0, le=100.0)
    country_code: str | None = Field(default=None, max_length=8)

    @field_validator("ip")
    @classmethod
    def normalize_ip(cls, value: str) -> str:
        try:
            return ipaddress.ip_address(value.strip()).compressed
        except ValueError as exc:
            raise ValueError("ip must be a valid IPv4 or IPv6 address") from exc


def parse_alert_query(query: str) -> dict[str, Any]:
    """Convert a narrow English query to validated filters, never SQL."""
    lowered = query.lower()
    filters: dict[str, Any] = {}
    attack = re.search(r"(brute force|port scan|web attack|botnet|ddos|dos)", lowered)
    hours = re.search(r"last\s+(\d+)\s+hours?", lowered)
    confidence = re.search(r"confidence\s+(?:above|over|>)\s*(0(?:\.\d+)?|1(?:\.0)?)", lowered)
    if attack:
        filters["attack_type"] = attack.group(1).title()
    if hours:
        filters["since"] = datetime.now() - timedelta(hours=min(int(hours.group(1)), 24 * 365))
    if confidence:
        filters["min_confidence"] = float(confidence.group(1))
    return filters


@router.post("/alerts/{alert_id}/feedback", summary="Record analyst feedback")
def add_feedback(alert_id: int, request: FeedbackRequest, admin: dict = Depends(get_current_admin)):
    db = SessionLocal()
    try:
        if not db.query(models.Alert).filter(models.Alert.id == alert_id).first():
            raise HTTPException(status_code=404, detail="Alert not found")
        feedback = models.AlertFeedback(alert_id=alert_id, label=request.label, notes=request.notes, analyst=admin.get("username"))
        db.add(feedback)
        db.commit()
        return {"id": feedback.id, "alert_id": alert_id, "label": feedback.label}
    finally:
        db.close()


@router.get("/feedback/summary", summary="Summarize analyst feedback")
def feedback_summary(_user: dict = Depends(get_current_user)):
    db = SessionLocal()
    try:
        rows = db.query(models.AlertFeedback).all()
        by_label: dict[str, int] = {}
        for row in rows:
            by_label[row.label] = by_label.get(row.label, 0) + 1
        total = len(rows)
        return {"total": total, "by_label": by_label, "false_positive_rate": (by_label.get("false_positive", 0) / total if total else 0.0), "uncertain_count": len(feedback_queue(rows))}
    finally:
        db.close()


@router.get("/threat-intel/{ip}", summary="Look up local threat intelligence")
def threat_intel(ip: str, _user: dict = Depends(get_current_user)):
    try:
        normalized_ip = ipaddress.ip_address(ip).compressed
    except ValueError as exc:
        raise HTTPException(status_code=422, detail="ip must be a valid IPv4 or IPv6 address") from exc
    db = SessionLocal()
    try:
        rows = db.query(models.ThreatFeed).filter(models.ThreatFeed.ip == normalized_ip).order_by(models.ThreatFeed.last_seen.desc()).all()
        return {"ip": normalized_ip, "known_bad": bool(rows), "items": [{"source": row.source, "threat_type": row.threat_type, "severity": row.severity, "abuse_score": row.abuse_score, "country_code": row.country_code} for row in rows]}
    finally:
        db.close()


@router.get("/model-health", summary="Return model registry health")
def model_health(_user: dict = Depends(get_current_user)):
    try:
        runtime = load_runtime()
    except Exception as exc:
        return {
            "active_model": None,
            "validation_accuracy": None,
            "drift_status": "unavailable",
            "evaluation_status": "unavailable",
            "capture_overlap_warning": None,
            "model_error": str(exc),
        }

    metadata = runtime.get("metadata") or {}
    db = SessionLocal()
    try:
        active = db.query(models.ModelRun).filter(models.ModelRun.is_active.is_(True)).order_by(models.ModelRun.trained_at.desc()).first()
        split_strategy = str(metadata.get("split_strategy", ""))
        capture_overlap = bool(metadata.get("capture_overlap_warning", False)) or (
            "capture_overlap" in split_strategy
        )
        return {
            "active_model": Path(runtime["bundle_dir"]).name,
            "registered_version": active.version if active else None,
            "accuracy": active.accuracy if active else None,
            "f1_score": active.f1_score if active else None,
            "validation_accuracy": metadata.get("val_accuracy"),
            "drift_status": "baseline_unavailable",
            "evaluation_status": (
                "exploratory"
                if capture_overlap or "capture_overlap" in split_strategy
                else "not_independently_verified"
            ),
            "capture_overlap_warning": capture_overlap,
            "retrain_status": "idle",
        }
    finally:
        db.close()


@router.get("/assets", summary="List discovered assets")
def list_assets(_user: dict = Depends(get_current_user)):
    db = SessionLocal()
    try:
        return {"items": [{"ip": asset.ip, "hostname": asset.hostname, "criticality": asset.criticality, "tags": asset.tags or [], "compromised": asset.compromised, "isolated": asset.isolated} for asset in db.query(models.Asset).order_by(models.Asset.ip).all()]}
    finally:
        db.close()


@router.put("/assets/{ip}", summary="Set asset criticality")
def upsert_asset(ip: str, request: AssetRequest, _admin: dict = Depends(get_current_admin)):
    db = SessionLocal()
    try:
        asset = db.query(models.Asset).filter(models.Asset.ip == ip).first()
        if asset is None:
            asset = models.Asset(ip=ip)
            db.add(asset)
        asset.hostname, asset.criticality, asset.tags = request.hostname, request.criticality, request.tags
        db.commit()
        return {"ip": asset.ip, "criticality": asset.criticality, "tags": asset.tags}
    finally:
        db.close()


@router.post("/alerts/search", summary="Search alerts with validated natural language filters")
def search_alerts(query: str = Query(min_length=2, max_length=500), _user: dict = Depends(get_current_user)):
    filters = parse_alert_query(query)
    db = SessionLocal()
    try:
        rows = db.query(models.Alert).join(models.Detection, models.Detection.alert_id == models.Alert.id).all()
        items = []
        for alert in rows:
            detections = alert.detections or []
            if filters.get("attack_type") and not any(d.predicted_class == filters["attack_type"] for d in detections):
                continue
            if filters.get("since") and (alert.timestamp is None or alert.timestamp < filters["since"]):
                continue
            if filters.get("min_confidence") and not any(float(d.confidence or 0) >= filters["min_confidence"] for d in detections):
                continue
            items.append({"id": alert.id, "source_ip": alert.source_ip, "dest_ip": alert.dest_ip, "timestamp": alert.timestamp.isoformat() if alert.timestamp else None})
        return {"filters": {key: value.isoformat() if isinstance(value, datetime) else value for key, value in filters.items()}, "items": items}
    finally:
        db.close()


@router.get("/posture", summary="Calculate current security posture")
def posture(_user: dict = Depends(get_current_user)):
    db = SessionLocal()
    try:
        unresolved = db.query(models.Incident).filter(models.Incident.status.not_in(["closed", "contained"])).count()
        total_alerts = db.query(models.Alert).count()
        score = max(0, min(100, 100 - unresolved * 10 - min(total_alerts, 50)))
        return posture_digest(attack_volume=total_alerts, blocked=0, unresolved_incidents=unresolved, model_health=1.0)
    finally:
        db.close()


@router.get("/feedback/queue", summary="List uncertain feedback samples")
def feedback_queue_endpoint(_admin: dict = Depends(get_current_admin)):
    db = SessionLocal()
    try:
        return {"items": [{"id": row.id, "alert_id": row.alert_id, "notes": row.notes, "created_at": row.created_at.isoformat() if row.created_at else None} for row in feedback_queue(db.query(models.AlertFeedback).all())]}
    finally:
        db.close()


@router.post("/attack-lab/simulate", summary="Run a packet-free attack simulation")
def simulate(request: SimulationRequest, _admin: dict = Depends(get_current_admin)):
    return simulate_scenario(request.stages, request.speed, request.false_positive_count)


@router.post("/model-health/drift", summary="Calculate feature population stability")
def drift(request: DriftRequest, _user: dict = Depends(get_current_user)):
    value = psi(request.baseline, request.current)
    return {"psi": value, "status": "degraded" if value >= 0.25 else "watch" if value >= 0.1 else "healthy"}


@router.post("/network/graph", summary="Build a live flow graph")
def graph(events: list[dict[str, Any]], _user: dict = Depends(get_current_user)):
    result = network_graph(events)
    db = SessionLocal()
    try:
        for node in result["nodes"]:
            asset = db.query(models.Asset).filter(models.Asset.ip == node["id"]).first()
            if asset is None:
                db.add(models.Asset(ip=node["id"], criticality=str(node.get("criticality", "low"))))
            else:
                asset.last_seen = datetime.now()
        db.commit()
    finally:
        db.close()
    return result | {"persisted_assets": len(result["nodes"])}


@router.post("/alerts/explain", summary="Explain a prediction")
def explain(request: dict[str, Any], _user: dict = Depends(get_current_user)):
    return explain_prediction_2(str(request.get("predicted_class", "unknown")), dict(request.get("features", {})))


@router.post("/searches", summary="Save a validated alert search")
def save_search(request: SavedSearchRequest, user: dict = Depends(get_current_user)):
    filters = parse_alert_query(request.query)
    db = SessionLocal()
    try:
        row = models.SavedSearch(name=request.name, query=request.query, filters={key: value.isoformat() if isinstance(value, datetime) else value for key, value in filters.items()}, owner=user.get("username"))
        db.add(row); db.commit(); db.refresh(row)
        return {"id": row.id, "name": row.name, "filters": row.filters}
    finally:
        db.close()


@router.get("/searches", summary="List saved alert searches")
def list_searches(user: dict = Depends(get_current_user)):
    db = SessionLocal()
    try:
        rows = db.query(models.SavedSearch).filter(models.SavedSearch.owner == user.get("username")).all()
        return {"items": [{"id": row.id, "name": row.name, "query": row.query, "filters": row.filters} for row in rows]}
    finally:
        db.close()


@router.post("/watchlists", summary="Create an IP watchlist entry")
def create_watchlist(request: WatchlistRequest, user: dict = Depends(get_current_user)):
    db = SessionLocal()
    try:
        row = models.Watchlist(name=request.name, ip=request.ip, owner=user.get("username"))
        db.add(row); db.commit(); db.refresh(row)
        return {"id": row.id, "name": row.name, "ip": row.ip, "enabled": row.enabled}
    finally:
        db.close()


@router.post("/threat-intel/import", summary="Import local threat feed entries")
def import_feed(items: list[FeedItem], _admin: dict = Depends(get_current_admin)):
    db = SessionLocal()
    try:
        created = 0
        updated = 0
        for item in items:
            values = item.model_dump()
            row = (
                db.query(models.ThreatFeed)
                .filter(
                    models.ThreatFeed.ip == values["ip"],
                    models.ThreatFeed.source == values["source"],
                    models.ThreatFeed.threat_type == values["threat_type"],
                )
                .first()
            )
            if row is None:
                db.add(models.ThreatFeed(**values))
                created += 1
            else:
                for key, value in values.items():
                    setattr(row, key, value)
                row.last_seen = models.utc_now()
                updated += 1
            db.flush()
        db.commit()
        return {"imported": len(items), "created": created, "updated": updated}
    finally:
        db.close()


@router.get("/threat-intel/export", summary="Export local threat feed entries")
def export_feed(_admin: dict = Depends(get_current_admin)):
    db = SessionLocal()
    try:
        rows = db.query(models.ThreatFeed).order_by(models.ThreatFeed.ip).all()
        return {"items": [{"ip": row.ip, "threat_type": row.threat_type, "source": row.source, "severity": row.severity, "abuse_score": row.abuse_score, "country_code": row.country_code} for row in rows]}
    finally:
        db.close()


@router.get("/posture/digest", summary="Generate a posture digest")
def digest(_user: dict = Depends(get_current_user)):
    db = SessionLocal()
    try:
        unresolved = db.query(models.Incident).filter(models.Incident.status.not_in(["closed", "contained"])).count()
        return posture_digest(attack_volume=db.query(models.Alert).count(), blocked=0, unresolved_incidents=unresolved, model_health=1.0) | {"period": "daily"}
    finally:
        db.close()