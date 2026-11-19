"""Stateless incident correlation and report export endpoints."""
from __future__ import annotations

import hashlib
import json
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from fastapi.responses import Response

from agents.reporting import generate_incident_report, generate_pdf_report
from agents.reporting.incident_correlation import correlate_incidents, merge_incidents, split_incident
from backend.auth import get_current_admin, get_current_user
from database import models
from database.init_db import SessionLocal

router = APIRouter(prefix="/api/v1/incidents", tags=["incidents"])


class IncidentQuery(BaseModel):
    events: list[dict[str, Any]] = Field(default_factory=list, max_length=1000)
    window_seconds: int = Field(default=300, ge=1, le=86400)


class IncidentReportRequest(BaseModel):
    incident: dict[str, Any]
    export_format: Literal["json", "markdown", "text", "pdf"] = "json"


@router.get("", summary="List persisted incidents")
def list_incidents(_user: dict = Depends(get_current_user)):
    db = SessionLocal()
    try:
        rows = db.query(models.Incident).order_by(models.Incident.updated_at.desc()).limit(200).all()
        return {"items": [{"id": row.id, "incident_key": row.incident_key, "source_ip": row.source_ip, "dest_ip": row.dest_ip, "attack_type": row.attack_type, "severity": row.severity, "status": row.status, "kill_chain_stage": row.kill_chain_stage, "merged_into_id": row.merged_into_id, "split_from_id": row.split_from_id, "events": row.events or [], "timeline": row.timeline or []} for row in rows]}
    finally:
        db.close()


@router.post("/correlate", summary="Correlate events into incidents")
def correlate(request: IncidentQuery, _user: dict = Depends(get_current_user)):
    incidents = correlate_incidents(request.events, request.window_seconds)
    db = SessionLocal()
    try:
        for item in incidents:
            key = f"{item['source_ip']}|{item['dest_ip']}|{item['attack_type']}"
            row = db.query(models.Incident).filter(models.Incident.incident_key == key).first()
            if row is None:
                row = models.Incident(incident_key=key)
                db.add(row)
            row.source_ip = item["source_ip"]
            row.dest_ip = item["dest_ip"]
            row.attack_type = item["attack_type"]
            row.severity = item["severity"]
            row.kill_chain_stage = item["kill_chain_stage"]
            row.events = item["events"]
            row.timeline = item["timeline"]
        db.commit()
    finally:
        db.close()
    return {"items": incidents, "persisted": len(incidents)}


@router.post("/report", summary="Generate an incident report")
def report(request: IncidentReportRequest, _user: dict = Depends(get_current_user)):
    incident = dict(request.incident)
    if "events" not in incident:
        incident["events"] = incident.get("timeline", [])
    if request.export_format == "json":
        return {"report": generate_incident_report(incident, request.export_format)}
    if request.export_format == "markdown":
        return Response(generate_incident_report(incident, request.export_format), media_type="text/markdown")
    if request.export_format == "text":
        return Response(generate_incident_report(incident, request.export_format), media_type="text/plain")
    return Response(generate_pdf_report(incident), media_type="application/pdf", headers={"Content-Disposition": "attachment; filename=incident-report.pdf"})


class IncidentStatusRequest(BaseModel):
    status: Literal["open", "investigating", "contained", "closed"]


class IncidentMergeRequest(BaseModel):
    incident_ids: list[int] | None = Field(default=None, min_length=2, max_length=50)
    events: list[dict[str, Any]] = Field(default_factory=list, max_length=1000)
    window_seconds: int = Field(default=300, ge=1, le=86400)


@router.post("/{incident_id}/status", summary="Update an incident workflow status")
def status(
    incident_id: int,
    request: IncidentStatusRequest,
    _admin: dict = Depends(get_current_admin),
):
    db = SessionLocal()
    try:
        incident = db.query(models.Incident).filter(models.Incident.id == incident_id).first()
        if incident is None:
            raise HTTPException(status_code=404, detail="Incident not found")
        incident.status = request.status
        incident.updated_at = models.utc_now()
        db.commit()
        db.refresh(incident)
        return {
            "id": incident.id,
            "status": incident.status,
            "updated_at": incident.updated_at.isoformat() if incident.updated_at else None,
        }
    finally:
        db.close()


@router.post("/merge", summary="Merge incidents")
def merge(request: IncidentMergeRequest, _admin: dict = Depends(get_current_admin)):
    if request.incident_ids is None:
        if not request.events:
            raise HTTPException(status_code=422, detail="Provide incident_ids or at least one incident event")
        return merge_incidents(request.events)
    if len(set(request.incident_ids)) != len(request.incident_ids):
        raise HTTPException(status_code=422, detail="incident_ids must be unique")
    db = SessionLocal()
    try:
        rows = db.query(models.Incident).filter(models.Incident.id.in_(request.incident_ids)).all()
        by_id = {row.id: row for row in rows}
        if len(by_id) != len(request.incident_ids):
            raise HTTPException(status_code=404, detail="One or more incidents were not found")
        if any(by_id[incident_id].merged_into_id is not None for incident_id in request.incident_ids):
            raise HTTPException(status_code=409, detail="An incident has already been merged")
        primary = by_id[request.incident_ids[0]]
        selected = [by_id[incident_id] for incident_id in request.incident_ids]
        events = [event for row in selected for event in (row.events or [])]
        if any(not isinstance(event, dict) for event in events):
            raise HTTPException(status_code=409, detail="Stored incident event data is invalid")
        events.sort(key=lambda event: str(event.get("timestamp") or ""))
        timeline = [event["timestamp"] for event in events if event.get("timestamp") is not None]
        attacks = list(dict.fromkeys(row.attack_type for row in selected if row.attack_type))
        severities = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
        highest_severity = max(
            (row.severity or "info" for row in selected),
            key=lambda severity: severities.get(severity.lower(), 0),
        )
        sources = {row.source_ip for row in selected}
        destinations = {row.dest_ip for row in selected}
        stages = {row.kill_chain_stage for row in selected}
        primary.source_ip = next(iter(sources)) if len(sources) == 1 else None
        primary.dest_ip = next(iter(destinations)) if len(destinations) == 1 else None
        primary.attack_type = attacks[0] if len(attacks) == 1 else "Multiple"
        primary.severity = highest_severity
        primary.kill_chain_stage = next(iter(stages)) if len(stages) == 1 else "multiple"
        primary.events = events
        primary.timeline = timeline
        primary.status = "investigating"
        primary.updated_at = models.utc_now()
        for incident in selected[1:]:
            incident.status = "closed"
            incident.merged_into_id = primary.id
            incident.updated_at = models.utc_now()
        db.commit()
        db.refresh(primary)
        return {
            "id": primary.id,
            "status": primary.status,
            "merged_incident_ids": request.incident_ids[1:],
            "event_count": len(primary.events or []),
        }
    finally:
        db.close()


@router.post("/split", summary="Split incident events", deprecated=True)
def split_legacy(incident: dict[str, Any], _admin: dict = Depends(get_current_admin)):
    return {"items": split_incident(incident)}


@router.post("/{incident_id}/split", summary="Split an incident into event incidents")
def split(incident_id: int, _admin: dict = Depends(get_current_admin)):
    db = SessionLocal()
    try:
        incident = db.query(models.Incident).filter(models.Incident.id == incident_id).first()
        if incident is None:
            raise HTTPException(status_code=404, detail="Incident not found")
        events = incident.events or []
        if len(events) < 2:
            raise HTTPException(status_code=409, detail="At least two stored events are required to split an incident")
        children = []
        for index, event in enumerate(events, 1):
            if not isinstance(event, dict):
                raise HTTPException(status_code=409, detail="Stored incident event data is invalid")
            digest = hashlib.sha256(
                json.dumps(event, sort_keys=True, default=str).encode("utf-8")
            ).hexdigest()[:16]
            key = f"split-{incident.id}-{index}-{digest}"
            child = db.query(models.Incident).filter(models.Incident.incident_key == key).first()
            if child is None:
                child = models.Incident(incident_key=key)
                db.add(child)
            child.source_ip = str(event.get("source_ip") or incident.source_ip or "unknown")
            child.dest_ip = str(event.get("dest_ip") or incident.dest_ip or "unknown")
            child.attack_type = str(event.get("attack_type") or incident.attack_type or "unknown")
            child.severity = str(event.get("severity") or incident.severity or "info")
            child.status = "open"
            child.kill_chain_stage = incident.kill_chain_stage
            child.split_from_id = incident.id
            child.events = [event]
            child.timeline = [event.get("timestamp")]
            children.append(child)
            db.flush()
        incident.status = "closed"
        incident.updated_at = models.utc_now()
        db.commit()
        return {
            "parent_id": incident.id,
            "items": [
                {"id": child.id, "incident_key": child.incident_key, "status": child.status}
                for child in children
            ],
        }
    finally:
        db.close()