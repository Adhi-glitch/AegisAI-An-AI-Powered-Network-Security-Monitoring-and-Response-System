"""Authenticated controls for live packet capture and flow detection."""
from __future__ import annotations

import asyncio
import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field, field_validator

from agents.coordinator.coordinator import get_recorded_action, load_runtime, process_features
from agents.detection.live_rules import RULE_DETECTION_LABELS, is_rule_detection
from agents.detection.threat_policy import threat_severity
from backend.auth import get_current_admin, get_current_user
from backend.routers.ws import manager as ws_manager
from database import models
from database.init_db import SessionLocal
from ml.data.multidataset import LIVE_FEATURE_COLUMNS
from network_capture import get_capture_status, get_interfaces, start_capture, stop_capture

router = APIRouter(prefix="/api/v1/capture", tags=["live capture"])
_LOGGER = logging.getLogger(__name__)


class CaptureStart(BaseModel):
    interface: str | None = Field(default=None, max_length=256)
    bpf_filter: str = Field(default="ip", min_length=1, max_length=512)
    idle_timeout: float = Field(default=2.0, ge=0.1, le=30.0)

    @field_validator("bpf_filter")
    @classmethod
    def normalize_bpf_filter(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized or "\x00" in normalized:
            raise ValueError("bpf_filter must be a non-empty BPF expression")
        return normalized


def _validate_live_model_schema() -> None:
    try:
        runtime = load_runtime()
    except Exception as exc:
        _LOGGER.exception("Could not load the active model for live capture")
        raise RuntimeError(f"Could not load the active model bundle: {exc}") from exc

    columns = runtime.get("columns") or []
    if columns != LIVE_FEATURE_COLUMNS:
        bundle_dir = runtime.get("bundle_dir", "unknown bundle")
        raise RuntimeError(
            "The active model bundle does not match the live flow feature schema. "
            f"Expected {len(LIVE_FEATURE_COLUMNS)} ordered live features, got {len(columns)} "
            f"from {bundle_dir}. Activate a live-compatible bundle and restart the backend."
        )


def _persist_rule_detection(features: dict[str, Any], loop: asyncio.AbstractEventLoop) -> None:
    detection_source = features.get("detection_source")
    predicted_class = features.get("predicted")
    if not is_rule_detection(detection_source, predicted_class):
        raise ValueError("Live rule event has an unknown source or threat class.")

    severity = features.get("severity")
    if severity not in {"low", "medium", "high"}:
        raise ValueError("Live rule event has an invalid severity.")

    protocol_number = features.get("protocol")
    protocol = {6: "TCP", 17: "UDP", 1: "ICMP"}.get(
        protocol_number,
        str(protocol_number or "unknown"),
    )
    db = SessionLocal()
    try:
        alert = models.Alert(
            source_ip=str(features["source_ip"]),
            dest_ip=str(features["dest_ip"]),
            protocol=protocol,
            raw_features=features,
            severity=severity,
        )
        db.add(alert)
        db.flush()

        detection = models.Detection(
            alert_id=alert.id,
            predicted_class=RULE_DETECTION_LABELS[detection_source],
            confidence=None,
            model_version="behavioral_rule",
            detection_source=detection_source,
        )
        db.add(detection)
        db.commit()
        db.refresh(alert)

        payload = {
            "id": detection.id,
            "alert_id": alert.id,
            "predicted_class": detection.predicted_class,
            "confidence": None,
            "severity": severity,
            "source_ip": alert.source_ip,
            "dest_ip": alert.dest_ip,
            "protocol": alert.protocol,
            "detection_source": detection_source,
            "indicator": features.get("indicator"),
            "window_seconds": features.get("window_seconds"),
            "action": "observed_only",
            "timestamp": alert.timestamp.isoformat() if alert.timestamp else None,
            "source": "live_capture",
        }
        for metric in (
            "distinct_destination_ports",
            "distinct_connection_attempts",
            "packet_count",
            "distinct_source_count",
            "source_ips",
            "dest_port",
            "evidence_note",
            "request_count",
            "concurrent_incomplete_connections",
            "minimum_age_seconds",
            "interval_seconds",
            "interval_count",
            "relative_jitter",
        ):
            if metric in features:
                payload[metric] = features[metric]
        if not loop.is_closed():
            asyncio.run_coroutine_threadsafe(ws_manager.broadcast(payload), loop)
    finally:
        db.close()


def _persist_live_flow(features: dict[str, Any], loop: asyncio.AbstractEventLoop) -> None:
    if features.get("detection_source") in RULE_DETECTION_LABELS:
        _persist_rule_detection(features, loop)
        return

    result = process_features(features)
    severity = threat_severity(result.get("predicted"), result.get("confidence"))
    traffic_payload = {
        "type": "traffic_flow",
        "source_ip": str(features.get("source_ip", "unknown")),
        "dest_ip": str(features.get("dest_ip", "unknown")),
        "protocol": str(features.get("protocol", "unknown")),
        "packets": int(features.get("total_packets", 0)),
        "bytes": int(features.get("total_bytes", 0)),
        "model_prediction": result.get("predicted"),
        "model_score": result.get("confidence"),
        "model_severity": severity,
    }
    if not loop.is_closed():
        asyncio.run_coroutine_threadsafe(ws_manager.broadcast(traffic_payload), loop)

    if severity is None:
        return

    db = SessionLocal()
    try:
        alert = models.Alert(
            source_ip=str(features.get("source_ip", "unknown")),
            dest_ip=str(features.get("dest_ip", "unknown")),
            protocol=str(features.get("protocol", "unknown")),
            raw_features=features,
            severity=severity,
        )
        db.add(alert)
        db.flush()

        detection = models.Detection(
            alert_id=alert.id,
            predicted_class=str(result["predicted"]),
            confidence=str(result["confidence"]),
            model_version="active_bundle",
            detection_source="model",
        )
        db.add(detection)
        db.flush()

        action = models.Action(
            detection_id=detection.id,
            action_type=get_recorded_action(result),
        )
        db.add(action)
        db.commit()
        db.refresh(alert)

        payload = {
            "id": detection.id,
            "alert_id": alert.id,
            "predicted_class": result["predicted"],
            "confidence": result["confidence"],
            "severity": severity,
            "source_ip": alert.source_ip,
            "action": action.action_type,
            "timestamp": alert.timestamp.isoformat() if alert.timestamp else None,
            "source": "live_capture",
        }
        if not loop.is_closed():
            asyncio.run_coroutine_threadsafe(ws_manager.broadcast(payload), loop)
    finally:
        db.close()


@router.get("/status", summary="Get live capture status")
def capture_status(_user: dict = Depends(get_current_user)):
    return get_capture_status()


@router.get("/interfaces", summary="List packet capture interfaces")
def capture_interfaces(_admin: dict = Depends(get_current_admin)):
    try:
        return {"interfaces": get_interfaces()}
    except Exception as exc:
        _LOGGER.exception("Could not enumerate packet capture interfaces")
        raise HTTPException(
            status_code=503,
            detail=f"Could not enumerate packet capture interfaces: {exc}",
        ) from exc


@router.post("/start", summary="Start live packet capture")
async def capture_start(request: CaptureStart, _admin: dict = Depends(get_current_admin)):
    loop = asyncio.get_running_loop()
    try:
        _validate_live_model_schema()
        return start_capture(
            lambda flow: _persist_live_flow(flow, loop),
            interface=request.interface,
            bpf_filter=request.bpf_filter,
            idle_timeout=request.idle_timeout,
        )
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


@router.post("/stop", summary="Stop live packet capture")
async def capture_stop(_admin: dict = Depends(get_current_admin)):
    import asyncio
    loop = asyncio.get_running_loop()
    try:
        # Run stop_capture in a thread so the blocking flush doesn't crash the event loop
        result = await loop.run_in_executor(None, stop_capture)
        if result.get("status") == "error":
            raise HTTPException(
                status_code=503,
                detail=result.get("last_error") or "Capture shutdown did not complete.",
            )
        return result
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc