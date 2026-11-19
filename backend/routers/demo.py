"""Admin-only, non-persistent replay of held-out model examples."""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Literal
from uuid import uuid4

import pandas as pd
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from agents.coordinator.coordinator import load_runtime
from agents.detection.inference import infer
from agents.detection.threat_policy import threat_severity
from backend.auth import get_current_admin
from backend.routers.ws import manager as ws_manager
from ml.data.multidataset import LABEL_TO_ID
from ml.models.bundle import vectorize_features

router = APIRouter(prefix="/api/v1/demo", tags=["safe demonstration"])
REPLAY_DATASET = (
    Path(__file__).resolve().parents[2]
    / "ml"
    / "data"
    / "splits"
    / "prototype"
    / "test.csv"
)
MAX_EXAMPLES_PER_LABEL = 128

ReplayLabel = Literal[
    "Botnet",
    "Brute Force",
    "DDoS",
    "DoS",
    "Port Scan",
    "Web Attack",
]


class ReplayRequest(BaseModel):
    labels: list[ReplayLabel] = Field(min_length=1, max_length=4)


@router.post("/replay", summary="Replay held-out samples as simulated detections")
async def replay_held_out_samples(
    request: ReplayRequest,
    _admin: dict = Depends(get_current_admin),
):
    """Run safe test-set examples through inference without sending or storing traffic."""
    if len(set(request.labels)) != len(request.labels):
        raise HTTPException(status_code=422, detail="Replay labels must be distinct.")
    if not REPLAY_DATASET.is_file():
        raise HTTPException(
            status_code=503,
            detail="Held-out demo samples are unavailable; no simulated events were produced.",
        )

    try:
        runtime = load_runtime()
    except Exception as exc:
        raise HTTPException(
            status_code=503,
            detail="The active model is unavailable; no simulated events were produced.",
        ) from exc

    if not runtime.get("model") or not runtime.get("columns") or not runtime.get("bundle_dir"):
        raise HTTPException(
            status_code=503,
            detail="The active model is incomplete; no simulated events were produced.",
        )

    samples = pd.read_csv(REPLAY_DATASET)
    if "label" not in samples.columns:
        raise HTTPException(
            status_code=503,
            detail="Held-out demo samples have no labels; no simulated events were produced.",
        )

    numeric_labels = pd.to_numeric(samples["label"], errors="coerce")
    replay_items: list[dict] = []
    model = runtime["model"]
    columns = runtime["columns"]
    bundle_dir = runtime["bundle_dir"]
    model_labels = runtime.get("label_classes") or []

    for label in request.labels:
        if label not in model_labels:
            raise HTTPException(
                status_code=503,
                detail=f"The active model does not include {label}; no simulated events were produced.",
            )

        candidates = samples.loc[numeric_labels == LABEL_TO_ID[label]].head(
            MAX_EXAMPLES_PER_LABEL
        )
        matched_score = None
        for _, row in candidates.iterrows():
            features = vectorize_features(row.to_dict(), columns)
            predicted, score = infer(model, features, bundle_dir=bundle_dir)
            severity = threat_severity(predicted, score)
            if predicted == label and severity is not None:
                matched_score = score
                replay_items.append(
                    {
                        "id": f"SIM-{uuid4().hex[:10]}",
                        "alert_id": None,
                        "predicted_class": predicted,
                        "confidence": score,
                        "severity": severity,
                        "model_version": "active_bundle",
                        "detection_source": "dataset_replay",
                        "simulated": True,
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "notice": "Held-out dataset sample; not a live or persisted detection.",
                    }
                )
                break

        if matched_score is None:
            raise HTTPException(
                status_code=503,
                detail=(
                    f"No held-out {label} example passed the active model and recording "
                    "threshold; no simulated events were produced."
                ),
            )

    for item in replay_items:
        await ws_manager.broadcast(item)

    return {
        "simulated": True,
        "persisted": False,
        "network_packets_sent": 0,
        "response_actions": 0,
        "items": replay_items,
        "notice": (
            "These are real-time model replays of held-out samples, not captured attacks. "
            "They are shown temporarily and are not saved."
        ),
    }
