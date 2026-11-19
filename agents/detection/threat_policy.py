"""Conservative policy for deciding which model outputs are actionable threats."""
from __future__ import annotations

import math
from typing import Any


PHASE1_THREAT_CLASSES = (
    "DoS",
    "DDoS",
    "Port Scan",
    "Brute Force",
    "Web Attack",
    "Botnet",
)
MIN_THREAT_CONFIDENCE = 0.5


def threat_severity(predicted: Any, confidence: Any) -> str | None:
    """Return a severity only for supported, sufficiently confident threat labels."""
    if not isinstance(predicted, str):
        return None
    if predicted.strip().casefold() not in {label.casefold() for label in PHASE1_THREAT_CLASSES}:
        return None

    try:
        score = float(confidence)
    except (TypeError, ValueError):
        return None
    if not math.isfinite(score) or not MIN_THREAT_CONFIDENCE <= score <= 1.0:
        return None
    if score >= 0.8:
        return "high"
    if score >= 0.65:
        return "medium"
    return "low"
