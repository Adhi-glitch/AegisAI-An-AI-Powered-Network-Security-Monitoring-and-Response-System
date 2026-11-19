"""Database query helpers for keeping read APIs focused on threat records."""
from __future__ import annotations

from sqlalchemy import Float, and_, cast, or_

from agents.detection.live_rules import RULE_DETECTION_LABELS
from agents.detection.threat_policy import (
    MIN_THREAT_CONFIDENCE,
    PHASE1_THREAT_CLASSES,
)
from database import models


def harmful_detection_filters():
    """Filter supported model threats and explicit network-behavior indicators."""
    model_threat = and_(
        models.Detection.predicted_class.in_(PHASE1_THREAT_CLASSES),
        cast(models.Detection.confidence, Float) >= MIN_THREAT_CONFIDENCE,
    )
    behavioral_rules = or_(
        *(
            and_(
                models.Detection.detection_source == source,
                models.Detection.predicted_class == label,
            )
            for source, label in RULE_DETECTION_LABELS.items()
        )
    )
    return (or_(model_threat, behavioral_rules),)
