"""
AegisAI SQLAlchemy models — v0.4

Tables:
  alerts      — inbound network alerts
  detections  — ML classification results
  actions     — automated response actions
  reports     — periodic summary reports
  users       — auth users (admin / viewer roles)
  threat_feed — enriched IP threat intelligence cache
  model_runs  — training history and model registry
"""
from datetime import datetime, timezone

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    JSON,
    String,
    Text,
)
from sqlalchemy.orm import declarative_base, relationship

Base = declarative_base()


def utc_now():
    """Return a naive UTC timestamp for the existing SQLite schema."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


# ── Core NIDS models ──────────────────────────────────────────────────────────

class Alert(Base):
    """Raw network event ingested via POST /alerts."""
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=utc_now)
    source_ip = Column(String(45))
    dest_ip = Column(String(45))
    protocol = Column(String(32))
    severity = Column(String(32), default="info")  # info / low / medium / high / critical
    raw_features = Column(JSON)

    detections = relationship("Detection", back_populates="alert")


class Detection(Base):
    """ML classification result linked to an Alert."""
    __tablename__ = "detections"

    id = Column(Integer, primary_key=True, index=True)
    alert_id = Column(Integer, ForeignKey("alerts.id"))
    predicted_class = Column(String(64))
    confidence = Column(String(32))   # kept as String for DB compat; normalised in API
    model_version = Column(String(64))

    alert = relationship("Alert", back_populates="detections")
    actions = relationship("Action", back_populates="detection")


class Action(Base):
    """Automated response action triggered by a Detection."""
    __tablename__ = "actions"

    id = Column(Integer, primary_key=True, index=True)
    detection_id = Column(Integer, ForeignKey("detections.id"))
    action_type = Column(String(64))
    timestamp = Column(DateTime, default=utc_now)
    reversed_at = Column(DateTime, nullable=True)

    detection = relationship("Detection", back_populates="actions")


class Report(Base):
    """Periodic summary report."""
    __tablename__ = "reports"

    id = Column(Integer, primary_key=True, index=True)
    period_start = Column(DateTime)
    period_end = Column(DateTime)
    summary = Column(Text)


# ── Auth ──────────────────────────────────────────────────────────────────────

class User(Base):
    """Application user — admin or viewer role."""
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(64), unique=True, nullable=False, index=True)
    hashed_password = Column(String(256), nullable=False)
    role = Column(String(32), default="viewer")  # "admin" | "viewer"
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=utc_now)


# ── Threat intelligence cache ─────────────────────────────────────────────────

class ThreatFeed(Base):
    """Cached IP threat intelligence from external feeds (AbuseIPDB, VT, etc.)."""
    __tablename__ = "threat_feed"

    id = Column(Integer, primary_key=True, index=True)
    ip = Column(String(45), index=True)
    threat_type = Column(String(64))
    source = Column(String(64))    # e.g., "abuseipdb" | "virustotal"
    severity = Column(String(32))  # "low" | "medium" | "high" | "critical"
    abuse_score = Column(Float, nullable=True)
    country_code = Column(String(8), nullable=True)
    first_seen = Column(DateTime, default=utc_now)
    last_seen = Column(DateTime, default=utc_now)


# ── Model registry ────────────────────────────────────────────────────────────

class ModelRun(Base):
    """Training run record — tracks model versions and their performance metrics."""
    __tablename__ = "model_runs"

    id = Column(Integer, primary_key=True, index=True)
    version = Column(String(64))
    algorithm = Column(String(64))   # "random_forest" | "xgboost"
    accuracy = Column(Float, nullable=True)
    f1_score = Column(Float, nullable=True)
    precision = Column(Float, nullable=True)
    recall = Column(Float, nullable=True)
    trained_at = Column(DateTime, default=utc_now)
    is_active = Column(Boolean, default=False)
    notes = Column(Text, nullable=True)
