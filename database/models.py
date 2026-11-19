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
    """Return local timestamp (matches host machine / India Standard Time)."""
    return datetime.now()


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
    confidence = Column(String(32))   # model score; rule detections have no model score
    model_version = Column(String(64))
    detection_source = Column(
        String(32), nullable=False, default="model", server_default="model"
    )

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
    mode = Column(String(32), nullable=True)
    policy_rule_id = Column(String(96), nullable=True)
    approval_status = Column(String(32), nullable=True)
    expires_at = Column(DateTime, nullable=True)
    target_ip = Column(String(45), nullable=True)
    audit_metadata = Column(JSON, nullable=True)

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


class PolicyRule(Base):
    """Configurable response policy rule stored as JSON predicates."""
    __tablename__ = "policy_rules"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(96), unique=True, nullable=False)
    enabled = Column(Boolean, default=True, nullable=False)
    priority = Column(Integer, default=100, nullable=False)
    attack_types = Column(JSON, default=list)
    min_confidence = Column(Float, nullable=True)
    min_severity = Column(String(32), nullable=True)
    min_asset_criticality = Column(String(32), nullable=True)
    action = Column(String(32), nullable=False)
    mode = Column(String(32), default="dry-run", nullable=False)
    created_at = Column(DateTime, default=utc_now)
    updated_at = Column(DateTime, default=utc_now, onupdate=utc_now)


class Incident(Base):
    """Correlated alert group with analyst workflow state."""
    __tablename__ = "incidents"

    id = Column(Integer, primary_key=True, index=True)
    incident_key = Column(String(128), unique=True, nullable=False, index=True)
    source_ip = Column(String(45), nullable=True)
    dest_ip = Column(String(45), nullable=True)
    attack_type = Column(String(64), nullable=True)
    severity = Column(String(32), default="info")
    status = Column(String(32), default="open")
    kill_chain_stage = Column(String(64), nullable=True)
    merged_into_id = Column(
        Integer,
        ForeignKey("incidents.id", name="fk_incidents_merged_into_id"),
        nullable=True,
    )
    split_from_id = Column(
        Integer,
        ForeignKey("incidents.id", name="fk_incidents_split_from_id"),
        nullable=True,
    )
    events = Column(JSON, default=list)
    timeline = Column(JSON, default=list)
    created_at = Column(DateTime, default=utc_now)
    updated_at = Column(DateTime, default=utc_now, onupdate=utc_now)


class AlertFeedback(Base):
    """Analyst label used for evaluation and future active learning."""
    __tablename__ = "alert_feedback"

    id = Column(Integer, primary_key=True, index=True)
    alert_id = Column(Integer, ForeignKey("alerts.id"), nullable=False, index=True)
    label = Column(String(32), nullable=False)
    notes = Column(Text, nullable=True)
    analyst = Column(String(64), nullable=True)
    created_at = Column(DateTime, default=utc_now)


class Asset(Base):
    """Discovered host inventory used by response policy criticality."""
    __tablename__ = "assets"

    id = Column(Integer, primary_key=True, index=True)
    ip = Column(String(45), unique=True, nullable=False, index=True)
    hostname = Column(String(255), nullable=True)
    criticality = Column(String(32), default="low", nullable=False)
    tags = Column(JSON, default=list)
    compromised = Column(Boolean, default=False, nullable=False)
    isolated = Column(Boolean, default=False, nullable=False)
    last_seen = Column(DateTime, default=utc_now)


class ResponseAudit(Base):
    """Durable audit record for every requested or executed response."""
    __tablename__ = "response_audit"

    id = Column(Integer, primary_key=True, index=True)
    ip = Column(String(45), nullable=False, index=True)
    action = Column(String(32), nullable=False)
    mode = Column(String(32), nullable=False)
    status = Column(String(32), nullable=False)
    actor = Column(String(64), nullable=True)
    reason = Column(String(255), nullable=True)
    metadata_json = Column(JSON, nullable=True)
    created_at = Column(DateTime, default=utc_now)


class ResponseApproval(Base):
    """Pending admin approval for a non-trivial response action."""
    __tablename__ = "response_approvals"

    id = Column(Integer, primary_key=True, index=True)
    ip = Column(String(45), nullable=False)
    action = Column(String(32), nullable=False)
    requested_by = Column(String(64), nullable=True)
    status = Column(String(32), default="pending", nullable=False)
    decision_by = Column(String(64), nullable=True)
    decision_reason = Column(Text, nullable=True)
    created_at = Column(DateTime, default=utc_now)
    decided_at = Column(DateTime, nullable=True)


class SavedSearch(Base):
    """Validated natural-language alert search saved by an analyst."""
    __tablename__ = "saved_searches"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(96), nullable=False)
    query = Column(String(500), nullable=False)
    filters = Column(JSON, nullable=False)
    owner = Column(String(64), nullable=True)
    created_at = Column(DateTime, default=utc_now)


class Watchlist(Base):
    """IP watchlist derived from a saved search or analyst decision."""
    __tablename__ = "watchlists"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(96), nullable=False)
    ip = Column(String(45), nullable=False, index=True)
    enabled = Column(Boolean, default=True, nullable=False)
    owner = Column(String(64), nullable=True)
    created_at = Column(DateTime, default=utc_now)


class AdminToolAudit(Base):
    """Audit trail for allowlisted admin toolbox commands."""
    __tablename__ = "admin_tool_audit"

    id = Column(Integer, primary_key=True, index=True)
    command_key = Column(String(96), nullable=False)
    actor = Column(String(64), nullable=True)
    success = Column(Boolean, nullable=False, default=True)
    arguments = Column(JSON, nullable=True)
    output = Column(JSON, nullable=True)
    created_at = Column(DateTime, default=utc_now)
