from datetime import datetime, timezone
from sqlalchemy import (
    Column,
    DateTime,
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


class Alert(Base):
    __tablename__ = "alerts"
    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime, default=utc_now)
    source_ip = Column(String(45))
    dest_ip = Column(String(45))
    protocol = Column(String(32))
    raw_features = Column(JSON)
    detections = relationship("Detection", back_populates="alert")

class Detection(Base):
    __tablename__ = "detections"
    id = Column(Integer, primary_key=True)
    alert_id = Column(Integer, ForeignKey("alerts.id"))
    predicted_class = Column(String(64))
    confidence = Column(String(32))
    model_version = Column(String(64))
    alert = relationship("Alert", back_populates="detections")

class Action(Base):
    __tablename__ = "actions"
    id = Column(Integer, primary_key=True)
    detection_id = Column(Integer, ForeignKey("detections.id"))
    action_type = Column(String(64))
    timestamp = Column(DateTime, default=utc_now)
    reversed_at = Column(DateTime, nullable=True)

class Report(Base):
    __tablename__ = "reports"
    id = Column(Integer, primary_key=True)
    period_start = Column(DateTime)
    period_end = Column(DateTime)
    summary = Column(Text)
