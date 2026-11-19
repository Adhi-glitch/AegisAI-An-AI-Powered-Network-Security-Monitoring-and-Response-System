"""Deterministic grouping of related detections into analyst incidents."""
from __future__ import annotations

from collections import defaultdict
from datetime import datetime
from typing import Any, Iterable

from agents.analytics.features import technique_for


KILL_CHAIN = {
    "port scan": "discovery",
    "brute force": "credential-access",
    "web attack": "initial-access",
    "botnet": "command-and-control",
    "dos": "impact",
    "ddos": "impact",
}


def correlate_incidents(events: Iterable[dict[str, Any]], window_seconds: int = 300) -> list[dict[str, Any]]:
    """Group events by source, target, and attack pattern within a time window."""
    groups: dict[tuple[str, str, str], list[dict[str, Any]]] = defaultdict(list)
    for event in sorted(events, key=lambda item: str(item.get("timestamp", ""))):
        attack = str(event.get("attack_type") or event.get("predicted") or "unknown").lower()
        source = str(event.get("source_ip") or "unknown")
        target = str(event.get("dest_ip") or "unknown")
        current = groups[(source, target, attack)]
        if current:
            previous = _timestamp(current[-1].get("timestamp"))
            current_time = _timestamp(event.get("timestamp"))
            if previous is not None and current_time is not None and (current_time - previous).total_seconds() > window_seconds:
                groups[(source, target, attack + f"-{len(current)}")].append(event)
                continue
        current.append(event)

    incidents = []
    for index, ((source, target, attack), items) in enumerate(groups.items(), 1):
        severities = {str(item.get("severity", "info")).lower() for item in items}
        severity = "critical" if "critical" in severities else "high" if "high" in severities else "medium" if "medium" in severities else "low"
        incidents.append({
            "incident_id": f"INC-{index:04d}",
            "source_ip": source,
            "dest_ip": target,
            "attack_type": attack,
            "severity": severity,
            "status": "open",
            "kill_chain_stage": KILL_CHAIN.get(attack, "unknown"),
            "mitre_technique": technique_for(attack),
            "events": items,
            "timeline": [item.get("timestamp") for item in items],
        })
    return incidents


def update_incident_status(incident: dict[str, Any], status: str) -> dict[str, Any]:
    if status not in {"open", "investigating", "contained", "closed"}:
        raise ValueError("invalid incident status")
    updated = dict(incident)
    updated["status"] = status
    return updated


def merge_incidents(incidents: Iterable[dict[str, Any]]) -> dict[str, Any]:
    items = list(incidents)
    if not items:
        raise ValueError("at least one incident is required")
    merged = dict(items[0])
    merged["incident_id"] = "INC-MERGED"
    merged["events"] = [event for item in items for event in item.get("events", [])]
    merged["timeline"] = [stamp for item in items for stamp in item.get("timeline", [])]
    merged["status"] = "investigating"
    return merged


def split_incident(incident: dict[str, Any]) -> list[dict[str, Any]]:
    return [{**incident, "incident_id": f"{incident.get('incident_id', 'INC')}-{index + 1}", "events": [event], "timeline": [event.get("timestamp")]} for index, event in enumerate(incident.get("events", []))]


def _timestamp(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        return value
    if isinstance(value, str):
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
    return None