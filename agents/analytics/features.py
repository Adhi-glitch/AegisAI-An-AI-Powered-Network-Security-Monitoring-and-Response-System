"""Deterministic, testable analytics used by the feature APIs."""
from __future__ import annotations

from collections import Counter
from statistics import mean
from typing import Any, Iterable

ATTACK_TECHNIQUES = {
    "port scan": {"id": "T1046", "name": "Network Service Scanning", "stage": "discovery"},
    "brute force": {"id": "T1110", "name": "Brute Force", "stage": "credential-access"},
    "web attack": {"id": "T1190", "name": "Exploit Public-Facing Application", "stage": "initial-access"},
    "botnet": {"id": "T1071", "name": "Application Layer Protocol", "stage": "command-and-control"},
    "dos": {"id": "T1498", "name": "Network Denial of Service", "stage": "impact"},
    "ddos": {"id": "T1498", "name": "Network Denial of Service", "stage": "impact"},
}


def technique_for(attack_type: str) -> dict[str, str]:
    return dict(ATTACK_TECHNIQUES.get(attack_type.lower(), {"id": "unknown", "name": "Unmapped", "stage": "unknown"}))


def psi(expected: Iterable[float], actual: Iterable[float], bins: int = 10) -> float:
    """Calculate population stability index without assuming a distribution."""
    baseline, current = list(expected), list(actual)
    if not baseline or not current:
        return 0.0
    low, high = min(baseline), max(baseline)
    if high == low:
        return 0.0
    step = (high - low) / bins
    def counts(values: list[float]) -> list[float]:
        output = [0] * bins
        for value in values:
            index = min(bins - 1, max(0, int((value - low) / step)))
            output[index] += 1
        return [(count / len(values)) or 1e-6 for count in output]
    expected_rates, actual_rates = counts(baseline), counts(current)
    return sum((actual_rate - expected_rate) * __import__("math").log(actual_rate / expected_rate) for expected_rate, actual_rate in zip(expected_rates, actual_rates))


def simulate_scenario(stages: list[str], speed: float = 1.0, false_positive_count: int = 0) -> dict[str, Any]:
    if not stages:
        raise ValueError("at least one scenario stage is required")
    if speed <= 0:
        raise ValueError("speed must be positive")
    detected = len([stage for stage in stages if stage.lower() in ATTACK_TECHNIQUES])
    latency = round(1.0 / speed, 3)
    return {"stages": stages, "speed": speed, "events": len(stages), "detected": detected, "detection_rate": detected / len(stages), "false_positives": false_positive_count, "response_latency_seconds": latency, "before_policy": {"blocked": 0}, "after_policy": {"blocked": detected}}


def network_graph(events: Iterable[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    hosts: dict[str, dict[str, Any]] = {}
    flows: list[dict[str, Any]] = []
    for event in events:
        source, target = str(event.get("source_ip", "unknown")), str(event.get("dest_ip", "unknown"))
        hosts.setdefault(source, {"id": source, "kind": "source", "criticality": event.get("source_criticality", "low")})
        hosts.setdefault(target, {"id": target, "kind": "destination", "criticality": event.get("dest_criticality", "low")})
        flows.append({"source": source, "target": target, "attack_type": event.get("attack_type") or event.get("predicted")})
    return {"nodes": list(hosts.values()), "edges": flows}


def posture_digest(*, attack_volume: int, blocked: int, unresolved_incidents: int, model_health: float) -> dict[str, Any]:
    score = max(0, min(100, round(100 - min(attack_volume, 50) - unresolved_incidents * 10 + min(blocked, attack_volume) * 0.5 + model_health * 10)))
    return {"score": score, "trend": "stable", "summary": f"Posture score is {score}/100 with {unresolved_incidents} unresolved incident(s).", "components": {"attack_volume": attack_volume, "blocked": blocked, "unresolved_incidents": unresolved_incidents, "model_health": model_health}}


def feedback_queue(rows: Iterable[Any]) -> list[Any]:
    return [row for row in rows if getattr(row, "label", None) == "unsure"]