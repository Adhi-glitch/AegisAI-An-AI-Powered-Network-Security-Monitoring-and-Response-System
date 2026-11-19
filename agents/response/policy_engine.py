"""Pure policy evaluation for response decisions."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Final

ALLOWED_ACTIONS: Final[frozenset[str]] = frozenset(
    {"log", "alert", "rate_limit", "block", "isolate", "quarantine", "notify"}
)
SEVERITY_RANK: Final[dict[str, int]] = {
    "info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4,
}
CRITICALITY_RANK: Final[dict[str, int]] = {
    "low": 0, "medium": 1, "high": 2, "critical": 3,
}


@dataclass(frozen=True)
class PolicyDecision:
    """The explainable result of evaluating one response policy."""

    action: str
    rule_id: str
    reason: str
    requires_approval: bool = False


def _normalise(value: str | None, default: str) -> str:
    return (value or default).strip().lower()


def evaluate_policy(
    *,
    attack_type: str | None = None,
    confidence: float = 0.0,
    severity: str | None = None,
    asset_criticality: str | None = None,
    mode: str = "dry-run",
) -> PolicyDecision:
    """Select a safe default action from detection and asset context."""
    bounded_confidence = max(0.0, min(1.0, float(confidence)))
    attack = _normalise(attack_type, "unknown")
    severity_name = _normalise(severity, "info")
    criticality = _normalise(asset_criticality, "low")

    if severity_name not in SEVERITY_RANK:
        severity_name = "info"
    if criticality not in CRITICALITY_RANK:
        criticality = "low"

    if attack == "benign" or bounded_confidence < 0.5:
        decision = PolicyDecision("log", "default-low-confidence", "Low-confidence or benign detection")
    elif attack in {"dos", "ddos", "botnet"} and bounded_confidence >= 0.8:
        decision = PolicyDecision("block", "high-confidence-volume-attack", "High-confidence volumetric or botnet attack")
    elif severity_name == "critical" and bounded_confidence >= 0.8:
        decision = PolicyDecision("block", "critical-high-confidence", "Critical high-confidence detection")
    elif SEVERITY_RANK[severity_name] >= SEVERITY_RANK["high"] and bounded_confidence >= 0.8:
        decision = PolicyDecision("rate_limit", "high-severity-detection", "High-severity detection requires traffic control")
    else:
        decision = PolicyDecision("alert", "medium-confidence-detection", "Detection should be surfaced for analyst review")

    if criticality == "critical" and decision.action == "block":
        decision = PolicyDecision(
            "quarantine",
            "critical-asset-quarantine",
            "Blocking a critical asset is replaced with quarantine for controlled response",
        )

    if mode not in {"dry-run", "approval-required", "auto-live"}:
        raise ValueError("mode must be dry-run, approval-required, or auto-live")
    if mode == "approval-required" and decision.action not in {"log", "alert"}:
        return PolicyDecision(decision.action, decision.rule_id, decision.reason, True)
    return decision