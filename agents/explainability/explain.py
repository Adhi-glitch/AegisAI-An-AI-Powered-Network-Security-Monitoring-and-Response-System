"""
Explainability: top contributing features via RandomForest importances
aligned to the input feature vector. Falls back to a readable stub.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple


def _top_features_from_importances(
    feature_vector: Dict[str, Any],
    importances: List[float],
    feature_names: List[str],
    top_k: int = 5,
) -> List[Tuple[str, float, float]]:
    pairs = []
    for name, imp in zip(feature_names, importances):
        value = feature_vector.get(name, feature_vector.get(str(name).strip()))
        if value is None:
            continue
        try:
            val = float(value)
        except (TypeError, ValueError):
            continue
        pairs.append((name, float(imp), val))
    pairs.sort(key=lambda t: t[1], reverse=True)
    return pairs[:top_k]


def explain_detection(
    predicted_class: str,
    feature_vector: Dict[str, Any],
    model: Any = None,
    feature_names: Optional[List[str]] = None,
) -> str:
    if model is not None and hasattr(model, "feature_importances_") and feature_names:
        tops = _top_features_from_importances(
            feature_vector,
            list(model.feature_importances_),
            feature_names,
            top_k=5,
        )
        if tops:
            parts = [f"{name} (importance={imp:.4f}, value={val:.4f})" for name, imp, val in tops]
            return (
                f"Predicted class: {predicted_class}. "
                f"Top contributing features: " + "; ".join(parts) + "."
            )

    # Fallback: show a few numeric highlights from the vector itself
    numeric = []
    for k, v in feature_vector.items():
        if k in ("source_ip", "dest_ip", "protocol"):
            continue
        try:
            numeric.append((k, abs(float(v)), float(v)))
        except (TypeError, ValueError):
            continue
    numeric.sort(key=lambda t: t[1], reverse=True)
    highlights = ", ".join(f"{k}={val:.4f}" for k, _, val in numeric[:5]) or "n/a"
    return f"Predicted class: {predicted_class}. Feature highlights: {highlights}."
