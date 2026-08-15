"""
Coordinator orchestrates:
  feature vector -> detection -> anomaly -> explainability -> response -> reporting
"""
from __future__ import annotations

from typing import Any, Dict, Optional

from agents.anomaly.isolation import AnomalyDetector
from agents.detection import inference
from agents.explainability.explain import explain_detection
from agents.reporting import generate_report
from agents.response.response_engine import engine as response_engine
from ml.models.bundle import (
    load_anomaly,
    load_feature_columns,
    load_rf,
    vectorize_features,
)

_cached = {
    "model": None,
    "columns": None,
    "anomaly": None,
}


def load_runtime(force: bool = False):
    """Load model bundle into process cache."""
    if force or _cached["model"] is None:
        _cached["model"] = load_rf()
        _cached["columns"] = load_feature_columns()
        raw = load_anomaly()
        _cached["anomaly"] = AnomalyDetector.from_sklearn(raw) if raw is not None else None
    return _cached


def process_features(
    feature_vector: Dict[str, Any],
    model=None,
    anomaly_detector: Optional[AnomalyDetector] = None,
) -> Dict[str, Any]:
    runtime = None
    columns = None

    if model is None:
        try:
            runtime = load_runtime()
            model = runtime["model"]
            columns = runtime["columns"]
            if anomaly_detector is None:
                anomaly_detector = runtime["anomaly"]
        except FileNotFoundError:
            model = None

    if columns is None:
        try:
            columns = load_feature_columns()
        except FileNotFoundError:
            columns = [k for k in feature_vector.keys() if k not in ("source_ip", "dest_ip", "protocol")]

    ordered = vectorize_features(feature_vector, columns) if columns else list(feature_vector.values())

    # 1) detection
    if model is None:
        predicted, confidence = ("Benign", 0.0)
    else:
        predicted, confidence = inference.infer(model, ordered)

    # 2) anomaly scoring
    anomaly_score = 0.0
    if anomaly_detector is not None:
        try:
            anomaly_score = float(anomaly_detector.score(ordered))
        except Exception:
            anomaly_score = 0.0

    # 3) explanation
    explanation = explain_detection(predicted, feature_vector, model=model, feature_names=columns)

    # 4) response decision
    action = response_engine.decide_action(confidence)
    src_ip = str(feature_vector.get("source_ip", "unknown"))
    response_result = response_engine.apply_action(src_ip, action)

    # 5) reporting
    report = generate_report(None, None, [predicted])

    return {
        "predicted": predicted,
        "confidence": confidence,
        "anomaly_score": anomaly_score,
        "explanation": explanation,
        "action": action,
        "response": response_result,
        "report": report,
    }


def demo_run():
    fv = {"source_ip": "192.0.2.1", "feature1": 0.1, "feature2": 1.2}
    result = process_features(fv, model=None)
    print(result)


if __name__ == "__main__":
    demo_run()
