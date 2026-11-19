"""
Coordinator orchestrates:
  feature vector -> detection -> anomaly -> explainability -> response -> reporting
"""
from __future__ import annotations

from threading import RLock
from typing import Any, Dict, Optional

from agents.anomaly.isolation import AnomalyDetector
from agents.detection import inference
from agents.detection.threat_policy import threat_severity
from agents.explainability.explain import explain_detection
from agents.reporting import generate_report
from agents.response.response_engine import engine as response_engine
from ml.models.bundle import (
    load_anomaly,
    load_bundle,
    load_feature_columns,
    vectorize_features,
)

_cached = {
    "model": None,
    "columns": None,
    "label_classes": None,
    "bundle_dir": None,
    "anomaly": None,
    "metadata": None,
}
_runtime_lock = RLock()


class ModelUnavailableError(RuntimeError):
    """Raised when a prediction cannot be made with the active model bundle."""


def get_recorded_action(result: Dict[str, Any]) -> str:
    """Return the applied response status, preserving dry-run semantics."""
    response = result.get("response")
    if isinstance(response, dict) and response.get("status"):
        return str(response["status"])
    return str(result.get("action") or "log")


def load_runtime(force: bool = False):
    """Load model bundle into process cache."""
    with _runtime_lock:
        if force or _cached["model"] is None:
            bundle = load_bundle()
            raw = load_anomaly(bundle.directory / "anomaly_iforest.pkl")
            anomaly = AnomalyDetector.from_sklearn(raw) if raw is not None else None
            _cached.update(
                {
                    "model": bundle.model,
                    "columns": bundle.feature_columns,
                    "label_classes": bundle.label_classes,
                    "bundle_dir": bundle.directory,
                    "metadata": bundle.metadata,
                    "anomaly": anomaly,
                }
            )
        return dict(_cached)


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
        except Exception as exc:
            raise ModelUnavailableError(
                "The active model bundle could not be loaded; inference was not run."
            ) from exc

    if model is None:
        raise ModelUnavailableError(
            "The active model is unavailable; inference was not run."
        )

    if columns is None:
        try:
            columns = load_feature_columns()
        except FileNotFoundError:
            columns = [k for k in feature_vector.keys() if k not in ("source_ip", "dest_ip", "protocol")]

    ordered = vectorize_features(feature_vector, columns) if columns else list(feature_vector.values())

    # 1) detection
    try:
        predicted, confidence = inference.infer(
            model,
            ordered,
            bundle_dir=runtime["bundle_dir"] if runtime is not None else None,
        )
    except Exception as exc:
        raise ModelUnavailableError(
            "The active model failed during inference; no classification was produced."
        ) from exc

    # 2) anomaly scoring
    anomaly_score = 0.0
    if anomaly_detector is not None:
        try:
            anomaly_score = float(anomaly_detector.score(ordered))
        except Exception:
            anomaly_score = 0.0

    # 3) explanation
    explanation = explain_detection(predicted, feature_vector, model=model, feature_names=columns)

    # 4) only threat classifications can trigger response decisions
    severity = threat_severity(predicted, confidence)
    if severity is None:
        action = "ignore"
        response_result = {"status": "not_actionable"}
    else:
        action = response_engine.decide_action(
            confidence,
            attack_type=predicted,
            severity=severity,
        )
        src_ip = str(feature_vector.get("source_ip", "unknown"))
        response_result = response_engine.apply_action(src_ip, action)

    # 5) reporting
    report = generate_report(None, None, [predicted])

    return {
        "predicted": predicted,
        "confidence": confidence,
        "severity": severity,
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
