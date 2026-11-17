from pathlib import Path
from types import SimpleNamespace

import pytest

from agents.coordinator import coordinator
from agents.coordinator.coordinator import ModelUnavailableError, process_features


class DummyModel:
    classes_ = [0, 1]

    def predict_proba(self, X):
        return [[0.9, 0.1]]


def test_coordinator_pipeline_without_model():
    fv = {"source_ip": "198.51.100.5", "feature1": 0.1, "Flow Duration": 1.0}
    res = process_features(fv, model=DummyModel())
    assert "predicted" in res and "response" in res
    assert "explanation" in res
    assert "anomaly_score" in res
    assert isinstance(res["confidence"], float)


def test_coordinator_explanation_nonempty():
    fv = {"source_ip": "198.51.100.5", "Flow Duration": 12.0, "Fwd IAT Mean": 0.5}
    res = process_features(fv, model=DummyModel())
    assert isinstance(res["explanation"], str)
    assert len(res["explanation"]) > 10


def test_coordinator_does_not_report_benign_when_model_bundle_is_unavailable(monkeypatch):
    def unavailable():
        raise ValueError("invalid bundle")

    monkeypatch.setattr(coordinator, "load_runtime", unavailable)

    with pytest.raises(ModelUnavailableError, match="inference was not run"):
        process_features({"source_ip": "198.51.100.10", "duration": 1.0})


def test_failed_model_reload_does_not_leave_a_partial_runtime_cache(monkeypatch):
    previous_runtime = coordinator._cached.copy()
    bundle = SimpleNamespace(
        model=object(),
        feature_columns=["duration"],
        label_classes=["Benign"],
        directory=Path("bundle"),
        metadata={},
    )

    def broken_anomaly(_path):
        raise ValueError("invalid anomaly model")

    monkeypatch.setattr(coordinator, "load_bundle", lambda: bundle)
    monkeypatch.setattr(coordinator, "load_anomaly", broken_anomaly)

    with pytest.raises(ValueError, match="invalid anomaly model"):
        coordinator.load_runtime(force=True)

    assert coordinator._cached == previous_runtime
