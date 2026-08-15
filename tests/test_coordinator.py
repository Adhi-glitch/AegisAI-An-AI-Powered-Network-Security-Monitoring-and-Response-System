from agents.coordinator.coordinator import process_features


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
