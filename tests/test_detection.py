from agents.detection import inference
import numpy as np


def test_infer_interface():
    class Dummy:
        classes_ = np.array(["Benign", "DoS"])

        def predict_proba(self, X):
            return [[0.2, 0.8]]

    model = Dummy()
    label, conf = inference.infer(model, [0.1, 0.2])
    assert label in ("Benign", "DoS") or label in Dummy.classes_
    assert isinstance(conf, float)
    assert conf == 0.8


def test_infer_from_dict_without_columns(monkeypatch):
    class Dummy:
        classes_ = np.array([0, 1])

        def predict_proba(self, X):
            return [[0.7, 0.3]]

    # Force missing feature columns file path behavior by passing list
    label, conf = inference.infer(Dummy(), [1.0, 2.0, 3.0])
    assert isinstance(label, str)
    assert conf == 0.7


def test_infer_decodes_canonical_multiclass_label(monkeypatch):
    labels = ["Benign", "Botnet", "Brute Force", "DDoS", "DoS", "Port Scan", "Web Attack"]
    monkeypatch.setattr(inference, "load_label_classes", lambda bundle_dir=None: labels)

    class Dummy:
        classes_ = np.arange(7)

        def predict_proba(self, X):
            return [[0.01, 0.01, 0.01, 0.01, 0.01, 0.01, 0.94]]

    label, confidence = inference.infer(Dummy(), [0.0])

    assert label == "Web Attack"
    assert confidence == 0.94


def test_infer_sanitizes_non_finite_feature_values(monkeypatch):
    monkeypatch.setattr(inference, "load_label_classes", lambda bundle_dir=None: ["Benign", "DoS"])

    class Dummy:
        classes_ = np.array([0, 1])

        def predict_proba(self, X):
            assert np.isfinite(np.asarray(X, dtype=float)).all()
            return [[0.25, 0.75]]

    label, confidence = inference.infer(Dummy(), [np.nan, np.inf, -np.inf])

    assert label == "DoS"
    assert confidence == 0.75
