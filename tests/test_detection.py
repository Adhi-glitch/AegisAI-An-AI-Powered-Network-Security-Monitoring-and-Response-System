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
