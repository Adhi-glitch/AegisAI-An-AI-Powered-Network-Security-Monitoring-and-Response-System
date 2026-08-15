from agents.explainability.explain import explain_detection
from ml.models.bundle import vectorize_features


def test_explain_with_importances():
    class Dummy:
        feature_importances_ = [0.1, 0.7, 0.2]

    text = explain_detection(
        "DoS",
        {"Flow Duration": 1.0, "Total Fwd Packets": 9.0, "Fwd IAT Mean": 0.2},
        model=Dummy(),
        feature_names=["Flow Duration", "Total Fwd Packets", "Fwd IAT Mean"],
    )
    assert "DoS" in text
    assert "Total Fwd Packets" in text


def test_vectorize_features_order():
    cols = ["a", "b", "c"]
    vec = vectorize_features({"c": 3, "a": 1}, cols)
    assert vec == [1.0, 0.0, 3.0]


def test_vectorize_features_matches_normalized_cicids_headers():
    vec = vectorize_features({"Flow Duration": 12}, [" Flow Duration"])
    assert vec == [12.0]
