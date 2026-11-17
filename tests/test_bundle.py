import json

import numpy as np
import pandas as pd
import pytest
from sklearn.dummy import DummyClassifier

from agents.coordinator import coordinator
from ml.evaluation import evaluate as evaluation
from ml.models import bundle
from ml.training import train as training


def test_active_bundle_is_shared_by_default_loaders(tmp_path, monkeypatch):
    model_dir = tmp_path / "ml" / "models"
    custom_bundle = model_dir / "candidate"
    monkeypatch.setattr(bundle, "ROOT", tmp_path)
    monkeypatch.setattr(bundle, "MODEL_DIR", model_dir)

    model = DummyClassifier(strategy="most_frequent").fit(
        np.array([[1.0, 2.0], [3.0, 4.0]]), np.array([0, 1])
    )
    bundle.save_bundle(
        model=model,
        feature_columns=["first_feature", "second_feature"],
        label_classes=["Benign", "DoS"],
        bundle_dir=custom_bundle,
    )
    bundle.activate_bundle(custom_bundle)

    loaded_model = bundle.load_rf()

    assert bundle.resolve_bundle_dir() == custom_bundle
    assert loaded_model.classes_.tolist() == [0, 1]
    assert bundle.load_feature_columns() == ["first_feature", "second_feature"]
    assert bundle.load_label_classes() == ["Benign", "DoS"]


def test_load_bundle_fails_when_model_artifacts_are_missing(tmp_path):
    with pytest.raises(FileNotFoundError, match="Model not found"):
        bundle.load_bundle(tmp_path / "missing-bundle")


def test_load_bundle_rejects_incompatible_feature_manifest(tmp_path):
    model = DummyClassifier(strategy="most_frequent").fit(
        np.array([[1.0, 2.0], [3.0, 4.0]]), np.array([0, 1])
    )
    bundle.save_bundle(
        model=model,
        feature_columns=["only_feature"],
        label_classes=["Benign", "DoS"],
        bundle_dir=tmp_path / "incompatible-bundle",
    )

    with pytest.raises(ValueError, match="expects 2 features but bundle lists 1"):
        bundle.load_bundle(tmp_path / "incompatible-bundle")


def test_training_evaluation_and_api_runtime_share_bundle(tmp_path, monkeypatch):
    model_dir = tmp_path / "ml" / "models"
    split_dir = tmp_path / "splits"
    target_bundle = model_dir / "custom"
    split_dir.mkdir(parents=True)
    monkeypatch.setattr(bundle, "ROOT", tmp_path)
    monkeypatch.setattr(bundle, "MODEL_DIR", model_dir)
    monkeypatch.setattr(training, "MODEL_DIR", model_dir)
    monkeypatch.setattr(evaluation, "ARTIFACTS", tmp_path / "evaluation")

    labels = [(0, "Benign"), (4, "DoS"), (5, "Port Scan")]
    for split_name, rows_per_class in (("train", 8), ("val", 3), ("test", 3)):
        rows = []
        for class_id, class_name in labels:
            for row_id in range(rows_per_class):
                rows.append(
                    {
                        "label": class_id,
                        "label_name": class_name,
                        "feature_a": float(class_id + row_id / 10),
                        "feature_b": float(row_id),
                    }
                )
        pd.DataFrame(rows).to_csv(split_dir / f"{split_name}.csv", index=False)

    previous_runtime = coordinator._cached.copy()
    try:
        training.train_and_save(
            n_estimators=3,
            engine="random_forest",
            splits_dir=split_dir,
            bundle_dir=target_bundle,
        )
        trained_bundle = bundle.load_bundle()
        api_runtime = coordinator.load_runtime(force=True)
        evaluation.evaluate()
        report = json.loads((tmp_path / "evaluation" / "test_report.json").read_text())

        assert trained_bundle.directory == target_bundle.resolve()
        assert api_runtime["bundle_dir"] == trained_bundle.directory
        assert api_runtime["model"].classes_.tolist() == trained_bundle.model.classes_.tolist()
        assert api_runtime["columns"] == trained_bundle.feature_columns
        assert api_runtime["label_classes"] == trained_bundle.label_classes
        assert report["bundle_dir"] == str(trained_bundle.directory)
        assert report["test_csv"] == str(split_dir / "test.csv")
        assert report["feature_columns"] == trained_bundle.feature_columns
        assert report["label_classes"] == trained_bundle.label_classes
        assert set(report["false_positive_rate_by_class"]) == set(trained_bundle.label_classes)
        assert len(report["confusion_matrix"]) == len(trained_bundle.label_classes)
    finally:
        coordinator._cached.update(previous_runtime)