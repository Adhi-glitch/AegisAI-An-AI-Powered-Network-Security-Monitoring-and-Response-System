from pathlib import Path

import numpy as np
import pandas as pd
import pytest

from agents.detection.inference import infer
from ml.data.multidataset import LABEL_TO_ID
from ml.models.bundle import load_bundle


def test_active_prototype_model_classifies_held_out_examples_for_every_class():
    split_path = Path("ml/data/splits/prototype/test.csv")
    assert split_path.exists(), "Build the prototype dataset, splits, and active model before running this test"
    bundle = load_bundle()
    held_out = pd.read_csv(split_path)
    sampling_seeds = {name: (1 if name == "Botnet" else 0) for name in bundle.label_classes}

    assert set(bundle.label_classes) == set(LABEL_TO_ID)
    for expected_label in bundle.label_classes:
        class_id = LABEL_TO_ID[expected_label]
        class_rows = held_out.loc[held_out["label"] == class_id]
        examples = class_rows.sample(n=3, random_state=sampling_seeds[expected_label])
        for _, row in examples.iterrows():
            predicted_label, confidence = infer(
                bundle.model,
                row.to_dict(),
                bundle_dir=bundle.directory,
            )
            assert predicted_label == expected_label
            assert 0.0 <= confidence <= 1.0


def test_active_model_accepts_reordered_and_missing_features():
    bundle = load_bundle()
    row = pd.read_csv("ml/data/splits/prototype/test.csv").iloc[0]
    features = {column: row[column] for column in bundle.feature_columns}
    expected = infer(bundle.model, features, bundle_dir=bundle.directory)
    reordered = dict(reversed(list(features.items())))

    reordered_prediction = infer(bundle.model, reordered, bundle_dir=bundle.directory)
    assert reordered_prediction[0] == expected[0]
    assert reordered_prediction[1] == pytest.approx(expected[1], abs=1e-12)

    missing = dict(features)
    missing.pop(bundle.feature_columns[0])
    predicted_label, confidence = infer(bundle.model, missing, bundle_dir=bundle.directory)
    assert predicted_label in bundle.label_classes
    assert 0.0 <= confidence <= 1.0


def test_active_model_sanitizes_non_finite_feature_values():
    bundle = load_bundle()
    row = pd.read_csv("ml/data/splits/prototype/test.csv").iloc[0]
    features = {column: row[column] for column in bundle.feature_columns}
    features[bundle.feature_columns[0]] = np.nan
    features[bundle.feature_columns[1]] = np.inf

    predicted_label, confidence = infer(bundle.model, features, bundle_dir=bundle.directory)

    assert predicted_label in bundle.label_classes
    assert np.isfinite(confidence)