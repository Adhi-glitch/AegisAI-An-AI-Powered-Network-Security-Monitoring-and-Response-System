"""
Generic detection inference helper.
Returns (predicted_class_label, confidence_score).
"""
from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Tuple, Union

import numpy as np
import pandas as pd

from ml.models.bundle import (
    load_feature_columns,
    load_label_classes,
    load_rf,
    resolve_label,
    vectorize_features,
)


def load_model(path: str | None = None):
    if path is None:
        return load_rf()
    return load_rf(Path(path))


def infer(
    model: Any,
    feature_vector: Union[List[float], Dict[str, Any], np.ndarray],
    bundle_dir: Path | str | None = None,
) -> Tuple[str, float]:
    """
    Infer label + confidence.
    Accepts an ordered list/array matching training columns, or a feature dict.
    """
    expected_features = None
    feature_columns = None
    if hasattr(model, "n_features_in_"):
        expected_features = int(model.n_features_in_)

    if isinstance(feature_vector, dict):
        try:
            cols = load_feature_columns(bundle_dir=bundle_dir)
            feature_columns = cols
            feature_vector = vectorize_features(feature_vector, cols)
            expected_features = len(cols)
        except FileNotFoundError:
            feature_vector = list(feature_vector.values())

    x = np.asarray(feature_vector, dtype=float).reshape(-1)
    x = np.nan_to_num(x, copy=False, nan=0.0, posinf=0.0, neginf=0.0)
    if expected_features is not None:
        if x.size < expected_features:
            x = np.pad(x, (0, expected_features - x.size), mode="constant", constant_values=0.0)
        elif x.size > expected_features:
            x = x[:expected_features]
    if feature_columns is None:
        try:
            candidate_columns = load_feature_columns(bundle_dir=bundle_dir)
            if len(candidate_columns) == x.size:
                feature_columns = candidate_columns
        except FileNotFoundError:
            pass
    if feature_columns is not None and len(feature_columns) == x.size:
        x = pd.DataFrame([x], columns=feature_columns)
    else:
        x = x.reshape(1, -1)

    try:
        probs = model.predict_proba(x)[0]
        conf = float(np.max(probs))
        pred_idx = int(np.argmax(probs))
        if hasattr(model, "classes_"):
            raw = model.classes_[pred_idx]
            label = resolve_label(model, raw, bundle_dir=bundle_dir)
        else:
            label = str(pred_idx)
        classes = load_label_classes(bundle_dir=bundle_dir)
        if classes and hasattr(model, "classes_"):
            raw_class = model.classes_[pred_idx]
            try:
                label = classes[int(raw_class)]
            except Exception:
                label = str(raw_class)
        return label, conf
    except Exception:
        pred = model.predict(x)[0]
        conf = 0.0
        if hasattr(model, "decision_function"):
            try:
                val = model.decision_function(x)[0]
                conf = float(np.max(val))
            except Exception:
                conf = 0.0
        return resolve_label(model, pred, bundle_dir=bundle_dir), conf
