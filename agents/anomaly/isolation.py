"""
IsolationForest-based anomaly detector.
Interface: fit(X), score(feature_vector) -> anomaly score (lower/more negative => more anomalous)
"""
from __future__ import annotations

from typing import Any, List, Sequence, Union

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest


class AnomalyDetector:
    def __init__(self, **kwargs):
        self.model = IsolationForest(**kwargs)
        self.fitted = False

    def fit(self, X):
        self.model.fit(X)
        self.fitted = True
        return self

    @classmethod
    def from_sklearn(cls, model: IsolationForest) -> "AnomalyDetector":
        det = cls()
        det.model = model
        det.fitted = True
        return det

    def score(self, feature_vector: Union[List[float], np.ndarray, Sequence[float], pd.DataFrame]) -> float:
        if not self.fitted:
            raise RuntimeError("Anomaly detector not fitted")

        if hasattr(self.model, "feature_names_in_"):
            columns = [str(name) for name in self.model.feature_names_in_]
            if isinstance(feature_vector, pd.DataFrame):
                x = feature_vector.reindex(columns=columns, fill_value=0.0)
            else:
                vec = np.asarray(feature_vector, dtype=float).reshape(-1)
                if vec.size < len(columns):
                    vec = np.pad(vec, (0, len(columns) - vec.size), mode="constant", constant_values=0.0)
                elif vec.size > len(columns):
                    vec = vec[: len(columns)]
                x = pd.DataFrame([vec], columns=columns)
        else:
            x = np.asarray(feature_vector, dtype=float).reshape(1, -1)

        # decision_function: higher => more normal; invert-ish for "anomaly score"
        decision = float(self.model.decision_function(x)[0])
        # Map to a 0..1-ish anomaly score where higher means more anomalous
        anomaly_score = float(max(0.0, min(1.0, 0.5 - decision)))
        return anomaly_score
