"""
Evaluate a saved model on the sample (default) or full test split.
Saves metrics to artifacts/test_report.json
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.metrics import classification_report, confusion_matrix

from ml.data.multidataset import CANONICAL_LABELS, LABEL_TO_ID
from ml.models.bundle import ROOT, load_bundle

SAMPLE_TEST = Path("ml/data/splits/sample/test.csv")
FULL_TEST = Path("ml/data/splits/test.csv")
MULTI_TEST = Path("ml/data/splits/multi_dataset/test.csv")
ARTIFACTS = Path("artifacts")


def _false_positive_rates(confusion: list[list[int]], class_names: list[str]) -> dict[str, float | None]:
    matrix = np.asarray(confusion, dtype=np.int64)
    if matrix.shape != (len(class_names), len(class_names)):
        raise ValueError("Confusion matrix shape must match the model label list")

    total = int(matrix.sum())
    rates = {}
    for index, name in enumerate(class_names):
        true_positive = int(matrix[index, index])
        false_positive = int(matrix[:, index].sum()) - true_positive
        false_negative = int(matrix[index, :].sum()) - true_positive
        true_negative = total - true_positive - false_positive - false_negative
        denominator = false_positive + true_negative
        rates[name] = false_positive / denominator if denominator else None
    return rates


def evaluate(use_full: bool = False, bundle_dir: Path | None = None):
    bundle = load_bundle(bundle_dir)
    model = bundle.model
    columns = bundle.feature_columns
    label_names = bundle.label_classes

    recorded_test = bundle.metadata.get("test_csv")
    if recorded_test:
        test_csv = Path(recorded_test)
        if not test_csv.is_absolute():
            test_csv = ROOT / test_csv
    else:
        is_multiclass_bundle = set(label_names) == set(CANONICAL_LABELS)
        if is_multiclass_bundle and MULTI_TEST.exists():
            test_csv = MULTI_TEST
        else:
            test_csv = FULL_TEST if use_full else (SAMPLE_TEST if SAMPLE_TEST.exists() else FULL_TEST)
    if not test_csv.exists():
        raise FileNotFoundError(f"Test CSV not found: {test_csv}")

    print(f"Evaluating on {test_csv} ...")
    df = pd.read_csv(test_csv)
    y = df["label"].map(
        {LABEL_TO_ID[name]: model_id for model_id, name in enumerate(label_names) if name in LABEL_TO_ID}
    )
    if y.isna().any():
        unknown_ids = sorted(int(value) for value in df.loc[y.isna(), "label"].unique())
        raise ValueError(f"Test split contains canonical labels not present in the model bundle: {unknown_ids}")
    X = df.drop(columns=["label"]).select_dtypes(include=["number"])
    X = X.reindex(columns=columns, fill_value=0.0)

    preds = model.predict(X)
    present = list(range(len(label_names)))
    report = classification_report(
        y,
        preds,
        labels=present,
        target_names=label_names,
        output_dict=True,
        zero_division=0,
    )
    cm = confusion_matrix(y, preds, labels=present).tolist()
    false_positive_rates = _false_positive_rates(cm, label_names)
    for label_name, rate in false_positive_rates.items():
        report[label_name]["false_positive_rate"] = rate

    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    payload = {
        "test_csv": str(test_csv),
        "bundle_dir": str(bundle.directory),
        "label_classes": label_names,
        "feature_columns": columns,
        "split_strategy": bundle.metadata.get("split_strategy", "unspecified"),
        "capture_overlap_warning": bool(bundle.metadata.get("capture_overlap_warning", False)),
        "source_groups_by_class": bundle.metadata.get("source_groups_by_class", {}),
        "n_rows": int(len(df)),
        "labels": present,
        "target_names": label_names,
        "false_positive_rate_by_class": false_positive_rates,
        "classification_report": report,
        "confusion_matrix": cm,
    }
    with open(ARTIFACTS / "test_report.json", "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)

    print(f"Test accuracy: {report.get('accuracy')}")
    print("Evaluation saved to artifacts/test_report.json")
    return report, cm


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--full", action="store_true")
    parser.add_argument("--bundle-dir", type=Path, default=None)
    args = parser.parse_args()
    evaluate(use_full=args.full, bundle_dir=args.bundle_dir)
