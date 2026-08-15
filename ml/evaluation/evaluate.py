"""
Evaluate a saved model on the sample (default) or full test split.
Saves metrics to artifacts/test_report.json
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import pandas as pd
from sklearn.metrics import classification_report, confusion_matrix

from ml.models.bundle import load_feature_columns, load_label_classes, load_rf

MODEL_PATH = Path("ml/models/baseline_rf.pkl")
SAMPLE_TEST = Path("ml/data/splits/sample/test.csv")
FULL_TEST = Path("ml/data/splits/test.csv")
ARTIFACTS = Path("artifacts")


def evaluate(use_full: bool = False):
    test_csv = FULL_TEST if use_full else (SAMPLE_TEST if SAMPLE_TEST.exists() else FULL_TEST)
    if not MODEL_PATH.exists():
        raise FileNotFoundError("Model not found; run ml/training/train.py first")
    if not test_csv.exists():
        raise FileNotFoundError(f"Test CSV not found: {test_csv}")

    model = load_rf(MODEL_PATH)
    columns = load_feature_columns()
    label_names = load_label_classes() or []

    print(f"Evaluating on {test_csv} ...")
    df = pd.read_csv(test_csv)
    y = df["label"]
    X = df.drop(columns=["label"]).select_dtypes(include=["number"])
    X = X.reindex(columns=columns, fill_value=0.0)

    preds = model.predict(X)
    present = sorted(set(y.tolist()) | set(preds.tolist()))
    target_names = [label_names[i] if i < len(label_names) else str(i) for i in present]
    report = classification_report(
        y,
        preds,
        labels=present,
        target_names=target_names,
        output_dict=True,
        zero_division=0,
    )
    cm = confusion_matrix(y, preds, labels=present).tolist()

    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    payload = {
        "test_csv": str(test_csv),
        "n_rows": int(len(df)),
        "labels": present,
        "target_names": target_names,
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
    args = parser.parse_args()
    evaluate(use_full=args.full)
