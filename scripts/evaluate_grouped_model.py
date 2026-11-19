"""Train and evaluate the seven-class model with strict source-group splits."""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import pandas as pd
import sklearn
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import confusion_matrix

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from ml.data.multidataset import (
    CANONICAL_LABELS,
    LIVE_FEATURE_COLUMNS,
    _grouped_holdout,
)
from scripts.build_prototype_dataset import build_sample

PHASE1_DIR = ROOT / "data" / "phase1"
DEFAULT_OUTPUT = ROOT / "artifacts" / "strict_group_evaluation.json"
EVALUATED_LABEL_IDS = tuple(range(len(CANONICAL_LABELS)))
ATTACK_LABEL_IDS = tuple(range(1, len(CANONICAL_LABELS)))
GROUP_SEED = 0
MODEL_SEED = 42
ROWS_PER_GROUP_CLASS = 10_000
N_ESTIMATORS = 120
MIN_ATTACK_RECALL = 0.90
MIN_ATTACK_PRECISION = 0.80
MAX_BENIGN_FALSE_ALARM_RATE = 0.005


def build_evaluation_splits(frame: pd.DataFrame) -> dict[str, pd.DataFrame]:
    required = {"label", "label_name", "source_group", *LIVE_FEATURE_COLUMNS}
    missing_columns = required - set(frame.columns)
    if missing_columns:
        raise ValueError(f"Dataset is missing required columns: {sorted(missing_columns)}")
    if frame["source_group"].isna().any() or frame["source_group"].astype(str).str.strip().eq("").any():
        raise ValueError("Every row must have a non-empty source_group")
    expected_labels = set(EVALUATED_LABEL_IDS)
    if set(frame["label"].astype(int).unique()) != expected_labels:
        raise ValueError("The sampled dataset must contain all seven canonical classes")
    group_counts = frame.groupby("label")["source_group"].nunique()
    insufficient_groups = {
        CANONICAL_LABELS[int(label)]: int(count)
        for label, count in group_counts.items()
        if count < 3
    }
    if insufficient_groups:
        raise ValueError(
            "At least three independent source groups per class are required for "
            f"train/validation/test; found {insufficient_groups}"
        )

    train_validation, test = _grouped_holdout(
        frame,
        0.2,
        GROUP_SEED,
        split_name="test",
        minimum_train_groups_per_class=2,
    )
    train, validation = _grouped_holdout(
        train_validation,
        0.125,
        GROUP_SEED + 1,
        split_name="validation",
    )
    splits = {"train": train, "validation": validation, "test": test}
    for split_name, split in splits.items():
        if set(split["label"].astype(int)) != expected_labels:
            raise ValueError(f"The {split_name} split is missing one or more canonical classes")
    group_sets = {
        split_name: set(split["source_group"])
        for split_name, split in splits.items()
    }
    if (
        group_sets["train"] & group_sets["validation"]
        or group_sets["train"] & group_sets["test"]
        or group_sets["validation"] & group_sets["test"]
    ):
        raise RuntimeError("Source-group leakage detected between train, validation, and test")
    return splits


def _wilson_interval(successes: int, trials: int) -> list[float]:
    if trials == 0:
        return [0.0, 0.0]
    z = 1.96
    proportion = successes / trials
    denominator = 1 + z * z / trials
    center = (proportion + z * z / (2 * trials)) / denominator
    margin = z * np.sqrt(
        proportion * (1 - proportion) / trials + z * z / (4 * trials * trials)
    ) / denominator
    return [float(max(0.0, center - margin)), float(min(1.0, center + margin))]


def _summarize_predictions(actual: np.ndarray, predicted: np.ndarray) -> dict:
    matrix = confusion_matrix(actual, predicted, labels=list(EVALUATED_LABEL_IDS))
    per_class = {}
    for label_id in EVALUATED_LABEL_IDS:
        true_positive = int(matrix[label_id, label_id])
        support = int(matrix[label_id, :].sum())
        predicted_count = int(matrix[:, label_id].sum())
        precision = true_positive / predicted_count if predicted_count else 0.0
        recall = true_positive / support if support else 0.0
        f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
        per_class[CANONICAL_LABELS[label_id]] = {
            "precision": precision,
            "precision_ci_95": _wilson_interval(true_positive, predicted_count),
            "recall": recall,
            "recall_ci_95": _wilson_interval(true_positive, support),
            "f1": f1,
            "support": support,
        }
    benign_rows = actual == 0
    false_alarms = int(np.count_nonzero(predicted[benign_rows] != 0))
    benign_count = int(np.count_nonzero(benign_rows))
    return {
        "per_class": per_class,
        "confusion_matrix": {
            "labels": [CANONICAL_LABELS[label_id] for label_id in EVALUATED_LABEL_IDS],
            "values": matrix.tolist(),
        },
        "benign_false_alarm_rate": false_alarms / benign_count if benign_count else 0.0,
        "benign_false_alarm_rate_ci_95": _wilson_interval(false_alarms, benign_count),
    }


def evaluate_frame(frame: pd.DataFrame, *, sample_sha256: str) -> dict:
    splits = build_evaluation_splits(frame)
    model = RandomForestClassifier(
        n_estimators=N_ESTIMATORS,
        class_weight="balanced_subsample",
        max_depth=28,
        min_samples_leaf=2,
        n_jobs=-1,
        random_state=MODEL_SEED,
    )
    train = splits["train"]
    model.fit(
        train.reindex(columns=LIVE_FEATURE_COLUMNS, fill_value=0.0),
        train["label"].astype(int),
    )
    summaries = {}
    for split_name in ("validation", "test"):
        split = splits[split_name]
        predictions = model.predict(
            split.reindex(columns=LIVE_FEATURE_COLUMNS, fill_value=0.0)
        ).astype(int)
        summaries[split_name] = _summarize_predictions(
            split["label"].astype(int).to_numpy(),
            predictions,
        )

    source_groups_by_class = {
        CANONICAL_LABELS[int(label_id)]: sorted(group_values.astype(str).unique().tolist())
        for label_id, group_values in frame.groupby("label")["source_group"]
    }
    attack_thresholds = {
        CANONICAL_LABELS[label_id]: (
            "pass"
            if summaries["test"]["per_class"][CANONICAL_LABELS[label_id]]["recall"] >= MIN_ATTACK_RECALL
            and summaries["test"]["per_class"][CANONICAL_LABELS[label_id]]["precision"] >= MIN_ATTACK_PRECISION
            else "fail"
        )
        for label_id in ATTACK_LABEL_IDS
    }
    benign_threshold_status = (
        "pass"
        if summaries["test"]["benign_false_alarm_rate"] <= MAX_BENIGN_FALSE_ALARM_RATE
        else "fail"
    )
    threshold_status = [*attack_thresholds.values(), benign_threshold_status]
    split_summaries = {
        split_name: {
            "rows": len(split),
            "source_group_count": int(split["source_group"].nunique()),
            "source_groups": sorted(split["source_group"].astype(str).unique().tolist()),
            "source_groups_by_class": {
                CANONICAL_LABELS[int(label_id)]: int(group_values.nunique())
                for label_id, group_values in split.groupby("label")["source_group"]
            },
        }
        for split_name, split in splits.items()
    }
    return {
        "evaluated_at_utc": datetime.now(timezone.utc).isoformat(),
        "status": "thresholds_not_met" if "fail" in threshold_status else "thresholds_met_operational_gates_pending",
        "dataset": {
            "root": "data/phase1",
            "sample_rows": len(frame),
            "sample_sha256": sample_sha256,
            "rows_per_source_group_class_cap": ROWS_PER_GROUP_CLASS,
            "sample_seed": 42,
            "source_group_count_by_class": {
                name: len(groups) for name, groups in source_groups_by_class.items()
            },
            "source_groups_by_class": source_groups_by_class,
        },
        "evaluation": {
            "strategy": "group-disjoint train/validation/test holdouts",
            "group_seed": GROUP_SEED,
            "group_overlap": 0,
            "confidence_interval_method": (
                "Row-level Wilson score intervals; they do not adjust for within-capture dependence."
            ),
            "evaluated_classes": list(CANONICAL_LABELS),
            "splits": split_summaries,
        },
        "model": {
            "estimator": "RandomForestClassifier",
            "n_estimators": N_ESTIMATORS,
            "class_weight": "balanced_subsample",
            "max_depth": 28,
            "min_samples_leaf": 2,
            "random_state": MODEL_SEED,
            "sklearn_version": sklearn.__version__,
            "feature_columns": LIVE_FEATURE_COLUMNS,
            "hyperparameter_tuning": False,
        },
        "approved_thresholds": {
            "attack_recall_min": MIN_ATTACK_RECALL,
            "attack_precision_min": MIN_ATTACK_PRECISION,
            "benign_false_alarm_rate_max": MAX_BENIGN_FALSE_ALARM_RATE,
        },
        "results": {
            "validation": summaries["validation"],
            "test": summaries["test"],
            "attack_threshold_status": attack_thresholds,
            "benign_false_alarm_threshold_status": benign_threshold_status,
        },
        "limitations": [
            "Dataset source-group independence does not establish generalization to a deployment network or site.",
            "CSE-CIC-IDS2018 captures do not provide source and destination port fields in this flow export; normalized port features are zero.",
            "The live flow extractor is a limited feature implementation and has not been proven semantically equivalent to every offline dataset feature.",
            "No hyperparameter tuning, probability calibration, or deployment-network validation was performed.",
            "Confidence intervals assume independent rows and may understate uncertainty within a held-out capture.",
        ],
    }


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=PHASE1_DIR)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()

    with tempfile.TemporaryDirectory(prefix="aegis-strict-groups-") as temp_dir:
        sample_path = Path(temp_dir) / "sample.csv"
        build_sample(args.root, sample_path, ROWS_PER_GROUP_CLASS, seed=42)
        frame = pd.read_csv(sample_path)
        report = evaluate_frame(frame, sample_sha256=_sha256(sample_path))

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"Strict group evaluation saved to {args.output}")
    print(f"Test rows: {report['evaluation']['splits']['test']['rows']:,}")
    print(f"Benign false-alarm rate: {report['results']['test']['benign_false_alarm_rate']:.4%}")
    print(f"Attack thresholds: {report['results']['attack_threshold_status']}")


if __name__ == "__main__":
    main()
