"""
Baseline training: RandomForest on stratified sample splits (default) or full splits.

Also fits an IsolationForest anomaly model on rows labeled Benign (or majority class).

Usage:
  python ml/training/train.py
  python ml/training/train.py --full
"""
from __future__ import annotations

import argparse
import json
import shutil
import sys
from pathlib import Path

if __package__ in (None, ""):
    ROOT = Path(__file__).resolve().parents[2]
    if str(ROOT) not in sys.path:
        sys.path.insert(0, str(ROOT))

import pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.metrics import classification_report

try:
    from xgboost import XGBClassifier
except Exception:  # pragma: no cover
    XGBClassifier = None

from ml.models.bundle import save_bundle

# Prefer sample splits for the week milestone; fall back to full splits.
SAMPLE_DIR = Path("ml/data/splits/sample")
FULL_DIR = Path("ml/data/splits")
MODEL_DIR = Path("ml/models")

# Human-readable names matching LabelEncoder order used by data_loader
# (alphabetical EXPECTED_LABELS). Only classes present in y are kept.
DEFAULT_CLASS_NAMES = [
    "Benign",
    "Botnet",
    "Brute Force",
    "DDoS",
    "DoS",
    "Port Scan",
    "Web Attack",
]


def _split_paths(use_full: bool) -> tuple[Path, Path, Path]:
    base = FULL_DIR if use_full else (SAMPLE_DIR if (SAMPLE_DIR / "train.csv").exists() else FULL_DIR)
    return base / "train.csv", base / "val.csv", base / "test.csv"


def load_split(csv_path: Path):
    df = pd.read_csv(csv_path)
    if "label" not in df.columns:
        raise ValueError(f"No 'label' column in {csv_path}")
    y = df["label"]
    X = df.drop(columns=["label"])
    # Keep only numeric feature columns
    X = X.select_dtypes(include=["number"]).copy()
    return X, y


def _label_names_for_model(y) -> list[str]:
    present = sorted(int(v) for v in pd.unique(y))
    names = []
    for idx in present:
        if 0 <= idx < len(DEFAULT_CLASS_NAMES):
            names.append(DEFAULT_CLASS_NAMES[idx])
        else:
            names.append(str(idx))
    # If contiguous from 0, return full list for those indices
    if present == list(range(len(present))):
        return [DEFAULT_CLASS_NAMES[i] if i < len(DEFAULT_CLASS_NAMES) else str(i) for i in present]
    # Sparse indices: build a list indexed by class id with placeholders
    max_id = max(present)
    out = [str(i) for i in range(max_id + 1)]
    for i in present:
        out[i] = DEFAULT_CLASS_NAMES[i] if i < len(DEFAULT_CLASS_NAMES) else str(i)
    return out


def _gpu_available() -> bool:
    if shutil.which("nvidia-smi") is None:
        return False
    try:
        import subprocess

        result = subprocess.run(
            ["nvidia-smi", "--query-gpu=name", "--format=csv,noheader"],
            capture_output=True,
            text=True,
            check=False,
        )
        return result.returncode == 0 and bool(result.stdout.strip())
    except Exception:
        return False


def _train_model(X_train, y_train, X_val, y_val, *, engine: str, n_estimators: int, random_state: int):
    label_names = _label_names_for_model(y_train)

    if engine == "xgboost" and XGBClassifier is not None:
        if _gpu_available():
            model = XGBClassifier(
                n_estimators=n_estimators,
                max_depth=8,
                learning_rate=0.08,
                objective="multi:softprob",
                eval_metric="mlogloss",
                tree_method="hist",
                device="cuda",
                random_state=random_state,
                n_jobs=0,
                verbosity=0,
                num_class=len(label_names),
            )
            print("Training XGBoost model on CUDA GPU...")
        else:
            model = XGBClassifier(
                n_estimators=n_estimators,
                max_depth=8,
                learning_rate=0.08,
                objective="multi:softprob",
                eval_metric="mlogloss",
                tree_method="hist",
                device="cpu",
                random_state=random_state,
                n_jobs=0,
                verbosity=0,
                num_class=len(label_names),
            )
            print("Training XGBoost model on CPU (CUDA unavailable)...")
        model.fit(X_train, y_train)
        preds = model.predict(X_val)
        return model, preds, label_names

    print(f"Training RandomForest (n_estimators={n_estimators}) on {len(X_train):,} rows ...")
    model = RandomForestClassifier(
        n_estimators=n_estimators,
        class_weight="balanced_subsample",
        max_depth=28,
        min_samples_leaf=2,
        n_jobs=-1,
        random_state=random_state,
    )
    model.fit(X_train, y_train)
    preds = model.predict(X_val)
    return model, preds, label_names


def train_and_save(
    use_full: bool = False,
    n_estimators: int = 120,
    random_state: int = 42,
    engine: str = "auto",
):
    train_csv, val_csv, test_csv = _split_paths(use_full)
    if not train_csv.exists():
        raise FileNotFoundError(
            f"Train CSV not found at {train_csv}. Run scripts/sample_splits.py "
            "or ml/data/data_loader.load_dataset first."
        )

    print(f"Loading train from {train_csv} ...")
    X_train, y_train = load_split(train_csv)
    print(f"Loading val from {val_csv} ...")
    X_val, y_val = load_split(val_csv)

    # Align columns
    feature_columns = list(X_train.columns)
    X_val = X_val.reindex(columns=feature_columns, fill_value=0.0)

    selected_engine = engine
    if engine == "auto":
        selected_engine = "xgboost" if XGBClassifier is not None and _gpu_available() else "random_forest"

    model, preds, label_names = _train_model(
        X_train,
        y_train,
        X_val,
        y_val,
        engine=selected_engine,
        n_estimators=n_estimators,
        random_state=random_state,
    )

    present_labels = sorted(set(y_val.tolist()) | set(preds.tolist()))
    target_names = [label_names[i] if i < len(label_names) else str(i) for i in present_labels]
    report = classification_report(
        y_val,
        preds,
        labels=present_labels,
        target_names=target_names,
        output_dict=True,
        zero_division=0,
    )

    MODEL_DIR.mkdir(parents=True, exist_ok=True)
    with open(MODEL_DIR / "val_metrics.json", "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    # Anomaly model on presumed Benign (=0) if present, else all rows
    benign_mask = y_train == 0
    if benign_mask.sum() >= 50:
        X_benign = X_train.loc[benign_mask]
        if len(X_benign) > 80_000:
            X_benign = X_benign.sample(n=80_000, random_state=random_state)
        print(f"Fitting IsolationForest on {len(X_benign):,} benign rows ...")
        anomaly = IsolationForest(
            n_estimators=100,
            contamination=0.05,
            random_state=random_state,
            n_jobs=-1,
        )
        anomaly.fit(X_benign)
    else:
        print("Fitting IsolationForest on a random training subset ...")
        X_sub = X_train.sample(n=min(80_000, len(X_train)), random_state=random_state)
        anomaly = IsolationForest(
            n_estimators=100,
            contamination=0.05,
            random_state=random_state,
            n_jobs=-1,
        )
        anomaly.fit(X_sub)

    meta = {
        "train_csv": str(train_csv),
        "val_csv": str(val_csv),
        "test_csv": str(test_csv),
        "n_train": int(len(X_train)),
        "n_val": int(len(X_val)),
        "n_features": len(feature_columns),
        "n_estimators": n_estimators,
        "val_accuracy": report.get("accuracy"),
        "classes": label_names,
        "engine": selected_engine,
        "gpu_enabled": selected_engine == "xgboost" and _gpu_available(),
    }
    save_bundle(
        model=model,
        feature_columns=feature_columns,
        label_classes=label_names,
        anomaly_model=anomaly,
        meta=meta,
    )

    print("Model bundle saved under ml/models/")
    print(f"Validation accuracy: {report.get('accuracy')}")
    print("Validation report -> ml/models/val_metrics.json")
    if selected_engine == "xgboost":
        print(f"Model engine: XGBoost ({'CUDA' if _gpu_available() else 'CPU'})")
    else:
        print("Model engine: RandomForest (CPU)")
    return model, report


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--full", action="store_true", help="Train on full splits instead of sample/")
    parser.add_argument("--n-estimators", type=int, default=120)
    parser.add_argument(
        "--engine",
        choices=["auto", "random_forest", "xgboost"],
        default="auto",
        help="Model engine to use. Auto picks XGBoost on CUDA when available.",
    )
    args = parser.parse_args()
    train_and_save(use_full=args.full, n_estimators=args.n_estimators, engine=args.engine)
