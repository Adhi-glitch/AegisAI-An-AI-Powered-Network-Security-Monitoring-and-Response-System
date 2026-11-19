"""
Model bundle helpers: load/save RF classifier + feature columns + label names + anomaly model.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
import math
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import joblib
from ml.data.multidataset import CANONICAL_LABELS

ROOT = Path(__file__).resolve().parents[2]
MODEL_DIR = ROOT / "ml" / "models"
DEFAULT_RF = MODEL_DIR / "baseline_rf.pkl"
DEFAULT_ANOMALY = MODEL_DIR / "anomaly_iforest.pkl"
FEATURE_COLUMNS = MODEL_DIR / "feature_columns.json"
LABEL_CLASSES = MODEL_DIR / "label_classes.json"
BUNDLE_META = MODEL_DIR / "bundle_meta.json"
ACTIVE_BUNDLE = MODEL_DIR / "active_bundle.json"


@dataclass(frozen=True)
class ModelBundle:
    directory: Path
    model: Any
    feature_columns: List[str]
    label_classes: List[str]
    metadata: Dict[str, Any]


def _default_bundle_dir() -> Path:
    active_manifest = MODEL_DIR / "active_bundle.json"
    if active_manifest.exists():
        try:
            with open(active_manifest, encoding="utf-8") as f:
                selected = Path(json.load(f)["bundle_dir"])
            if not selected.is_absolute():
                selected = ROOT / selected
            return selected
        except (OSError, KeyError, json.JSONDecodeError, TypeError) as exc:
            raise ValueError(f"Invalid active model bundle manifest: {active_manifest}") from exc

    multi_bundle = MODEL_DIR / "multi_dataset_bundle"
    labels_path = multi_bundle / "label_classes.json"
    if labels_path.exists():
        try:
            with open(labels_path, encoding="utf-8") as f:
                if set(json.load(f)) == set(CANONICAL_LABELS):
                    return multi_bundle
        except (OSError, json.JSONDecodeError, TypeError):
            pass
    return MODEL_DIR


def _resolve_bundle_dir(bundle_dir: Optional[Path | str] = None) -> Path:
    if bundle_dir is not None:
        directory = Path(bundle_dir)
        return directory if directory.is_absolute() else ROOT / directory
    return _default_bundle_dir()


def resolve_bundle_dir(bundle_dir: Optional[Path | str] = None) -> Path:
    return _resolve_bundle_dir(bundle_dir).resolve()


def _bundle_paths(bundle_dir: Optional[Path | str] = None) -> Dict[str, Path]:
    directory = _resolve_bundle_dir(bundle_dir)
    directory.mkdir(parents=True, exist_ok=True)
    return {
        "dir": directory,
        "rf": directory / "baseline_rf.pkl",
        "anomaly": directory / "anomaly_iforest.pkl",
        "features": directory / "feature_columns.json",
        "labels": directory / "label_classes.json",
        "meta": directory / "bundle_meta.json",
    }


def ensure_model_dir(bundle_dir: Optional[Path | str] = None) -> Path:
    return _bundle_paths(bundle_dir)["dir"]


def save_bundle(
    model: Any,
    feature_columns: List[str],
    label_classes: Optional[List[str]] = None,
    anomaly_model: Any = None,
    meta: Optional[Dict[str, Any]] = None,
    bundle_dir: Optional[Path | str] = None,
) -> None:
    paths = _bundle_paths(bundle_dir)
    joblib.dump(model, paths["rf"])
    with open(paths["features"], "w", encoding="utf-8") as f:
        json.dump(feature_columns, f, indent=2)
    if label_classes is not None:
        with open(paths["labels"], "w", encoding="utf-8") as f:
            json.dump(label_classes, f, indent=2)
    if anomaly_model is not None:
        joblib.dump(anomaly_model, paths["anomaly"])
    if meta is not None:
        with open(paths["meta"], "w", encoding="utf-8") as f:
            json.dump(meta, f, indent=2)


def activate_bundle(bundle_dir: Path | str) -> Path:
    directory = resolve_bundle_dir(bundle_dir)
    required = [directory / "baseline_rf.pkl", directory / "feature_columns.json", directory / "label_classes.json"]
    missing = [path.name for path in required if not path.is_file()]
    if missing:
        raise FileNotFoundError(f"Cannot activate incomplete model bundle at {directory}: missing {missing}")
    try:
        selected_dir = directory.relative_to(ROOT.resolve()).as_posix()
    except ValueError:
        selected_dir = str(directory)

    manifest = MODEL_DIR / "active_bundle.json"
    manifest.parent.mkdir(parents=True, exist_ok=True)
    with open(manifest, "w", encoding="utf-8") as f:
        json.dump({"bundle_dir": selected_dir}, f, indent=2)
    return directory


def load_bundle(bundle_dir: Optional[Path | str] = None) -> ModelBundle:
    directory = resolve_bundle_dir(bundle_dir)
    paths = _bundle_paths(directory)
    model = load_rf(paths["rf"])
    feature_columns = load_feature_columns(directory)
    label_classes = load_label_classes(directory)
    if not label_classes:
        raise ValueError(f"Missing label classes in model bundle: {directory}")
    if hasattr(model, "n_features_in_") and int(model.n_features_in_) != len(feature_columns):
        raise ValueError(
            f"Model expects {model.n_features_in_} features but bundle lists {len(feature_columns)}: {directory}"
        )
    if hasattr(model, "classes_"):
        try:
            class_ids = [int(value) for value in model.classes_]
        except (TypeError, ValueError) as exc:
            raise ValueError(f"Model classes are not integer-encoded in bundle: {directory}") from exc
        if class_ids != list(range(len(label_classes))):
            raise ValueError(
                f"Model classes {class_ids} do not align with {len(label_classes)} bundle labels: {directory}"
            )
    metadata = {}
    if paths["meta"].exists():
        with open(paths["meta"], encoding="utf-8") as f:
            metadata = json.load(f)
    return ModelBundle(directory, model, feature_columns, label_classes, metadata)


def load_feature_columns(bundle_dir: Optional[Path | str] = None) -> List[str]:
    paths = _bundle_paths(bundle_dir)
    if paths["features"].exists():
        with open(paths["features"], encoding="utf-8") as f:
            return list(json.load(f))

    model = None
    try:
        model = load_rf(paths["rf"])
    except FileNotFoundError:
        model = None

    if model is not None and hasattr(model, "feature_names_in_"):
        columns = [str(name) for name in model.feature_names_in_]
        with open(paths["features"], "w", encoding="utf-8") as f:
            json.dump(columns, f, indent=2)
        return columns

    raise FileNotFoundError(f"Missing {paths['features']}; train a model first")


def load_label_classes(bundle_dir: Optional[Path | str] = None) -> Optional[List[str]]:
    paths = _bundle_paths(bundle_dir)
    if not paths["labels"].exists():
        return None
    with open(paths["labels"], encoding="utf-8") as f:
        return list(json.load(f))


def load_rf(path: Optional[Path | str] = None):
    if path is None:
        path = _bundle_paths()["rf"]
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"Model not found: {path}")
    return joblib.load(path)


def load_anomaly(path: Optional[Path | str] = None):
    if path is None:
        path = _bundle_paths()["anomaly"]
    path = Path(path)
    if not path.exists():
        return None
    return joblib.load(path)


def vectorize_features(feature_vector: Dict[str, Any], columns: List[str]) -> List[float]:
    """Align a dict/Series-like feature map to the trained column order."""
    out: List[float] = []
    for col in columns:
        # Older CICIDS splits preserved whitespace in CSV headers, while the
        # CSV extractor normalizes those keys. Support both representations so
        # saved bundles remain usable and new ingestion stays predictable.
        val = feature_vector.get(col, feature_vector.get(str(col).strip(), 0.0))
        try:
            number = float(val)
            out.append(number if math.isfinite(number) else 0.0)
        except (TypeError, ValueError):
            out.append(0.0)

    if len(out) < len(columns):
        out.extend([0.0] * (len(columns) - len(out)))
    elif len(out) > len(columns):
        out = out[: len(columns)]
    return out


def resolve_label(model: Any, pred_idx_or_label, bundle_dir: Optional[Path | str] = None) -> str:
    classes = load_label_classes(bundle_dir)
    if classes is not None:
        try:
            idx = int(pred_idx_or_label)
            if 0 <= idx < len(classes):
                return classes[idx]
        except (TypeError, ValueError):
            pass
    if hasattr(model, "classes_"):
        try:
            idx = int(pred_idx_or_label)
            return str(model.classes_[idx])
        except Exception:
            return str(pred_idx_or_label)
    return str(pred_idx_or_label)
