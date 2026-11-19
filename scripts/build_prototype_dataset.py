"""Build a bounded, source-tagged sample from the datasets under data/phase1."""
from __future__ import annotations

import argparse
import sys
from collections import Counter
from pathlib import Path

import numpy as np
import pandas as pd
import pyarrow.parquet as pq

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from ml.data.multidataset import (  # noqa: E402
    CANONICAL_LABELS,
    FEATURE_ALIASES,
    _combine_feature_vector,
    _protocol_number,
)

PHASE1_DIR = ROOT / "data" / "phase1"
DEFAULT_OUTPUT = ROOT / "ml" / "data" / "processed" / "multi_dataset_prototype.csv"
NSL_FEATURE_NAMES = [
    "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes", "land",
    "wrong_fragment", "urgent", "hot", "num_failed_logins", "logged_in", "num_compromised",
    "root_shell", "su_attempted", "num_root", "num_file_creations", "num_shells",
    "num_access_files", "num_outbound_cmds", "is_host_login", "is_guest_login", "count",
    "srv_count", "serror_rate", "srv_serror_rate", "rerror_rate", "srv_rerror_rate",
    "same_srv_rate", "diff_srv_rate", "srv_diff_host_rate", "dst_host_count", "dst_host_srv_count",
    "dst_host_same_srv_rate", "dst_host_diff_srv_rate", "dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate", "dst_host_serror_rate", "dst_host_srv_serror_rate",
    "dst_host_rerror_rate", "dst_host_srv_rerror_rate", "label", "difficulty",
]


def _sample_frame(
    frame: pd.DataFrame,
    group: str,
    reservoirs: dict[tuple[str, int], tuple[pd.DataFrame, np.ndarray]],
    rows_per_group_class: int,
    random: np.random.Generator,
) -> None:
    for label_id, class_frame in frame.groupby("label", sort=True):
        key = (group, int(label_id))
        previous = reservoirs.get(key)
        if previous is None:
            candidate = class_frame.reset_index(drop=True)
            priorities = random.random(len(candidate))
        else:
            previous_frame, previous_priorities = previous
            candidate = pd.concat([previous_frame, class_frame], ignore_index=True)
            priorities = np.concatenate((previous_priorities, random.random(len(class_frame))))

        if len(candidate) > rows_per_group_class:
            keep = np.argpartition(priorities, rows_per_group_class - 1)[:rows_per_group_class]
            candidate = candidate.iloc[keep].reset_index(drop=True)
            priorities = priorities[keep]
        reservoirs[key] = candidate, priorities


def _consume_csv(
    path: Path,
    dataset: str,
    group: str,
    reservoirs: dict[tuple[str, int], tuple[pd.DataFrame, np.ndarray]],
    rows_per_group_class: int,
    random: np.random.Generator,
    *,
    encoding: str = "utf-8-sig",
    chunksize: int = 100_000,
) -> None:
    for raw in pd.read_csv(path, chunksize=chunksize, low_memory=False, encoding=encoding):
        frame = _combine_feature_vector(raw)
        if dataset == "CIC-IDS-2017" and "infilteration" in path.name.casefold():
            frame = frame[frame["label_name"] != "Botnet"]
        frame["dataset"] = dataset
        frame["source_group"] = group
        _sample_frame(frame, group, reservoirs, rows_per_group_class, random)


def build_sample(
    root: Path,
    output_path: Path,
    rows_per_group_class: int = 10_000,
    seed: int = 42,
) -> pd.DataFrame:
    if rows_per_group_class < 1:
        raise ValueError("rows_per_group_class must be positive")
    random = np.random.default_rng(seed)
    reservoirs: dict[tuple[str, int], tuple[pd.DataFrame, np.ndarray]] = {}

    for path in sorted((root / "CIC-IDS-2017").glob("*.csv")):
        _consume_csv(path, "CIC-IDS-2017", f"CIC-IDS-2017/{path.name}", reservoirs,
                     rows_per_group_class, random)

    unsw_dir = root / "UNSW-NB15" / "Training and Testing Sets"
    for path in sorted(unsw_dir.glob("*.csv")):
        if path.name.endswith("_GT.csv") or path.name.endswith("LIST_EVENTS.csv"):
            continue
        _consume_csv(path, "UNSW-NB15", "UNSW-NB15/combined-capture-set", reservoirs,
                     rows_per_group_class, random, encoding="cp1252")

    bot_iot_dir = root / "Bot-IoT" / "All features"
    for path in sorted(bot_iot_dir.glob("*.csv")):
        _consume_csv(path, "Bot-IoT", "Bot-IoT/Full5pc", reservoirs,
                     rows_per_group_class, random)

    for path in sorted((root / "CSE-CIC-IDS2018").glob("*.parquet")):
        group = f"CSE-CIC-IDS2018/{path.name}"
        parquet = pq.ParquetFile(path)
        aliases = {
            alias.strip().casefold()
            for feature_aliases in FEATURE_ALIASES.values()
            for alias in feature_aliases
        } | {"label"}
        columns = [
            column
            for column in parquet.schema_arrow.names
            if column.strip().casefold() in aliases
        ]
        if not any(column.strip().casefold() == "label" for column in columns):
            raise ValueError(f"No label column found in {path}")
        for batch in parquet.iter_batches(columns=columns, batch_size=100_000):
            frame = _combine_feature_vector(batch.to_pandas())
            frame["dataset"] = "CSE-CIC-IDS2018"
            frame["source_group"] = group
            _sample_frame(frame, group, reservoirs, rows_per_group_class, random)

    for path in sorted((root / "CTU-13").glob("*.parquet")):
        group = f"CTU-13/{path.name}"
        parquet = pq.ParquetFile(path)
        for batch in parquet.iter_batches(batch_size=100_000):
            frame = _combine_feature_vector(batch.to_pandas())
            frame["dataset"] = "CTU-13"
            frame["source_group"] = group
            _sample_frame(frame, group, reservoirs, rows_per_group_class, random)

    nsl_dir = root / "NSL-KDD"
    for name in ("KDDTrain+.txt", "KDDTest+.txt"):
        path = nsl_dir / name
        if not path.exists():
            continue
        for raw in pd.read_csv(path, header=None, chunksize=100_000, low_memory=False):
            if len(raw.columns) != len(NSL_FEATURE_NAMES):
                raise ValueError(f"Unexpected NSL-KDD column count in {path}: {len(raw.columns)}")
            raw.columns = NSL_FEATURE_NAMES
            raw = raw.drop(columns=["difficulty"])
            frame = _combine_feature_vector(raw)
            frame["dataset"] = "NSL-KDD"
            group = "NSL-KDD/official-train-test"
            frame["source_group"] = group
            _sample_frame(frame, group, reservoirs, rows_per_group_class, random)

    if not reservoirs:
        raise FileNotFoundError(f"No supported labeled dataset files found under {root}")

    frames = [sample for sample, _ in reservoirs.values()]
    unified = pd.concat(frames, ignore_index=True)
    missing = sorted(set(CANONICAL_LABELS) - set(unified["label_name"].unique()))
    if missing:
        raise ValueError(f"Prototype sample is missing canonical classes: {missing}")

    unified["protocol"] = unified["protocol"].map(_protocol_number)
    for column in ("service", "state", "src_ip", "dst_ip"):
        unified[column] = pd.factorize(unified[column].fillna("missing").astype(str))[0]
    for column in unified.columns:
        if column in {"label", "label_name", "attack_family", "dataset", "source_group"}:
            continue
        unified[column] = pd.to_numeric(unified[column], errors="coerce")
        unified[column] = unified[column].replace([np.inf, -np.inf], np.nan).fillna(0.0)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    unified.to_csv(output_path, index=False)
    counts = Counter(unified["label_name"])
    print(f"Wrote {len(unified):,} sampled rows to {output_path}")
    print(f"Per-class rows: {dict(counts)}")
    print(f"Per-class source groups: {unified.groupby('label_name')['source_group'].nunique().to_dict()}")
    return unified


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=PHASE1_DIR)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--rows-per-group-class", type=int, default=10_000)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()
    build_sample(args.root, args.output, args.rows_per_group_class, args.seed)


if __name__ == "__main__":
    main()