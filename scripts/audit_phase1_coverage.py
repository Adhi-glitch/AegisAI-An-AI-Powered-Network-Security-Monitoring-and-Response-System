"""Stream label counts from datasets under data/phase1 without loading features."""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
from pathlib import Path
import sys

import pandas as pd
import pyarrow.parquet as pq

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from ml.data.multidataset import CANONICAL_LABELS, canonicalize_label

PHASE1_DIR = ROOT / "data" / "phase1"


def _csv_label_column(path: Path, preferred: tuple[str, ...]) -> int:
    header = pd.read_csv(path, nrows=0, encoding="utf-8-sig", low_memory=False).columns
    columns = [str(value).strip().casefold() for value in header]
    for name in preferred:
        if name in columns:
            return columns.index(name)
    raise ValueError(f"No label column {preferred} in {path}")


def _count_csv(path: Path, preferred: tuple[str, ...], encoding: str = "utf-8-sig") -> Counter[str]:
    label_index = _csv_label_column(path, preferred)
    counts: Counter[str] = Counter()
    for chunk in pd.read_csv(
        path,
        usecols=[label_index],
        chunksize=500_000,
        encoding=encoding,
        low_memory=False,
    ):
        for raw_label in chunk.iloc[:, 0].dropna().astype(str):
            canonical = canonicalize_label(raw_label)
            if canonical is not None:
                counts[canonical] += 1
    return counts


def _count_parquet(path: Path) -> Counter[str]:
    parquet = pq.ParquetFile(path)
    label_column = next(
        (column for column in parquet.schema_arrow.names if column.strip().casefold() == "label"),
        None,
    )
    if label_column is None:
        raise ValueError(f"No label column found in {path}")
    counts: Counter[str] = Counter()
    for batch in parquet.iter_batches(columns=[label_column], batch_size=500_000):
        for raw_label in batch.column(0).to_pylist():
            canonical = canonicalize_label(raw_label)
            if canonical is not None:
                counts[canonical] += 1
    return counts


def collect_counts(root: Path) -> tuple[dict[str, Counter[str]], dict[str, Counter[str]]]:
    by_file: dict[str, Counter[str]] = {}
    by_dataset: dict[str, Counter[str]] = defaultdict(Counter)

    sources = [
        ("CIC-IDS-2017", root / "CIC-IDS-2017", ("label",)),
        ("UNSW-NB15", root / "UNSW-NB15" / "Training and Testing Sets", ("attack_cat", "label")),
        ("Bot-IoT", root / "Bot-IoT" / "All features", ("category", "subcategory", "label")),
    ]
    for dataset, directory, label_columns in sources:
        for path in sorted(directory.glob("*.csv")):
            counts = _count_csv(path, label_columns, encoding="cp1252" if dataset == "UNSW-NB15" else "utf-8-sig")
            if "infilteration" in path.name.casefold() or "infiltration" in path.name.casefold():
                counts.pop("Botnet", None)
            by_file[f"{dataset}/{path.name}"] = counts
            by_dataset[dataset].update(counts)

    ctu_dir = root / "CTU-13"
    for path in sorted(ctu_dir.glob("*.parquet")):
        counts = _count_parquet(path)
        by_file[f"CTU-13/{path.name}"] = counts
        by_dataset["CTU-13"].update(counts)

    cse_dir = root / "CSE-CIC-IDS2018"
    for path in sorted(cse_dir.glob("*.parquet")):
        counts = _count_parquet(path)
        by_file[f"CSE-CIC-IDS2018/{path.name}"] = counts
        by_dataset["CSE-CIC-IDS2018"].update(counts)

    nsl_dir = root / "NSL-KDD"
    for path in sorted(nsl_dir.glob("*.txt")):
        if path.name in {"KDDTest-21.txt", "KDDTrain+_20Percent.txt"}:
            continue
        frame = pd.read_csv(path, header=None, usecols=[41], dtype="string", low_memory=False)
        counts: Counter[str] = Counter()
        for raw_label in frame.iloc[:, 0].dropna().astype(str):
            canonical = canonicalize_label(raw_label)
            if canonical is not None:
                counts[canonical] += 1
        by_file[f"NSL-KDD/{path.name}"] = counts
        by_dataset["NSL-KDD"].update(counts)

    return by_file, by_dataset


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=PHASE1_DIR)
    args = parser.parse_args()

    by_file, by_dataset = collect_counts(args.root)
    groups_by_label: dict[str, set[str]] = defaultdict(set)
    total_by_label: Counter[str] = Counter()

    print("Per-file canonical row counts:")
    for source, counts in by_file.items():
        print(f"{source}: {dict(counts)}")
        for label, count in counts.items():
            if count:
                dataset = source.split("/", 1)[0]
                group = source if dataset in {"CIC-IDS-2017", "CTU-13", "CSE-CIC-IDS2018"} else dataset
                groups_by_label[label].add(group)
                total_by_label[label] += count

    print("\nPer-dataset canonical row counts:")
    for dataset, counts in by_dataset.items():
        print(f"{dataset}: {dict(counts)}")

    print("\nCanonical totals:")
    for label in CANONICAL_LABELS:
        print(f"{label}: rows={total_by_label[label]:,}, conservative_source_groups={len(groups_by_label[label])}")
    print("\nGroup policy: CICIDS day files, CSE-CIC-IDS2018 scenario files, and CTU-13 scenarios are separate captures; UNSW, Bot-IoT shards, and NSL-KDD benchmark partitions count as one source group each.")


if __name__ == "__main__":
    main()