"""
Create stratified sample splits from the full CICIDS train/val/test CSVs.

Default target: ~300k train rows (proportional val/test) for a week-milestone
baseline that trains in reasonable time on a laptop.

Usage:
  python scripts/sample_splits.py
  python scripts/sample_splits.py --train-size 300000 --seed 42
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import pandas as pd
from sklearn.model_selection import train_test_split

ROOT = Path(__file__).resolve().parent.parent
SPLITS = ROOT / "ml" / "data" / "splits"
OUT = SPLITS / "sample"


def _sample_frame(df: pd.DataFrame, n: int, seed: int) -> pd.DataFrame:
    if n >= len(df):
        return df.reset_index(drop=True)
    counts = df["label"].value_counts()
    if counts.min() >= 2 and df["label"].nunique() > 1:
        try:
            sampled, _ = train_test_split(
                df,
                train_size=n,
                stratify=df["label"],
                random_state=seed,
            )
            return sampled.reset_index(drop=True)
        except ValueError:
            pass
    return df.sample(n=n, random_state=seed).reset_index(drop=True)


def main():
    parser = argparse.ArgumentParser(description="Stratified sample of CICIDS splits")
    parser.add_argument("--train-size", type=int, default=300_000)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument(
        "--val-ratio",
        type=float,
        default=None,
        help="If set, size val as this fraction of train-size (else scale from full split sizes)",
    )
    parser.add_argument(
        "--test-ratio",
        type=float,
        default=None,
        help="If set, size test as this fraction of train-size (else scale from full split sizes)",
    )
    args = parser.parse_args()

    train_path = SPLITS / "train.csv"
    val_path = SPLITS / "val.csv"
    test_path = SPLITS / "test.csv"
    for p in (train_path, val_path, test_path):
        if not p.exists():
            raise FileNotFoundError(f"Missing split: {p}")

    print("Loading full splits (this can take a minute)...")
    train = pd.read_csv(train_path)
    val = pd.read_csv(val_path)
    test = pd.read_csv(test_path)
    print(f"  full train={len(train):,} val={len(val):,} test={len(test):,}")

    train_n = min(args.train_size, len(train))
    if args.val_ratio is not None:
        val_n = max(1, int(train_n * args.val_ratio))
    else:
        val_n = max(1, int(len(val) * (train_n / len(train))))
    if args.test_ratio is not None:
        test_n = max(1, int(train_n * args.test_ratio))
    else:
        test_n = max(1, int(len(test) * (train_n / len(train))))
    val_n = min(val_n, len(val))
    test_n = min(test_n, len(test))

    train_s = _sample_frame(train, train_n, args.seed)
    val_s = _sample_frame(val, val_n, args.seed + 1)
    test_s = _sample_frame(test, test_n, args.seed + 2)

    OUT.mkdir(parents=True, exist_ok=True)
    train_s.to_csv(OUT / "train.csv", index=False)
    val_s.to_csv(OUT / "val.csv", index=False)
    test_s.to_csv(OUT / "test.csv", index=False)

    meta = {
        "seed": args.seed,
        "train_rows": len(train_s),
        "val_rows": len(val_s),
        "test_rows": len(test_s),
        "train_label_counts": train_s["label"].value_counts().sort_index().to_dict(),
        "val_label_counts": val_s["label"].value_counts().sort_index().to_dict(),
        "test_label_counts": test_s["label"].value_counts().sort_index().to_dict(),
        "source": {
            "train": str(train_path),
            "val": str(val_path),
            "test": str(test_path),
        },
    }
    # JSON keys must be strings
    for key in ("train_label_counts", "val_label_counts", "test_label_counts"):
        meta[key] = {str(k): int(v) for k, v in meta[key].items()}

    with open(OUT / "sample_meta.json", "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2)

    print(f"Wrote samples to {OUT}")
    print(json.dumps(meta, indent=2))


if __name__ == "__main__":
    main()
