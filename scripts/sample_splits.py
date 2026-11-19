"""
Create stratified sample splits from the unified CSV.
Enforces that independent source groups are never split across train/val/test
to prevent data leakage (using GroupShuffleSplit logic).
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import pandas as pd
import numpy as np

ROOT = Path(__file__).resolve().parent.parent
SPLITS = ROOT / "ml" / "data" / "splits"
OUT = SPLITS / "trustworthy"

def main():
    parser = argparse.ArgumentParser(description="Group-based split of unified CSV")
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    unified_path = ROOT / "ml" / "data" / "unified_full.csv"
    if not unified_path.exists():
        raise FileNotFoundError(f"Missing {unified_path}")

    print("Loading unified CSV...")
    df = pd.read_csv(unified_path)
    
    if "source_group" not in df.columns:
        raise ValueError("source_group column missing from unified CSV")

    # Check that each class has at least 3 source groups
    group_counts = df.groupby('label')['source_group'].nunique()
    if (group_counts < 3).any():
        print(group_counts)
        raise ValueError("Some classes lack >= 3 distinct source groups. Cannot split safely without leakage.")

    # We will split groups, not rows.
    # To stratify somewhat, we assign groups to train/val/test.
    # Since groups might have different label distributions, we just randomly assign groups.
    # We want roughly 60/20/20.
    
    np.random.seed(args.seed)
    
    train_groups = []
    val_groups = []
    test_groups = []

    for label in df['label'].unique():
        class_df = df[df['label'] == label]
        unique_groups = class_df['source_group'].unique()
        unique_groups = list(unique_groups) # safe for shuffling
        np.random.shuffle(unique_groups)
        
        # assign groups 60/20/20 approximately by items
        # since we have exactly 3 groups for many classes, let's just put
        # at least 1 in train, 1 in val, 1 in test if there are exactly 3.
        if len(unique_groups) >= 3:
            train_groups.append(unique_groups[0])
            val_groups.append(unique_groups[1])
            test_groups.append(unique_groups[2])
            # any extras go to train
            train_groups.extend(unique_groups[3:])
        else:
            # fallback
            train_groups.extend(unique_groups)

    # ensure lists are unique
    train_groups = list(set(train_groups))
    val_groups = list(set(val_groups))
    test_groups = list(set(test_groups))

    # Remove overlaps if any (should not happen if groups are unique per class)
    val_groups = [g for g in val_groups if g not in train_groups]
    test_groups = [g for g in test_groups if g not in train_groups and g not in val_groups]

    train_s = df[df['source_group'].isin(train_groups)].reset_index(drop=True)
    val_s = df[df['source_group'].isin(val_groups)].reset_index(drop=True)
    test_s = df[df['source_group'].isin(test_groups)].reset_index(drop=True)

    OUT.mkdir(parents=True, exist_ok=True)
    train_s.to_csv(OUT / "train.csv", index=False)
    val_s.to_csv(OUT / "val.csv", index=False)
    test_s.to_csv(OUT / "test.csv", index=False)

    meta = {
        "seed": args.seed,
        "train_rows": len(train_s),
        "val_rows": len(val_s),
        "test_rows": len(test_s),
        "train_groups": len(train_groups),
        "val_groups": len(val_groups),
        "test_groups": len(test_groups),
        "train_label_counts": train_s["label"].value_counts().sort_index().to_dict(),
        "val_label_counts": val_s["label"].value_counts().sort_index().to_dict(),
        "test_label_counts": test_s["label"].value_counts().sort_index().to_dict(),
    }
    for key in ("train_label_counts", "val_label_counts", "test_label_counts"):
        meta[key] = {str(k): int(v) for k, v in meta[key].items()}

    with open(OUT / "sample_meta.json", "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2)

    print(f"Wrote trustworthy splits to {OUT}")
    print(json.dumps(meta, indent=2))

if __name__ == "__main__":
    main()
