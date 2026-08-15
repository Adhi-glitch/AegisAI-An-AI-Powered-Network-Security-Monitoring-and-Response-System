"""
Validate and combine CICIDS-style CSVs in ml/data/raw/ into a single processed CSV
Usage:
  python scripts/prepare_cicids.py --label-col Label --out ml/data/processed/combined.csv

It will:
 - scan ml/data/raw/*.csv
 - verify label column exists and labels are in EXPECTED_LABELS
 - concatenate files that pass checks into a single CSV
 - write the combined CSV to ml/data/processed/combined.csv
"""
import argparse
from pathlib import Path
import pandas as pd
from ml.data.data_loader import EXPECTED_LABELS

RAW_DIR = Path("ml/data/raw")
PROCESSED_DIR = Path("ml/data/processed")
PROCESSED_DIR.mkdir(parents=True, exist_ok=True)


def validate_file(path: Path, label_col: str = "Label"):
    df = pd.read_csv(path)
    if label_col not in df.columns:
        return False, f"Missing label column '{label_col}'"
    labels = set(df[label_col].astype(str).unique())
    bad = labels - set(EXPECTED_LABELS)
    if bad:
        return False, f"Unknown labels found: {sorted(list(bad))}"
    return True, {"rows": len(df), "labels": sorted(list(labels))}


def combine_all(label_col: str = "Label", out: Path = PROCESSED_DIR / "combined.csv"):
    files = sorted(RAW_DIR.glob("*.csv"))
    if not files:
        print("No CSV files found in", RAW_DIR)
        return
    ok_frames = []
    summary = {}
    for f in files:
        valid, info = validate_file(f, label_col)
        if valid:
            df = pd.read_csv(f)
            ok_frames.append(df)
            summary[f.name] = info
            print(f"Validated {f.name}: {info}")
        else:
            print(f"Skipping {f.name}: {info}")
    if not ok_frames:
        print("No valid CSVs to combine")
        return
    combined = pd.concat(ok_frames, ignore_index=True)
    combined.to_csv(out, index=False)
    print(f"Wrote combined CSV to {out} ({len(combined)} rows)")
    return out


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--label-col", default="Label")
    parser.add_argument("--out", default=str(PROCESSED_DIR / "combined.csv"))
    args = parser.parse_args()
    combine_all(label_col=args.label_col, out=Path(args.out))
