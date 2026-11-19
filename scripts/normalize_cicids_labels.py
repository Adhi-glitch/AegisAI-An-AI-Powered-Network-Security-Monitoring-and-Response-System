"""
Normalize CIC-IDS2017 labels to Phase 1 attack categories.
Maps various label formats in raw CIC-IDS CSVs to standardized labels:
  - Benign
  - DoS
  - DDoS
  - Port Scan
  - Brute Force
  - Web Attack
  - Botnet

Usage:
  python scripts/normalize_cicids_labels.py --input-dir data/phase1/CIC-IDS-2017 --output-dir ml/data/raw
"""
import argparse
from pathlib import Path
import sys
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from ml.data.multidataset import canonicalize_label

def normalize_csv(input_path: Path, output_path: Path):
    """
    Read CSV, normalize labels, write to output.
    Returns True if successful, False otherwise.
    """
    try:
        df = pd.read_csv(input_path)
        
        # Find label column (may have leading/trailing spaces)
        label_col = None
        for col in df.columns:
            if col.strip().lower() == "label":
                label_col = col
                break
        
        if label_col is None:
            print(f"  Warning: No 'Label' column in {input_path.name}, skipping")
            return False
        
        original_values = df[label_col].copy()
        normalized_labels = original_values.map(canonicalize_label)
        if "infilteration" in input_path.name.casefold() or "infiltration" in input_path.name.casefold():
            normalized_labels = normalized_labels.mask(
                original_values.astype(str).str.strip().str.casefold().eq("botnet")
            )

        unmapped = normalized_labels.isna()
        if unmapped.any():
            unmapped_counts = original_values[unmapped].value_counts(dropna=False)
            print(f"  Dropping unsupported labels in {input_path.name}: {unmapped_counts.to_dict()}")
        df[label_col] = normalized_labels
        df = df.loc[~unmapped].copy()

        # Rename to standard "Label"
        df = df.rename(columns={label_col: "Label"})

        df.to_csv(output_path, index=False)
        print(f"  ✓ Normalized {input_path.name} ({len(df)} rows)")
        print(f"    Per-class rows: {df['Label'].value_counts().sort_index().to_dict()}")
        return True
        
    except Exception as e:
        print(f"  ✗ Error processing {input_path.name}: {e}")
        return False


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--input-dir",
        type=Path,
        default=None,
        help="Directory with raw CIC-IDS CSVs"
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("ml/data/processed/cicids-normalized"),
        help="Directory to write normalized CSVs"
    )
    args = parser.parse_args()
    
    phase1_input = ROOT / "data" / "phase1" / "CIC-IDS-2017"
    input_dir = args.input_dir or (
        phase1_input if phase1_input.exists() else ROOT / "ml" / "data" / "raw"
    )
    output_dir = args.output_dir
    
    if not input_dir.exists():
        print(f"Input directory not found: {input_dir}")
        return
    
    output_dir.mkdir(parents=True, exist_ok=True)
    
    print(f"Normalizing CSVs from {input_dir} -> {output_dir}\n")
    
    csv_files = sorted(input_dir.glob("*.csv"))
    if not csv_files:
        print(f"No CSV files found in {input_dir}")
        return
    
    successful = 0
    for csv_file in csv_files:
        output_file = output_dir / csv_file.name
        if normalize_csv(csv_file, output_file):
            successful += 1
    
    print(f"\n✓ Successfully normalized {successful}/{len(csv_files)} files")


if __name__ == "__main__":
    main()
