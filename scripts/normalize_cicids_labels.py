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
import pandas as pd

# Mapping from raw labels to Phase 1 labels
LABEL_MAPPING = {
    "BENIGN": "Benign",
    "Benign": "Benign",
    "benign": "Benign",
    
    # DoS attacks
    "DoS GoldenEye": "DoS",
    "DoS Hulk": "DoS",
    "DoS Slowhttptest": "DoS",
    "DoS slowloris": "DoS",
    "Heartbleed": "DoS",
    
    # DDoS
    "DDoS": "DDoS",
    
    # Port Scan
    "PortScan": "Port Scan",
    "Port Scan": "Port Scan",
    
    # Brute Force
    "FTP-Patator": "Brute Force",
    "SSH-Patator": "Brute Force",
    "Brute Force": "Brute Force",
    
    # Web Attack
    "Web Attack ï¿½ Brute Force": "Web Attack",
    "Web Attack – Brute Force": "Web Attack",
    "Web Attack ï¿½ Sql Injection": "Web Attack",
    "Web Attack – SQL Injection": "Web Attack",
    "Web Attack ï¿½ XSS": "Web Attack",
    "Web Attack – XSS": "Web Attack",
    "Web Attack": "Web Attack",
    
    # Botnet
    "Bot": "Botnet",
    "Botnet": "Botnet",
    
    # Infiltration (map to Botnet if not in Phase 1)
    "Infiltration": "Botnet",
}


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
        
        original_labels = df[label_col].unique()
        
        # Normalize labels
        df[label_col] = df[label_col].map(LABEL_MAPPING)
        
        # Check for unmapped labels
        unmapped = df[df[label_col].isna()]
        if len(unmapped) > 0:
            print(f"  Warning: Found unmapped labels in {input_path.name}:")
            print(f"    {unmapped[label_col].unique() if label_col in unmapped.columns else 'N/A'}")
            # Drop unmapped rows
            df = df.dropna(subset=[label_col])
        
        # Rename to standard "Label"
        df = df.rename(columns={label_col: "Label"})
        
        df.to_csv(output_path, index=False)
        print(f"  ✓ Normalized {input_path.name} ({len(df)} rows)")
        print(f"    Labels: {df['Label'].unique().tolist()}")
        return True
        
    except Exception as e:
        print(f"  ✗ Error processing {input_path.name}: {e}")
        return False


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--input-dir",
        type=Path,
        default=Path("data/phase1/CIC-IDS-2017"),
        help="Directory with raw CIC-IDS CSVs"
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("ml/data/raw"),
        help="Directory to write normalized CSVs"
    )
    args = parser.parse_args()
    
    input_dir = args.input_dir
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
