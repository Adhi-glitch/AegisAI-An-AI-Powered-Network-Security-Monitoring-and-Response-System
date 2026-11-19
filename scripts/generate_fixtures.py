import pandas as pd
import json
from pathlib import Path
import os

ROOT = Path(__file__).resolve().parent.parent
TEST_CSV = ROOT / "ml" / "data" / "splits" / "trustworthy" / "test.csv"
OUT_FILE = ROOT / "tests" / "fixtures" / "heldout_examples.json"

def main():
    if not TEST_CSV.exists():
        print(f"Waiting for {TEST_CSV} to be generated...")
        return
        
    df = pd.read_csv(TEST_CSV)
    
    # 1 example per class
    examples = []
    
    for label in sorted(df['label'].unique()):
        # get first row
        row = df[df['label'] == label].iloc[0]
        # remove metadata columns
        d = row.to_dict()
        expected_label = int(d.pop('label'))
        capture_id = str(d.pop('capture_id', ''))
        source_group = str(d.pop('source_group', ''))
        
        # ensure floats
        features = {}
        for k, v in d.items():
            if pd.isna(v):
                features[k] = 0.0
            else:
                features[k] = float(v)
                
        examples.append({
            "expected_label": expected_label,
            "capture_id": capture_id,
            "source_group": source_group,
            "features": features
        })
        
    OUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(OUT_FILE, "w", encoding="utf-8") as f:
        json.dump(examples, f, indent=2)
        
    print(f"Generated {len(examples)} examples in {OUT_FILE}")

if __name__ == "__main__":
    main()
