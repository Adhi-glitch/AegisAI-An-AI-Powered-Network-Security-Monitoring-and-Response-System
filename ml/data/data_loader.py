"""
Data loader for CICIDS2017-style CSVs.
Expected CSV columns (example subset):
- Flow Duration
- Total Fwd Packets
- Total Backward Packets
- Total Length of Fwd Packets
- Total Length of Bwd Packets
- ... (CICFlowMeter standard features)
- Label  (one of: Benign, DoS, DDoS, Port Scan, Brute Force, Web Attack, Botnet)

Usage: call `load_dataset(path)` with path to CSV. It will:
- read CSV via pandas
- drop NA rows
- filter/validate labels
- encode labels
- scale numeric features
- export splits to `ml/data/splits/` and return a dict of DataFrames
"""
from pathlib import Path
from typing import Dict
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler


EXPECTED_LABELS = [
    "Benign",
    "DoS",
    "DDoS",
    "Port Scan",
    "Brute Force",
    "Web Attack",
    "Botnet",
]


def load_dataset(path: str, label_column: str = "Label", test_size=0.2, val_size=0.1, random_state=42) -> Dict[str, pd.DataFrame]:
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"CSV path not found: {path}")

    print(f"Loading dataset from {p}...")
    df = pd.read_csv(p)
    print(f"  Loaded {len(df)} rows, {len(df.columns)} columns")
    
    # Drop completely empty rows and columns
    df = df.dropna(how='all')
    df = df.dropna(axis=1, how='all')
    print(f"  After dropping empty rows/cols: {len(df)} rows")
    
    if label_column not in df.columns:
        raise ValueError(f"Label column '{label_column}' not found in CSV")

    # Keep only known labels
    df = df[df[label_column].isin(EXPECTED_LABELS)]
    print(f"  After filtering labels: {len(df)} rows")
    
    labels = df[label_column].astype(str)
    features = df.drop(columns=[label_column])

    # Encode labels
    le = LabelEncoder()
    y = le.fit_transform(labels)
    print(f"  Label distribution: {dict(zip(le.classes_, [(y == i).sum() for i in range(len(le.classes_))]))}")

    # Handle numeric features: replace inf with NaN, then fill with median
    numeric_cols = features.select_dtypes(include=["number"]).columns.tolist()
    print(f"  Found {len(numeric_cols)} numeric columns")
    
    X = features[numeric_cols].copy()
    
    # Replace infinity with NaN
    X = X.replace([float('inf'), float('-inf')], float('nan'))
    
    # Fill NaN with column median
    for col in X.columns:
        median_val = X[col].median()
        X[col] = X[col].fillna(median_val)
    
    # Remove rows with any remaining NaN
    X = X.dropna()
    y = y[:len(X)]  # Align y with X
    
    print(f"  After cleaning NaN/inf: {len(X)} rows")
    
    # Scale numeric features
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)
    X = pd.DataFrame(X_scaled, columns=numeric_cols)

    # Stratified split: first train+val/test
    X_trainval, X_test, y_trainval, y_test = train_test_split(X, y, test_size=test_size, stratify=y, random_state=random_state)
    # then split train/val
    val_relative = val_size / (1.0 - test_size)
    X_train, X_val, y_train, y_val = train_test_split(X_trainval, y_trainval, test_size=val_relative, stratify=y_trainval, random_state=random_state)

    out_dir = Path("ml/data/splits")
    out_dir.mkdir(parents=True, exist_ok=True)

    train_df = X_train.copy()
    train_df["label"] = y_train
    val_df = X_val.copy()
    val_df["label"] = y_val
    test_df = X_test.copy()
    test_df["label"] = y_test

    train_df.to_csv(out_dir / "train.csv", index=False)
    val_df.to_csv(out_dir / "val.csv", index=False)
    test_df.to_csv(out_dir / "test.csv", index=False)

    print(f"✓ Created data splits:")
    print(f"  - Train: {len(train_df)} rows ({out_dir / 'train.csv'})")
    print(f"  - Val:   {len(val_df)} rows ({out_dir / 'val.csv'})")
    print(f"  - Test:  {len(test_df)} rows ({out_dir / 'test.csv'})")

    return {"train": train_df, "val": val_df, "test": test_df}
