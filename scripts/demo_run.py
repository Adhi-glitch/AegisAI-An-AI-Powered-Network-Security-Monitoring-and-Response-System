import sys
from pathlib import Path
import pandas as pd
import numpy as np

# ensure project root is on sys.path so package imports work when running this script
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

# generate a tiny synthetic CICIDS-like CSV for demo
RAW = Path("ml/data/raw")
RAW.mkdir(parents=True, exist_ok=True)
CSV = RAW / "demo_cicids.csv"

labels = ["Benign", "DoS", "DDoS", "Port Scan", "Brute Force", "Web Attack", "Botnet"]

# create synthetic features matching feature_schema numeric keys
cols = [
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Total Length of Fwd Packets",
    "Total Length of Bwd Packets",
    "Fwd Packet Length Max",
    "Fwd Packet Length Min",
    "Bwd Packet Length Max",
    "Bwd Packet Length Min",
    "Fwd IAT Mean",
    "Bwd IAT Mean",
]

n = 200
rng = np.random.RandomState(42)
X = {c: rng.randint(1, 1000, size=n) for c in cols}
# add some float columns
X["Fwd IAT Mean"] = rng.random(size=n) * 1000
X["Bwd IAT Mean"] = rng.random(size=n) * 1000
X["Label"] = [labels[i % len(labels)] for i in range(n)]

df = pd.DataFrame(X)
df.to_csv(CSV, index=False)
print(f"Wrote demo CSV to {CSV}")

# run data loader
from ml.data.data_loader import load_dataset
splits = load_dataset(str(CSV), label_column="Label", test_size=0.2, val_size=0.1)
print("Created splits:", list(splits.keys()))

# run training
from ml.training.train import train_and_save
train_and_save()

# run evaluation
from ml.evaluation.evaluate import evaluate
evaluate()

# run coordinator demo
from agents.coordinator.coordinator import demo_run
print("Coordinator demo:")
demo_run()
