"""Create explicitly capture-overlapping row splits for a local prototype demo."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from ml.data.multidataset import prepare_multidataset_splits  # noqa: E402


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, default=ROOT / "ml/data/processed/multi_dataset_prototype.csv")
    parser.add_argument("--output-dir", type=Path, default=ROOT / "ml/data/splits/prototype")
    parser.add_argument("--sample-size", type=int, default=250_000)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()
    paths = prepare_multidataset_splits(
        input_csv=args.input,
        output_dir=args.output_dir,
        sample_size=args.sample_size,
        seed=args.seed,
        prototype_row_split=True,
    )
    print(f"Wrote prototype row splits: {paths}")
    print("WARNING: rows from the same capture can occur in multiple partitions; metrics are exploratory only.")


if __name__ == "__main__":
    main()