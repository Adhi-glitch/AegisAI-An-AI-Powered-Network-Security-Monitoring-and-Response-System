import pandas as pd
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SPLITS = ROOT / "ml" / "data" / "splits" / "trustworthy"

def main():
    splits = {}
    for s in ["train", "val", "test"]:
        p = SPLITS / f"{s}.csv"
        if not p.exists():
            raise FileNotFoundError(f"Missing {p}")
        splits[s] = pd.read_csv(p, usecols=['label', 'source_group'])

    # 1. Verify that no source_group overlaps between splits
    train_groups = set(splits['train']['source_group'].unique())
    val_groups = set(splits['val']['source_group'].unique())
    test_groups = set(splits['test']['source_group'].unique())

    assert len(train_groups.intersection(val_groups)) == 0, "Leakage between train and val!"
    assert len(train_groups.intersection(test_groups)) == 0, "Leakage between train and test!"
    assert len(val_groups.intersection(test_groups)) == 0, "Leakage between val and test!"

    # 2. Verify that every class has >= 3 distinct source_group values ACROSS all splits
    all_df = pd.concat(splits.values(), ignore_index=True)
    group_counts = all_df.groupby('label')['source_group'].nunique()
    
    print("Distinct source groups per class across all splits:")
    print(group_counts)
    assert (group_counts >= 3).all(), "Some classes lack >= 3 distinct source groups!"
    
    print("Validation passed! Groups are independent and properly stratified.")

if __name__ == "__main__":
    main()
