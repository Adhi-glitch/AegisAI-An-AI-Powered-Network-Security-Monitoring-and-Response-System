import pandas as pd
import pytest

from ml.data.multidataset import CANONICAL_LABELS, LIVE_FEATURE_COLUMNS
from scripts.evaluate_grouped_model import build_evaluation_splits


def test_grouped_train_validation_test_splits_cover_all_classes_without_leakage():
    rows = []
    for group_id in range(4):
        for label_id, label_name in enumerate(CANONICAL_LABELS):
            row = {
                "label": label_id,
                "label_name": label_name,
                "source_group": f"capture-{group_id}",
            }
            row.update({column: float(group_id + label_id) for column in LIVE_FEATURE_COLUMNS})
            rows.append(row)

    splits = build_evaluation_splits(pd.DataFrame(rows))

    assert set(splits) == {"train", "validation", "test"}
    for split in splits.values():
        assert set(split["label"].unique()) == set(range(len(CANONICAL_LABELS)))
    assert set(splits["train"]["source_group"]).isdisjoint(splits["validation"]["source_group"])
    assert set(splits["train"]["source_group"]).isdisjoint(splits["test"]["source_group"])
    assert set(splits["validation"]["source_group"]).isdisjoint(splits["test"]["source_group"])


def test_grouped_evaluation_requires_three_source_groups_for_every_class():
    rows = []
    for label_id, label_name in enumerate(CANONICAL_LABELS):
        for group_id in range(3 if label_id != 6 else 2):
            row = {
                "label": label_id,
                "label_name": label_name,
                "source_group": f"capture-{group_id}",
            }
            row.update({column: float(group_id + label_id) for column in LIVE_FEATURE_COLUMNS})
            rows.append(row)

    with pytest.raises(ValueError, match="three independent source groups"):
        build_evaluation_splits(pd.DataFrame(rows))
