import pandas as pd
import pytest

from ml.data.multidataset import (
    CANONICAL_LABELS,
    _grouped_holdout,
    _combine_feature_vector,
    _load_bot_iot,
    _load_cse_cic_ids_2018,
    _load_ctu_13,
    _load_nsl_kdd,
    _load_unsw_files,
    canonicalize_label,
    prepare_multidataset_splits,
)
from scripts.build_prototype_dataset import build_sample


def test_canonicalize_supported_and_unsupported_labels():
    assert canonicalize_label("BENIGN") == "Benign"
    assert canonicalize_label("DoS Hulk") == "DoS"
    assert canonicalize_label("DDoS") == "DDoS"
    assert canonicalize_label("PortScan") == "Port Scan"
    assert canonicalize_label("FTP-Patator") == "Brute Force"
    assert canonicalize_label("Web Attack ï¿½ Brute Force") == "Web Attack"
    assert canonicalize_label("Brute Force -Web") == "Web Attack"
    assert canonicalize_label("Brute Force -XSS") == "Web Attack"
    assert canonicalize_label("Bot") == "Botnet"
    assert canonicalize_label("Infiltration") is None
    assert canonicalize_label("Attack") is None
    assert CANONICAL_LABELS == [
        "Benign", "Botnet", "Brute Force", "DDoS", "DoS", "Port Scan", "Web Attack"
    ]


def test_attack_category_takes_precedence_over_binary_label():
    frame = pd.DataFrame(
        {
            "label": [0, 1, 1, 1],
            "attack_cat": ["Normal", "DoS", "Reconnaissance", "Generic"],
            "dur": [1, 2, 3, 4],
        }
    )

    normalized = _combine_feature_vector(frame)

    assert normalized["label_name"].tolist() == ["Benign", "DoS", "Port Scan"]
    assert normalized["label"].tolist() == [0, 4, 5]


def test_unsw_and_botiot_partitions_are_one_source_group(tmp_path):
    unsw_dir = tmp_path / "UNSW-NB15" / "Training and Testing Sets"
    bot_iot_dir = tmp_path / "Bot-IoT" / "All features"
    unsw_dir.mkdir(parents=True)
    bot_iot_dir.mkdir(parents=True)
    for name, attack_category in (("training.csv", "DoS"), ("testing.csv", "Normal")):
        pd.DataFrame({"attack_cat": [attack_category], "label": [1], "dur": [1]}).to_csv(
            unsw_dir / name, index=False
        )
    for name, category in (("part1.csv", "DoS"), ("part2.csv", "DDoS")):
        pd.DataFrame({"category": [category], "attack": [1], "dur": [1]}).to_csv(
            bot_iot_dir / name, index=False
        )

    unsw = _load_unsw_files(tmp_path)
    bot_iot = _load_bot_iot(tmp_path)

    assert set(unsw["source_group"]) == {"UNSW-NB15/combined-capture-set"}
    assert set(bot_iot["source_group"]) == {"Bot-IoT/Full5pc"}


def test_nsl_kdd_omits_overlapping_subsets_and_groups_official_splits(tmp_path):
    nsl_dir = tmp_path / "NSL-KDD"
    nsl_dir.mkdir()
    row = [0] * 41 + ["guess_passwd", 0]
    for name in ("KDDTrain+.txt", "KDDTest+.txt", "KDDTest-21.txt", "KDDTrain+_20Percent.txt"):
        pd.DataFrame([row]).to_csv(nsl_dir / name, header=False, index=False)

    normalized = _load_nsl_kdd(tmp_path)

    assert len(normalized) == 2
    assert set(normalized["label_name"]) == {"Brute Force"}
    assert set(normalized["source_group"]) == {"NSL-KDD/official-train-test"}


def test_ctu_parquet_scenarios_keep_separate_botnet_groups(tmp_path):
    ctu_dir = tmp_path / "CTU-13"
    ctu_dir.mkdir()
    for scenario, botnet_label in (("1-Neris", "From-Botnet"), ("2-Neris", "To-Botnet")):
        pd.DataFrame({"label": [botnet_label, "Background"], "Dur": [1.0, 2.0]}).to_parquet(
            ctu_dir / f"{scenario}.binetflow.parquet", index=False
        )

    normalized = _load_ctu_13(tmp_path)

    assert normalized["label_name"].tolist().count("Botnet") == 2
    assert normalized["label_name"].tolist().count("Benign") == 2
    botnet_groups = set(normalized.loc[normalized["label_name"] == "Botnet", "source_group"])
    assert len(botnet_groups) == 2


def test_cse_cic_ids_2018_parquet_groups_and_features(tmp_path):
    cse_dir = tmp_path / "CSE-CIC-IDS2018"
    cse_dir.mkdir()
    common = {
        "Protocol": [6, 6, 17],
        "Flow Duration": [10, 20, 30],
        "Total Fwd Packets": [1, 2, 3],
        "Total Backward Packets": [4, 5, 6],
        "Fwd Packets Length Total": [100, 200, 300],
        "Bwd Packets Length Total": [400, 500, 600],
        "Flow Bytes/s": [50, 60, 70],
        "Flow Packets/s": [5, 6, 7],
    }
    pd.DataFrame({**common, "Label": ["Brute Force -Web", "Brute Force -XSS", "SQL Injection"]}).to_parquet(
        cse_dir / "Web1-TrafficForML.parquet", index=False
    )
    pd.DataFrame({**common, "Label": ["FTP-BruteForce", "Benign", "Infilteration"]}).to_parquet(
        cse_dir / "Bruteforce-TrafficForML.parquet", index=False
    )

    normalized = _load_cse_cic_ids_2018(tmp_path)

    web_rows = normalized.loc[normalized["dataset"] == "CSE-CIC-IDS2018"]
    assert set(web_rows["label_name"]) == {"Web Attack", "Brute Force", "Benign"}
    assert set(web_rows["source_group"]) == {
        "CSE-CIC-IDS2018/Web1-TrafficForML.parquet",
        "CSE-CIC-IDS2018/Bruteforce-TrafficForML.parquet",
    }
    assert set(web_rows.loc[web_rows["label_name"] == "Web Attack", "src_bytes"]) == {100.0, 200.0, 300.0}
    assert set(web_rows.loc[web_rows["label_name"] == "Web Attack", "dst_bytes"]) == {400.0, 500.0, 600.0}
    assert web_rows["src_port"].eq(0).all()
    assert web_rows["dst_port"].eq(0).all()


def test_prototype_builder_samples_cse_captures_as_separate_groups(tmp_path):
    cse_dir = tmp_path / "CSE-CIC-IDS2018"
    cse_dir.mkdir()
    labels = [
        "Benign",
        "Bot",
        "FTP-BruteForce",
        "DDoS-LOIC-HTTP",
        "DoS attacks-GoldenEye",
        "PortScan",
        "Brute Force -Web",
    ]
    for capture_id in range(3):
        pd.DataFrame(
            {
                "Flow Duration": [capture_id + 1] * len(labels),
                "Total Fwd Packets": [1] * len(labels),
                "Total Backward Packets": [1] * len(labels),
                "Fwd Packets Length Total": [10] * len(labels),
                "Bwd Packets Length Total": [20] * len(labels),
                "Label": labels,
            }
        ).to_parquet(cse_dir / f"capture-{capture_id}.parquet", index=False)

    sample = build_sample(tmp_path, tmp_path / "sample.csv", rows_per_group_class=1)

    assert set(sample["label_name"]) == set(CANONICAL_LABELS)
    assert sample.groupby("label_name")["source_group"].nunique().eq(3).all()


def test_split_generation_refuses_incomplete_target_coverage(tmp_path):
    input_csv = tmp_path / "unified.csv"
    pd.DataFrame(
        {"label": [0, 0], "label_name": ["Benign", "Benign"], "source_group": ["capture-a"] * 2}
    ).to_csv(input_csv, index=False)

    with pytest.raises(ValueError, match="Web Attack"):
        prepare_multidataset_splits(input_csv=input_csv, output_dir=tmp_path / "splits")


def test_grouped_holdout_keeps_captures_and_classes_disjoint():
    rows = [
        {"label": label_id, "source_group": f"capture-{group_id}"}
        for group_id in range(10)
        for label_id in range(len(CANONICAL_LABELS))
    ]
    frame = pd.DataFrame(rows)

    train, held_out = _grouped_holdout(frame, 0.2, 42, split_name="test")

    assert set(train["source_group"]).isdisjoint(set(held_out["source_group"]))
    assert set(train["label"]) == set(held_out["label"]) == set(range(len(CANONICAL_LABELS)))


def test_prepare_splits_keeps_source_groups_disjoint(tmp_path):
    input_csv = tmp_path / "unified.csv"
    rows = [
        {
            "label": label_id,
            "label_name": label,
            "source_group": f"capture-{group_id}",
            "feature": float(group_id + label_id),
        }
        for group_id in range(5)
        for label_id, label in enumerate(CANONICAL_LABELS)
    ]
    pd.DataFrame(rows).to_csv(input_csv, index=False)

    output_paths = prepare_multidataset_splits(
        input_csv=input_csv,
        output_dir=tmp_path / "splits",
        sample_size=14,
    )
    splits = [pd.read_csv(path) for path in output_paths]
    groups = [set(split["source_group"]) for split in splits]

    assert groups[0].isdisjoint(groups[1])
    assert groups[0].isdisjoint(groups[2])
    assert groups[1].isdisjoint(groups[2])
    assert all(set(split["label_name"]) == set(CANONICAL_LABELS) for split in splits)
    assert len(splits[0]) == 14
    assert len(splits[1]) == 7
    assert len(splits[2]) == 7


def test_grouped_split_refuses_single_capture_per_class(tmp_path):
    input_csv = tmp_path / "unified.csv"
    rows = [
        {"label": label_id, "label_name": label, "source_group": f"only-{label}"}
        for label_id, label in enumerate(CANONICAL_LABELS)
        for _ in range(3)
    ]
    pd.DataFrame(rows).to_csv(input_csv, index=False)

    with pytest.raises(ValueError, match="three independent source groups"):
        prepare_multidataset_splits(input_csv=input_csv, output_dir=tmp_path / "splits")


def test_prototype_row_split_is_explicitly_marked_as_capture_overlapping(tmp_path):
    input_csv = tmp_path / "unified.csv"
    rows = [
        {
            "label": label_id,
            "label_name": label,
            "source_group": f"only-{label}",
            "duration": float(row_id),
        }
        for label_id, label in enumerate(CANONICAL_LABELS)
        for row_id in range(20)
    ]
    pd.DataFrame(rows).to_csv(input_csv, index=False)

    output_paths = prepare_multidataset_splits(
        input_csv=input_csv,
        output_dir=tmp_path / "splits",
        sample_size=20,
        prototype_row_split=True,
    )
    metadata = pd.read_json(tmp_path / "splits" / "split_meta.json", typ="series")

    assert all(path.exists() for path in output_paths)
    assert metadata["split_strategy"] == "stratified_random_rows_prototype_capture_overlap"
    assert metadata["capture_overlap_warning"] is True