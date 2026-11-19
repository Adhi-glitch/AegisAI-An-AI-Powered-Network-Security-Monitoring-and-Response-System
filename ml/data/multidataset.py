from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable

import numpy as np
import pandas as pd
import pyarrow.parquet as pq
from sklearn.model_selection import StratifiedGroupKFold, train_test_split

ROOT = Path(__file__).resolve().parents[2]
PHASE1_DIR = ROOT / "data" / "phase1"
UNIFIED_OUTPUT = ROOT / "ml" / "data" / "processed" / "multi_dataset_unified.csv"
MULTI_SPLITS_DIR = ROOT / "ml" / "data" / "splits" / "multi_dataset"

FEATURE_ALIASES = {
    "duration": ["dur", "duration", "Flow Duration", "flow_duration"],
    "src_packets": ["spkts", "Total Fwd Packets", "src_packets", "tot_fwd_packets"],
    "dst_packets": ["dpkts", "Total Backward Packets", "dst_packets", "tot_bwd_packets"],
    "src_bytes": ["sbytes", "Total Length of Fwd Packets", "Fwd Packets Length Total", "src_bytes", "tot_fwd_bytes"],
    "dst_bytes": ["dbytes", "Total Length of Bwd Packets", "Bwd Packets Length Total", "dst_bytes", "tot_bwd_bytes"],
    "total_packets": ["tot_pkts", "total_packets", "pkts"],
    "total_bytes": ["tot_bytes", "total_bytes", "bytes"],
    "packet_rate": ["rate", "Flow Packets/s", "packet_rate", "pkts_per_sec"],
    "byte_rate": ["Flow Bytes/s", "bytes_per_second", "byte_rate"],
    "src_port": ["sport", "Source Port", "src_port", "sport_number"],
    "dst_port": ["dport", "Destination Port", "dst_port", "dport_number"],
    "protocol": ["proto", "protocol", "Protocol", "proto_name"],
    "service": ["service", "Service"],
    "state": ["state", "State"],
    "src_ip": ["saddr", "src_ip", "Source IP", "sip"],
    "dst_ip": ["daddr", "dst_ip", "Destination IP", "dip"],
}

CANONICAL_LABELS = [
    "Benign",
    "Botnet",
    "Brute Force",
    "DDoS",
    "DoS",
    "Port Scan",
    "Web Attack",
]
LABEL_TO_ID = {name: index for index, name in enumerate(CANONICAL_LABELS)}
LIVE_FEATURE_COLUMNS = [
    "duration",
    "src_packets",
    "dst_packets",
    "src_bytes",
    "dst_bytes",
    "total_packets",
    "total_bytes",
    "packet_rate",
    "byte_rate",
    "src_port",
    "dst_port",
    "protocol",
]
PROTOCOL_NUMBERS = {"icmp": 1.0, "tcp": 6.0, "udp": 17.0, "icmpv6": 58.0}


def _normalize_columns(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()
    df.columns = [str(col).strip() for col in df.columns]
    return df


def _string_series(series: pd.Series, fallback: str = "unknown") -> pd.Series:
    if series is None:
        return pd.Series([fallback], dtype="string")
    if pd.api.types.is_categorical_dtype(series):
        series = series.astype("string")
    return series.fillna(fallback).astype(str)


def _first_present(df: pd.DataFrame, aliases: Iterable[str]) -> str | None:
    for alias in aliases:
        if alias in df.columns:
            return alias
    return None


def _get_numeric(df: pd.DataFrame, aliases: Iterable[str]) -> pd.Series:
    key = _first_present(df, aliases)
    if key is None:
        return pd.Series(np.nan, index=df.index, dtype="float64")
    return pd.to_numeric(df[key], errors="coerce")


def canonicalize_label(raw_label: str | int | float | None) -> str | None:
    if raw_label is None or pd.isna(raw_label):
        return None

    label_text = str(raw_label).strip()
    normalized = label_text.casefold()
    tokens = set(re.findall(r"[a-z0-9]+", normalized))
    canonical = None

    if normalized in {"0", "0.0"} or tokens.intersection({"benign", "normal", "background"}):
        canonical = "Benign"
    elif "botnet" in tokens or normalized == "bot":
        canonical = "Botnet"
    elif normalized.startswith("web attack") or normalized in {
        "sql injection",
        "xss",
        "cross site scripting",
        "brute force -web",
        "brute force -xss",
    }:
        canonical = "Web Attack"
    elif any(term in normalized for term in ("brute force", "brute-force", "bruteforce", "patator", "guess_passwd")):
        canonical = "Brute Force"
    elif normalized.startswith("ddos"):
        canonical = "DDoS"
    elif normalized.startswith("dos") or normalized in {
        "heartbleed", "apache2", "land", "mailbomb", "neptune", "pod", "processtable",
        "smurf", "teardrop", "udpstorm",
    }:
        canonical = "DoS"
    elif normalized in {"portscan", "port scan", "probe", "reconnaissance", "ipsweep", "nmap", "portsweep"}:
        canonical = "Port Scan"
    if canonical is None:
        return None
    return canonical


def _protocol_number(value: object) -> float:
    if value is None or pd.isna(value):
        return 0.0
    try:
        return float(value)
    except (TypeError, ValueError):
        return PROTOCOL_NUMBERS.get(str(value).strip().casefold(), 0.0)


def _canonical_label(raw_label: str | int | float | None) -> tuple[int, str, str] | None:
    canonical = canonicalize_label(raw_label)
    if canonical is None:
        return None
    return LABEL_TO_ID[canonical], canonical, str(raw_label).strip()


def _combine_feature_vector(frame: pd.DataFrame) -> pd.DataFrame:
    frame = _normalize_columns(frame)

    duration = _get_numeric(frame, FEATURE_ALIASES["duration"])
    src_packets = _get_numeric(frame, FEATURE_ALIASES["src_packets"])
    dst_packets = _get_numeric(frame, FEATURE_ALIASES["dst_packets"])
    src_bytes = _get_numeric(frame, FEATURE_ALIASES["src_bytes"])
    dst_bytes = _get_numeric(frame, FEATURE_ALIASES["dst_bytes"])
    total_packets = _get_numeric(frame, FEATURE_ALIASES["total_packets"])
    total_bytes = _get_numeric(frame, FEATURE_ALIASES["total_bytes"])
    packet_rate = _get_numeric(frame, FEATURE_ALIASES["packet_rate"])
    byte_rate = _get_numeric(frame, FEATURE_ALIASES["byte_rate"])

    if total_packets.isna().all():
        total_packets = src_packets.fillna(0) + dst_packets.fillna(0)
    if total_bytes.isna().all():
        total_bytes = src_bytes.fillna(0) + dst_bytes.fillna(0)

    if src_packets.isna().all() and "spkts" in frame.columns:
        src_packets = pd.to_numeric(frame["spkts"], errors="coerce")
    if dst_packets.isna().all() and "dpkts" in frame.columns:
        dst_packets = pd.to_numeric(frame["dpkts"], errors="coerce")

    src_port = _get_numeric(frame, FEATURE_ALIASES["src_port"])
    dst_port = _get_numeric(frame, FEATURE_ALIASES["dst_port"])
    protocol = frame[_first_present(frame, FEATURE_ALIASES["protocol"])] if _first_present(frame, FEATURE_ALIASES["protocol"]) else pd.Series("unknown", index=frame.index)
    service = frame[_first_present(frame, FEATURE_ALIASES["service"])] if _first_present(frame, FEATURE_ALIASES["service"]) else pd.Series("unknown", index=frame.index)
    state = frame[_first_present(frame, FEATURE_ALIASES["state"])] if _first_present(frame, FEATURE_ALIASES["state"]) else pd.Series("unknown", index=frame.index)
    src_ip = frame[_first_present(frame, FEATURE_ALIASES["src_ip"])] if _first_present(frame, FEATURE_ALIASES["src_ip"]) else pd.Series("0.0.0.0", index=frame.index)
    dst_ip = frame[_first_present(frame, FEATURE_ALIASES["dst_ip"])] if _first_present(frame, FEATURE_ALIASES["dst_ip"]) else pd.Series("0.0.0.0", index=frame.index)

    protocol = _string_series(protocol, "unknown")
    service = _string_series(service, "unknown")
    state = _string_series(state, "unknown")
    src_ip = _string_series(src_ip, "0.0.0.0")
    dst_ip = _string_series(dst_ip, "0.0.0.0")

    label_col = None
    for candidate in ("attack_cat", "category", "subcategory", "Label", "label", "attack"):
        match = next((column for column in frame.columns if column.strip().casefold() == candidate.casefold()), None)
        if match is not None:
            label_col = match
            break

    if label_col is None:
        raise ValueError(f"Could not find label column in frame with columns: {list(frame.columns[:20])}")

    raw_label = frame[label_col]
    label_values = [
        _canonical_label(v)
        for v in raw_label.tolist()
    ]

    normalized = pd.DataFrame(
        {
            "label": [item[0] if item is not None else np.nan for item in label_values],
            "label_name": [item[1] if item is not None else None for item in label_values],
            "attack_family": [item[2] if item is not None else None for item in label_values],
            "duration": duration.fillna(0.0),
            "src_packets": src_packets.fillna(0.0),
            "dst_packets": dst_packets.fillna(0.0),
            "src_bytes": src_bytes.fillna(0.0),
            "dst_bytes": dst_bytes.fillna(0.0),
            "total_packets": total_packets.fillna(0.0),
            "total_bytes": total_bytes.fillna(0.0),
            "packet_rate": packet_rate.fillna(0.0),
            "byte_rate": byte_rate.fillna(0.0),
            "src_port": pd.to_numeric(src_port, errors="coerce").fillna(0),
            "dst_port": pd.to_numeric(dst_port, errors="coerce").fillna(0),
            "protocol": protocol,
            "service": service,
            "state": state,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
        }
    )
    normalized = normalized.dropna(subset=["label"]).copy()
    normalized["label"] = normalized["label"].astype(int)
    return normalized


def _load_cicids_files(root: Path) -> pd.DataFrame:
    frames = []
    cicids_dir = root / "CIC-IDS-2017"
    if not cicids_dir.exists() and root == PHASE1_DIR:
        cicids_dir = ROOT / "ml" / "data" / "raw"
    for csv_path in sorted(cicids_dir.glob("*.csv")):
        df = pd.read_csv(csv_path, low_memory=False)
        normalized = _combine_feature_vector(df)
        if "infilteration" in csv_path.name.casefold() or "infiltration" in csv_path.name.casefold():
            normalized = normalized[normalized["label_name"] != "Botnet"]
        normalized["dataset"] = "CIC-IDS-2017"
        normalized["source_group"] = f"CIC-IDS-2017/{csv_path.name}"
        frames.append(normalized)
    return pd.concat(frames, ignore_index=True) if frames else pd.DataFrame()


def _load_unsw_files(root: Path) -> pd.DataFrame:
    frames = []
    unsw_dir = root / "UNSW-NB15" / "Training and Testing Sets"
    for csv_path in sorted(unsw_dir.glob("*.csv")):
        if csv_path.name.endswith("_GT.csv") or csv_path.name.endswith("LIST_EVENTS.csv"):
            continue
        df = pd.read_csv(csv_path, encoding="cp1252", low_memory=False)
        normalized = _combine_feature_vector(df)
        normalized["dataset"] = "UNSW-NB15"
        normalized["source_group"] = "UNSW-NB15/combined-capture-set"
        frames.append(normalized)
    return pd.concat(frames, ignore_index=True) if frames else pd.DataFrame()


def _load_bot_iot(root: Path) -> pd.DataFrame:
    frames = []
    bot_dir = root / "Bot-IoT" / "All features"
    for csv_path in sorted(bot_dir.glob("*.csv")):
        df = pd.read_csv(csv_path, low_memory=False)
        normalized = _combine_feature_vector(df)
        normalized["dataset"] = "Bot-IoT"
        normalized["source_group"] = "Bot-IoT/Full5pc"
        frames.append(normalized)
    return pd.concat(frames, ignore_index=True) if frames else pd.DataFrame()


def _load_ctu_13(root: Path) -> pd.DataFrame:
    frames = []
    for parquet_path in sorted((root / "CTU-13").glob("*.parquet")):
        df = pd.read_parquet(parquet_path)
        normalized = _combine_feature_vector(df)
        normalized["dataset"] = "CTU-13"
        normalized["source_group"] = f"CTU-13/{parquet_path.name}"
        frames.append(normalized)
    return pd.concat(frames, ignore_index=True) if frames else pd.DataFrame()


def _load_cse_cic_ids_2018(root: Path) -> pd.DataFrame:
    frames = []
    aliases = {
        alias.strip().casefold()
        for feature_aliases in FEATURE_ALIASES.values()
        for alias in feature_aliases
    } | {"label"}
    for parquet_path in sorted((root / "CSE-CIC-IDS2018").glob("*.parquet")):
        parquet = pq.ParquetFile(parquet_path)
        columns = [
            column
            for column in parquet.schema_arrow.names
            if column.strip().casefold() in aliases
        ]
        if not any(column.strip().casefold() == "label" for column in columns):
            raise ValueError(f"No label column found in {parquet_path}")
        for batch in parquet.iter_batches(columns=columns, batch_size=100_000):
            normalized = _combine_feature_vector(batch.to_pandas())
            normalized["dataset"] = "CSE-CIC-IDS2018"
            normalized["source_group"] = f"CSE-CIC-IDS2018/{parquet_path.name}"
            frames.append(normalized)
    return pd.concat(frames, ignore_index=True) if frames else pd.DataFrame()


def _load_nsl_kdd(root: Path) -> pd.DataFrame:
    frames = []
    nsl_dir = root / "NSL-KDD"

    feature_names = [
        "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes", "land",
        "wrong_fragment", "urgent", "hot", "num_failed_logins", "logged_in", "num_compromised",
        "root_shell", "su_attempted", "num_root", "num_file_creations", "num_shells",
        "num_access_files", "num_outbound_cmds", "is_host_login", "is_guest_login", "count",
        "srv_count", "serror_rate", "srv_serror_rate", "rerror_rate", "srv_rerror_rate",
        "same_srv_rate", "diff_srv_rate", "srv_diff_host_rate", "dst_host_count", "dst_host_srv_count",
        "dst_host_same_srv_rate", "dst_host_diff_srv_rate", "dst_host_same_src_port_rate",
        "dst_host_srv_diff_host_rate", "dst_host_serror_rate", "dst_host_srv_serror_rate",
        "dst_host_rerror_rate", "dst_host_srv_rerror_rate", "label", "difficulty"
    ]

    for txt_path in sorted(nsl_dir.glob("*.txt")):
        if txt_path.name in {"KDDTest-21.txt", "KDDTrain+_20Percent.txt"}:
            continue
        df = pd.read_csv(txt_path, header=None, low_memory=False)
        if len(df.columns) < len(feature_names):
            continue
        df.columns = feature_names
        if "difficulty" in df.columns:
            df = df.drop(columns=["difficulty"])
        normalized = _combine_feature_vector(df)
        normalized["dataset"] = "NSL-KDD"
        normalized["source_group"] = "NSL-KDD/official-train-test"
        frames.append(normalized)

    return pd.concat(frames, ignore_index=True) if frames else pd.DataFrame()


def build_unified_dataset(
    root: Path | str = PHASE1_DIR,
    output_path: Path | str = UNIFIED_OUTPUT,
) -> pd.DataFrame:
    root_path = Path(root).resolve()
    unified_frames = []

    for loader in (
        _load_cicids_files,
        _load_unsw_files,
        _load_bot_iot,
        _load_ctu_13,
        _load_cse_cic_ids_2018,
        _load_nsl_kdd,
    ):
        frame = loader(root_path)
        if not frame.empty:
            unified_frames.append(frame)

    if not unified_frames:
        raise FileNotFoundError(f"No dataset files found under {root_path}")

    unified = pd.concat(unified_frames, ignore_index=True)
    unified = unified.dropna(subset=["label"]).copy()
    unified = unified.loc[unified["label"].isin(range(len(CANONICAL_LABELS)))].copy()
    unified["label"] = unified["label"].astype(int)

    if "protocol" in unified.columns:
        unified["protocol"] = unified["protocol"].map(_protocol_number)

    for col in ["service", "state", "src_ip", "dst_ip"]:
        if col in unified.columns:
            unified[col] = pd.factorize(unified[col].fillna("missing").astype(str))[0]

    for col in unified.columns:
        if col in {"label", "label_name", "attack_family", "dataset", "source_group"}:
            continue
        unified[col] = pd.to_numeric(unified[col], errors="coerce")
        unified[col] = unified[col].replace([np.inf, -np.inf], np.nan).fillna(0.0)

    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    unified.to_csv(output, index=False)

    return unified


def _grouped_holdout(
    frame: pd.DataFrame,
    fraction: float,
    seed: int,
    *,
    split_name: str,
    minimum_train_groups_per_class: int = 1,
) -> tuple[pd.DataFrame, pd.DataFrame]:
    labels = set(frame["label"].unique())
    group_count = frame["source_group"].nunique()
    desired_folds = min(group_count, max(2, round(1 / fraction)))
    for fold_count in range(desired_folds, 1, -1):
        splitter = StratifiedGroupKFold(n_splits=fold_count, shuffle=True, random_state=seed + fold_count)
        candidates = []
        try:
            folds = splitter.split(frame, frame["label"], frame["source_group"])
            for train_indices, holdout_indices in folds:
                train_part = frame.iloc[train_indices]
                holdout_part = frame.iloc[holdout_indices]
                train_counts = train_part.groupby("label")["source_group"].nunique()
                if set(train_part["label"].unique()) != labels or set(holdout_part["label"].unique()) != labels:
                    continue
                if train_counts.min() < minimum_train_groups_per_class:
                    continue
                size_error = abs(len(holdout_part) / len(frame) - fraction)
                candidates.append((size_error, train_part, holdout_part))
        except ValueError:
            continue
        if candidates:
            _, train_part, holdout_part = min(candidates, key=lambda item: item[0])
            return train_part.copy(), holdout_part.copy()

    coverage = {
        CANONICAL_LABELS[int(label)]: int(count)
        for label, count in frame.groupby("label")["source_group"].nunique().items()
    }
    raise ValueError(
        f"Cannot create a group-disjoint {split_name} split with every class in train and holdout; "
        f"source-group counts by class: {coverage}"
    )


def _sample_split(frame: pd.DataFrame, row_budget: int, seed: int) -> pd.DataFrame:
    if row_budget >= len(frame):
        return frame
    per_class_budget = max(1, row_budget // frame["label"].nunique())
    sampled = [
        class_frame.sample(n=min(len(class_frame), per_class_budget), random_state=seed + int(label))
        for label, class_frame in frame.groupby("label", sort=True)
    ]
    return pd.concat(sampled, ignore_index=True)


def prepare_multidataset_splits(
    input_csv: Path | str = UNIFIED_OUTPUT,
    output_dir: Path | str = MULTI_SPLITS_DIR,
    sample_size: int | None = 250_000,
    seed: int = 42,
    prototype_row_split: bool = False,
) -> tuple[Path, Path, Path]:
    input_path = Path(input_csv)
    if not input_path.exists():
        raise FileNotFoundError(f"Unified dataset not found: {input_path}")

    df = pd.read_csv(input_path)
    if "label" not in df.columns:
        raise ValueError("Unified dataset must contain a label column")
    if "source_group" not in df.columns or df["source_group"].isna().any():
        raise ValueError("Unified dataset must include a non-empty source_group capture/dataset identifier")

    class_counts = df["label"].value_counts()
    missing = [
        CANONICAL_LABELS[label_id]
        for label_id in range(len(CANONICAL_LABELS))
        if class_counts.get(label_id, 0) == 0
    ]
    if missing:
        counts = {
            CANONICAL_LABELS[int(label_id)]: int(count)
            for label_id, count in class_counts.items()
        }
        raise ValueError(f"Cannot create seven-class splits; missing {missing}. Available row counts: {counts}")
    undersized = [
        CANONICAL_LABELS[int(label_id)]
        for label_id, count in class_counts.items()
        if count < 3
    ]
    if undersized:
        raise ValueError(f"At least three rows are required per class for stratified splits: {undersized}")

    group_counts = df.groupby("label")["source_group"].nunique()
    insufficient_groups = {
        CANONICAL_LABELS[int(label)]: int(count)
        for label, count in group_counts.items()
        if count < 3
    }
    if insufficient_groups and not prototype_row_split:
        raise ValueError(
            "At least three independent source groups per class are required for train/validation/test; "
            f"found {insufficient_groups}"
        )

    if prototype_row_split:
        trainval_df, test_df = train_test_split(
            df,
            test_size=0.2,
            stratify=df["label"],
            random_state=seed,
        )
        train_df, val_df = train_test_split(
            trainval_df,
            test_size=0.125,
            stratify=trainval_df["label"],
            random_state=seed + 1,
        )
        split_strategy = "stratified_random_rows_prototype_capture_overlap"
    else:
        trainval_df, test_df = _grouped_holdout(
            df,
            0.2,
            seed,
            split_name="test",
            minimum_train_groups_per_class=2,
        )
        train_df, val_df = _grouped_holdout(
            trainval_df,
            0.125,
            seed + 1,
            split_name="validation",
        )
        split_strategy = "stratified_group_by_source_group"

    if sample_size is not None and sample_size < len(train_df):
        train_df = _sample_split(train_df, sample_size, seed)

    group_sets = [set(part["source_group"]) for part in (train_df, val_df, test_df)]
    if not prototype_row_split and (
        group_sets[0] & group_sets[1] or group_sets[0] & group_sets[2] or group_sets[1] & group_sets[2]
    ):
        raise RuntimeError("Source-group leakage detected between train, validation, and test splits")

    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    train_path = out_dir / "train.csv"
    val_path = out_dir / "val.csv"
    test_path = out_dir / "test.csv"

    train_df.to_csv(train_path, index=False)
    val_df.to_csv(val_path, index=False)
    test_df.to_csv(test_path, index=False)

    meta = {
        "source_csv": str(input_path),
        "source_rows": int(len(df)),
        "train_sample_size": int(len(train_df)),
        "train_rows": int(len(train_df)),
        "val_rows": int(len(val_df)),
        "test_rows": int(len(test_df)),
        "split_strategy": split_strategy,
        "capture_overlap_warning": bool(prototype_row_split and insufficient_groups),
        "train_groups": int(train_df["source_group"].nunique()),
        "val_groups": int(val_df["source_group"].nunique()),
        "test_groups": int(test_df["source_group"].nunique()),
        "source_groups_by_class": {
            split_name: {
                CANONICAL_LABELS[int(label)]: int(count)
                for label, count in split.groupby("label")["source_group"].nunique().items()
            }
            for split_name, split in (("train", train_df), ("val", val_df), ("test", test_df))
        },
        "label_counts": {
            CANONICAL_LABELS[int(label)]: int(count)
            for label, count in df["label"].value_counts().sort_index().items()
        },
        "split_label_counts": {
            split_name: {
                CANONICAL_LABELS[int(label)]: int(count)
                for label, count in split["label"].value_counts().sort_index().items()
            }
            for split_name, split in (("train", train_df), ("val", val_df), ("test", test_df))
        },
    }
    (out_dir / "split_meta.json").write_text(pd.Series(meta).to_json(indent=2), encoding="utf-8")

    return train_path, val_path, test_path
