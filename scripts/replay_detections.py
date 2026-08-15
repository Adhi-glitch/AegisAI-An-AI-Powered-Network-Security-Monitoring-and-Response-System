"""
Replay sample/test CSV rows through the detection pipeline and optionally POST to the API.

Usage:
  python scripts/replay_detections.py --limit 50
  python scripts/replay_detections.py --limit 20 --post-api
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from agents.coordinator.coordinator import process_features
from agents.feature_extraction.csv_extractor import extract_from_row


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--csv",
        default=str(ROOT / "ml" / "data" / "splits" / "sample" / "test.csv"),
        help="CSV with numeric features + label column",
    )
    parser.add_argument("--limit", type=int, default=50)
    parser.add_argument("--post-api", action="store_true", help="Also POST each row to http://127.0.0.1:8000/alerts")
    parser.add_argument("--api", default="http://127.0.0.1:8000")
    parser.add_argument("--out", default=str(ROOT / "artifacts" / "replay_report.json"))
    args = parser.parse_args()

    path = Path(args.csv)
    if not path.exists():
        raise FileNotFoundError(f"CSV not found: {path}. Run scripts/sample_splits.py first.")

    df = pd.read_csv(path)
    df = df.head(args.limit)
    results = []
    pred_counts = Counter()

    for i, row in df.iterrows():
        true_label = row["label"] if "label" in row else None
        feats = extract_from_row(row)
        feats.setdefault("source_ip", f"10.0.0.{(i % 250) + 1}")
        feats.setdefault("dest_ip", "10.0.0.254")
        out = process_features(feats)
        pred_counts[out["predicted"]] += 1
        entry = {
            "row": int(i),
            "true_label": None if true_label is None else int(true_label),
            "predicted": out["predicted"],
            "confidence": out["confidence"],
            "anomaly_score": out["anomaly_score"],
            "action": out.get("action"),
            "explanation": out["explanation"],
            "response": out["response"],
        }
        results.append(entry)

        if args.post_api:
            import urllib.request

            payload = json.dumps(
                {
                    "source_ip": feats["source_ip"],
                    "dest_ip": feats["dest_ip"],
                    "protocol": "TCP",
                    "raw_features": {k: v for k, v in feats.items() if k not in ("source_ip", "dest_ip")},
                    "run_detection": True,
                }
            ).encode("utf-8")
            req = urllib.request.Request(
                f"{args.api.rstrip('/')}/alerts",
                data=payload,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=30) as resp:
                resp.read()

        print(
            f"[{i}] pred={out['predicted']} conf={out['confidence']:.3f} "
            f"anom={out['anomaly_score']:.3f} action={out.get('action')}"
        )

    report = {
        "csv": str(path),
        "n": len(results),
        "predicted_counts": dict(pred_counts),
        "results": results,
    }
    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
    print(f"Wrote {out_path}")
    print("Predicted counts:", dict(pred_counts))


if __name__ == "__main__":
    main()
