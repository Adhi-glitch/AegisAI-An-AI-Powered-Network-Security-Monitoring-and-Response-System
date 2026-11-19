import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
REPORT_FILE = ROOT / "artifacts" / "test_report.json"
OUT_MD = ROOT / "docs" / "EVALUATION_TRUSTWORTHY.md"

def main():
    if not REPORT_FILE.exists():
        raise FileNotFoundError(f"Missing {REPORT_FILE}")

    with open(REPORT_FILE, "r") as f:
        data = json.load(f)

    classes = data["label_classes"]
    cr = data["classification_report"]
    cm = data["confusion_matrix"]
    fpr = data["false_positive_rate_by_class"]

    lines = []
    lines.append("# AegisAI Trustworthy Evaluation Report")
    lines.append(f"\n**Test CSV**: `{data['test_csv']}`")
    lines.append(f"**Bundle**: `{data['bundle_dir']}`")
    lines.append(f"**Total Rows**: {data['n_rows']}")
    lines.append(f"**Overall Accuracy**: {cr.get('accuracy', 'N/A'):.4f}")

    lines.append("\n## Per-Class Metrics")
    lines.append("| Class | Precision | Recall | F1-Score | Support | FPR |")
    lines.append("|-------|-----------|--------|----------|---------|-----|")
    for cls in classes:
        metrics = cr.get(cls, {})
        p = metrics.get('precision', 0)
        r = metrics.get('recall', 0)
        f1 = metrics.get('f1-score', 0)
        sup = metrics.get('support', 0)
        f_rate = fpr.get(cls, 0)
        lines.append(f"| {cls} | {p:.4f} | {r:.4f} | {f1:.4f} | {sup} | {f_rate:.6f} |")

    lines.append("\n## Confusion Matrix")
    header = "| True \\ Predicted | " + " | ".join(classes) + " |"
    sep = "|" + ("---|" * (len(classes) + 1))
    lines.append(header)
    lines.append(sep)

    for i, row in enumerate(cm):
        row_str = " | ".join(str(x) for x in row)
        lines.append(f"| **{classes[i]}** | {row_str} |")

    lines.append("\n*Note: Rows represent True classes, columns represent Predicted classes.*")

    OUT_MD.parent.mkdir(parents=True, exist_ok=True)
    with open(OUT_MD, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")

    print(f"Wrote markdown report to {OUT_MD}")

if __name__ == "__main__":
    main()
