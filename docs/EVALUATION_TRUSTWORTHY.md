# Historical Evaluation Report (Do Not Present as Trustworthy)

This report belongs to the older 78-feature `bundle_trustworthy` model and is retained for audit history only. The source-group audit does not support a strict independent-capture seven-class evaluation, and this result is not the active model's report. Do not cite the metrics below as generalization performance. The current active 12-feature prototype evaluation is in `artifacts/test_report.json` and is explicitly marked capture-overlapping and exploratory.

**Test CSV**: `C:\Users\vadit\Desktop\AegisAI\ml\data\splits\trustworthy\test.csv`
**Bundle**: `C:\Users\vadit\Desktop\AegisAI\ml\models\bundle_trustworthy`
**Total Rows**: 147705
**Overall Accuracy**: 0.9990

## Per-Class Metrics
| Class | Precision | Recall | F1-Score | Support | FPR |
|-------|-----------|--------|----------|---------|-----|
| Benign | 0.9996 | 0.9992 | 0.9994 | 114721.0 | 0.001395 |
| Botnet | 0.8427 | 0.7653 | 0.8021 | 98.0 | 0.000095 |
| Brute Force | 1.0000 | 0.9986 | 0.9993 | 693.0 | 0.000000 |
| DDoS | 0.9998 | 0.9989 | 0.9994 | 6539.0 | 0.000007 |
| DoS | 0.9970 | 0.9993 | 0.9982 | 12744.0 | 0.000282 |
| Port Scan | 0.9945 | 0.9987 | 0.9966 | 7910.0 | 0.000315 |
| Web Attack | 1.0000 | 1.0000 | 1.0000 | 5000.0 | 0.000000 |

## Confusion Matrix
| True \ Predicted | Benign | Botnet | Brute Force | DDoS | DoS | Port Scan | Web Attack |
|---|---|---|---|---|---|---|---|
| **Benign** | 114628 | 14 | 0 | 1 | 34 | 44 | 0 |
| **Botnet** | 23 | 75 | 0 | 0 | 0 | 0 | 0 |
| **Brute Force** | 1 | 0 | 692 | 0 | 0 | 0 | 0 |
| **DDoS** | 6 | 0 | 0 | 6532 | 1 | 0 | 0 |
| **DoS** | 9 | 0 | 0 | 0 | 12735 | 0 | 0 |
| **Port Scan** | 7 | 0 | 0 | 0 | 3 | 7900 | 0 |
| **Web Attack** | 0 | 0 | 0 | 0 | 0 | 0 | 5000 |

*Note: Rows represent True classes, columns represent Predicted classes.*
