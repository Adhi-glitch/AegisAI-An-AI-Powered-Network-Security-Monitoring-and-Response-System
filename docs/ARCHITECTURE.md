# AegisAI Architecture

Pipeline: network capture → feature extraction → detection + anomaly → explainability → response → reporting → dashboard

## Modules

| Path | Role | Milestone status |
|------|------|------------------|
| `agents/feature_extraction` | CSV row → feature dict; live packet stub | CSV done; live stub |
| `agents/detection` | RF inference (`label`, `confidence`) | Done (bundle-aware) |
| `agents/anomaly` | IsolationForest anomaly score | Done (trained with baseline) |
| `agents/explainability` | Top feature-importance explanation | Thin but real |
| `agents/response` | Confidence → log / rate_limit / block (dry-run) | Done (dry-run) |
| `agents/coordinator` | End-to-end orchestration | Done |
| `agents/reporting` | Detection summary dict | Basic |
| `agents/threat_intelligence` | IP enrichment | Stub |
| `agents/knowledge_graph` | Entity graph | Stub |
| `backend/` | FastAPI: alerts, detections, stats, dashboard | Done for milestone |
| `ml/` | Loader, sample splits, train, evaluate, model bundle | Done for milestone |
| `database/` | SQLAlchemy Alert / Detection / Action / Report | Done |
| `network_capture/` | Live capture | Stub |
| `frontend/` | Reserved; dashboard currently served by FastAPI | Empty (API UI used) |
| `rag/`, `notifications/` | Future | Empty |

## Runtime flow (week milestone)

```text
ml/data/splits/sample/*.csv
        │
        ▼
csv_extractor.extract_from_row
        │
        ▼
coordinator.process_features
   ├─ detection.infer (baseline_rf.pkl)
   ├─ anomaly.score (anomaly_iforest.pkl)
   ├─ explain_detection (RF feature_importances_)
   └─ response_engine.decide_action / apply_action (dry-run)
        │
        ▼
SQLite (database/aegisai.db) via POST /alerts
        │
        ▼
GET /stats + dashboard at GET /
```

## Model bundle (`ml/models/`)

- `baseline_rf.pkl` — trained classifier (RandomForest by default, or XGBoost when CUDA is available)
- `anomaly_iforest.pkl` — IsolationForest anomaly detector
- `feature_columns.json` — training column order
- `label_classes.json` — human-readable class names
- `bundle_meta.json` — train provenance
- `val_metrics.json` — validation report

Helpers live in `ml/models/bundle.py`.

## Training mode

The training pipeline automatically prefers CUDA-enabled XGBoost when `nvidia-smi` reports an NVIDIA GPU and the XGBoost CUDA build is available. If GPU support is unavailable, the project falls back to a reliable CPU-trained RandomForest model.

Training command:

```powershell
python ml\training\train.py --engine auto
```

## API surface

- `GET /` — dashboard
- `GET /health` — liveness + model loaded flag
- `POST /alerts` — store alert; run detection; store Detection + Action
- `POST /detect` — detect without DB write
- `GET /alerts`, `/detections`, `/actions`, `/stats`
- `POST /actions/unblock` — dry-run unblock

## Deployment

```powershell
uvicorn backend.app:app --reload --port 8000
```

Training:

```powershell
python scripts\sample_splits.py
python ml\training\train.py
python ml\evaluation\evaluate.py
```
