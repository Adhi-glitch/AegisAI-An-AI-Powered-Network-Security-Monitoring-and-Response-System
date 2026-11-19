# AegisAI Architecture

Pipeline: network capture → feature extraction → detection + anomaly → explainability → response → reporting → dashboard

## Modules

| Path | Role | Milestone status |
|------|------|------------------|
| `agents/feature_extraction` | CSV row → feature dict; IPv4 packet → bidirectional flow | CSV and 12-feature live prototype implemented |
| `agents/detection` | RF inference (`label`, `confidence`) | Done (bundle-aware) |
| `agents/anomaly` | IsolationForest anomaly score | Done (trained with baseline) |
| `agents/explainability` | Feature importance and explainability 2.0 fallback | Implemented |
| `agents/response` | Policy evaluation, safety, adapters, approvals, playbooks | Implemented; dry-run default |
| `agents/coordinator` | End-to-end orchestration | Done |
| `agents/reporting` | Incident correlation and JSON/Markdown/text/PDF reports | Implemented |
| `agents/analytics` | Simulation, PSI, posture, graph, ATT&CK helpers | Implemented |
| `agents/threat_intelligence` | ThreatFeed-backed IP enrichment routes | Local implementation |
| `agents/knowledge_graph` | Entity graph | Stub |
| `backend/` | FastAPI: alerts, detections, stats, React app, live capture controls | Versioned routes implemented; production hardening in progress |
| `ml/` | Loader, sample splits, train, evaluate, model bundle | Done for milestone |
| `database/` | SQLAlchemy Alert / Detection / Action / Report | Done |
| `network_capture/` | Scapy async packet capture → flow callback | Integrated; Windows capture needs Npcap and suitable privileges; live sniffing remains unverified on this host |
| `frontend/` | Separate React/Vite operations console | Served at `/console` after `npm --prefix frontend run build`; includes its own sign-in screen |
| `rag/` | Offline lexical retrieval, citations, in-memory ingestion/chunking | Implemented; ingested documents clear on restart |
| `notifications/` | Opt-in webhook, Telegram, SMTP hooks | Implemented; credentials required |

## Offline runtime flow

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
GET /stats + Jinja live dashboard at GET /dashboard
```

## Live prototype flow

```text
Scapy AsyncSniffer (admin starts through /api/v1/capture/start)
        │
        ▼
FlowTracker (bidirectional IPv4, idle/stop flush)
        │
        ▼
12 ordered numeric model features
        │
        ▼
coordinator.process_features (active ModelBundle)
   ├─ class prediction + confidence
   ├─ anomaly score + explanation
   └─ response decision (dry-run)
        │
        ▼
SQLite Alert → Detection → Action
        │
        ├─ WS /ws/feed
        ├─ Jinja live dashboard at `/dashboard` (`/legacy` is an alias)
        └─ React/Vite console at `/console` (build required)
```

The live feature schema is defined in `ml/data/multidataset.py` as `LIVE_FEATURE_COLUMNS`. The active bundle manifest selects `ml/models/multi_dataset_bundle`, whose ordered features match that schema; capture refuses a mismatched bundle. Current flow features are a prototype subset, not a full CICFlowMeter implementation. Scapy reports `conf.use_pcap=True`, but a non-elevated loopback probe captured zero packets, so real sniffing remains unverified here.

## Model bundle (`ml/models/`)

- `baseline_rf.pkl` — trained classifier (RandomForest by default, or XGBoost when CUDA is available)
- `anomaly_iforest.pkl` — IsolationForest anomaly detector
- `feature_columns.json` — training column order
- `label_classes.json` — human-readable class names
- `bundle_meta.json` — train provenance
- `val_metrics.json` — validation report
- `active_bundle.json` — selects the active bundle; currently `multi_dataset_bundle` for the 12-feature live prototype

Helpers live in `ml/models/bundle.py`.

## Training mode

The training pipeline automatically prefers CUDA-enabled XGBoost when `nvidia-smi` reports an NVIDIA GPU and the XGBoost CUDA build is available. If GPU support is unavailable, the project falls back to a reliable CPU-trained RandomForest model.

Training command:

```powershell
python ml\training\train.py --engine auto
```

## API surface

- `GET /` — Jinja public homepage
- `GET /signin` — Jinja sign-in page
- `GET /dashboard` and `/legacy` — Jinja live dashboard and compatibility alias
- `GET /console` — separate React/Vite console; build with `npm --prefix frontend run build`
- `GET /health` — liveness + model loaded flag
- `POST /alerts` — store alert; run detection; store Detection + Action
- `POST /detect` — detect without DB write
- `GET /alerts`, `/detections`, `/actions`, `/stats`
- `POST /actions/unblock` — dry-run unblock
- `/api/v1/capture/*` — admin-only interface listing, status, start, and stop
- `/api/v1/response/*` — policy preview, policies, approvals, audit, blocks; `auto-live` execution is rejected
- `/api/v1/copilot/*` — grounded queries, admin document ingestion, actions
- `/api/v1/incidents/*` — correlation, persistence, lifecycle, reports
- `/api/v1/attack-lab/simulate` — packet-free scenario metrics
- `/api/v1/model-health/drift` — PSI drift calculation
- `/api/v1/network/graph` — flow graph and asset persistence
- `/api/v1/posture*` — posture score and digest

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

Prototype training/report commands and the capture-overlap warning are documented in `docs/RUNNING.md`. See `docs/PROTOTYPE_PROGRESS.md` for current status and remaining demo prerequisites.
