# AegisAI Progress Log

## Milestone target (~35% by end of week)

Demoable vertical slice **plus** minimal dashboard:

1. Stratified CICIDS sample training (not the 200-row synthetic demo)
2. Honest val/test metrics artifacts
3. CSV replay → detect → explain → dry-run response
4. Persist alerts/detections/actions in SQLite
5. FastAPI dashboard with live stats

## Completed in this milestone

### Data / ML
- Full CICIDS splits already present under `ml/data/splits/`
- Added `scripts/sample_splits.py` → `ml/data/splits/sample/`
- Retrain path: `ml/training/train.py` with auto-GPU support and CPU fallback
- Evaluate path: `ml/evaluation/evaluate.py` → `artifacts/test_report.json`
- Model bundle helpers: `ml/models/bundle.py`
- Current training stack supports either XGBoost on CUDA or RandomForest on CPU.

### Agents / backend
- Coordinator loads model bundle automatically
- Real anomaly scoring when `anomaly_iforest.pkl` exists
- Feature-importance explanations in `agents/explainability/explain.py`
- `POST /alerts` runs detection and writes `Detection` + `Action`
- Dashboard: `backend/templates/dashboard.html` + static assets
- Replay: `scripts/replay_detections.py`

### Docs
- Updated `README.md`, `docs/ARCHITECTURE.md`, this progress file

## Intentionally deferred (later phases)

- Live packet capture (`network_capture/`, `live_extractor.py`)
- Real firewall block / rate-limit enforcement
- SHAP / LLM explanations
- Multi-dataset training (UNSW, CTU-13, Bot-IoT fusion)
- RAG, threat intelligence feeds, knowledge graph, notifications
- Polished standalone frontend SPA under `frontend/`

## How to verify

```powershell
python scripts\sample_splits.py --train-size 300000
python ml\training\train.py
python ml\evaluation\evaluate.py
python database\init_db.py
python scripts\replay_detections.py --limit 20
pytest -q
uvicorn backend.app:app --port 8000
```

Then open http://127.0.0.1:8000/ and optionally:

```powershell
python scripts\replay_detections.py --limit 30 --post-api
```

## Change inventory (code touched this milestone)

| Area | Files |
|------|--------|
| Sampling | `scripts/sample_splits.py` |
| Train/eval | `ml/training/train.py`, `ml/evaluation/evaluate.py`, `ml/models/bundle.py` |
| Agents | `agents/coordinator/coordinator.py`, `agents/detection/inference.py`, `agents/explainability/explain.py`, `agents/anomaly/isolation.py`, `agents/feature_extraction/csv_extractor.py`, `agents/reporting/__init__.py` |
| API/UI | `backend/app.py`, `backend/templates/dashboard.html`, `backend/static/*` |
| Replay | `scripts/replay_detections.py` |
| Config | `config/config.yaml`, `config/__init__.py` |
| Docs | `README.md`, `docs/ARCHITECTURE.md`, `docs/PROGRESS.md` |
| Tests | `tests/test_*.py` (expanded) |

## Known notes

- Label ids in splits are numeric encodings from `LabelEncoder` over Phase 1 labels. Human names are restored via `ml/models/label_classes.json`.
- Web Attack may be scarce/absent after label normalization depending on source CSV encoding; metrics reflect classes present in the sample.
- Response engine remains **dry-run** by default for safety.
- Large raw/full split CSVs stay gitignored; sample + models are local artifacts.
