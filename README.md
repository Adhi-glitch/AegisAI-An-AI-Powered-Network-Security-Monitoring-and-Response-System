"""
AegisAI — AI-powered network intrusion detection and response.

Current state: end-to-end baseline pipeline is working with CICIDS sample splits,
model training, anomaly detection, explainability, SQLite persistence, and a FastAPI dashboard.
The project now supports automatic GPU-aware training when CUDA is available, with a reliable
CPU fallback.
"""

## What this project does today

This project builds a network intrusion detection and response baseline for CICIDS-style traffic:

- loads and normalizes CICIDS CSV data
- creates stratified training/validation/test samples
- trains a detection model and an IsolationForest anomaly detector
- explains the prediction using feature importance
- stores alert, detection, and action records in SQLite
- exposes the dashboard and stats via FastAPI
- supports replay of detections for offline testing

This is a complete milestone pipeline, not a placeholder.

## Quickstart

Run everything in one PowerShell session:

```powershell
cd "c:\Users\vadit\Desktop\AegisAI"
.\.venv\Scripts\Activate.ps1
python scripts\sample_splits.py --train-size 300000
python -m ml.training.train
python -m ml.evaluation.evaluate
python database\init_db.py
uvicorn backend.app:app --reload --port 8000
```

Open http://127.0.0.1:8000/ for the dashboard.

Optional: replay detections into the local DB/API:

```powershell
python scripts\replay_detections.py --limit 30 --post-api
```

## GPU support

The training script automatically prefers XGBoost on CUDA when a supported NVIDIA GPU is detected.
If CUDA is unavailable, it falls back to CPU-based training automatically.

```powershell
python -m ml.training.train --engine auto
```

You can force a specific engine:

```powershell
python -m ml.training.train --engine xgboost
python -m ml.training.train --engine random_forest
```

## Docs

- `docs/ARCHITECTURE.md` — system pipeline and module map
- `docs/PROGRESS.md` — current milestone status and implementation history
- `docs/dataset_requirements.md` — dataset sources
- `docs/phase1_attack_dataset_plan.md` — Phase 1 attack categories and workflow

## Tests

```powershell
.\.venv\Scripts\python.exe -m pytest -q
```
