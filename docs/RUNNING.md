# AegisAI — Run & Operation Guide

Complete guide to running, configuring, testing, and operating the AegisAI Autonomous Network Intrusion Detection and Response System.

---

## 🛠️ Prerequisites

1. **Python 3.10+** (with virtual environment in `.venv-local` or `.venv`)
2. **Node.js 18+ & npm 9+**
3. **Npcap** *(Optional for future live packet sniffing on Windows)*: Installed with "WinPcap API-compatible Mode" enabled.

---

## 🚀 Running the Full Stack

Running AegisAI requires starting two services: the **FastAPI Backend API Server** and the **Vite React Frontend**.

### 1. Start the Backend API Server

Open a terminal in the project root:

```powershell
cd "c:\Users\vadit\Desktop\AegisAI"

# Activate virtual environment
.\.venv-local\Scripts\Activate.ps1

# Run backend API server
python -m uvicorn backend.app:app --host 0.0.0.0 --port 8000 --reload
```

* **API Server Base URL**: `http://localhost:8000`
* **Swagger API Interactive Docs**: `http://localhost:8000/api/docs`
* **ReDoc API Documentation**: `http://localhost:8000/api/redoc`
* **Prometheus Metrics**: `http://localhost:8000/metrics`
* **WebSocket Feed URI**: `ws://localhost:8000/ws/feed`

---

### 2. Start the Frontend Dashboard

Open a **second terminal** in the `frontend/` directory:

```powershell
cd "c:\Users\vadit\Desktop\AegisAI\frontend"

# Start Vite dev server
npm run dev
```

* **Frontend Dashboard URL**: `http://localhost:5173`

---

## 🔐 Default Credentials

| Role | Username | Password | Privileges |
|------|----------|----------|------------|
| **Administrator** | `admin` | `aegisai2024` | Full access, manual IP unblocking, packet simulation, configuration |
| **Security Analyst (Viewer)** | `viewer` | `viewer2024` | Read-only telemetry, detection analytics, alert inspection |

*Quick-fill demo buttons are also available on the login page.*

---

## 🧭 Application Pages & Capabilities

| Page | Route | Description |
|------|-------|-------------|
| **Dashboard** | `/` | Real-time SOC dashboard with live metrics, 24h attack timeline, threat donut chart, automated action distribution, and live WebSocket event stream. |
| **Alerts** | `/alerts` | Paginated raw network event logs with IP/protocol search and JSON Feature Inspector modal. |
| **Detections** | `/detections` | Machine learning classification outputs with confidence probability meters and explainability breakdown. |
| **Actions & Response** | `/actions` | Automated mitigation logs with Admin-only manual IP unblock dialog. |
| **Settings & Health** | `/settings` | System health checks, model registry metadata, JWT session parameters, and live burst telemetry generator. |

---

## 🧪 Testing & Verification

### Run Backend Pytest Suite
```powershell
$env:PYTHONPATH="."
.\.venv-local\Scripts\pytest.exe -v
```

### Run Frontend Linter & Production Build
```powershell
cd frontend
npm run lint
npm run build
```

---

## 🏋️ Retraining the ML Detection Model (Optional)

To train new model bundles from raw or sampled CICIDS datasets:

```powershell
# 1. Generate stratified sample splits
python scripts\sample_splits.py --train-size 300000

# 2. Train baseline Random Forest / CUDA XGBoost model
python -m ml.training.train --engine auto

# 3. Evaluate model on test split and generate report
python -m ml.evaluation.evaluate
```

### Multi-dataset workflow (current milestone)

```powershell
# Build the unified multi-dataset CSV and stratified splits
python -c "from pathlib import Path; from ml.data.multidataset import build_unified_dataset, prepare_multidataset_splits; root=Path('data/phase1'); build_unified_dataset(root=root, output_path='ml/data/processed/multi_dataset_unified.csv'); prepare_multidataset_splits(input_csv='ml/data/processed/multi_dataset_unified.csv', output_dir='ml/data/splits/multi_dataset', sample_size=250000, seed=42)"

# Train the multi-dataset ensemble bundle
python ml/training/train.py --splits-dir ml/data/splits/multi_dataset --bundle-dir ml/models/multi_dataset_bundle --engine auto

# Evaluate using the saved multi-dataset bundle
python -m ml.evaluation.evaluate
```
