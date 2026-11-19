# AegisAI — Run & Operation Guide

Guide to running, configuring, testing, and operating the AegisAI network-security monitoring and response prototype.

---

## 🛠️ Prerequisites

1. **Python 3.12** with a virtual environment (the CI-tested version; other versions are not currently validated)
2. **Node.js 20.19+ or 22.12+** and npm for the React console build
3. **Npcap** for live packet capture on Windows. Run the backend from elevated PowerShell when administrator access is required by the host.

---

## 🚀 Running the Full Stack

The public project homepage is served at `/`. `/signin` and `/dashboard` serve the Jinja sign-in and live-operations pages; `/legacy` is a compatibility alias for that dashboard. The separate React/Vite console is at `/console` and requires a frontend build before it can be served.

### 1. Start the Backend API Server

Open a terminal in the project root:

```powershell
cd "c:\Users\vadit\Desktop\AegisAI"

# Install dependencies once (skip if already installed)
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
npm --prefix frontend ci
npm --prefix frontend run build
if (-not (Test-Path .env)) { Copy-Item .env.example .env }
# Edit .env and replace the example signing key and both account passwords.

# Start backend API and dashboards
python -m uvicorn backend.app:app --host 127.0.0.1 --port 8000 --reload
```

* **AegisAI public homepage**: `http://127.0.0.1:8000/`
* **Operator sign-in**: `http://127.0.0.1:8000/signin`
* **Jinja live-operations dashboard**: `http://127.0.0.1:8000/dashboard`
* **Jinja dashboard compatibility alias**: `http://127.0.0.1:8000/legacy`
* **React/Vite operator console**: `http://127.0.0.1:8000/console`
* **API health**: `http://127.0.0.1:8000/health` and `http://127.0.0.1:8000/api/v1/health`
* **Swagger API docs**: `http://127.0.0.1:8000/api/docs`
* **ReDoc API docs**: `http://127.0.0.1:8000/api/redoc`
* **Prometheus metrics** (when the optional instrumentation package is installed): `http://127.0.0.1:8000/metrics`
* **WebSocket feed**: `ws://127.0.0.1:8000/ws/feed`

### Self-hosted Docker Compose (no managed cloud services)

Docker Compose starts the FastAPI application and PostgreSQL on the local machine. It does not create a cloud account or managed cloud resource. Docker image downloads require network access and disk space; running the services consumes local machine resources.

```powershell
if (-not (Test-Path .env)) { Copy-Item .env.example .env }
# Edit .env: replace all placeholder values with unique local secrets.
npm --prefix frontend run build
docker compose up --build
```

Open `http://127.0.0.1:8000/` for the homepage or `/console` for the React console. The web container is non-root, read-only, and has all Linux capabilities dropped. Consequently, it does not sniff host interfaces or change host firewall rules. Live capture is not available from this container. This Compose stack requires deployment validation before production use.

---

## 🔐 Authentication configuration

Set distinct admin and viewer passwords in `.env`; each must be 12-72 bytes. Set `SECRET_KEY` to at least 32 random bytes. The sample values in `.env.example` are placeholders and the backend refuses to start while they remain unchanged. Bootstrap accounts are created in the database on first startup; changing environment passwords later does not overwrite existing database users.

---

## 🗃️ Schema migrations and SQLite recovery

Back up an existing SQLite database before an application upgrade. AegisAI uses Alembic revisions; startup applies pending revisions, and operators can inspect or apply them explicitly:

```powershell
python -m alembic current
python -m alembic upgrade head
```

After changing SQLAlchemy models, generate a migration with `python -m alembic revision --autogenerate -m "describe change"` and review its operations before applying it. Do not edit an already-released revision.

The SQLite copy utility uses SQLite's online backup API, verifies the copy, and refuses to overwrite an existing destination:

```powershell
New-Item -ItemType Directory -Force database\backups
python scripts\db_backup.py backup database\backups\aegisai-backup.db
python scripts\db_backup.py restore database\backups\aegisai-backup.db database\aegisai-restored.db
```

Restore creates a new database file; stop the app, verify the restored copy, then point `DATABASE_URL` to that file before restarting. The utility intentionally rejects PostgreSQL URLs; use `pg_dump`/`pg_restore` with credentials supplied through a protected local mechanism. PostgreSQL restore and migration operations still require deployment verification.

## 🧭 Application Pages & Capabilities

| Page | Route | Description |
|------|-------|-------------|
| **Jinja live-operations dashboard** | `/dashboard` (also `/legacy`) | Capture controls, status, detections, and operator-facing telemetry. |
| **React console overview** | `/console#overview` | API-backed overview and live sensor controls. |
| **Response Center** | `/console#response` | Policy preview and dry-run or approval-required action workflows. |
| **Incidents** | `/console#incidents` | Correlate saved alerts, search incidents, inspect timelines, update status, and merge/split as admin. |
| **Threat Intel** | `/console#intel` | Local IP reputation lookup; admins can import validated local feed entries. |
| **Attack Lab** | `/console#lab` | Admin-only packet-free synthetic simulation. |
| **Reports** | `/console#reports` | Export a persisted incident as JSON, Markdown, text, or PDF. |
| **Model Health / Network Map** | `/console#health`, `/console#network` | API-backed model metadata and asset inventory. |
| **Copilot / Admin Tools** | `/console#copilot`, `/console#tools` | Offline retrieval with citations; ingested documents are memory-only and reset on restart. Admin Tools expose fixed-key operations. |

---

## 🧪 Testing & Verification

### Run Backend Pytest Suite
```powershell
$env:PYTHONPATH="."
\.venv\Scripts\python.exe -m pytest -q
```

Run the frontend type-check/build from the repository root with `npm --prefix frontend run build`; run its TypeScript test script with `npm --prefix frontend test`.

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
# Build a bounded sample while preserving source capture IDs
python scripts/build_prototype_dataset.py --rows-per-group-class 10000 --seed 42

# Create explicitly capture-overlapping row splits for prototype use only
python scripts/prepare_prototype_splits.py --sample-size 250000 --seed 42

# Train a CPU-friendly presentation model and activate its bundle
python -m ml.training.train --splits-dir ml/data/splits/prototype --bundle-dir ml/models/multi_dataset_bundle --engine random_forest --n-estimators 120

# Evaluate the active bundle; report includes an overlap warning
python -m ml.evaluation.evaluate
```

Check `docs/dataset_requirements.md` before training. The supplied data now has at least three conservative source groups per canonical class, so a separate strict group-disjoint evaluation is available:

```powershell
.\.venv\Scripts\python.exe scripts\evaluate_grouped_model.py
```

The current result is **not release-qualified**: all six attack classes missed the approved precision/recall gates, and benign false-alarm rate was 2.7928% (0.5% maximum). See `artifacts/strict_group_evaluation.json`. The prototype row-random splits described above still allow related flows from one capture into multiple partitions and must not be used as evidence of independent generalization.
`sample_size` caps training rows only; validation and test retain all rows from their held-out source groups.
Restart the backend after training so its process cache loads the newly active bundle.

### Live capture demonstration

Run PowerShell as Administrator if capture reports zero packets or a permission error. Scapy must report `conf.use_pcap=True`; the interface list returns friendly Scapy names and the API also normalizes NPF device paths. Start the backend:

```powershell
python -m uvicorn backend.app:app --host 127.0.0.1 --port 8000 --reload
```

Open `http://127.0.0.1:8000/dashboard` or `/console`, sign in with an admin account, then select an interface before starting the sensor. Keep the packet filter at `ip` for a basic authorized smoke test and confirm packet and flow counters increase. Each completed flow is passed to the active ML bundle; its predicted class and raw model score appear only in the ephemeral live-flow view. The score is not a calibrated probability. Only supported model predictions scoring at least 0.50 are persisted.

The sensor also emits explicitly labeled, no-confidence behavioral indicators, none of which triggers a response action:

| Indicator | Evidence threshold | Important limitation |
|-----------|--------------------|----------------------|
| Port Scan | 20 distinct initial TCP SYN destination ports for one source/target pair within 60 seconds | Indicates scan-like behavior, not malicious intent |
| DoS-like SYN rate | 250 initial TCP SYN packets from one source to one destination service within 5 seconds | Covers high-rate TCP SYN patterns, not every DoS technique |
| DDoS-like SYN rate | 1,000 initial TCP SYN packets from at least 5 sources to one destination service within 5 seconds | Requires multiple observed sources; not a single-client test |
| Brute-force-like connection pattern | 10 distinct TCP source ports connecting to one authentication-service port within 60 seconds | Packet capture cannot confirm whether any login failed |
| Web Attack signature | High-specificity SQLi, script-tag, or traversal signature in a visible HTTP request | HTTP only; no HTTPS decryption, and a signature is not proof that an exploit succeeded |
| Botnet IOC | A DNS question or packet endpoint matches an entry in `config/threat_iocs.json` | The bundled file is empty; this detects known listed indicators only, not arbitrary C2 |

The packet-level rules are indicators, not ML predictions, and have no response action. HTTP payloads are inspected only in memory for matching signatures and are not included in stored event details. For Botnet IOC matching, configure the `domains` and `ips` arrays in `config/threat_iocs.json` from a trusted, current feed before starting capture; the example file contains no indicators. The model's Botnet label has not been independently validated on live captures. Do not repeat flood or password-wordlist tests for a presentation. Use only approved, bounded tests on systems you own or have explicit authorization to assess. Response actions remain dry-run; do not enable firewall enforcement for the prototype. Ordinary packet capture cannot show HTTPS URLs/page paths or names hidden by encrypted DNS.

### Safe model demonstration

An administrator can click **Replay four sample detections** on the dashboard to run held-out Botnet, Brute Force, DDoS, and Web Attack examples through the active model. These are labeled `Sample replay · simulated`, broadcast to connected dashboards, and kept only in the open browser session. The replay sends no network packets, writes no alert/detection/action rows, and cannot invoke response actions. Treat the scores as model outputs on labeled samples—not as proof that those attacks occurred or as calibrated probabilities. The live capture path and its rule-based indicators are documented above; replay does not validate live detection.
