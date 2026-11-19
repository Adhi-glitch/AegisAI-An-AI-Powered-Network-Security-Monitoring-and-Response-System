# AegisAI Project Status & Model Architecture

This document summarizes the progress of the AegisAI project, remaining tasks, and provides a deep dive into how the machine learning models are structured and operate up to this point.

---

## 1. What Has Been Done (Completed)

### Core Backend & Security (Phase 1)
- **FastAPI Modularization:** All routes are modularized under `/api/v1/` (`auth`, `ws`, `alerts`, `detections`, `actions`, `stats`).
- **Authentication:** JWT-based authentication using bcrypt for password hashing. Role-based access control is implemented (Admin vs Viewer).
- **Security Middleware:** Strict security headers (CSP, X-Frame-Options, XSS protection) and request tracing (Structlog with UUID injection).
- **Real-Time Feeds:** WebSocket integration (`/ws/feed`) to stream live detections directly to the frontend.
- **Database:** SQLite backend using SQLAlchemy for alerts, detections, and actions.

### Frontend UI (Phase 2)
- The React/Vite source is in `frontend/src`; FastAPI serves its build at `/console` after a frontend build.
- FastAPI currently serves the Jinja homepage at `/`, the Jinja sign-in page at `/signin`, and the Jinja live dashboard at `/dashboard`; `/legacy` aliases that dashboard.
- The React dashboard, legacy page, and API use the authenticated WebSocket feed for live detection events.

### ML Data & Prototype Evaluation (Phase 3 - Partially Complete)
- Seven canonical classes are represented in the supplied datasets and bounded prototype dataset. CSE-CIC-IDS2018 scenario Parquet captures are normalized, sampled with per-file provenance, and included in coverage audits.
- The active CPU RandomForest bundle uses the same 12 ordered features as live flow extraction. The older 78-feature XGBoost bundles are not used for live capture.
- The active report is row-random with source-capture overlap: 94.9178% accuracy is exploratory, not an independent generalization estimate.
- The updated audit confirms at least three source groups for every canonical class. The strict seven-class evaluation held out 123,018 test rows with zero source-group overlap, but every attack class failed its approved precision/recall gate and benign false-alarm rate was 2.7928% against the 0.5% limit. Results and row-level Wilson intervals are in [the strict report](../artifacts/strict_group_evaluation.json); the intervals are not capture-cluster adjusted.
- `docs/EVALUATION_TRUSTWORTHY.md` retains an older report for audit history and warns against presenting it as trustworthy.
- Automated tests cover inference, bundle parity, capture lifecycle, persistence, and API integration.

---

## 2. What Is Pending

- **Real capture verification:** Npcap is available and Scapy integration is implemented, but a non-elevated loopback probe captured no packets. Run the smoke test from elevated PowerShell on a selected interface.
- **Model release qualification:** Meet the approved precision, recall, and benign false-alarm thresholds on the strict held-out test split, and verify that the tested model bundle is the version actually activated by the application.
- **Production prevention:** OS firewall enforcement remains intentionally unimplemented; the prototype is dry-run only.
- **Production integrations:** Threat intelligence, knowledge graph, RAG, notifications, and distributed sensors remain future work.

---

## 3. Model Architecture & Workflow

### What We Are Using
- **Primary Engine (Supervised):** Active CPU RandomForest with seven classes and 12 ordered prototype features.
- **Secondary Engine (Unsupervised):** Isolation Forest (Scikit-Learn), used as a prototype anomaly score.
- **Feature Extraction:** IPv4 bidirectional flow totals, rates, ports, duration, and protocol. This is a 12-feature subset, not full CICFlowMeter equivalence.

### How the Model Works

1. **The Classes (7 Categories):**
   The model is trained to classify traffic into one of seven distinct buckets:
   *Benign, Botnet, Brute Force, DDoS, DoS, Port Scan, and Web Attack.*

2. **The Pipeline Workflow:**
   - **Ingestion:** Features arrive through the alert API or the live flow pipeline.
   - **Vectorization:** `agents/detection/inference.py` aligns input with the active bundle's ordered 12-feature contract and handles absent/non-finite values according to the runtime schema.
   - **Supervised Inference:** The active RandomForest produces class scores used for the predicted class. These scores are not established as calibrated probabilities.
   - **Anomaly Detection:** In parallel, the Isolation Forest checks if the traffic pattern looks fundamentally "alien" compared to baseline Benign traffic.
   - **Explainability:** Compatible SHAP values or deterministic feature-importance fallbacks provide analyst-facing explanations; they are not proof of causation.
   - **Response Engine:** Actions default to dry-run and approval-required paths. `auto-live` firewall execution is explicitly disabled.

### Data Integrity ("Trustworthy Splits")
- The unified data and bounded sample retain a `source_group` for each capture or conservative dataset partition. CSE-CIC-IDS2018 scenario Parquet files are separate groups.
- The audit finds at least three groups for every class, so the seven-class group-disjoint train/validation/test evaluation now runs.
- The strict run sampled 573,986 rows and held out 123,018 test rows with zero group overlap. All six attack classes failed approved precision/recall thresholds; benign false-alarm rate was 2.7928% against the 0.5% maximum. The tested model was trained in memory and did not replace the active bundle.
- The test split has one group each for Brute Force, DDoS, DoS, Port Scan, and Web Attack. Reported Wilson intervals are row-level, not capture-cluster adjusted. See `artifacts/strict_group_evaluation.json`.
- The separate active bundle report's 94.9178% row-random accuracy is exploratory because capture groups overlap between partitions; it is not an independent generalization result.
