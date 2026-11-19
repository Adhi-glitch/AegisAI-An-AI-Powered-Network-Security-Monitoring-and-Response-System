# AegisAI Project Documentation

Date: 2026-11-18

This document is the project’s master record of what has been built, what has been verified, what remains to be validated, and how the system fits together. It consolidates the implementation status across the backend, ML pipeline, frontend console, response engine, datasets, and security operations features. A passing code test suite does not imply that the model or host-specific integrations meet release requirements.

## 1. Executive summary

AegisAI is an AI-powered network security monitoring and response system designed to detect suspicious network activity, explain model decisions, persist security events, support analyst workflows, and safely evaluate response actions in a dry-run-first environment.

At the current milestone, the project includes:

- A working end-to-end intrusion detection baseline pipeline
- Feature extraction from CICIDS-style, CSE-CIC-IDS2018, and other supported datasets, plus live flow features
- Model training and evaluation for anomaly and classification tasks
- Source-group-aware seven-class evaluation using train/validation/test partitions
- SQLite-backed persistence for alerts, detections, actions, incidents, feedback, assets, and approvals
- A FastAPI backend with role-aware authentication and API routing
- A Vite + React operations console with admin/viewer separation
- Offline Copilot-style grounded retrieval and incident/reporting workflows
- Response policy evaluation with approval gates and audit logging
- Demo and replay tooling for safe, packet-free scenario testing

The project is not a theoretical prototype only. It includes working local mechanisms, assets, and API flows, but it is **not release-qualified**: the latest strict grouped model evaluation misses its approved thresholds, and live capture, Docker runtime, and some external integrations still need environment-specific verification.

## 2. Mission and scope

The project aims to provide a practical security monitoring solution that combines:

- network telemetry ingestion and feature generation
- model-based detection of attacks and anomalies
- explainability and confidence reporting
- operator-facing dashboards
- incident and report correlation
- policy-driven defensive response decisions
- persistent auditability and approval workflows

The system is intentionally designed to operate in a controlled, offline-first manner. It does not assume that the environment has paid cloud services, public APIs, or privileged packet capture access by default.

## 3. What has been implemented so far

### 3.1 Core ML and detection pipeline

The repository contains a functioning intrusion detection baseline built around a network dataset pipeline and model training stack:

- data loading and normalization for CICIDS, CSE-CIC-IDS2018 Parquet captures, and related intrusion datasets
- feature schema handling for network flow features
- stratified prototype splits and strict source-group train/validation/test splitting
- per-file `source_group` provenance, including individual CSE-CIC-IDS2018 scenario captures
- RandomForest-based detection and IsolationForest anomaly scoring
- model bundle management and active bundle resolution
- evaluation outputs for accuracy, confusion matrices, FPR, and class metrics
- explainability support using feature importance and fallback logic

The active live bundle is a CPU RandomForest designed for a 12-feature live detection flow. The model bundle system supports swapping trained artifacts without changing the runtime contract. The strict evaluation script trains a fresh in-memory model and does not replace or activate the production bundle.

### 3.2 Live capture and flow prototype

A live flow prototype is integrated into the backend and model runtime:

- bidirectional IPv4 flow aggregation
- ordered numeric feature construction matching the active model schema
- admin-only capture start/stop interfaces
- transient flow scoring
- severity bands for model scores (not calibrated probabilities)
- dry-run response policy evaluation
- detection persistence only for supported non-benign labels above policy thresholds

The system includes rule-based indicators for patterns such as:

- Port scan-like volume behavior
- repeated authentication attempts and suspicious port activity
- cleartext HTTP pattern heuristics
- optional local Botnet IOC matching

These rules are designed as bounded, low-risk indicators and do not manufacture ML confidence nor trigger direct firewall actions.

### 3.3 Security response engine

The response logic has been implemented as a safety-focused subsystem:

- policy preview and policy management
- typed response rules based on attack type, confidence, severity, and asset criticality
- allowlist, TTL block, rate-limit, rollback, and audit support
- approval workflow with pending/approve/reject statuses
- dry-run default response execution
- action auditing and durable approval history
- optional integration adapters for notification channels

This is a significant milestone because it turns the project from raw detection into an operational decision-support system. It is designed to remain safe by default until an operator explicitly approves and executes actions.

### 3.4 Copilot / grounded retrieval layer

The project includes an offline-first knowledge and retrieval layer:

- local retrieval over seed MITRE and AegisAI documents
- citation support in responses
- weak-retrieval refusal when local retrieval is insufficient
- admin document ingestion and chunking
- grounded response generation using local knowledge rather than an external LLM dependency

This layer is intentionally honest about limitations and does not claim to provide a production-grade embedding index or external-model retrieval.
Documents ingested at runtime are held in process memory and are cleared when the
service restarts; this is not persistent document storage.

### 3.5 Incident reporting and analytics

A structured incident and reporting system has been integrated:

- incident correlation and lifecycle management
- ATT&CK-style mapping support
- severity, status, admin-only persisted merge/split actions with parent/merge lineage
- report generation in JSON, Markdown, text, and dependency-light PDF output
- model health monitoring
- posture scoring and digest generation
- threat feed, asset, and search workflows
- feedback collection for true positive / false positive / unsure labels

These features create the foundation for a real analyst workbench rather than just a detector.

### 3.6 Dashboard and front-end operations console

The React frontend source is under `frontend/src` and the app is built with Vite:

- sign-in flow for admin and viewer roles
- dashboard and legacy console views
- live API-connected operational panels
- alert and detection display surfaces
- threat feed and posture views
- safe demo replay and admin controls
- strict TypeScript and Vite production-build validation

The current FastAPI route mapping is important when launching the prototype:
`/` is the Jinja public homepage, `/signin` is the Jinja sign-in page, and
`/dashboard` is the Jinja live-operations dashboard (`/legacy` is an alias).
The separately built React/Vite console, which contains its own sign-in screen,
is served at `/console`. A successful React build is required before that route
is available. Do not describe `/dashboard` as the React console unless the
application routes have first been changed and verified.

The frontend is designed as a strict, role-aware operational shell rather than a purely static mockup.

## 4. Architectural overview

The main project architecture follows a layered design:

### 4.1 Backend

The backend is built with FastAPI and includes role-aware routers such as:

- auth
- alerts
- detections
- actions
- stats
- capture
- response
- incidents
- copilot
- operations
- demo
- WebSocket feed

The backend provides the core API surface, auth, middleware, policy enforcement, dashboards, and persistence interfaces.

### 4.2 Database

Persistent storage is primarily handled through SQLite and SQLAlchemy models.
Alembic versioned migrations maintain schema upgrades, including stored incident
event details and merge/split lineage. Legacy unversioned SQLite databases are
preserved through the compatibility migration path described in
`RUNNING.md`.

Key persisted records include:

- users and roles
- alerts
- detections
- actions
- response approvals
- audit records
- incidents
- feedback
- assets
- threat feeds
- saved searches and watchlists
- model-run metadata

This persists the operational state necessary for a realistic SOC-like workflow.

### 4.3 ML stack

The ML stack includes:

- data preparation scripts
- feature schema utilities
- training, evaluation, and inference flows
- model bundle manifests
- alert/explainability support
- anomaly scoring logic

Key modules exist under:

- ml/data/
- ml/training/
- ml/evaluation/
- ml/models/

### 4.4 Frontend

The frontend is built in React + Vite and is meant to provide the operations console. It consumes the FastAPI backend and follows strict UI state handling for loading, errors, and empty states.

### 4.5 Supporting scripts and tooling

The repository includes a wide set of operational scripts for dataset prep, demo replay, model training, evaluation, verification, and system checking. Examples include:

- scripts/sample_splits.py
- scripts/prepare_cicids.py
- scripts/build_prototype_dataset.py
- scripts/prepare_prototype_splits.py
- scripts/replay_detections.py
- scripts/demo_scenario.py
- scripts/verify_full_system.py
- scripts/start_live_capture.py

These scripts make the project reproducible and support end-to-end local testing.

## 5. Project milestones completed

### Phase 1: Backend hardening and API versioning

This phase established the secure foundation of the application:

- JWT authentication and role separation
- bcrypt-based password hashing
- request middleware and security headers
- structured request logging and trace IDs
- modular versioned API routes
- health and telemetry endpoints
- database schema expansion

### Phase 2: Unified role-aware web console

This phase delivered the operational console and a role-aware product experience:

- admin/viewer separation
- shared home and dashboard experience
- live sensor panel
- capture status and role restrictions
- threat-only reporting and safe operational views

### Phase 3: Live flow prototype

This phase integrated detection into a flow-based live prototype:

- packet aggregation into identifiable flows
- feature extraction for active models
- scoring and alert persistence under a safety threshold
- warning and monitoring logic for suspicious traffic patterns
- transient live visualization without direct host-level destructive actions

### Phase 4: Security response and approval system

This phase added policy-driven response logic and safety-oriented execution controls:

- preview and policy management
- pending approvals and durable audit records
- rollback support and action simulation
- response workflow persistence

### Phase 5: Multi-dataset detector and evaluation

This phase established the active model bundle and prototype dataset strategy:

- bounded multi-dataset sampling
- source-group provenance tracking
- active bundle selection
- evaluation metadata and confusion matrices
- warning around exploratory metrics versus independent generalization
- later integration of CSE-CIC-IDS2018 Parquet captures, including CSE-specific label mapping, packet-length aliases, case-insensitive `Label` handling, and per-scenario source groups
- a fresh coverage audit showing at least three source groups for each class and a strict grouped evaluation over all seven labels; the evaluation did not pass the approved detector thresholds and did not update the active bundle

## 6. Data and model details

### 6.1 Supported data sources

The project has operational support for a range of intrusion datasets, including:

- CIC-IDS-2017
- CSE-CIC-IDS2018
- NSL-KDD
- UNSW-NB15
- CTU-13
- Bot-IoT

The workspace includes the datasets under `data/phase1/`, as well as prepared data and model artifacts under `ml/data/` and `ml/models/`. The reproducible coverage audit reports at least three conservative source groups for each canonical class; exact counts are in `dataset_requirements.md`.

CSE-CIC-IDS2018 `TrafficForML` Parquet exports have no source/destination port fields. Those features are normalized to zero for these rows; do not interpret this dataset's evaluation as port-feature validation.

### 6.2 Model training flow

The system supports training using prepared CSV splits and bundle-aware model artifacts. Training options include RandomForest and XGBoost; the active live bundle currently uses RandomForest and 12 numeric features.

The training pipeline is designed to:

- load and normalize labeled dataset rows
- split data into train/validation/test sets
- train a baseline classifier and anomaly detector
- persist model bundle metadata
- update active model references

### 6.3 Explainability

Feature importance and model explainability are part of the project’s operational output. This is important for trust and analyst review and supports the response workflow by making the model’s decisions interpretable at a useful level.

## 7. Security and governance features

The current project is built with a defensive-by-default posture.

Key governance and security features include:

- JWT auth and role-based authorization
- security headers and request tracing
- approval workflows for sensitive response actions
- dry-run default for firewall or active response actions
- audit persistence for all executed or attempted response decisions
- admin-only controls for system actions
- risk-aware labeling of live rules and alerts

The project explicitly avoids claiming live packet capture or host firewall execution as working without proper verification or privileges.

## 8. Frontend and user experience state

The codebase includes a UI stack that provides:

- sign-in and authorization-aware screens
- dashboard panels for detection and operations
- admin-only controls for system actions
- viewer-only access patterns
- live API-driven interaction states
- clear separation between safe demo and real operational functions

The app is designed to support both security operations and research workflows without exposing unsafe controls to viewers.

## 9. Testing and validation status

The repository contains a substantial test suite covering backend functionality, API behavior, response logic, evaluation, and operational workflows.

The documentation in the repo records:

- backend regression suite passing
- frontend production build passing
- dry-run demo scenario working without firewall or packet changes
- route-level feature verification across admin and viewer capabilities

Important validation caveat:

- live packet capture and real host firewall execution require elevated Windows privileges and environment-specific verification
- some integrations depend on external services or credentials that are not configured by default
- the strict grouped evaluation trained a fresh model on 573,986 bounded samples and held out 123,018 test rows with zero source-group overlap. All six attack classes failed the approved test precision/recall gates; benign false-alarm rate was 2.7928% against a 0.5% maximum.
- test coverage has one held-out source group each for Brute Force, DDoS, DoS, Port Scan, and Web Attack. The reported Wilson intervals are row-level and do not account for within-capture dependence.
- latest full backend suite (2026-11-17): 167 passed and one PostgreSQL integration test skipped without `AEGIS_TEST_POSTGRES_URL`. Frontend and host-specific runtime checks are tracked separately.

## 10. Known limitations and current caveats

The project has already reached a mature local demo and API milestone, but several limitations remain honest and explicit:

- Live packet sniffing is not fully verified on this host without elevated privileges and proper Npcap setup.
- Actual firewall execution is dry-run only and remains intentionally safe.
- External webhook, SMTP, Telegram, or GeoIP integrations are not claimed as active until their credentials and environment are configured.
- The prior 94.9178% row-random prototype metric is exploratory and must not be presented as independent-capture generalization. Although minimum group counts now permit strict splits, the strict evaluation fails the model release thresholds.
- The React console connects the principal response, threat-feed, simulation,
  incident-report, asset, and model-health views to backend APIs. Its layouts
  remain intentionally compact; richer analytics and full incident workflow
  controls are still incomplete.
- Background retraining or scheduled digests are not yet implemented as autonomous services.

This honesty is a strength of the project: it distinguishes implemented local functionality from unverified production integrations and real-world capture conditions.

## 11. Recommended operational workflow

For local development and validation:

```powershell
if (-not (Test-Path .env)) { Copy-Item .env.example .env }
# set credentials and SECRET_KEY
python database\init_db.py
python -m uvicorn backend.app:app --reload --port 8000
```

For data preparation and training:

```powershell
python scripts\sample_splits.py --train-size 300000
python -m ml.training.train
python -m ml.evaluation.evaluate
```

For the safe demo:

```powershell
cd frontend
npm run build
npm run dev
cd ..
python scripts\demo_scenario.py
```

## 12. Key documentation set in the repository

The repo already contains detailed supporting documents, including:

- [README.md](../README.md) — current project overview and quickstart
- [docs/ARCHITECTURE.md](./ARCHITECTURE.md) — architecture and module map
- [docs/PROGRESS.md](./PROGRESS.md) — implementation progress and milestone notes
- [docs/FEATURE_STATUS.md](./FEATURE_STATUS.md) — verified feature matrix and role capabilities
- [docs/PROJECT_COMPLETION_PLAN.md](./PROJECT_COMPLETION_PLAN.md) — subsystem inventory, release criteria, and remaining work
- [docs/PROJECT_STATUS_AND_MODEL_ARCHITECTURE.md](./PROJECT_STATUS_AND_MODEL_ARCHITECTURE.md) — model and data-flow status
- [docs/PROTOTYPE_PROGRESS.md](./PROTOTYPE_PROGRESS.md) — prototype history and current release-gate status
- [docs/dataset_requirements.md](./dataset_requirements.md) — data coverage and source-group constraints
- [artifacts/strict_group_evaluation.json](../artifacts/strict_group_evaluation.json) — current seven-class grouped evaluation and threshold results
- [docs/phase1_attack_dataset_plan.md](./phase1_attack_dataset_plan.md) — attack categories and dataset planning
- [docs/RUNNING.md](./RUNNING.md) — running instructions and operational notes
- [docs/FUTURE_ROADMAP.md](./FUTURE_ROADMAP.md) — roadmap and likely next steps

## 13. Current project status

As of 2026-11-15, the project is in a strong local implementation milestone state, but it is not complete for release:

- The backend and API stack are largely implemented and operational.
- The ML pipeline is functional with active bundle-based detection.
- The frontend console is built and role-aware.
- Response policy, approval, incident, and Copilot workflows are present.
- The system is safe by default and intentionally conservative about live host actions.
- The CSE-integrated dataset pipeline has enough conservative source groups to form strict seven-class splits, but the latest model failed every attack-class precision/recall gate and the benign false-alarm gate.
- Real external integrations, authorized privileged network capture, Docker runtime verification, and model release qualification remain open before production use.

This gives AegisAI a credible foundation as a local, offline-first AI security monitoring and response platform with a clear path toward operational hardening and production deployment.
