# AegisAI Progress Log

## Current Status (2026-11-18): Local-First Workflows Implemented; Release Gates Remain

AegisAI has a FastAPI backend, versioned SQLite migrations, Jinja pages at `/`, `/signin`, and `/dashboard`, and a separate React/Vite console at `/console`; `/legacy` aliases the Jinja live dashboard. Incident status, merge/split lineage, reports, threat intelligence, feedback, search, asset, explainability, and posture workflows are API-backed. Copilot document ingestion is administrator-only and in-memory. The response API defaults to dry-run and explicitly rejects `auto-live`. CSE-CIC-IDS2018 is integrated into dataset normalization, sampling, auditing, and seven-class strict group evaluation. Actual packet sniffing still needs authorized isolated-host verification.

## Defensive Rule Coverage (2026-11-17)

- Added bounded packet-pattern indicators for UDP/ICMP rate surges, UDP multi-port probes, high HTTP request volume, aged incomplete cleartext HTTP headers, repeated HTTP login requests, and periodic connections. Existing TCP SYN-rate, TCP port-scan, authentication-port, cleartext signature, and configured IOC rules remain.
- In-memory Scapy tests cover these patterns and selected ordinary HTTP traffic without sending packets. Focused detector, capture API, and policy checks: **49 passed**; full backend suite: **167 passed, 1 skipped**.
- These are heuristic indicators, not universal attack detection. Rule events intentionally have no probability confidence; they carry evidence and coarse severity. Periodic benign services can resemble beacons; encrypted HTTP payloads and actual authentication outcomes remain unavailable to these rules. The grouped Random Forest evaluation still fails the project release gates; live packet capture remains unverified.

## Verified Feature Checkpoint (2026-11-15)

- Backend regression suite: **127 passed, 1 skipped**, with 71 warnings. The skipped PostgreSQL test requires `AEGIS_TEST_POSTGRES_URL`.
- The updated dataset audit finds at least three source groups for every canonical class. The strict evaluation held out 123,018 test rows with zero source-group overlap, but all six attack classes failed the approved precision/recall gates and benign false-alarm rate was 2.7928% (0.5% maximum). See [strict_group_evaluation.json](../artifacts/strict_group_evaluation.json); the earlier best-effort report is historical only.
- Frontend production build: `npm run build` passes with strict TypeScript.
- Manual browser smokes covered the role-aware React console, including persisted admin incident merge/split.
- CI covers PostgreSQL integration, migrations, tests, Compose validation, frontend build/type checks, and npm audit; hosted workflow execution remains pending.
- F1-F10 feature services and API routes are documented in [FEATURE_STATUS.md](FEATURE_STATUS.md).
- Response approvals, durable response audit records, saved searches, watchlists, incidents, assets, and feedback have database models and versioned migrations.
- The offline Copilot supports citations, weak-retrieval refusal, and validated admin document ingestion/chunking; ingested text is cleared when the service restarts.
- The packet-free demo scenario is available at `scripts/demo_scenario.py`.

---

## Historical Verification Checkpoint (2026-10-26)

The following count and implementation notes describe the earlier checkpoint
only; use the current verification section above for present status.

## 🚀 Completed Milestones

### Phase 1: Backend Hardening & API Versioning (100% Complete)
- **JWT Authentication** (`backend/auth.py`): Bcrypt hashing, 8-hour access token lifecycle, role-based access control (`admin` / `viewer`).
- **Security Middleware** (`backend/middleware.py`): Security headers (CSP, X-Frame-Options, XSS, Referrer-Policy) and structlog request logging with UUID tracing.
- **Modular Versioned API** (`backend/routers/`):
  - `auth.py`: `POST /api/v1/auth/token` & `GET /api/v1/auth/me`
  - `ws.py`: WebSocket live event connection manager with keep-alive at `/ws/feed`
  - `alerts.py`: Paginated alert listings, detail endpoint, and real-time detection broadcast
  - `detections.py`: Paginated classifications and 24-hour timeline analytics endpoint
  - `actions.py`: Paginated mitigation logs and admin-guarded manual IP unblock
  - `stats.py`: Aggregate telemetry metrics and `/api/v1/health`
- **Expanded Database Schema** (`database/models.py`): Added `User`, `ThreatFeed`, `ModelRun`, and `Alert.severity` with automatic SQLite schema migration.
- **Prometheus Metrics**: Exported at `/metrics` when the optional `prometheus-fastapi-instrumentator` package is installed.

### Phase 2: Unified Role-Aware Web Console
- FastAPI serves the public Jinja homepage at `/`, Jinja sign-in at `/signin`, and the Jinja live dashboard at `/dashboard` (`/legacy` is an alias). The separate React/Vite console is at `/console`.
- Admins can configure, start, and stop the live sensor and access admin-only response controls. Viewers share the dashboard, see capture status, cannot invoke admin commands, and can export the threat-only CSV report.
- The console combines threat-only records and severity indicators with an ephemeral live flow visualization. DNS A/AAAA answers enrich matching flow endpoints with observed domain names; otherwise the IP is shown. HTTPS URLs/page paths and encrypted DNS names are not available from ordinary packet capture.
- Threat APIs and the WebSocket feed require an authenticated role. Live traffic and DNS-name mappings are transient and are not persisted as alerts.
- WebSocket events update live telemetry and refresh the threat feed. The responsive interface respects reduced-motion preferences.

### Phase 5: Prototype Multi-Dataset Detector
- The bounded builder created 413,104 sampled rows from all supplied datasets, capped at 10,000 rows per canonical class/source group, while retaining `source_group` provenance.
- The active bundle was trained as a 7-class CPU RandomForest with 120 trees and 12 ordered features. Training, evaluation, inference, and API runtime resolve the same active bundle.
- `artifacts/test_report.json` was regenerated from the active bundle and records 82,621 test rows and 94.9178% accuracy, with per-class metrics, confusion matrix, and FPR. The metadata says `stratified_random_rows_prototype_capture_overlap`; this is exploratory, not an independent generalization estimate.
- Strict group-disjoint test coverage is still blocked: Brute Force has 2 groups, DDoS 2, and Web Attack 1. One more Brute Force group, one more DDoS group, and two more Web Attack groups are needed.

### Phase 3: Live Flow Prototype
- `FlowTracker` aggregates IPv4 packets bidirectionally and emits the same ordered 12 numeric features used for model training.
- Admin-only API routes provide interface listing, start, and stop; authenticated viewers can read capture status. Completed flows go through the active model, but only supported non-benign Phase 1 labels scoring at least 0.50 persist as alert/detection/action records. Other flows are broadcast transiently for visualization.
- A separate bounded rule counts distinct initial TCP SYN destination ports per source/target pair. Twenty ports within a rolling 60 seconds create one low-severity `Port Scan` indicator without a fabricated model confidence or firewall action; a 60-second cooldown limits duplicate records. This means scan-like traffic was observed, not that malicious intent was confirmed.
- Admins can replay four correctly classified held-out samples (Botnet, Brute Force, DDoS, Web Attack) through inference for a clearly tagged, non-persistent dashboard demo. This sends no packets and triggers no response action; it does not claim live attack detection for those classes.
- Live capture now exposes the active model's per-flow prediction and raw score ephemerally. Separate bounded packet rules identify high-rate single-source/multi-source TCP SYN patterns, repeated connections to authentication-service ports, high-specificity signatures in visible cleartext HTTP, and matches against an optional local Botnet IOC list. These rule events have no ML confidence and trigger no response action. The IOC list is empty by default; login failures and HTTPS payloads are not visible, and independent live-capture validation is still required.
- Model severity bands are low (0.50–0.64), medium (0.65–0.79), and high (0.80+); firewall response remains dry-run.
- Synthetic packet tests and a real-model API persistence test pass. Scapy reports `conf.use_pcap=True`; however, this non-elevated process captured zero packets during a loopback probe. Run the real capture smoke test from elevated PowerShell before claiming live sniffing works.

## Verified Checkpoint (2026-10-08)

- The data audit and conservative source-group counts are in [dataset_requirements.md](dataset_requirements.md); run `scripts/audit_phase1_coverage.py` to reproduce them.
- `scripts/build_prototype_dataset.py` creates a bounded, source-tagged sample. `scripts/prepare_prototype_splits.py` intentionally creates row-random prototype splits and marks capture overlap in metadata.
- The active bundle is `ml/models/multi_dataset_bundle` and its ordered features match `LIVE_FEATURE_COLUMNS`; capture refuses a mismatched bundle.
- FastAPI serves the public Jinja homepage at `/`, Jinja sign-in at `/signin`, and the Jinja live dashboard at `/dashboard` (`/legacy` is an alias). The separate React/Vite console is at `/console`.
- Npcap is available, but live sniffing remains unverified because the current process is not elevated and captured no packets.
- Full regression suite: 48 passed; 46 dependency deprecation warnings remain.

## Remaining Work

1. Run the live-capture demo from elevated PowerShell on a selected interface; verify packets, flows, database records, and WebSocket updates. Keep prevention in dry-run mode.
2. Keep the current 94.9178% metric labeled exploratory. Add independent source groups before publishing a generalization claim.
3. Configure and verify any external webhook, Telegram, SMTP, GeoIP, or ASN services before claiming those integrations work.
4. Add a background scheduler for retraining and digest delivery if scheduled operation is required.
5. The live console currently visualizes IP-level flow endpoints; domain-name attribution is not available without DNS/hostname enrichment.

The strict group-disjoint data requirements are listed in [dataset_requirements.md](dataset_requirements.md).
