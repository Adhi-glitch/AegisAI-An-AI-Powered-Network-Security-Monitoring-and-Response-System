# AegisAI Feature Status

Updated: 2026-11-18

This document records what is implemented and verified in the workspace. It
distinguishes working local/demo behavior from integrations that require real
external services, labeled data, or elevated Windows privileges.

## Verification

- Backend: the latest full regression run recorded 167 passing tests and one
  skipped PostgreSQL integration test. The skipped test requires
  `AEGIS_TEST_POSTGRES_URL`.
- Frontend: `npm run build` passes in `frontend/` with strict TypeScript.
- The CSE-integrated evaluator now uses group-disjoint train/validation/test
  splits across all seven classes and reports Wilson confidence intervals.
  Its test thresholds and limitations are in the
  [strict evaluation report](../artifacts/strict_group_evaluation.json).
- Default response mode: dry-run.
- Offline demo: `python scripts\demo_scenario.py` completes without packets or
  firewall changes.

## Feature Matrix

| Feature | Current implementation | Main locations | Status |
|---|---|---|---|
| Response policy | Typed rules using attack type, confidence, severity, and asset criticality | `agents/response/policy_engine.py`, `backend/routers/response.py` | Working locally |
| Response safety | Allowlists, TTL blocks, rate limiting, rollback, mock adapter, audit records | `agents/response/response_engine.py`, `agents/response/adapters.py`, `database/models.py` | Working in dry-run |
| Approvals | Persistent pending/approve/reject workflow | `backend/routers/response.py`, `database/models.py` | Working |
| Playbooks | DoS, DDoS, Port Scan, Brute Force, Web Attack, Botnet | `agents/response/playbooks.py` | Working as data |
| Notifications | Webhook, Telegram, SMTP hooks, disabled without environment configuration | `notifications/hooks.py`, `.env.example` | Implemented, unverified externally |
| RAG Copilot | Offline lexical retrieval, citations, weak-retrieval refusal, admin in-memory document ingestion/chunking | `rag/knowledge_base.py`, `backend/routers/copilot.py` | Working offline; memory-only ingestion and restart clearing are accepted release limitations |
| F1 incidents | Correlation, ATT&CK mapping, severity, persistence, status, merge/split, timeline | `agents/reporting/incident_correlation.py`, `backend/routers/incidents.py` | Working locally |
| F2 reports | JSON, Markdown, text, and dependency-free PDF output | `agents/reporting/__init__.py`, `backend/routers/incidents.py` | Working locally |
| F3 Attack Lab | Packet-free scenarios, detection rate, false positives, latency, policy comparison | `agents/analytics/features.py`, `backend/routers/operations.py` | Working as simulator |
| F4 threat intel | Local ThreatFeed lookup, import/export, reputation context | `database/models.py`, `backend/routers/operations.py` | Local feeds working |
| F5 model health | Model registry status and PSI drift calculation | `backend/routers/operations.py`, `agents/analytics/features.py` | Working with supplied baselines |
| F6 feedback | TP/FP/unsure labels, summary, uncertain queue | `database/models.py`, `backend/routers/operations.py` | Working; retraining handoff pending |
| F7 alert search | Validated natural-language filters, saved searches, watchlists | `backend/routers/operations.py`, `database/models.py` | Working for supported phrases |
| F8 network map | Graph generation and asset auto-persistence from submitted flow events | `agents/analytics/features.py`, `backend/routers/operations.py` | Working for API events |
| F9 explainability | Per-feature contributions, counterfactual guidance, calibration availability | `agents/explainability/explain.py` | Offline fallback working |
| F10 posture | 0-100 posture score and daily digest response | `agents/analytics/features.py`, `backend/routers/operations.py` | Working on current database state |
| Web consoles | Jinja homepage/sign-in/live dashboard plus a separate React/Vite console with API loading/error/empty states | `backend/templates/`, `frontend/src/` | React build verified; page depth varies |

## API Groups

- Response: `/api/v1/response/*`
- Copilot: `/api/v1/copilot/*`
- Incidents and reports: `/api/v1/incidents/*`
- Feedback, intel, model health, assets, search, Attack Lab, graph, posture:
  `/api/v1/feedback/*`, `/api/v1/threat-intel/*`,
  `/api/v1/model-health*`, `/api/v1/assets*`, `/api/v1/alerts/search`,
  `/api/v1/attack-lab/simulate`, `/api/v1/network/graph`,
  `/api/v1/posture*`
- OpenAPI: `/api/docs`

## Role Capability Matrix

Both roles authenticate through `POST /api/v1/auth/token` and can inspect
their identity through `GET /api/v1/auth/me`.

### Administrator

Admins can do everything a viewer can do, plus:

- Start, stop, and configure live capture:
  `/api/v1/capture/interfaces`, `/api/v1/capture/start`, and
  `/api/v1/capture/stop`.
- Ingest alerts and run the detection pipeline through `POST /api/v1/alerts`.
- Replay the safe held-out/demo scenarios through `/api/v1/demo/replay`.
- Create response policies through `POST /api/v1/response/policies`.
- Roll back blocks with `POST /api/v1/response/unblock`.
- Review pending approvals with `GET /api/v1/response/approvals`.
- Approve or reject actions through
  `POST /api/v1/response/approvals/{id}/decision`.
- Read durable response audit records with `GET /api/v1/response/audit`.
- Run dry-run immediate response actions through `/api/v1/response/execute`;
  live execution is disabled.
- Submit analyst feedback, manage asset criticality, and review the unsure
  feedback queue.
- Run Attack Lab simulations.
- Import and export local threat-intelligence feed entries.
- Ingest Copilot documents and execute Copilot-suggested actions.
- Merge, split, and update incident status.
- Use the Admin Tools console and its allowlisted command keys.

### Viewer

Viewers can:

- Sign in and inspect their role.
- View alerts, alert details, detections, timelines, stats, and health.
- Read response policy previews, active blocks, incidents, reports, threat
  intelligence, model health, posture, assets, and network graphs.
- Ask Copilot questions and receive grounded citations.
- Search alerts using supported natural-language filters.
- Save searches and create personal watchlist entries.
- Submit a response request in `approval-required` mode. This creates a
  pending approval but does not execute the action.
- Export the viewer threat report through the viewer-only detections export
  endpoint.

Viewers cannot start/stop capture, ingest alerts, execute response actions,
approve/reject actions, change policies or assets, import threat feeds, run
simulations, ingest Copilot documents, alter incidents, or use Admin Tools.

## Manual Setup

Required for local authentication:

1. Copy `.env.example` to `.env` only if `.env` does not already exist.
2. Set `SECRET_KEY` to a random value of at least 32 characters.
3. Set unique `AEGIS_ADMIN_PASSWORD` and `AEGIS_VIEWER_PASSWORD` values.
4. Run `python database\init_db.py` before the first start.

Optional integrations:

- Npcap and elevated PowerShell for live Windows packet capture.
- `AEGIS_WEBHOOK_URL` for webhook notifications.
- `AEGIS_TELEGRAM_BOT_TOKEN` and `AEGIS_TELEGRAM_CHAT_ID` for Telegram.
- `AEGIS_SMTP_*` for email.
- Public GeoIP or threat-intelligence credentials are not required for the
  local ThreatFeed workflow and are not bundled.

No external API key is required for tests, the offline Copilot, or the safe
Attack Lab demo.

## Startup And Usage

From the repository root:

```powershell
if (-not (Test-Path .env)) { Copy-Item .env.example .env }
notepad .env                      # set credentials and SECRET_KEY
.\.venv\Scripts\python.exe database\init_db.py
.\.venv\Scripts\python.exe -m uvicorn backend.app:app --reload --port 8000
```

Open `http://127.0.0.1:8000/console` for the React console and its sign-in
screen. `/` is the public homepage, `/signin` is the Jinja sign-in page, and
`/dashboard` is the Jinja live-operations dashboard (`/legacy` is an alias).
Use the configured admin credentials for the full control plane or the viewer
credentials for read-only analysis. The API documentation is at
`http://127.0.0.1:8000/api/docs`.

## Where To Add Future Work

- New response adapters or controls: `agents/response/`; expose them through
  `backend/routers/response.py` and add audit persistence.
- New knowledge sources or embedding backends: `rag/`; keep the
  `KnowledgeBase` retrieval contract and cite every result.
- New feature calculations: `agents/analytics/features.py`; expose validated
  endpoints in `backend/routers/operations.py`.
- New persistent state: add a SQLAlchemy model in `database/models.py` and a
  reviewed Alembic revision under `database/migrations/versions/`.
- New screens: add real API loading to `frontend/src/main.tsx` or split pages
  into `frontend/src/pages/`; keep strict TypeScript and responsive states.
- New tests: add focused backend tests under `tests/` and run the complete
  suite before changing claims in this file.

## Known Limitations

- Live firewall execution is disabled by the action API; `auto-live` requests
  receive an explicit conflict response. Npcap capture still requires
  host-specific verification.
- External GeoIP/ASN feeds are not configured by default.
- Automatic retraining, model bundle rollback, and scheduled digest delivery
  are not background services yet.
- SHAP is not guaranteed for every installed model; the deterministic fallback
  is used when compatible SHAP inputs are unavailable.
- Copilot-ingested documents are process-memory-only and clear on restart.
  Persistent storage, source deletion, and ingestion audit history are not
  completion requirements for this release, as explicitly accepted.
- The previous two-fold report is historical and should not be used as the
  current model result. In the strict CSE-integrated evaluation, all six
  attack classes failed the approved test precision/recall gates, and benign
  false-alarm rate was 2.7928% (0.5% maximum). Source-group coverage alone
  does not establish model release qualification or deployment-network
  generalization; the report's row-level confidence intervals are not
  capture-cluster adjusted.
- The React console exposes API-backed response controls, local threat-feed
  lookup/import, packet-free simulation, incident report export, incident
  status/merge/split controls, and asset/model-health views. Manual browser
  smoke testing covered incident merge/split, live model-health metadata, and
  honest empty asset states; an automated browser test and Docker runtime
  verification remain pending.