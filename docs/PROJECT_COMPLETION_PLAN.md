# AegisAI System Inventory and 100% Completion Plan

**Status snapshot:** 2026-11-18
**Purpose:** One actionable inventory of the system, what each subsystem contains, its current maturity, and the work required to finish the agreed local-first AegisAI product.

This plan is based on the checked-in source and the project status documents available at the snapshot date. “Implemented” means relevant code and tests or documentation exist; it does not automatically mean a feature has been validated in a production-like environment. The plan avoids treating optional enterprise-scale ambitions as prerequisites for a complete, reliable single-site product.

## 1. Product completion target

For this plan, **100% complete** means AegisAI can be installed and operated by a small security team as a self-hosted, single-site monitoring and incident-response application, with:

1. One supported, documented user interface and a consistent role-aware workflow.
2. Reproducible, independently evaluated detection models whose stated limits match their real performance.
3. Verified traffic collection on supported hosts, or a clearly supported imported-flow mode when live capture is unavailable.
4. Reliable alert-to-incident-to-report workflows backed by a supported database.
5. Safe, audited response behavior, with explicit human approval for consequential actions.
6. Secure configuration, deployment, backup/restore, upgrades, health monitoring, and operator documentation.
7. Automated tests for the critical flows and a repeatable release checklist.
8. Explicitly accepted limitations are visible to operators and are not represented as supported capabilities; memory-only Copilot ingestion is accepted for this release.

This definition **does not** make automatic host-firewall enforcement, a hosted LLM, external paid intelligence services, distributed sensor meshes, deep-learning models, or multi-cloud orchestration mandatory. Those are optional extensions that require separate product and security decisions.

## 2. System inventory

### 2.1 Operator interface and user experience

**What it contains**

- `backend/templates/` and `backend/static/`: FastAPI-served product home, sign-in, and Jinja operations dashboard.
- `frontend/src/`, `frontend/package.json`, and `frontend/dist/`: separate React/Vite console source and built output.
- UI concepts represented in the React source include Overview, Response Center, Copilot, Incidents, Threat Intel, Model Health, Attack Lab, Reports, Network Map, and Admin Tools.
- Admin and viewer roles, authentication state, API calls, and dashboard visualization/control surfaces.

**Current state**

- Both Jinja and React interface assets are present. The project owner selected React/Vite as the intended canonical console on 2026-11-14, but the route migration is not complete.
- The current FastAPI routes serve Jinja at `/` (homepage), `/signin`, and `/dashboard`; `/legacy` aliases the Jinja dashboard. The separately built React console is served at `/console`.
- React sign-in shares the existing browser token with the legacy dashboard. The overview includes explicit interface selection, role-gated capture controls, status polling, WebSocket events, and safe sample replay.
- The React console now includes paginated alert review and admin feedback, incident correlation/search/status/merge/split workflows, asset and model-health views, response controls, local threat feeds, packet-free simulation, and report export. Response UI actions are dry-run or approval-required; the UI does not offer auto-live firewall enforcement.
- Local browser smokes confirmed admin/viewer navigation, explicit capture-interface selection, dry-run response, viewer approval request/admin decision, safe simulation, local feed import/lookup, persisted incident merge/split, and truthful model-health/asset empty states. Incident API role checks are covered by tests; an automated browser test and Docker runtime verification remain outstanding. Docker is unavailable on the current workstation. The Jinja compatibility route should be removed only after all required capture operations work in React.
- Route/asset tests pass locally, but Docker runtime and browser-level interaction tests remain to be completed.

**Work to complete**

- [x] Choose the canonical production UI: React/Vite; retain Jinja only as a temporary compatibility route.
- [ ] Migrate the homepage, sign-in, and dashboard routes to the React build; currently these routes serve Jinja, and React is available separately at `/console`.
- [x] Complete incident workflow controls for persisted status changes, admin merge/split, and searchable/filterable incident review.
- [ ] Complete remaining in-scope screen behavior and verify operational filtering/pagination and consistent loading/error/empty states.
- [ ] Verify admin and viewer access in the browser, including direct navigation and API denial behavior.
- [ ] Ensure displayed telemetry is live/accurate; do not show static “nominal/live” status when the sensor is stopped or disconnected.
- [ ] Add accessible labels, keyboard navigation, responsive behavior, and clear confirmation/error states for consequential actions.
- [ ] Add a browser-level smoke test for sign-in, primary navigation, and one representative action from each role.
- [ ] Update README, running instructions, screenshots, and all route references to match the canonical UI.

### 2.2 AI, detection, and analytics

**What it contains**

- `ml/data/`: CSV loading, feature schemas, multi-dataset label mapping, and prepared data/splits.
- `ml/training/` and `ml/evaluation/`: model training and evaluation commands.
- `ml/models/`: trained model artifacts, manifests, active bundle selection, metadata, and metrics.
- `agents/feature_extraction/`: dataset-row and live-flow feature extraction.
- `agents/detection/`: model inference, live behavioral indicators, port-scan logic, and severity/threat policy.
- `agents/anomaly/`: IsolationForest anomaly scoring.
- `agents/explainability/`: feature-importance-based explanation and fallback behavior.
- `agents/analytics/`: Attack Lab simulation, drift, network graph, posture, and related analytics.
- `agents/coordinator/`: orchestration of inference, explanation, response decision, and persistence.

**Current state**

- A bundle-aware classification/anomaly pipeline and 12-feature live-flow contract exist.
- GPU-aware training is documented, with CPU fallback.
- The multi-dataset prototype includes seven canonical classes and source provenance. The source loader, streaming sampler, and coverage audit now include the supplied CSE-CIC-IDS2018 scenario Parquet captures.
- The reported 94.9178% active prototype accuracy is explicitly capture-overlapping and exploratory; it is not an independent-capture generalization result.
- The updated audit counts at least three source groups for each of the seven classes, meeting the coverage prerequisite for strict grouped train/validation/test evaluation.
- The CSE-integrated strict grouped evaluation held out 123,018 rows with zero source-group overlap, but all six attack classes failed the approved test precision/recall gates and benign false-alarm rate was 2.7928% against the 0.5% limit. The older best-effort report is historical and does not replace the strict results.
- The flow features are a prototype subset, not a complete CICFlowMeter implementation. Raw model scores are not established as calibrated probabilities.
- A historical high-accuracy report exists for a different bundle and is explicitly not trustworthy evidence for the active model.
- Product-owner-approved evaluation thresholds: at least 90% recall and 80% precision for each attack class, and no more than 0.5% false-positive rate on held-out benign traffic. Require group-disjoint evaluation and report per-class results with confidence intervals. These are approved gates, not evidence that the current model passes them.

**Work to complete**

- [x] Run a reproducible best-effort source-group evaluation on the available datasets and disclose unsupported metrics and threshold failures.
- [ ] Meet the three-way, seven-class release gate: all approved test thresholds must pass, and the evaluated model must be the same versioned bundle used by the product.
- [x] Create reproducible group-disjoint train/validation/test evaluation splits and fail closed when source-group separation or class coverage is violated.
- [x] Evaluate a reproducible seven-class model on the grouped splits and publish per-class metrics, confusion matrices, false-alarm rates, Wilson intervals, and data provenance.
- [x] Obtain product-owner approval of the per-class recall, precision, and false-positive thresholds above.
- [ ] Validate that offline evaluation features and live extraction have identical semantics, order, units, missing-value handling, and label mappings.
- [ ] Evaluate on independent captures and, when possible, benign traffic from the intended deployment environment.
- [ ] Decide whether scores are probabilities, raw decision scores, or calibrated values; calibrate and label them accordingly.
- [ ] Version model bundles with dataset/split provenance, code version, feature schema, training parameters, metrics, and rollback procedure.
- [ ] Test startup, inference, and API behavior for missing, corrupt, incompatible, and newly activated bundles.
- [ ] Document model limitations and ensure all UI/report claims use the verified active bundle’s results.

### 2.3 Network capture and flow processing

**What it contains**

- `network_capture/`: Scapy capture lifecycle and flow callback integration.
- `agents/feature_extraction/live_extractor.py`: IPv4 bidirectional flow aggregation and model features.
- `backend/routers/capture.py`: status, interface listing, start, and stop endpoints.
- `agents/detection/live_rules.py` and `port_scan.py`: bounded behavior indicators that are distinct from model predictions.
- WebSocket/dashboard telemetry and scripts/tests for capture demonstrations.

**Current state**

- Capture control routes, flow aggregation, inference, event persistence, and UI controls are implemented.
- Existing status notes say actual sniffing was not verified in the prior non-elevated environment; successful interface enumeration is not proof of packet capture.
- A bounded live-capture test has not been run. The only active local adapter is Wi-Fi; because this environment may be shared and no isolated lab target was identified, capture on it is not considered safe verification.
- Windows capture depends on Npcap and permissions. Linux/container deployment has different capture permissions and is not supplied a privileged host agent.
- Existing Compose deployment intentionally runs without privileges/capabilities and therefore does not capture host traffic.
- Flow features and packet rules have explicit coverage limitations; rules are indicators, not proof of malicious activity.

**Work to complete**

- [ ] Define and publish supported capture platforms, interface types, privileges, and packet/flow limits.
- [ ] Run a bounded, authorized smoke test on each supported platform/interface and verify packets received, flows emitted, feature vectors, persistence, and WebSocket delivery.
- [ ] Add a capture health state that distinguishes stopped, starting, running-with-traffic, running-without-traffic, and failed.
- [ ] Test clean shutdown, repeated start/stop, interface loss, malformed packets, high traffic, idle-flow expiry, and memory/CPU bounds.
- [ ] Document the limits of IPv4, fragments, IPv6, encrypted traffic, DNS visibility, and the current feature schema.
- [ ] Decide whether a separate authenticated host agent is required for Docker and remote sensors; if required, specify, implement, secure, and test its protocol before claiming those deployments support capture.
- [ ] Preserve the safe behavior that packet-level rules do not silently become model predictions or execute response actions.

### 2.4 Backend and API

**What it contains**

- `backend/app.py`: FastAPI application, startup/shutdown, UI routes, middleware, and router registration.
- `backend/auth.py` and `backend/middleware.py`: JWT role checks, security headers, request logging/tracing.
- `backend/routers/`: auth, alerts, detections, actions, capture, response, Copilot, incidents, operations, admin tools, statistics, demo replay, and WebSocket feed.
- Legacy endpoints retained for compatibility.
- OpenAPI documentation under `/api/docs` and `/api/redoc`; optional Prometheus instrumentation.

**Current state**

- The API surface is modular and includes versioned endpoints for the principal local workflows.
- Tests cover API routes and several integrated workflows.
- FastAPI generates OpenAPI from the route definitions, but contract/authorization checks do not yet cover every route. Current setup/status documents distinguish the Jinja routes from the React console at `/console`; older route claims should be treated as superseded.
- Authentication uses role checks, but production security properties such as token revocation, key rotation, brute-force protection, and deployment exposure need a deliberate release-level review.

**Work to complete**

- [ ] Maintain one authoritative API contract and generate/verify OpenAPI output in CI.
- [ ] Review every route for authentication, role authorization, input validation, response shape, pagination limits, and error semantics.
- [ ] Add API contract/integration tests for all critical workflows and verify unauthorized/forbidden responses.
- [ ] Define compatibility and deprecation policy for legacy endpoints.
- [ ] Add request size/rate limits where needed, stable request IDs, and consistent structured error responses.
- [ ] Review CORS, trusted hosts, proxy headers, TLS termination expectations, and production bind defaults.
- [ ] Replace optional/best-effort behavior that hides operational failures with explicit health/degraded status and actionable logs.
- [ ] Confirm startup and shutdown behavior for DB failures, model failures, and capture cleanup.

### 2.5 Database and persistence

**What it contains**

- `database/models.py`: SQLAlchemy models.
- `database/init_db.py`: engine/session setup, schema initialization, and compatibility migrations.
- Local SQLite database and documented PostgreSQL Compose service.
- Persisted entities include users, alerts, detections, actions, reports, threat-feed entries, model runs, policies, incidents, feedback, assets, response audit/approvals, saved searches, watchlists, and admin-tool audit records.

**Current state**

- SQLite is the local default in existing instructions; the Compose stack configures PostgreSQL.
- Alembic revisions manage fresh and upgraded schemas; unversioned SQLite databases use a compatibility bridge before being stamped at the baseline.
- SQLite backup/restore commands and an integrity-checked copy utility are documented and tested. PostgreSQL backup/restore procedures and a hosted PostgreSQL migration run remain outstanding.
- A local database file exists in the working tree; its presence alone is not evidence that DB upgrades or restore are safe.

**Work to complete**

- [ ] Select and declare supported database backends for development and production; test both or remove unsupported claims.
- [x] Add a versioned Alembic baseline, preserve unversioned SQLite data during baseline stamping, and test fresh creation, baseline checks, rollback/reapply, and a legacy schema upgrade.
- [ ] Test constraints, indexes, transaction boundaries, concurrent requests, and database failure behavior.
- [x] Establish and test a non-overwriting, integrity-checked SQLite backup/restore procedure.
- [ ] Establish and test PostgreSQL backup/restore, retention, privacy, and deletion procedures.
- [ ] Verify PostgreSQL Compose startup, migrations, CRUD workflows, restart persistence, and health checks.
- [ ] Standardize timestamp storage and timezone handling (prefer explicit UTC semantics throughout).
- [ ] Define retention and storage limits for alerts, raw features, audit records, documents, and uploaded data.

### 2.6 Response and safety

**What it contains**

- `agents/response/`: policy engine, response engine, adapters, and playbook data.
- `backend/routers/response.py`: policy preview/configuration, execution or approval queueing, approvals, audit records, and rollback.
- Database models for policy rules, approvals, action records, and response audits.
- Admin-only action surfaces and viewer approval requests.

**Current state**

- Dry-run-first policy evaluation, approvals, audit trails, and rollback-oriented interfaces are implemented. The action API now rejects `auto-live` execution with an explicit conflict response; approval decisions expose the actual dry-run result separately from approval state.
- Notifications/response adapters may be implemented but are not automatically verified against external services.
- Actual operating-system firewall enforcement is not a completion assumption in this plan and must not be represented as active until separately designed, reviewed, and tested.

**Work to complete**

- [ ] Specify allowed actions, targets, time-to-live, idempotency, rate limits, fail-safe behavior, and rollback semantics.
- [ ] Prove that viewer requests only queue approval and cannot execute actions; prove every execution path requires appropriate admin authorization.
- [ ] Add tests for allowlists, protected networks, duplicate requests, expiry, rollback, partial adapter failure, and audit completeness.
- [ ] Make the UI clearly display dry-run versus queued versus approved versus executed versus failed states.
- [ ] Decide whether real host enforcement is in scope. If it is, require a separate threat model, least-privilege helper/agent design, explicit opt-in, safe defaults, recovery plan, and platform-specific validation before implementation.
- [ ] Exercise notification adapters with test endpoints and document retry, timeout, and secret-handling behavior.

### 2.7 Copilot and local knowledge

**What it contains**

- `rag/`: local knowledge base and retrieval logic.
- `backend/routers/copilot.py`: query, document ingestion, and suggested-action operations.
- Seed local security/AegisAI documents, citations, weak-retrieval handling, and admin ingestion.

**Current state**

- Offline lexical retrieval with citations and weak-retrieval refusal is the documented implementation.
- Admin document ingestion is validated and chunked in process memory; ingested documents are not persisted across restarts and do not yet have source-deletion or ingestion-audit workflows.
- The product owner explicitly accepted memory-only ingestion and restart clearing as a limitation for this release; persistent document storage and lifecycle workflows are not completion requirements.
- It is not an embedding index or external LLM integration, and it should not be advertised as either.

**Work to complete**

- [x] Document that admin-ingested documents are process-memory-only, clear on restart, and have no persistent deletion/audit workflow; this is an accepted release limitation.
- [ ] Test retrieval relevance, citation accuracy, weak/no-match refusal, malformed documents, and prompt-injection-like content in retrieved documents.
- [ ] Ensure generated recommendations are advisory and cannot bypass response authorization or approval workflows.
- [ ] Label the interface accurately as offline lexical retrieval unless a separately reviewed model/index is actually shipped.

### 2.8 Incidents, reports, intelligence, and analyst operations

**What it contains**

- `agents/reporting/`: event correlation and report generation.
- `backend/routers/incidents.py`: incidents, correlation, status, merge/split, reports.
- `backend/routers/operations.py`: analyst feedback, local threat intelligence, assets, alert search, posture, Attack Lab, drift, network graph, saved searches, watchlists, and digest.
- F1-F10 features documented in `docs/FEATURE_STATUS.md`.

**Current state**

- Local workflows and persistence are implemented, including persisted admin-only incident merge/split with lineage, reports, and safe simulation.
- External GeoIP/ASN/reputation feeds are optional and not configured by default.
- Automated feedback-to-retraining and scheduled digests are not established as background services.
- Some dashboard views do not yet expose the full API capability.

**Work to complete**

- [ ] Verify the full analyst lifecycle: alert -> feedback/correlation -> incident -> status/merge/split -> report/export.
- [x] Add backend coverage for persisted incident merge/split, lineage, validation, and viewer authorization.
- [ ] Verify every supported export format against real records and malformed/empty datasets.
- [ ] Define incident correlation keys, duplicate handling, time windows, and explainable reasons for grouping.
- [ ] Complete threat-feed import validation, source attribution, staleness/expiry, and safe export behavior.
- [ ] Complete alert-search grammar documentation and tests for invalid/ambiguous phrases.
- [ ] Define whether feedback is only for analysis or is used for model retraining; do not imply automatic learning unless implemented and governed.
- [ ] If scheduled digests or integrations are in scope, implement bounded scheduling, retries, delivery logs, and disable/configure controls.

### 2.9 Deployment, configuration, and operations

**What it contains**

- `Dockerfile`, `compose.yaml`, `.env.example`, `.dockerignore`, and `requirements.txt`.
- FastAPI self-hosted container and PostgreSQL service.
- Health endpoint and optional metrics instrumentation.
- Windows local-development and capture instructions in the documentation.

**Current state**

- Compose configuration is designed to run the backend unprivileged with a read-only filesystem and a private PostgreSQL service.
- Compose is explicitly not a host-capture deployment.
- The documented Compose stack has not been runtime-verified in the current repository notes.
- Docker Engine is unavailable on the current workstation, so Compose/PostgreSQL runtime validation is deferred.
- README and running instructions now document the current Jinja routes and separate React console, and require placeholder credentials to be replaced. Docker/PostgreSQL runtime and production reverse-proxy/secrets guidance still need qualification.

**Work to complete**

- [ ] Reconcile all setup instructions with current source, remove all default/demo passwords from operational guidance, and require unique secrets.
- [ ] Build and start Compose on a supported Docker host; verify health, login, API, database persistence, restart, and shutdown.
- [ ] Verify secrets are never baked into the image, logged, committed, or exposed to the browser.
- [ ] Document supported OS/Python/Docker/browser/database versions and resource requirements.
- [ ] Add a production configuration example for TLS/reverse proxy, network binding, CORS, trusted proxies, and secure secret management.
- [ ] Add database backup/restore and application upgrade instructions.
- [ ] Define logs, metrics, health/degraded states, disk monitoring, and operator troubleshooting.
- [ ] Add dependency and container vulnerability scanning to the release process and establish a patch cadence.

### 2.10 Testing, quality, and release process

**What it contains**

- `tests/`: backend unit, API, integration, ML, capture, database, response, Copilot, and analytics tests.
- `frontend/`: TypeScript, Vite build, and a type-check script.
- `scripts/`: data auditing, preparation, demo, validation, and system verification.
- `pytest.ini` and test fixtures.

**Current state**

- The latest full backend suite recorded 167 passed and one PostgreSQL test skipped without `AEGIS_TEST_POSTGRES_URL`.
- The React type-check/production build passes; a manual local browser smoke confirmed sign-in and incident merge/split. An automated browser test is still absent.
- CI validates PostgreSQL integration, migrations, tests, Compose configuration, frontend checks/build, and npm audit. The workflow has not yet been run on hosted GitHub Actions.
- Tests and configuration validation do not replace privileged live-capture or Docker runtime verification.

**Work to complete**

- [x] Run the current full backend suite and record the exact command, environment, count, skips, and warnings.
- [x] Run frontend type-check/build and a manual browser smoke against the canonical UI.
- [x] Add CI for backend tests, frontend checks/build, migration checks, PostgreSQL integration, Compose validation, and dependency audit.
- [ ] Add formatter/linter CI and an automated browser smoke test.
- [ ] Keep network-capture tests synthetic in ordinary CI; run documented, authorized host smoke tests separately.
- [x] Add release-gate integration tests for core auth roles, alert persistence, incident/report flow, and response approval/audit.
- [ ] Add a release checklist and update status documents only from fresh, reproducible evidence.
- [x] Reconcile current status summaries across README and project docs; dated milestone notes are explicitly historical.

## 3. Cross-cutting completion checklist

These are release blockers regardless of which feature is being finished:

- [x] Select the canonical UI (React/Vite) and document the local-first deployment path; production database support still needs hosted PostgreSQL verification.
- [x] Create one current status source and update current interface, test, and limitation claims to agree with it.
- [x] Remove stale default credentials from operational instructions and clarify that placeholder secrets must be replaced.
- [ ] Define supported platforms and the exact boundary between tested and unverified behavior.
- [ ] Establish the independent model evaluation dataset and explicit per-class acceptance criteria.
- [ ] Verify live capture on supported target hosts or mark/import-only operation as the supported mode.
- [ ] Verify database migration, backup, restore, and upgrade paths.
- [ ] Test all admin/viewer security boundaries and all response-approval boundaries.
- [ ] Run the full automated suite and the documented manual release tests.
- [ ] Publish known limitations, operator runbook, incident recovery steps, and versioned release notes.

## 4. Recommended order of work

### Phase A — Establish the real baseline

- [ ] Reconcile conflicting documents and inspect the shipped UI/deployment paths.
- [ ] Run backend tests, frontend build/type-check, and existing system verification scripts.
- [ ] Record failures separately from pre-existing warnings and decide the canonical supported paths.
- **Exit:** reproducible baseline and a single agreed definition of “100% complete.”

### Phase B — Close product and interface gaps

- [ ] Choose and consolidate the UI.
- [ ] Finish role-aware end-to-end workflows for alerts, incidents, response, Copilot, reports, model health, and admin tools that remain in scope.
- [ ] Add browser smoke coverage and truthful live-sensor/system states.
- **Exit:** an operator can complete the documented workflows without placeholders or mismatched routes.

### Phase C — Validate data, model, and capture claims

- [ ] Complete independent source-group coverage for all target classes.
- [x] Produce a group-disjoint evaluation, define per-class thresholds, and document the failed gates.
- [ ] Meet the approved model precision, recall, and benign false-alarm thresholds on independent captures.
- [ ] Verify feature parity and model bundle integrity.
- [ ] Run authorized live-capture smoke tests on each supported platform and record limitations.
- **Exit:** public metrics are reproducible and capture is either demonstrated or explicitly excluded from the supported deployment mode.

### Phase D — Harden persistence, response, and security

- [ ] Establish supported database and versioned migrations.
- [ ] Test backup/restore, role boundaries, response approval, audit, and rollback.
- [ ] Complete configuration, secret handling, deployment, and security review.
- **Exit:** restart/upgrade/recovery and sensitive-action workflows are repeatable and auditable.

### Phase E — Release qualification

- [ ] Run CI-equivalent tests and deployment checks from a clean checkout.
- [ ] Verify setup and upgrade documentation with a new environment.
- [ ] Complete release notes, known limitations, and operator handoff.
- **Exit:** all mandatory acceptance criteria below pass and are evidenced in the release record.

## 5. Definition of done and release evidence

Do not mark the project 100% complete until all in-scope criteria below are backed by logs, test results, or a reproducible procedure:

| Area | Acceptance evidence |
|---|---|
| UI | One documented interface serves the intended routes; role-specific workflows pass browser smoke tests; no misleading placeholder status remains. |
| Authentication/authorization | Admin and viewer endpoint matrix passes, including negative tests for every privileged action. |
| Detection | Active model, schema, data provenance, group-disjoint evaluation, per-class results, and documented acceptance thresholds are reproducible. |
| Capture/import | Supported ingest mode works end to end; capture health is truthful; each supported platform has a recorded smoke-test result. |
| Copilot | Offline lexical retrieval, citations, and weak-match refusal work; process-memory-only document ingestion and restart clearing are disclosed and accepted for this release. |
| Incidents/reports | Alert-to-incident lifecycle and every advertised report/export format pass integration tests. |
| Response | Dry-run/approval/execute/rollback states are explicit, authorized, and durably audited; no unsafe default execution. |
| Database | Supported backend(s) pass migrations, restart persistence, backup, restore, and upgrade tests. |
| Deployment | Clean install, health check, secrets setup, restart, and documented upgrade pass on a supported host. |
| Quality | Backend and frontend checks pass in CI; release failures and warnings are reviewed rather than silently ignored. |
| Documentation | README, runbook, architecture, feature status, and this plan agree with tested behavior. |

## 6. Optional future extensions (not required for the completion target above)

Consider these only after the single-site release target is complete and there is a clear requirement:

- Real operating-system firewall enforcement or prevention.
- Distributed sensor/host-agent fleet and remote telemetry protocol.
- External threat-intelligence providers, GeoIP/ASN, and notification services.
- Embedding/vector retrieval or external/local LLM-based Copilot.
- Deep-learning or online-learning models.
- Automated retraining, scheduled digests, and model promotion/rollback services.
- Kubernetes/Helm, multi-cloud, multi-tenant, or enterprise-scale orchestration.

Each extension requires a separate scope decision, threat model, acceptance criteria, deployment design, and test plan. Listing an extension here does not imply it is already implemented or needed for a reliable local-first product.

## 7. Repository references

- [README.md](../README.md) — project overview and quickstart.
- [ARCHITECTURE.md](./ARCHITECTURE.md) — module and data-flow overview.
- [FEATURE_STATUS.md](./FEATURE_STATUS.md) — feature/API and role matrix.
- [PROGRESS.md](./PROGRESS.md) — milestone history and current status notes.
- [RUNNING.md](./RUNNING.md) — setup and operator instructions; reconcile its older/conflicting claims before release.
- [dataset_requirements.md](./dataset_requirements.md) — supported labels, data provenance, and source-group gaps.
- [strict_group_evaluation.json](../artifacts/strict_group_evaluation.json) — current seven-class group-disjoint train/validation/test evaluation.
- [best_effort_group_evaluation.json](../artifacts/best_effort_group_evaluation.json) — historical six-class, two-fold evaluation, retained for audit history only.
- [EVALUATION_TRUSTWORTHY.md](./EVALUATION_TRUSTWORTHY.md) — historical metrics explicitly not to be presented as active-model validation.
- [FUTURE_ROADMAP.md](./FUTURE_ROADMAP.md) — optional longer-term engineering directions.
