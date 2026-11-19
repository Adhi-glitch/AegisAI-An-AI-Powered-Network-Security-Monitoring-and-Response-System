# AegisAI Prototype Web Requirements

## Purpose and scope

This document defines the presentation-prototype web experience for AegisAI. The primary operator workflow is to authenticate as an administrator, select a capture interface, start or stop live flow detection, and inspect alerts and classifications as they arrive. The interface must make the prototype's data and capture limitations visible; it must not imply production-grade detection or prevention.

## Current implementation

- FastAPI currently serves the Jinja homepage at `/`, the Jinja sign-in page at `/signin`, and the Jinja live dashboard at `/dashboard` (`/legacy` is an alias). The separate React/Vite console is served at `/console`.
- The React console includes API-backed overview and capture status, alert review, incident correlation and merge/split workflows, response controls, local threat intelligence, Copilot, reports, and administrative tools.
- `frontend/dist/` is generated from the editable source in `frontend/src/` by Vite and is served by FastAPI.
- The Jinja dashboard uses `backend/templates/dashboard.html` and `backend/static/`. The React/Vite application is a separate console with its own sign-in screen; do not treat it as the page served at `/dashboard`.
- The backend's compatibility dashboard and versioned API are both served by `backend.app` on port 8000.

## Operator navigation

1. **Overview:** show API/model health, total alerts/detections/actions, predictions by class, and response action distribution.
2. **Live sensor:** provide administrator sign-in, available interface selection, a default IP packet filter editable for demonstrations, capture start/stop, current capture state, packet/flow counts, and actionable provider errors.
3. **Detections:** list time, source/destination, predicted class, confidence, action, and model bundle version; allow the operator to inspect the associated flow features.
4. **Alerts:** provide searchable and paginated raw event/flow records, with the original features and capture source available for inspection.
5. **Actions:** show dry-run decisions and make it clear that no host firewall change is made by the prototype.
6. **Model and data status:** expose active bundle name, class list, feature count, evaluation split strategy, and whether evaluation has capture overlap.

## Interaction requirements

- Capture controls are disabled until administrator authentication succeeds.
- Interface options come from `GET /api/v1/capture/interfaces`; an empty interface list or missing capture provider must be shown as an error, not as a running sensor.
- Start/stop transitions are visible (`stopped`, `starting`, `running`, `stopping`, `error`). Disable duplicate actions during transitions.
- A capture-start failure must preserve the error detail and leave the state recoverable; the operator can change interface/filter and retry.
- Capture status refreshes periodically. New WebSocket detections update the feed without requiring a page reload; reconnect automatically after a dropped connection.
- Empty, loading, API-unavailable, model-unavailable, unauthorized, and no-results states must be distinct and understandable.
- Forms must have visible labels, keyboard access, and a visible focus indicator. Tables must remain usable on narrow screens through horizontal scrolling or responsive row presentation.

## Frontend implementation requirements

- Keep monitoring views compact and scannable; emphasize the latest detection and sensor state rather than decorative content.
- Use consistent class names/colors but always display the class text, not color alone.
- Format confidence and timestamps consistently. Do not present confidence as calibrated probability unless calibration is added and evaluated.
- Escape or text-render untrusted IPs, labels, interface names, and feature values; do not interpolate them into HTML strings.
- Store only the short-lived prototype bearer token in browser storage; clear it on 401/403 and provide an explicit sign-out action. A production frontend should prefer an HttpOnly secure cookie or another reviewed session design.
- Keep the home and operations dashboard factual about prototype limits. Do not present the illustrative home-page flow graphic as live telemetry or confidence as calibrated probability.

## Backend requirements and API contract

Existing API routes remain the source of truth for alerts, detections, actions, stats, health, and the WebSocket feed. Live capture adds:

| Method | Route | Purpose | Access |
|--------|-------|---------|--------|
| `GET` | `/api/v1/capture/interfaces` | List interfaces discoverable by Scapy | Admin |
| `GET` | `/api/v1/capture/status` | Return state, packet/flow counts, selected interface/filter, and last error | Admin |
| `POST` | `/api/v1/capture/start` | Start one capture session | Admin |
| `POST` | `/api/v1/capture/stop` | Stop capture and flush pending flows | Admin |
| `WS` | `/ws/feed` | Push persisted detections to connected dashboard clients | Existing feed |

Capture request example:

```json
{
  "interface": "<selected interface>",
  "bpf_filter": "ip",
  "idle_timeout": 2.0
}
```

Each emitted flow is sent through the active `ModelBundle`, persisted as an alert with its features, associated with a detection and dry-run action, and broadcast to the WebSocket feed. The API process must be restarted after training activates a new bundle because its runtime caches model artifacts.

## Live feature contract

The current prototype model and live flow aggregator share this exact ordered feature list:

`duration`, `src_packets`, `dst_packets`, `src_bytes`, `dst_bytes`, `total_packets`, `total_bytes`, `packet_rate`, `byte_rate`, `src_port`, `dst_port`, `protocol`.

The live extractor aggregates IPv4 flows bidirectionally using the first observed packet direction as forward. Duration is emitted in microseconds to match the CICIDS flow convention; byte counts use captured IP packet lengths; rates use packets/bytes divided by elapsed seconds. Protocol is the IANA numeric protocol value. IP identities and high-cardinality service/state codes are excluded from the prototype model features.

## Capture prerequisites and safety

- On Windows, install Npcap and ensure Scapy can load its libpcap provider. A list of interfaces by itself does not prove packet capture is working.
- Run with appropriate local permissions (Administrator may be required) and select a specific friendly interface. The capture module normalizes NPF device paths to Scapy-resolvable names. Do not start capture automatically on application startup.
- Capture controls require the admin role. Keep BPF input editable but bounded by backend validation before exposing it beyond a local prototype.
- Response actions remain dry-run. The dashboard must not offer a firewall-enforcement toggle in this milestone.
- Stop capture on API shutdown/reload and flush pending flows exactly once.

## Prototype quality gates

- Training, evaluator, and API report the same active bundle path, feature list, and label list.
- Automated tests cover the feature vector order, bidirectional accounting, idle/stop flush, capture lifecycle/errors, persistence, and WebSocket event shape.
- A real-model capture integration test checks that the stored class equals the active model's inference result for the same flow.
- The active bundle's row-random report is capture-overlapping and exploratory. A separate source-group-disjoint evaluation now runs, but it fails the approved attack-class precision/recall and benign false-alarm gates; report both facts and do not claim deployment-level generalization.
- Before presenting live packets, perform a short capture in a controlled network and confirm packet/flow counts and persistence. This host reports `conf.use_pcap=True`, but a non-elevated loopback probe captured zero packets; live capture is not yet verified here.

## Known prototype limitations

- Capture permissions are environment-dependent; this workspace has Npcap enabled but the current non-elevated process captured zero packets, so real sniffing remains unverified.
- Flow extraction is IPv4-only and intentionally limited to 12 numeric features; it is not full CICFlowMeter equivalence.
- The active bundle's row-random score has source-capture overlap. The separate group-disjoint evaluation has zero group overlap in its held-out test partition but still fails the agreed performance gates; additional independent capture data and model work are required.
- The current database schema stores confidence as text and has no explicit capture-session or source-group table. Flow features carry their capture context in the raw JSON for this prototype; a later production design should normalize session/provenance fields.