# AegisAI — Future Work & Engineering Roadmap

This document outlines the next engineering phases to evolve AegisAI from a hardened vertical baseline into a production-grade Autonomous Network Intrusion Detection & Prevention System (NIDS/IPS).

---

## 🗺️ High-Level Milestone Map

```
┌─────────────────────────────────────────────────────────────┐
│  Phase 1 & 2 (COMPLETED)                                    │
│  - Hardened FastAPI v1 API + JWT Authentication             │
│  - Real-Time WebSocket Telemetry Feed (/ws/feed)            │
│  - Dark Glassmorphism React + TypeScript Dashboard          │
│  - Stratified CICIDS-2017 ML Baseline (RF & XGBoost)        │
└──────────────────────────────┬──────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────┐
│  Phase 3: Real-Time Live Packet Capture Engine              │
│  - Npcap / Scapy asynchronous network interface capture     │
│  - Stateful TCP/UDP flow aggregator (CICFlowMeter-style)    │
│  - Real-time rolling feature vectorization                  │
└──────────────────────────────┬──────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────┐
│  Phase 4: Active OS Firewall Prevention & IPS Enforcement   │
│  - Live Windows Firewall (`netsh`) & Linux (`iptables`)     │
│  - Dynamic blocklist synchronization & subnet whitelisting  │
│  - Automated ban reaper & incident rollback workflows       │
└──────────────────────────────┬──────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────┐
│  Phase 5: Multi-Dataset Fusion & Advanced Deep Learning      │
│  - Multi-dataset ingestion: UNSW-NB15, Bot-IoT, CTU-13      │
│  - Temporal sequence modeling (BiLSTM / 1D-CNN + Attention) │
│  - Online learning & drift detection (River / Evidently)    │
└──────────────────────────────┬──────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────┐
│  Phase 6: GenAI Agentic Triage & Threat Intelligence        │
│  - SHAP / LIME explainability waterfall visualizations      │
│  - Gemini / Local LLM agent for automated SOC incident RCA  │
│  - Threat Intelligence APIs: AbuseIPDB, VirusTotal, AlienVault│
└──────────────────────────────┬──────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────┐
│  Phase 7: Distributed Sensor Mesh & Multi-Cloud Deployment  │
│  - Distributed edge sniffer probes communicating via gRPC   │
│  - Production Docker Compose & Helm chart deployments       │
│  - Webhook notifications: Slack, Discord, PagerDuty, Email  │
└─────────────────────────────────────────────────────────────┘
```

---

## 📌 Detailed Phase Breakdown

### Phase 3: Real-Time Live Packet Sniffing (`network_capture/`)
* **Objective**: Replace simulated / replay-based packet inputs with live frame sniffing on physical/virtual network adapters.
* **Key Tasks**:
  1. **Scapy AsyncSniffer Integration**:
     - Hook into physical network adapters via `scapy.sendrecv.AsyncSniffer`.
     - Support Windows Npcap and Linux raw sockets.
  2. **Stateful Flow Aggregation**:
     - Implement sliding-window flow tracking (IP 5-tuple: `src_ip`, `dst_ip`, `src_port`, `dst_port`, `proto`).
     - Compute real-time flow metrics matching CICIDS features (`flow_duration`, `packet_rate`, `byte_rate`, `fwd/bwd packet count`, `inter-arrival times`, `TCP flags`).
  3. **Capture Lifecycle Controls**:
     - REST and WebSocket controls to start, pause, stop, and select network interfaces dynamically from the UI.

---

### Phase 4: Active OS Firewall Prevention & IPS (`agents/response/`)
* **Objective**: Transition response engine from dry-run mode to live firewall rule enforcement.
* **Key Tasks**:
  1. **OS Firewall Drivers**:
     - **Windows**: Invoke `netsh advfirewall firewall add rule name="AegisAI-Block-<IP>" dir=in action=block remoteip=<IP>`.
     - **Linux**: Invoke `iptables -A INPUT -s <IP> -j DROP` or `nftables`.
  2. **Critical Infrastructure Whitelist**:
     - Hardened whitelist protecting localhost (`127.0.0.1`, `::1`), default gateways, DNS servers, and internal trusted subnets.
  3. **Active Defense Toggle in UI**:
     - Switch in Settings page for "Safe Simulation Mode" vs. "Active Prevention Mode".
     - Real-time display of currently active OS firewall rules with one-click revocation.

---

### Phase 5: Multi-Dataset Fusion & Next-Gen ML
* **Objective**: Expand threat detection capability beyond CICIDS-2017 to handle zero-day and modern IoT attack vectors.
* **Key Tasks**:
  1. **Cross-Dataset Standardization**:
     - Ingest UNSW-NB15, CTU-13, and Bot-IoT datasets.
     - Build unified schema mapper for 80+ network flow features.
  2. **Temporal & Deep Architecture**:
     - Train 1D-CNN + BiLSTM models to capture sequential packet payload patterns.
     - Implement LightGBM & CatBoost comparison models with hyperparameter tuning.
  3. **Drift & Anomaly Detection**:
     - Continuous concept drift detection for evolving network traffic distributions.

---

### Phase 6: GenAI Agentic Triage & Threat Intelligence Enrichment
* **Objective**: Provide automated human-readable incident root-cause analysis (RCA) and external intelligence lookup.
* **Key Tasks**:
  1. **Threat Intelligence Caching (`database/models.py:ThreatFeed`)**:
     - Integration with AbuseIPDB, VirusTotal, and AlienVault OTX APIs.
     - Cache IP reputation scores, geographical origin, and known malicious ASN metadata.
  2. **Local / Gemini LLM Incident Summaries**:
     - Autonomous agent summarizing attack chains, impacted ports, and recommending remediation policies.
  3. **SHAP Waterfall Explainability**:
     - Exact per-packet feature attribution visualizations for security analysts.

---

### Phase 7: Distributed Sensor Probes & Enterprise Notifications
* **Objective**: Scale from single-node monitoring to multi-server distributed enterprise network environments.
* **Key Tasks**:
  1. **Lightweight Edge Sensor Agents**:
     - Distributed Go / Rust / Python probes capturing traffic on edge nodes and streaming telemetry over gRPC to the central AegisAI coordinator.
  2. **Multi-Channel Alerting (`notifications/`)**:
     - Immediate dispatch of high-severity alerts to Slack, Discord, Microsoft Teams, Email, and SIEM webhooks.
  3. **Production Orchestration**:
     - Multi-container `docker-compose.yml` (FastAPI backend + Vite frontend + Redis queue + PostgreSQL).
