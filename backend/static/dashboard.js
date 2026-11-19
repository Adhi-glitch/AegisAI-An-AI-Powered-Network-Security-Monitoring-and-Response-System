(() => {
  "use strict";

  const TOKEN_KEY = "aegisai-capture-token";
  const API_ROOT = "/api/v1";
  const CLASSES = ["Benign", "Botnet", "Brute Force", "DDoS", "DoS", "Port Scan", "Web Attack"];
  const FEATURES = [
    "duration", "src_packets", "dst_packets", "src_bytes", "dst_bytes",
    "total_packets", "total_bytes", "packet_rate", "byte_rate",
    "src_port", "dst_port", "protocol",
  ];
  const CLASS_COLORS = {
    Benign: "#64d89b",
    Botnet: "#a98bff",
    "Brute Force": "#ff985c",
    DDoS: "#e94d68",
    DoS: "#ff6d79",
    "Port Scan": "#f0bf5b",
    "Web Attack": "#e879dd",
  };
  const ACTION_COLORS = { log: "#55dda9", rate_limit: "#f0bf5b", block: "#ff6d79" };
  const state = {
    user: null,
    socket: null,
    socketTimer: 0,
    socketDelay: 1000,
    capture: "unknown",
    interfaceNames: [],
    interfaceLoaded: false,
    captureSetupError: "",
    pages: { detections: 1, alerts: 1, actions: 1 },
    data: { stats: null, timeline: [], model: null, detections: [], alerts: [], actions: [] },
    detailCache: new Map(),
    detectionDetails: new Map(),
    paused: false,
    pausedEvents: [],
    flashIds: new Set(),
    lastDetectionId: null,
    lastCaptureSample: null,
    rateSamples: [],
    timelineMode: "count",
    timelineWindow: 24,
    detectionSort: { key: "id", direction: "desc" },
    classFilter: "",
    comfortable: false,
    kpiValues: {},
    activeDrawer: null,
    previousFocus: null,
    refreshTimer: 0,
    captureTimer: 0,
    refreshing: false,
    lastRefreshError: "",
  };

  const $ = (selector, root = document) => root.querySelector(selector);
  const $$ = (selector, root = document) => Array.from(root.querySelectorAll(selector));
  const byId = (id) => document.getElementById(id);
  const make = (tag, className, text) => {
    const element = document.createElement(tag);
    if (className) element.className = className;
    if (text !== undefined) element.textContent = String(text);
    return element;
  };
  const asNumber = (value) => {
    if (value === null || value === undefined || (typeof value === "string" && value.trim() === "")) return null;
    const number = Number(value);
    return Number.isFinite(number) ? number : null;
  };
  const formatNumber = (value) => Number(value || 0).toLocaleString();
  const formatTime = (value, includeDate = false) => {
    if (!value) return "—";
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return String(value);
    return new Intl.DateTimeFormat(undefined, includeDate
      ? { month: "short", day: "2-digit", hour: "2-digit", minute: "2-digit", second: "2-digit" }
      : { hour: "2-digit", minute: "2-digit", second: "2-digit" }).format(date);
  };
  const classSlug = (label) => CLASSES.includes(label)
    ? label.toLowerCase().replaceAll(" ", "-")
    : "unknown";
  const knownClass = (label) => CLASSES.includes(label) ? label : "Unknown";
  const setText = (id, value) => {
    const element = byId(id);
    if (element) element.textContent = value === null || value === undefined || value === "" ? "—" : String(value);
  };

  function toast(message, kind = "info") {
    const region = byId("toast-region");
    const item = make("div", `toast ${kind}`, message);
    item.setAttribute("role", kind === "error" ? "alert" : "status");
    region.append(item);
    window.setTimeout(() => item.remove(), 4200);
  }

  function animateKpi(id, target) {
    const element = byId(id);
    const start = Number(state.kpiValues[id] ?? target);
    const reducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    state.kpiValues[id] = target;
    element.classList.remove("skeleton-text");
    if (reducedMotion || start === target) {
      element.textContent = formatNumber(target);
      return;
    }
    const started = performance.now();
    const duration = 260;
    const tick = (now) => {
      const progress = Math.min(1, (now - started) / duration);
      const eased = 1 - ((1 - progress) ** 3);
      element.textContent = formatNumber(Math.round(start + (target - start) * eased));
      if (progress < 1) window.requestAnimationFrame(tick);
    };
    window.requestAnimationFrame(tick);
  }

  function updateHealthPill(status, message) {
    const pill = byId("api-health-pill");
    pill.className = `health-pill ${status}`;
    $("span", pill).textContent = message;
  }

  function updateSocketPill(connected, message = "") {
    const pill = byId("ws-health-pill");
    pill.classList.toggle("is-connected", connected);
    pill.classList.toggle("is-paused", state.paused);
    $("span", pill).textContent = message || (state.paused ? "Feed paused" : connected ? "Feed live" : "Feed offline");
    pill.title = message || (connected ? "Live event stream connected" : "Live event stream disconnected");
  }

  function updateSessionUI() {
    const loggedIn = Boolean(state.user);
    const isAdmin = state.user?.role === "admin";
    const sessionName = state.user ? `${state.user.username} · ${state.user.role}` : "Signed out";
    setText("session-label", sessionName);
    setText("capture-auth-state", isAdmin
      ? `Signed in as ${state.user.username}; administrator capture controls are enabled.`
      : loggedIn
        ? "Viewer account: capture controls require an administrator."
        : "Sign in as an administrator to control live capture.");
    byId("sign-in-btn").hidden = loggedIn;
    byId("sign-out-btn").hidden = !loggedIn;
    byId("sensor-sign-in").hidden = isAdmin;
    byId("capture-interface").disabled = !isAdmin || !["stopped", "error", "unknown"].includes(state.capture);
    byId("capture-filter").disabled = !isAdmin || !["stopped", "error", "unknown"].includes(state.capture);
    byId("capture-start").disabled = !isAdmin || !state.interfaceLoaded || !byId("capture-interface").value || !["stopped", "error", "unknown"].includes(state.capture);
    byId("capture-stop").disabled = !isAdmin || state.capture !== "running";
    byId("capture-status").classList.toggle("is-running", state.capture === "running");
    if (!loggedIn) {
      updateSocketPill(false);
      setText("detection-page-label", "Sign in to view detections");
      setText("alert-page-label", "Sign in to view alerts");
      setText("action-page-label", "Sign in to view actions");
    }
  }

  function clearSession(reason = "") {
    localStorage.removeItem(TOKEN_KEY);
    state.user = null;
    state.interfaceLoaded = false;
    state.interfaceNames = [];
    state.captureSetupError = "";
    state.data = { stats: null, timeline: [], model: null, detections: [], alerts: [], actions: [] };
    state.detailCache.clear();
    state.detectionDetails.clear();
    state.pausedEvents = [];
    state.flashIds.clear();
    state.kpiValues = {};
    state.classFilter = "";
    ["global-search", "detection-search", "alert-search"].forEach((id) => { byId(id).value = ""; });
    $$(".filter-chip", byId("detection-class-chips")).forEach((chip) => {
      const active = chip.dataset.class === "";
      chip.classList.toggle("is-active", active);
      chip.setAttribute("aria-pressed", String(active));
    });
    byId("capture-error").hidden = true;
    byId("capture-retry").hidden = true;
    if (state.socket) {
      state.socket.onclose = null;
      state.socket.close();
      state.socket = null;
    }
    window.clearTimeout(state.socketTimer);
    state.rateSamples = [];
    state.lastCaptureSample = null;
    Charts.clear();
    byId("attacker-ranking").replaceChildren(make("div", "chart-state", "Sign in to load alert source data."));
    byId("port-ranking").replaceChildren(make("div", "chart-state", "Sign in to load alert feature data."));
    byId("heatmap").replaceChildren(make("div", "chart-state", "Sign in to load alert details."));
    byId("sensor-log").replaceChildren(make("li", "log-empty", "No capture events received in this session."));
    setText("sensor-log-state", "Waiting for sensor");
    updateSessionUI();
    showTableMessage("detection-body", 7, "Sign in to load persisted detections.");
    showTableMessage("alert-body", 6, "Sign in to load persisted alerts.");
    showTableMessage("action-body", 6, "Sign in to load response records.");
    setText("kpi-alerts", "—");
    setText("kpi-detections", "—");
    setText("kpi-blocks", "—");
    ["spark-alerts", "spark-detections", "spark-actions", "spark-rate"].forEach((id) => drawSparkline(id, [], "#748198"));
    setText("trend-detections", "Sign-in required");
    ["kpi-alerts", "kpi-detections", "kpi-blocks"].forEach((id) => byId(id).classList.add("skeleton-text"));
    setText("latest-status", "Sign-in required");
    setText("latest-class", "No detection loaded");
    setText("latest-summary", "Sign in to view recent detection data.");
    setText("latest-confidence", "—");
    setText("latest-source", "—");
    setText("latest-time", "—");
    byId("latest-open").disabled = true;
    setText("model-bundle", "Sign in to load model status");
    setText("model-version", "—");
    setText("model-split", "Not available");
    setText("model-overlap", "Sign in to load model evaluation metadata.");
    if (reason) toast(reason, "error");
  }

  class ApiError extends Error {
    constructor(message, status) {
      super(message);
      this.name = "ApiError";
      this.status = status;
    }
  }

  const Api = {
    async request(path, options = {}) {
      const headers = new Headers(options.headers || {});
      const token = localStorage.getItem(TOKEN_KEY);
      if (token) headers.set("Authorization", `Bearer ${token}`);
      const response = await fetch(path, { ...options, headers });
      let payload = null;
      if (response.status !== 204) {
        const contentType = response.headers.get("content-type") || "";
        payload = contentType.includes("application/json") ? await response.json() : await response.text();
      }
      if ((response.status === 401 || response.status === 403) && token) {
        clearSession(response.status === 401 ? "Session expired. Please sign in again." : "Access denied. Sign in with an account that has permission.");
      }
      if (!response.ok) {
        const detail = payload && typeof payload === "object" ? payload.detail : payload;
        throw new ApiError(detail || `Request failed (${response.status})`, response.status);
      }
      return payload;
    },
    get(path) {
      return this.request(`${API_ROOT}${path}`);
    },
    async signIn(username, password) {
      const body = new URLSearchParams({ username, password });
      const response = await fetch(`${API_ROOT}/auth/token`, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body,
      });
      const payload = await response.json();
      if (!response.ok) throw new ApiError(payload.detail || `Sign in failed (${response.status})`, response.status);
      if (typeof payload.access_token !== "string" || !payload.access_token) {
        throw new Error("The authentication response did not contain an access token.");
      }
      localStorage.setItem(TOKEN_KEY, payload.access_token);
      return this.get("/auth/me");
    },
  };

  const chartRegistry = {};
  function chartState(canvasId, message, visible) {
    const canvas = byId(canvasId);
    const overlay = canvas?.parentElement?.querySelector(".chart-state");
    if (!overlay) return;
    overlay.textContent = message;
    overlay.classList.toggle("is-hidden", !visible);
  }

  function createChart(id, config) {
    const canvas = byId(id);
    if (!canvas || typeof window.Chart !== "function") {
      if (canvas) chartState(id, "Chart library unavailable; tabular records remain available.", true);
      return null;
    }
    const chart = new window.Chart(canvas, config);
    chartRegistry[id] = chart;
    return chart;
  }

  function gradientFor(context, top, bottom) {
    const gradient = context.createLinearGradient(0, 0, 0, context.canvas.height || 200);
    gradient.addColorStop(0, top);
    gradient.addColorStop(1, bottom);
    return gradient;
  }

  const Charts = {
    init() {
      if (typeof window.Chart !== "function") {
        ["timeline-chart", "class-chart", "action-chart", "confidence-chart", "protocol-chart"].forEach((id) => {
          chartState(id, "Chart library unavailable; tabular records remain available.", true);
        });
        return;
      }
      window.Chart.defaults.color = "#a4b0c1";
      window.Chart.defaults.font.family = "Inter, Segoe UI, sans-serif";
      window.Chart.defaults.font.size = 9;
      createChart("timeline-chart", {
        type: "line",
        data: { labels: [], datasets: [{ label: "Detections", data: [], borderColor: "#55dda9", borderWidth: 2, pointRadius: 0, pointHoverRadius: 4, pointHoverBackgroundColor: "#ecf3ee", tension: .36, fill: true, backgroundColor: (context) => {
          const chart = context.chart;
          const area = chart.chartArea;
          if (!area) return "rgba(85,221,169,.12)";
          return gradientFor(chart.ctx, "rgba(85,221,169,.25)", "rgba(85,221,169,0)");
        } }] },
        options: {
          responsive: true, maintainAspectRatio: false, animation: { duration: 260 },
          interaction: { intersect: false, mode: "index" },
          plugins: { legend: { display: false }, tooltip: { displayColors: false, backgroundColor: "#122521", borderColor: "rgba(188,220,207,.2)", borderWidth: 1, titleFont: { family: "JetBrains Mono" } } },
          scales: {
            x: { grid: { display: false }, ticks: { maxTicksLimit: 8, color: "#748198", font: { family: "JetBrains Mono", size: 8 } } },
            y: { beginAtZero: true, grid: { color: "rgba(188,220,207,.08)" }, border: { display: false }, ticks: { precision: 0, color: "#82998f", font: { family: "JetBrains Mono", size: 8 } } },
          },
        },
      });
      createChart("class-chart", {
        type: "doughnut",
        data: { labels: [], datasets: [{ data: [], backgroundColor: [], borderColor: "#0d1b18", borderWidth: 3, hoverOffset: 7 }] },
        options: { responsive: true, maintainAspectRatio: false, cutout: "70%", animation: { duration: 380 }, plugins: { legend: { display: false }, tooltip: { backgroundColor: "#122521", borderColor: "rgba(188,220,207,.2)", borderWidth: 1 } } },
      });
      createChart("action-chart", {
        type: "bar",
        data: { labels: [], datasets: [{ label: "Recorded actions", data: [], backgroundColor: [], borderRadius: 5, maxBarThickness: 22 }] },
        options: { indexAxis: "y", responsive: true, maintainAspectRatio: false, animation: { duration: 300 }, plugins: { legend: { display: false }, tooltip: { backgroundColor: "#122521", borderColor: "rgba(188,220,207,.2)", borderWidth: 1 } }, scales: { x: { beginAtZero: true, grid: { color: "rgba(188,220,207,.08)" }, ticks: { precision: 0, color: "#82998f" }, border: { display: false } }, y: { grid: { display: false }, ticks: { color: "#9bb2a8", font: { family: "JetBrains Mono", size: 9 } }, border: { display: false } } } },
      });
      createChart("confidence-chart", {
        type: "bar",
        data: { labels: [], datasets: [{ label: "Detections", data: [], backgroundColor: "rgba(50,168,120,.72)", borderColor: "#55dda9", borderWidth: 1, borderRadius: 4, maxBarThickness: 28 }] },
        options: { responsive: true, maintainAspectRatio: false, animation: { duration: 300 }, plugins: { legend: { display: false }, tooltip: { backgroundColor: "#122521" } }, scales: { x: { grid: { display: false }, ticks: { color: "#82998f", font: { family: "JetBrains Mono", size: 8 } } }, y: { beginAtZero: true, ticks: { precision: 0, color: "#82998f" }, grid: { color: "rgba(188,220,207,.08)" }, border: { display: false } } } },
      });
      createChart("protocol-chart", {
        type: "doughnut",
        data: { labels: [], datasets: [{ data: [], backgroundColor: ["#55dda9", "#a98bff", "#f0bf5b", "#82998f"], borderColor: "#0d1b18", borderWidth: 3, hoverOffset: 6 }] },
        options: { responsive: true, maintainAspectRatio: false, cutout: "68%", animation: { duration: 350 }, plugins: { legend: { position: "bottom", labels: { color: "#9bb2a8", boxWidth: 8, boxHeight: 8, padding: 12, font: { size: 8 } }, tooltip: { backgroundColor: "#122521" } } } },
      });
      createChart("throughput-chart", {
        type: "line",
        data: { labels: [], datasets: [
          { label: "Packets/s", data: [], borderColor: "#55dda9", borderWidth: 1.5, pointRadius: 0, tension: .35 },
          { label: "Flows/s", data: [], borderColor: "#a98bff", borderWidth: 1.5, pointRadius: 0, tension: .35 },
        ] },
        options: { responsive: true, maintainAspectRatio: false, animation: false, plugins: { legend: { display: false }, tooltip: { enabled: false } }, scales: { x: { display: false }, y: { display: false, beginAtZero: true } } },
      });
    },
    clear() {
      Object.values(chartRegistry).forEach((chart) => {
        chart.data.labels = [];
        chart.data.datasets.forEach((dataset) => { dataset.data = []; });
        chart.update("none");
      });
      [
        ["timeline-chart", "Sign in to load timeline data."],
        ["class-chart", "Sign in to load detection data."],
        ["action-chart", "Sign in to load response records."],
        ["confidence-chart", "Sign in to load detection scores."],
        ["protocol-chart", "Sign in to load protocol data."],
      ].forEach(([id, message]) => chartState(id, message, true));
      setText("timeline-note", "Sign in to load hourly timeline data.");
      setText("class-total", "—");
      byId("class-legend").replaceChildren();
    },
    updateTimeline(items) {
      state.data.timeline = Array.isArray(items) ? items : [];
      const chart = chartRegistry["timeline-chart"];
      if (!state.data.timeline.length) {
        chartState("timeline-chart", "No timeline records returned by the API.", true);
        return;
      }
      if (!chart) return;
      const visibleItems = state.data.timeline.slice(-state.timelineWindow);
      const labels = visibleItems.map((item) => String(item.hour ?? "—"));
      const counts = visibleItems.map((item) => Math.max(0, Number(item.count) || 0));
      const values = state.timelineMode === "rate" ? counts.map((count) => count / 3600) : counts;
      chart.data.labels = labels;
      chart.data.datasets[0].label = state.timelineMode === "rate" ? "Detections per second (hourly average)" : "Detections";
      chart.data.datasets[0].data = values;
      chart.options.scales.y.ticks.precision = state.timelineMode === "rate" ? 3 : 0;
      chart.update("none");
      chartState("timeline-chart", "", false);
      const note = `${state.timelineWindow}h view · ${state.timelineMode === "rate"
        ? "Hourly average derived from detection counts; not packet throughput."
        : "Hourly totals from the API; per-class hourly counts are not exposed."}`;
      setText("timeline-note", note);
      const fullCounts = state.data.timeline.map((item) => Math.max(0, Number(item.count) || 0));
      updateDetectionTrend(fullCounts);
      drawSparkline("spark-detections", fullCounts, "#a98bff");
      drawSparkline("spark-alerts", [], "#55dda9");
      drawSparkline("spark-actions", [], "#f0bf5b");
      drawSparkline("spark-rate", [], "#e879dd");
    },
    updateClassDistribution(byClass) {
      const chart = chartRegistry["class-chart"];
      const values = CLASSES.map((label) => Math.max(0, Number(byClass?.[label]) || 0));
      const total = values.reduce((sum, value) => sum + value, 0);
      setText("class-total", formatNumber(total));
      const legend = byId("class-legend");
      legend.replaceChildren();
      CLASSES.forEach((label, index) => {
        const item = make("span", "legend-item");
        const swatch = make("i", "legend-swatch");
        swatch.style.backgroundColor = CLASS_COLORS[label];
        const title = make("span", "", `${label} · ${formatNumber(values[index])}`);
        item.append(swatch, title);
        legend.append(item);
      });
      if (!total) {
        chartState("class-chart", "No persisted detection counts are available.", true);
        return;
      }
      if (!chart) return;
      chart.data.labels = CLASSES;
      chart.data.datasets[0].data = values;
      chart.data.datasets[0].backgroundColor = CLASSES.map((label) => CLASS_COLORS[label]);
      chart.update("none");
      chartState("class-chart", "", false);
    },
    updateActions(byAction) {
      const chart = chartRegistry["action-chart"];
      const labels = ["log", "rate_limit", "block"];
      const values = labels.map((label) => Math.max(0, Number(byAction?.[label]) || 0));
      if (!values.some((value) => value > 0)) {
        chartState("action-chart", "No recorded response actions.", true);
        return;
      }
      if (!chart) return;
      chart.data.labels = labels.map((value) => value.replace("_", " "));
      chart.data.datasets[0].data = values;
      chart.data.datasets[0].backgroundColor = labels.map((value) => ACTION_COLORS[value]);
      chart.update("none");
      chartState("action-chart", "", false);
    },
    updateConfidence(detections) {
      const chart = chartRegistry["confidence-chart"];
      const values = detections.map((item) => asNumber(item.confidence)).filter((value) => value !== null && value >= 0 && value <= 1);
      if (!values.length) {
        chartState("confidence-chart", "No model confidence scores in this loaded page.", true);
        return;
      }
      if (!chart) return;
      const bins = Array.from({ length: 10 }, () => 0);
      values.forEach((value) => bins[Math.min(9, Math.floor(value * 10))] += 1);
      chart.data.labels = bins.map((_, index) => `${index / 10}–${(index + 1) / 10}`);
      chart.data.datasets[0].data = bins;
      chart.update("none");
      chartState("confidence-chart", "", false);
    },
    updateProtocols(protocolCounts) {
      const chart = chartRegistry["protocol-chart"];
      const labels = ["TCP", "UDP", "ICMP", "Other"];
      const values = labels.map((label) => protocolCounts[label] || 0);
      if (!values.some((value) => value > 0)) {
        chartState("protocol-chart", "Protocol data unavailable for loaded alerts.", true);
        return;
      }
      if (!chart) return;
      chart.data.labels = labels;
      chart.data.datasets[0].data = values;
      chart.update("none");
      chartState("protocol-chart", "", false);
    },
    updateThroughput(packetsRate, flowsRate) {
      if (state.capture !== "running") return;
      const chart = chartRegistry["throughput-chart"];
      if (!chart) return;
      const label = new Date().toLocaleTimeString([], { minute: "2-digit", second: "2-digit" });
      state.rateSamples.push({ label, packets: packetsRate, flows: flowsRate });
      state.rateSamples = state.rateSamples.slice(-24);
      chart.data.labels = state.rateSamples.map((sample) => sample.label);
      chart.data.datasets[0].data = state.rateSamples.map((sample) => sample.packets);
      chart.data.datasets[1].data = state.rateSamples.map((sample) => sample.flows);
      chart.update("none");
    },
  };

  function drawSparkline(id, values, color) {
    const canvas = byId(id);
    if (!canvas) return;
    const context = canvas.getContext("2d");
    const width = canvas.clientWidth || 120;
    const height = canvas.clientHeight || 32;
    const ratio = Math.min(window.devicePixelRatio || 1, 2);
    canvas.width = width * ratio;
    canvas.height = height * ratio;
    context.setTransform(ratio, 0, 0, ratio, 0, 0);
    context.clearRect(0, 0, width, height);
    if (!values || values.length < 2) return;
    const max = Math.max(...values, 1);
    context.beginPath();
    values.forEach((value, index) => {
      const x = index / (values.length - 1) * width;
      const y = height - 3 - Number(value) / max * (height - 8);
      if (index === 0) context.moveTo(x, y);
      else context.lineTo(x, y);
    });
    context.strokeStyle = color;
    context.lineWidth = 1.4;
    context.stroke();
  }

  function updateDetectionTrend(counts) {
    const trend = byId("trend-detections");
    const half = Math.floor(counts.length / 2);
    if (!half) {
      trend.textContent = "24h trend unavailable";
      trend.className = "kpi-trend neutral";
      return;
    }
    const previous = counts.slice(0, half).reduce((sum, value) => sum + value, 0);
    const current = counts.slice(half).reduce((sum, value) => sum + value, 0);
    if (previous === 0 && current === 0) {
      trend.textContent = "No detections in timeline";
      trend.className = "kpi-trend neutral";
      return;
    }
    if (previous === 0) {
      trend.textContent = "↑ activity vs prior half";
      trend.className = "kpi-trend";
      return;
    }
    const change = ((current - previous) / previous) * 100;
    trend.textContent = `${change >= 0 ? "↑" : "↓"} ${Math.abs(change).toFixed(0)}% vs prior 12h`;
    trend.className = `kpi-trend${change < 0 ? " down" : ""}`;
  }

  function showTableMessage(bodyId, columns, message, kind = "") {
    const body = byId(bodyId);
    if (!body) return;
    const row = make("tr");
    const cell = make("td", `table-message ${kind}`, message);
    cell.colSpan = columns;
    row.append(cell);
    body.replaceChildren(row);
  }

  function setPagination(kind, pageData) {
    const page = Number(pageData.page || state.pages[kind]);
    const pages = Math.max(1, Number(pageData.pages || 1));
    state.pages[kind] = page;
    setText(`${kind.slice(0, -1)}-pagination-label`, `Page ${page} of ${pages} · ${formatNumber(pageData.total || 0)} records`);
    byId(`${kind.slice(0, -1)}-prev`).disabled = page <= 1;
    byId(`${kind.slice(0, -1)}-next`).disabled = page >= pages;
  }

  function classPill(label) {
    const known = knownClass(label);
    const pill = make("span", `threat-pill ${classSlug(known)}`);
    const dot = make("i", `class-dot ${classSlug(known)}`);
    pill.append(dot, make("span", "", known));
    return pill;
  }

  function confidenceCell(value) {
    const cell = make("td", "confidence-cell");
    const score = asNumber(value);
    if (score === null || score < 0 || score > 1) {
      cell.textContent = "Not scored";
      cell.title = "Rule-based records do not have a model confidence score.";
      return cell;
    }
    const track = make("span", "confidence-track");
    track.setAttribute("aria-hidden", "true");
    const fill = make("span", "confidence-fill");
    fill.style.width = `${Math.max(0, Math.min(100, score * 100))}%`;
    track.append(fill);
    const text = make("span", "confidence-value", score.toFixed(3));
    cell.append(track, text);
    cell.setAttribute("aria-label", `Model confidence ${score.toFixed(3)}; not a calibrated probability`);
    return cell;
  }

  function actionChip(action) {
    const value = typeof action === "string" ? action : "";
    const known = ["log", "rate_limit", "block"].includes(value) ? value : "unknown";
    const chip = make("span", `action-chip ${known}`);
    chip.textContent = value || "Not recorded";
    chip.title = "Dry-run decision only; no firewall action was performed.";
    return chip;
  }

  function severityChip(severity) {
    const value = ["low", "medium", "high", "critical"].includes(String(severity).toLowerCase())
      ? String(severity).toLowerCase()
      : "unknown";
    const chip = make("span", `severity-chip severity-${value}`, value === "unknown" ? "Unknown severity" : value);
    return chip;
  }

  function applyDetectionFilters(items) {
    const query = `${byId("detection-search").value} ${byId("global-search").value}`.trim().toLowerCase();
    const classFilter = state.classFilter;
    const filtered = items.filter((item) => {
      if (classFilter && item.predicted_class !== classFilter) return false;
      if (!query) return true;
      return [
        item.id, item.alert_id, item.source_ip, item.dest_ip, item.predicted_class,
        item.model_version, item.detection_source, item.protocol, item.action,
      ].some((value) => String(value ?? "").toLowerCase().includes(query));
    });
    const { key, direction } = state.detectionSort;
    filtered.sort((left, right) => {
      let a = left[key];
      let b = right[key];
      if (key === "timestamp") {
        a = a ? new Date(a).getTime() : 0;
        b = b ? new Date(b).getTime() : 0;
      }
      if (key === "id") {
        a = Number(a) || 0;
        b = Number(b) || 0;
      }
      const comparison = String(a ?? "").localeCompare(String(b ?? ""), undefined, { numeric: true, sensitivity: "base" });
      return direction === "asc" ? comparison : -comparison;
    });
    return filtered;
  }

  const Tables = {
    renderDetections() {
      const source = state.data.detections;
      const items = applyDetectionFilters(source);
      const body = byId("detection-body");
      setText("detection-page-label", `${items.length} shown · ${source.length} records on this page`);
      setText("detection-state", source.length ? "LIVE API RECORDS" : "EMPTY");
      if (!source.length) {
        showTableMessage("detection-body", 7, state.user ? "No persisted detections on this page." : "Sign in to load persisted detections.");
        return;
      }
      if (!items.length) {
        showTableMessage("detection-body", 7, "No results match the current search and class filter.");
        return;
      }
      const fragment = document.createDocumentFragment();
      for (const item of items) {
        const row = make("tr");
        if (state.flashIds.has(String(item.id))) row.classList.add(["DoS", "DDoS", "Botnet"].includes(item.predicted_class) ? "critical-row" : "new-row");
        row.dataset.detectionId = String(item.id);
        row.tabIndex = 0;
        row.setAttribute("aria-label", `Open detection ${item.id}, ${item.predicted_class || "unknown class"}`);
        row.addEventListener("click", (event) => {
          if (event.target.closest("button")) return;
          void Drawer.openDetection(item);
        });
        row.addEventListener("keydown", (event) => {
          if (event.key === "Enter" || event.key === " ") {
            event.preventDefault();
            void Drawer.openDetection(item);
          }
        });
        const idCell = make("td");
        const idButton = make("button", "row-button mono", `#${item.id}`);
        idButton.type = "button";
        idButton.addEventListener("click", () => void Drawer.openDetection(item));
        idCell.append(idButton);
        const time = make("td", "mono-cell", formatTime(item.timestamp));
        const endpoints = make("td", "mono-cell");
        endpoints.textContent = `${item.source_ip || "—"} → ${item.dest_ip || "—"}`;
        const threat = make("td");
        threat.append(classPill(item.predicted_class));
        const confidence = confidenceCell(item.confidence);
        const action = make("td");
        action.append(actionChip(item.action));
        const bundle = make("td", "table-secondary");
        bundle.textContent = item.detection_source === "dataset_replay"
          ? "Sample replay · simulated"
          : item.detection_source === "behavioral_rule"
            ? "Behavioral rule"
            : item.model_version || item.detection_source || "—";
        row.append(idCell, time, endpoints, threat, confidence, action, bundle);
        fragment.append(row);
      }
      body.replaceChildren(fragment);
      state.flashIds.clear();
    },
    renderAlerts() {
      const items = state.data.alerts;
      const query = `${byId("alert-search").value} ${byId("global-search").value}`.trim().toLowerCase();
      const filtered = items.filter((item) => !query || [
        item.id, item.timestamp, item.source_ip, item.dest_ip, item.protocol, item.severity,
      ].some((value) => String(value ?? "").toLowerCase().includes(query)));
      setText("alert-page-label", `${filtered.length} shown · ${items.length} records on this page`);
      setText("alert-state", items.length ? "LIVE API RECORDS" : "EMPTY");
      if (!items.length) return showTableMessage("alert-body", 6, state.user ? "No alerts on this page." : "Sign in to load persisted alerts.");
      if (!filtered.length) return showTableMessage("alert-body", 6, "No results match the current search.");
      const body = byId("alert-body");
      const fragment = document.createDocumentFragment();
      filtered.forEach((item) => {
        const row = make("tr");
        const id = make("td");
        const button = make("button", "row-button mono", `#${item.id}`);
        button.type = "button";
        button.addEventListener("click", () => void Drawer.openAlert(item));
        id.append(button);
        const endpoints = make("td", "mono-cell", `${item.source_ip || "—"} → ${item.dest_ip || "—"}`);
        const severity = make("td");
        severity.append(severityChip(item.severity));
        const inspect = make("td");
        const inspectButton = make("button", "button button-secondary row-inspect", "Inspect JSON");
        inspectButton.type = "button";
        inspectButton.addEventListener("click", () => void Drawer.openAlert(item, true));
        inspect.append(inspectButton);
        row.append(id, make("td", "mono-cell", formatTime(item.timestamp, true)), endpoints, make("td", "mono-cell", item.protocol || "—"), severity, inspect);
        fragment.append(row);
      });
      body.replaceChildren(fragment);
    },
    renderActions() {
      const items = state.data.actions;
      setText("action-page-label", `${items.length} response records on this page`);
      if (!items.length) return showTableMessage("action-body", 6, state.user ? "No response action records on this page." : "Sign in to load response records.");
      const body = byId("action-body");
      const fragment = document.createDocumentFragment();
      items.forEach((item) => {
        const row = make("tr");
        const decision = make("td");
        decision.append(actionChip(item.action_type));
        row.append(
          make("td", "mono-cell", `#${item.id}`),
          make("td", "mono-cell", item.detection_id ? `#${item.detection_id}` : "—"),
          decision,
          make("td", "mono-cell", formatTime(item.timestamp, true)),
          make("td", "mono-cell", formatTime(item.reversed_at, true)),
          make("td", "", "DRY-RUN"),
        );
        fragment.append(row);
      });
      body.replaceChildren(fragment);
    },
    fillClassFilter() {
      const root = byId("detection-class-chips");
      if (root.childElementCount) return;
      const entries = ["", ...CLASSES];
      entries.forEach((label) => {
        const button = make("button", `filter-chip${label === "" ? " is-active" : ""}`, label || "All classes");
        button.type = "button";
        button.setAttribute("aria-pressed", String(label === ""));
        button.addEventListener("click", () => {
          state.classFilter = label;
          $$(".filter-chip", root).forEach((chip) => {
            const active = chip.dataset.class === label;
            chip.classList.toggle("is-active", active);
            chip.setAttribute("aria-pressed", String(active));
          });
          Tables.renderDetections();
        });
        button.dataset.class = label;
        root.append(button);
      });
    },
  };

  function addHeatmap(alertDetails) {
    const root = byId("heatmap");
    root.replaceChildren();
    const counts = new Map(CLASSES.map((label) => [label, Array(24).fill(0)]));
    for (const alert of alertDetails) {
      const date = alert.timestamp ? new Date(alert.timestamp) : null;
      if (!date || Number.isNaN(date.getTime())) continue;
      for (const detection of alert.detections || []) {
        if (!counts.has(detection.predicted_class)) continue;
        counts.get(detection.predicted_class)[date.getHours()] += 1;
      }
    }
    const header = make("div", "heatmap-cell label hour-label", "CLASS / HOUR");
    root.append(header);
    for (let hour = 0; hour < 24; hour += 1) root.append(make("div", "heatmap-cell label hour-label", String(hour).padStart(2, "0")));
    const maximum = Math.max(0, ...Array.from(counts.values()).flat());
    for (const label of CLASSES) {
      root.append(make("div", `heatmap-cell label ${classSlug(label)}`, label));
      counts.get(label).forEach((value, hour) => {
        const cell = make("div", "heatmap-cell");
        const intensity = maximum ? value / maximum : 0;
        cell.style.backgroundColor = value ? `rgba(85,221,169,${.10 + intensity * .7})` : "rgba(188,220,207,.035)";
        cell.title = `${label}, ${String(hour).padStart(2, "0")}:00 · ${value} loaded alert detections`;
        cell.setAttribute("role", "cell");
        cell.setAttribute("aria-label", cell.title);
        root.append(cell);
      });
    }
    root.setAttribute("role", "table");
  }

  function renderRanking(id, values, emptyMessage) {
    const root = byId(id);
    root.replaceChildren();
    if (!values.length) {
      root.append(make("div", "chart-state", emptyMessage));
      return;
    }
    const max = Math.max(1, ...values.map((entry) => entry.count));
    for (const entry of values.slice(0, 6)) {
      const row = make("div", "ranking-row");
      const label = make("span", "ranking-label mono", entry.label);
      const track = make("span", "ranking-track");
      const fill = make("span", "ranking-fill");
      fill.style.width = `${Math.max(3, entry.count / max * 100)}%`;
      track.append(fill);
      const count = make("span", "ranking-count mono", entry.count);
      row.append(label, track, count);
      root.append(row);
    }
  }

  async function fetchAlertDetails(items) {
    const missing = items.filter((item) => !state.detailCache.has(String(item.id))).slice(0, 25);
    const results = await Promise.allSettled(missing.map((item) => Api.get(`/alerts/${encodeURIComponent(item.id)}`)));
    results.forEach((result, index) => {
      const key = String(missing[index].id);
      if (result.status === "fulfilled") {
        state.detailCache.set(key, result.value);
        if (state.detailCache.size > 200) state.detailCache.delete(state.detailCache.keys().next().value);
      }
    });
    const failed = results.filter((result) => result.status === "rejected").length;
    if (failed) appendSensorEvent(`${failed} alert detail request(s) failed; derived analytics may be incomplete.`);
    return items.map((item) => state.detailCache.get(String(item.id))).filter(Boolean);
  }

  function updateDerivedAnalytics(alertDetails) {
    const attackers = new Map();
    const ports = new Map();
    const protocols = { TCP: 0, UDP: 0, ICMP: 0, Other: 0 };
    alertDetails.forEach((alert) => {
      const source = String(alert.source_ip || "unknown");
      attackers.set(source, (attackers.get(source) || 0) + 1);
      const features = alert.raw_features && typeof alert.raw_features === "object" ? alert.raw_features : {};
      const port = asNumber(features.dst_port ?? features.destination_port ?? features.dest_port);
      if (port !== null && port >= 0 && port <= 65535) ports.set(String(Math.trunc(port)), (ports.get(String(Math.trunc(port))) || 0) + 1);
      const rawProtocol = String(alert.protocol ?? features.protocol ?? "").toUpperCase();
      const protocol = ["TCP", "UDP", "ICMP"].includes(rawProtocol) ? rawProtocol : "Other";
      protocols[protocol] += 1;
    });
    renderRanking("attacker-ranking", Array.from(attackers, ([label, count]) => ({ label, count })).sort((a, b) => b.count - a.count), "No alert source IPs available.");
    renderRanking("port-ranking", Array.from(ports, ([label, count]) => ({ label, count })).sort((a, b) => b.count - a.count), "Destination port features are not present in the loaded alerts.");
    Charts.updateProtocols(protocols);
    addHeatmap(alertDetails);
  }

  async function enrichDetections(items) {
    const missing = items.filter((item) => !state.detectionDetails.has(String(item.id))).slice(0, 30);
    const results = await Promise.allSettled(missing.map((item) => Api.get(`/detections/${encodeURIComponent(item.id)}`)));
    results.forEach((result, index) => {
      if (result.status === "fulfilled") state.detectionDetails.set(String(missing[index].id), result.value);
    });
    return items.map((item) => {
      const detail = state.detectionDetails.get(String(item.id)) || {};
      const alert = detail.alert || {};
      const action = state.data.actions.find((entry) => Number(entry.detection_id) === Number(item.id));
      return {
        ...item,
        timestamp: alert.timestamp || item.timestamp,
        source_ip: alert.source_ip || item.source_ip,
        dest_ip: alert.dest_ip || item.dest_ip,
        protocol: alert.protocol || item.protocol,
        action: action?.action_type || item.action,
      };
    });
  }

  function renderLatestDetection(items) {
    const latest = items[0];
    if (!latest) {
      setText("latest-status", state.user ? "No persisted detections" : "Sign-in required");
      setText("latest-class", "No detection loaded");
      setText("latest-summary", state.user ? "The API returned no persisted detection records." : "Sign in to view recent detection data.");
      setText("latest-confidence", "—");
      setText("latest-source", "—");
      setText("latest-time", "—");
      byId("latest-open").disabled = true;
      return;
    }
    const label = knownClass(latest.predicted_class);
    setText("latest-status", latest.severity || "Observed");
    setText("latest-class", label);
    setText("latest-summary", latest.source_ip || latest.dest_ip
      ? `${latest.source_ip || "Unknown source"} → ${latest.dest_ip || "Unknown destination"}${latest.protocol ? ` · ${latest.protocol}` : ""}`
      : `Detection #${latest.id}; endpoint details are not present in this API record.`);
    const score = asNumber(latest.confidence);
    setText("latest-confidence", score === null ? "Not scored" : score.toFixed(3));
    setText("latest-source", latest.detection_source || latest.model_version || "—");
    setText("latest-time", formatTime(latest.timestamp));
    byId("latest-dot").className = `class-dot class-${classSlug(label)}`;
    byId("latest-open").disabled = false;
    byId("latest-open").onclick = () => void Drawer.openDetection(latest);
  }

  function updateModelStatus(model, health) {
    state.data.model = model;
    setText("model-bundle", model?.active_model || "Unavailable");
    setText("model-version", model?.registered_version ? `Registered version ${model.registered_version}` : "Registered version not available");
    const status = model?.evaluation_status || "unavailable";
    const badge = byId("evaluation-badge");
    badge.textContent = status.replaceAll("_", " ");
    badge.className = `evaluation-badge${status === "verified" ? " is-good" : ""}`;
    const overlap = model?.capture_overlap_warning;
    setText("model-split", overlap === true
      ? "Exploratory; capture overlap flagged"
      : overlap === false
        ? "Overlap flag not reported"
        : "Not exposed by API");
    setText("model-overlap", overlap === true
      ? "Evaluation split is exploratory; related capture records may overlap."
      : "The model-health API does not provide split-strategy metadata.");
    const loaded = Boolean(health?.model_loaded);
    setText("model-caveat-text", model?.model_error
      ? `Model status error: ${model.model_error}`
      : loaded
        ? "The API reports a model bundle is loaded. This is availability—not evidence of accuracy. Evaluation is exploratory when capture overlap is flagged; confidence scores are not calibrated probabilities."
        : "The API reports that a model bundle is unavailable. Detection quality cannot be assessed until a compatible bundle is loaded.");
  }

  function updateKpis(stats) {
    state.data.stats = stats;
    animateKpi("kpi-alerts", Number(stats.alerts) || 0);
    animateKpi("kpi-detections", Number(stats.detections) || 0);
    animateKpi("kpi-blocks", Number(stats.by_action?.block) || 0);
    setText("kpi-attack-rate", "N/A");
    ["kpi-alerts", "kpi-detections", "kpi-blocks"].forEach((id) => byId(id).classList.remove("skeleton-text"));
    byId("kpi-blocks").title = "Dry-run block decisions only. No firewall action is performed.";
    Charts.updateClassDistribution(stats.by_class || {});
    Charts.updateActions(stats.by_action || {});
  }

  function updateCaptureStatus(status) {
    const known = ["stopped", "starting", "running", "stopping", "error"].includes(status.status)
      ? status.status
      : "unknown";
    state.capture = known;
    const labels = { stopped: "Stopped", starting: "Starting", running: "Running", stopping: "Stopping", error: "Error", unknown: "Unknown" };
    const badge = byId("capture-status");
    badge.className = `sensor-state state-${known}`;
    $("span", badge).textContent = labels[known];
    const top = byId("capture-top-state");
    top.className = `capture-pill state-${known}`;
    $("span", top).textContent = `Sensor ${labels[known].toLowerCase()}`;
    byId("sensor-radar").closest(".sensor-card").classList.toggle("is-running", known === "running");
    const message = providerMessage(status.last_error || state.captureSetupError || "");
    const errorBox = byId("capture-error");
    errorBox.textContent = message;
    errorBox.hidden = !message;
    byId("capture-retry").hidden = !message || state.user?.role !== "admin";
    setText("capture-packets", formatNumber(status.packet_count));
    setText("capture-flows", formatNumber(status.flow_count));
    updateCaptureRates(status);
    updateSessionUI();
  }

  function providerMessage(message) {
    const value = String(message || "");
    if (/npcap|libpcap|provider/i.test(value)) {
      return `${value} On Windows, verify the Npcap service is running, set SCAPY_USE_LIBPCAP=yes in the same PowerShell window, then restart the backend.`;
    }
    return value;
  }

  function updateCaptureRates(status) {
    const now = performance.now();
    const sample = {
      time: now,
      packets: Number(status.packet_count) || 0,
      flows: Number(status.flow_count) || 0,
    };
    let packetsRate = 0;
    let flowsRate = 0;
    const previous = state.lastCaptureSample;
    if (previous && sample.time > previous.time && state.capture === "running") {
      const seconds = (sample.time - previous.time) / 1000;
      packetsRate = Math.max(0, (sample.packets - previous.packets) / seconds);
      flowsRate = Math.max(0, (sample.flows - previous.flows) / seconds);
    }
    state.lastCaptureSample = sample;
    setText("capture-packets-rate", state.capture === "running" ? packetsRate.toFixed(1) : "—");
    setText("capture-flows-rate", state.capture === "running" ? flowsRate.toFixed(1) : "—");
    Charts.updateThroughput(packetsRate, flowsRate);
  }

  function appendSensorEvent(message, kind = "info") {
    const root = byId("sensor-log");
    const empty = $(".log-empty", root);
    if (empty) empty.remove();
    const row = make("li", kind === "critical" ? "critical-row" : "");
    row.append(make("time", "", formatTime(new Date().toISOString())));
    row.append(make("span", "", message));
    root.prepend(row);
    while (root.children.length > 12) root.lastElementChild.remove();
    setText("sensor-log-state", "Recent session events");
  }

  async function loadInterfaces() {
    if (state.user?.role !== "admin") return;
    state.captureSetupError = "";
    const result = await Api.get("/capture/interfaces");
    state.interfaceNames = Array.isArray(result.interfaces) ? result.interfaces : [];
    const select = byId("capture-interface");
    const previous = select.value;
    select.replaceChildren(make("option", "", state.interfaceNames.length ? "Select an interface" : "No interfaces available"));
    select.options[0].value = "";
    state.interfaceNames.forEach((name) => {
      const option = make("option", "", name);
      option.value = name;
      select.append(option);
    });
    if (state.interfaceNames.includes(previous)) select.value = previous;
    state.interfaceLoaded = true;
    if (!state.interfaceNames.length) throw new Error("No capture interfaces were returned. Check Npcap/libpcap and restart the backend.");
    updateSessionUI();
  }

  async function pollCaptureStatus() {
    if (!state.user) return;
    try {
      const status = await Api.get("/capture/status");
      updateCaptureStatus(status);
    } catch (error) {
      const message = error instanceof Error ? error.message : "Unable to read capture status.";
      updateCaptureStatus({ status: "error", last_error: message });
    }
  }

  async function handleCapture(action) {
    const isStart = action === "start";
    byId("capture-error").hidden = true;
    const pending = { status: isStart ? "starting" : "stopping" };
    updateCaptureStatus(pending);
    try {
      const result = await Api.request(`${API_ROOT}/capture/${action}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(isStart
          ? { interface: byId("capture-interface").value || null, bpf_filter: byId("capture-filter").value.trim() || "ip", idle_timeout: 2.0 }
          : {}),
      });
      updateCaptureStatus(result);
      appendSensorEvent(isStart ? "Capture started." : "Capture stopped and pending flows flushed.");
      toast(isStart ? "Live capture started." : "Capture stopped.", "success");
      if (!isStart) await Dashboard.refresh();
    } catch (error) {
      updateCaptureStatus({ status: "error", last_error: error instanceof Error ? error.message : "Capture operation failed." });
      appendSensorEvent(`Capture ${action} failed: ${error.message || "unknown error"}`, "critical");
      toast(error.message || `Could not ${action} capture.`, "error");
    }
  }

  const Drawer = {
    async openDetection(item) {
      state.previousFocus = document.activeElement;
      state.activeDrawer = { type: "detection", item };
      byId("drawer-eyebrow").textContent = `DETECTION #${item.id}`;
      setText("drawer-title", item.predicted_class || "Detection detail");
      byId("drawer-backdrop").hidden = false;
      byId("detail-drawer").hidden = false;
      showDrawerTab("summary");
      setText("drawer-record-summary", "Loading detection and linked alert details…");
      byId("drawer-feature-grid").replaceChildren();
      byId("drawer-explanation-bars").replaceChildren();
      setText("drawer-json", "Loading API record…");
      byId("drawer-close").focus();
      try {
        const detection = await Api.get(`/detections/${encodeURIComponent(item.id)}`);
        const alertId = detection.alert_id ?? item.alert_id;
        const alert = alertId ? await Api.get(`/alerts/${encodeURIComponent(alertId)}`) : null;
        const rawFeatures = alert?.raw_features && typeof alert.raw_features === "object" ? alert.raw_features : {};
        const fullRecord = { detection, alert };
        state.activeDrawer.features = rawFeatures;
        state.activeDrawer.raw = fullRecord;
        renderDrawerSummary(detection, alert);
        renderFeatureGrid(rawFeatures);
        setText("drawer-json", JSON.stringify(fullRecord, null, 2));
        if (Object.keys(rawFeatures).length) {
          const explanation = await Api.request(`${API_ROOT}/alerts/explain`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ predicted_class: detection.predicted_class, features: rawFeatures }),
          });
          renderExplanation(explanation);
        } else {
          byId("drawer-explanation-bars").append(make("p", "drawer-empty", "The linked alert contains no raw feature map."));
        }
      } catch (error) {
        setText("drawer-record-summary", error.message || "Could not load detection details.");
        setText("drawer-json", error.message || "Could not load API record.");
        toast(error.message || "Could not load detection details.", "error");
      }
    },
    async openAlert(item, rawTab = false) {
      state.previousFocus = document.activeElement;
      state.activeDrawer = { type: "alert", item };
      byId("drawer-eyebrow").textContent = `ALERT #${item.id}`;
      setText("drawer-title", "Alert record");
      byId("drawer-backdrop").hidden = false;
      byId("detail-drawer").hidden = false;
      showDrawerTab(rawTab ? "raw" : "summary");
      setText("drawer-record-summary", "Loading alert feature record…");
      byId("drawer-feature-grid").replaceChildren();
      byId("drawer-explanation-bars").replaceChildren();
      setText("drawer-json", "Loading API record…");
      byId("drawer-close").focus();
      try {
        const alert = await Api.get(`/alerts/${encodeURIComponent(item.id)}`);
        const rawFeatures = alert.raw_features && typeof alert.raw_features === "object" ? alert.raw_features : {};
        state.activeDrawer.features = rawFeatures;
        state.activeDrawer.raw = alert;
        renderDrawerSummary(alert.detections?.[0] || {}, alert);
        renderFeatureGrid(rawFeatures);
        setText("drawer-json", JSON.stringify(alert, null, 2));
        const detection = alert.detections?.[0];
        if (detection && Object.keys(rawFeatures).length) {
          const explanation = await Api.request(`${API_ROOT}/alerts/explain`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ predicted_class: detection.predicted_class, features: rawFeatures }),
          });
          renderExplanation(explanation);
        } else {
          byId("drawer-explanation-bars").append(make("p", "drawer-empty", "No detection explanation is available for this alert."));
        }
      } catch (error) {
        setText("drawer-record-summary", error.message || "Could not load alert details.");
        setText("drawer-json", error.message || "Could not load API record.");
        toast(error.message || "Could not load alert details.", "error");
      }
    },
    close() {
      byId("drawer-backdrop").hidden = true;
      byId("detail-drawer").hidden = true;
      state.activeDrawer = null;
      if (state.previousFocus && typeof state.previousFocus.focus === "function") state.previousFocus.focus();
    },
  };

  function showDrawerTab(tab) {
    ["summary", "features", "raw"].forEach((name) => {
      const selected = name === tab;
      byId(`drawer-tab-${name}`).setAttribute("aria-selected", String(selected));
      byId(`drawer-${name}`).hidden = !selected;
    });
  }

  function renderDrawerSummary(detection, alert) {
    const root = byId("drawer-record-summary");
    root.replaceChildren();
    const fields = [
      ["Classification", detection.predicted_class || "—"],
      ["Severity", detection.severity || alert?.severity || "—"],
      ["Source IP", alert?.source_ip || "—"],
      ["Destination IP", alert?.dest_ip || "—"],
      ["Protocol", alert?.protocol || "—"],
      ["Model confidence", detection.confidence === null || detection.confidence === undefined ? "Not scored" : detection.confidence],
      ["Detection source", detection.detection_source || "—"],
      ["Observed", formatTime(alert?.timestamp, true)],
    ];
    fields.forEach(([label, value]) => {
      const line = make("div", "record-line");
      line.append(make("span", "", label), make("span", "", value));
      root.append(line);
    });
  }

  function selectFeatures(rawFeatures) {
    const selected = {};
    FEATURES.forEach((name) => {
      selected[name] = Object.prototype.hasOwnProperty.call(rawFeatures, name) ? rawFeatures[name] : null;
    });
    return selected;
  }

  function renderFeatureGrid(rawFeatures) {
    const root = byId("drawer-feature-grid");
    root.replaceChildren();
    FEATURES.forEach((name) => {
      const item = make("div", "feature-item");
      const value = Object.prototype.hasOwnProperty.call(rawFeatures, name) ? rawFeatures[name] : "Not provided";
      item.append(make("span", "", name), make("strong", "", value));
      root.append(item);
    });
  }

  function renderExplanation(explanation) {
    const root = byId("drawer-explanation-bars");
    root.replaceChildren();
    const note = make("p", "chart-note", explanation.method === "feature_value_fallback"
      ? "Feature-value fallback: bar lengths show returned contribution magnitudes, not validated model importance."
      : "Explanation returned by the API; not a calibrated probability or causal claim.");
    root.append(note);
    const values = Array.isArray(explanation.values) ? explanation.values.slice(0, 10) : [];
    const maximum = Math.max(1e-12, ...values.map((item) => Math.abs(Number(item.contribution) || 0)));
    values.forEach((item) => {
      const row = make("div", "feature-row");
      const name = make("span", "feature-name", item.feature || "Feature");
      const track = make("span", "feature-track");
      const fill = make("span");
      fill.style.width = `${Math.min(100, Math.abs(Number(item.contribution) || 0) / maximum * 100)}%`;
      track.append(fill);
      const numericValue = asNumber(item.value);
      row.append(name, track, make("span", "feature-value", numericValue === null ? "—" : numericValue.toPrecision(4)));
      root.append(row);
    });
    if (!values.length) root.append(make("p", "drawer-empty", "No explanation values were returned."));
  }

  async function copyText(value) {
    try {
      await navigator.clipboard.writeText(value);
      toast("Copied to clipboard.", "success");
    } catch (error) {
      toast(`Clipboard unavailable: ${error.message || "copy manually from the Raw JSON tab."}`, "error");
    }
  }

  const Dashboard = {
    async refresh() {
      if (!state.user || state.refreshing) return;
      state.refreshing = true;
      const session = state.user;
      try {
        const results = await Promise.allSettled([
          Api.get("/health"),
          Api.get("/stats"),
          Api.get("/detections/timeline"),
          Api.get(`/detections?page=${state.pages.detections}&limit=25`),
          Api.get(`/alerts?page=${state.pages.alerts}&limit=25`),
          Api.get(`/actions?page=${state.pages.actions}&limit=25`),
          Api.get("/model-health"),
        ]);
        if (state.user !== session) return;
        const [healthResult, statsResult, timelineResult, detectionsResult, alertsResult, actionsResult, modelResult] = results;
        if (healthResult.status === "fulfilled") {
          updateHealthPill("state-ok", healthResult.value.status === "ok" ? "API online" : "API warning");
          updateModelStatus(modelResult.status === "fulfilled" ? modelResult.value : null, healthResult.value);
        } else {
          updateHealthPill("state-error", "API unavailable");
          setText("model-caveat-text", healthResult.reason?.message || "Health endpoint unavailable.");
        }
        if (statsResult.status === "fulfilled") updateKpis(statsResult.value);
        else toast(`Stats unavailable: ${statsResult.reason.message || "request failed"}`, "error");
        if (timelineResult.status === "fulfilled") Charts.updateTimeline(timelineResult.value);
        else chartState("timeline-chart", "Timeline API unavailable.", true);
        if (actionsResult.status === "fulfilled") {
          const page = actionsResult.value;
          state.data.actions = Array.isArray(page.items) ? page.items : [];
          setPagination("actions", page);
          Tables.renderActions();
        } else {
          showTableMessage("action-body", 6, actionsResult.reason.message || "Actions API unavailable.", "error-message");
        }
        if (detectionsResult.status === "fulfilled") {
          const page = detectionsResult.value;
          const rawItems = Array.isArray(page.items) ? page.items : [];
          setPagination("detections", page);
          state.data.detections = await enrichDetections(rawItems);
          Charts.updateConfidence(rawItems);
          if (!state.paused) {
            Tables.renderDetections();
            renderLatestDetection(state.data.detections);
          }
        } else {
          showTableMessage("detection-body", 7, detectionsResult.reason.message || "Detections API unavailable.", "error-message");
        }
        if (alertsResult.status === "fulfilled") {
          const page = alertsResult.value;
          state.data.alerts = Array.isArray(page.items) ? page.items : [];
          setPagination("alerts", page);
          Tables.renderAlerts();
          try {
            const details = await fetchAlertDetails(state.data.alerts);
            updateDerivedAnalytics(details);
          } catch (error) {
            appendSensorEvent(`Alert analytics unavailable: ${error.message || "detail request failed"}`);
          }
        } else {
          showTableMessage("alert-body", 6, alertsResult.reason.message || "Alerts API unavailable.", "error-message");
        }
        const failures = results.filter((result) => result.status === "rejected");
        if (failures.length) {
          state.lastRefreshError = failures.map((result) => result.reason?.message || "API request failed").join("; ");
        } else {
          state.lastRefreshError = "";
        }
        setText("last-updated", formatTime(new Date().toISOString()));
      } catch (error) {
        updateHealthPill("state-error", "API unavailable");
        console.error("Dashboard refresh failed", error);
      } finally {
        state.refreshing = false;
      }
    },
    async loadSession() {
      const token = localStorage.getItem(TOKEN_KEY);
      if (!token) {
        updateSessionUI();
        updateHealthPill("state-loading", "Sign in for data");
        return;
      }
      try {
        state.user = await Api.get("/auth/me");
        updateSessionUI();
        connectSocket();
        if (state.user.role === "admin" && !state.interfaceLoaded) {
          try {
            await loadInterfaces();
          } catch (error) {
            state.captureSetupError = error.message;
            byId("capture-error").textContent = providerMessage(error.message);
            byId("capture-error").hidden = false;
            byId("capture-retry").hidden = false;
          }
        }
        await pollCaptureStatus();
        await this.refresh();
      } catch (error) {
        clearSession(error.message || "Could not validate the current session.");
      }
    },
  };

  function appendNewFeedEvent(message) {
    const label = message.predicted_class || message.model_prediction || message.detection_source || message.type || "Network event";
    const source = message.source_ip || "Unknown source";
    const destination = message.dest_ip || "Unknown destination";
    const simulated = message.simulated === true || message.detection_source === "dataset_replay";
    const text = simulated
      ? `SIMULATED sample: ${label} · ${source} → ${destination}`
      : message.type === "traffic_flow"
        ? `Flow: ${source} → ${destination} · ${message.protocol || "IP"} · ${Number(message.packets) || 0} packets`
        : `${label}: ${source} → ${destination}${message.detection_source ? ` · ${message.detection_source}` : ""}`;
    appendSensorEvent(text, ["DoS", "DDoS", "Botnet"].includes(label) ? "critical" : "info");
  }

  function onSocketMessage(event) {
    let message;
    try {
      message = JSON.parse(event.data);
    } catch (error) {
      console.error("Invalid live event JSON", error);
      return;
    }
    if (message.ping) return;
    appendNewFeedEvent(message);
    if (message.type === "traffic_flow") return;
    if (state.paused) {
      state.pausedEvents.push(message);
      updatePausedCount();
      return;
    }
    if (message.id !== undefined) state.flashIds.add(String(message.id));
    if (message.predicted_class && message.detection_source !== "dataset_replay") {
      window.setTimeout(() => void Dashboard.refresh(), 180);
    } else if (message.detection_source === "dataset_replay" || message.simulated) {
      toast(`Simulated sample received: ${message.predicted_class || "sample"}. Not a live detection.`, "info");
    }
  }

  function connectSocket() {
    if (!state.user || !localStorage.getItem(TOKEN_KEY) || state.socket) return;
    const scheme = window.location.protocol === "https:" ? "wss:" : "ws:";
    const token = encodeURIComponent(localStorage.getItem(TOKEN_KEY));
    const socket = new WebSocket(`${scheme}//${window.location.host}/ws/feed?access_token=${token}`);
    state.socket = socket;
    updateSocketPill(false, "Connecting to event feed");
    socket.addEventListener("open", () => {
      state.socketDelay = 1000;
      updateSocketPill(true);
    });
    socket.addEventListener("message", onSocketMessage);
    socket.addEventListener("error", () => updateSocketPill(false, "Feed connection error"));
    socket.addEventListener("close", (event) => {
      state.socket = null;
      if (event.code === 4401 || event.code === 4403) {
        clearSession("Live event feed authorization expired. Please sign in again.");
        return;
      }
      updateSocketPill(false);
      if (localStorage.getItem(TOKEN_KEY)) {
        window.clearTimeout(state.socketTimer);
        state.socketTimer = window.setTimeout(connectSocket, state.socketDelay);
        state.socketDelay = Math.min(state.socketDelay * 2, 30000);
      }
    });
  }

  function updatePausedCount() {
    const count = state.pausedEvents.length;
    const pill = byId("new-events-pill");
    pill.hidden = count === 0;
    pill.textContent = `${count} new`;
    byId("feed-pause").textContent = state.paused ? "Resume feed" : "Pause feed";
    byId("feed-pause").setAttribute("aria-pressed", String(state.paused));
    updateSocketPill(Boolean(state.socket && state.socket.readyState === WebSocket.OPEN));
  }

  function setFeedPaused(paused) {
    state.paused = paused;
    updatePausedCount();
    if (!paused && state.pausedEvents.length) {
      state.pausedEvents.forEach((message) => {
        if (message.id !== undefined) state.flashIds.add(String(message.id));
      });
      state.pausedEvents = [];
      void Dashboard.refresh();
      toast("Live feed resumed.", "success");
    }
  }

  function setPage(kind, offset) {
    state.pages[kind] = Math.max(1, state.pages[kind] + offset);
    void Dashboard.refresh();
  }

  function exportRows() {
    const rows = applyDetectionFilters(state.data.detections);
    if (!rows.length) {
      toast("There are no loaded detection rows to export.", "info");
      return;
    }
    const columns = ["id", "timestamp", "source_ip", "dest_ip", "predicted_class", "confidence", "action", "model_version", "detection_source"];
    const csv = [
      columns.join(","),
      ...rows.map((row) => columns.map((key) => {
        const value = row[key] === null || row[key] === undefined ? "" : String(row[key]);
        return `"${value.replaceAll('"', '""')}"`;
      }).join(",")),
    ].join("\r\n");
    const url = URL.createObjectURL(new Blob([csv], { type: "text/csv;charset=utf-8" }));
    const link = make("a");
    link.href = url;
    link.download = `aegisai-detections-page-${state.pages.detections}.csv`;
    link.click();
    URL.revokeObjectURL(url);
    toast("Current filtered detection page exported.", "success");
  }

  function exportAlerts() {
    const query = `${byId("alert-search").value} ${byId("global-search").value}`.trim().toLowerCase();
    const rows = state.data.alerts.filter((item) => !query || [item.id, item.timestamp, item.source_ip, item.dest_ip, item.protocol, item.severity]
      .some((value) => String(value ?? "").toLowerCase().includes(query)));
    if (!rows.length) {
      toast("There are no loaded alert rows to export.", "info");
      return;
    }
    const columns = ["id", "timestamp", "source_ip", "dest_ip", "protocol", "severity"];
    const csv = [columns.join(","), ...rows.map((row) => columns.map((key) => `"${String(row[key] ?? "").replaceAll('"', '""')}"`).join(","))].join("\r\n");
    const url = URL.createObjectURL(new Blob([csv], { type: "text/csv;charset=utf-8" }));
    const link = make("a");
    link.href = url;
    link.download = `aegisai-alerts-page-${state.pages.alerts}.csv`;
    link.click();
    URL.revokeObjectURL(url);
    toast("Current filtered alert page exported.", "success");
  }

  function openDialog(id) {
    const dialog = byId(id);
    if (typeof dialog.showModal === "function") dialog.showModal();
  }

  function closeDialog(id) {
    const dialog = byId(id);
    if (dialog.open) dialog.close();
  }

  function bindEvents() {
    byId("detail-drawer").addEventListener("keydown", (event) => {
      if (event.key === "Escape") {
        event.preventDefault();
        Drawer.close();
        return;
      }
      if (event.key !== "Tab") return;
      const focusable = $$(
        "button:not([disabled]), a[href], input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex='-1'])",
        byId("detail-drawer"),
      ).filter((element) => !element.hidden && element.getClientRects().length);
      if (!focusable.length) return;
      const first = focusable[0];
      const last = focusable[focusable.length - 1];
      if (event.shiftKey && document.activeElement === first) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault();
        first.focus();
      }
    });
    byId("mobile-menu").addEventListener("click", () => {
      const sidebar = byId("sidebar");
      sidebar.classList.toggle("mobile-open");
      byId("mobile-menu").setAttribute("aria-expanded", String(sidebar.classList.contains("mobile-open")));
    });
    byId("sidebar-toggle").addEventListener("click", () => {
      const sidebar = byId("sidebar");
      if (window.matchMedia("(max-width: 700px)").matches) sidebar.classList.toggle("mobile-open");
      else document.body.classList.toggle("sidebar-collapsed");
      byId("sidebar-toggle").setAttribute("aria-expanded", String(!document.body.classList.contains("sidebar-collapsed") && !sidebar.classList.contains("mobile-open")));
    });
    $$(".nav-link").forEach((link) => link.addEventListener("click", () => {
      $$(".nav-link").forEach((item) => item.classList.toggle("is-active", item === link));
      byId("sidebar").classList.remove("mobile-open");
    }));
    byId("sign-in-btn").addEventListener("click", () => openDialog("signin-dialog"));
    byId("sensor-sign-in").addEventListener("click", () => openDialog("signin-dialog"));
    byId("signin-form").addEventListener("submit", async (event) => {
      event.preventDefault();
      const form = event.currentTarget;
      const button = byId("signin-submit");
      const errorBox = byId("signin-error");
      errorBox.hidden = true;
      button.disabled = true;
      button.textContent = "Signing in…";
      try {
        const formData = new FormData(form);
        state.user = await Api.signIn(String(formData.get("username") || ""), String(formData.get("password") || ""));
        form.reset();
        closeDialog("signin-dialog");
        updateSessionUI();
        await Dashboard.loadSession();
        connectSocket();
        toast(`Signed in as ${state.user.username} (${state.user.role}).`, "success");
      } catch (error) {
        errorBox.textContent = error.message || "Sign-in failed.";
        errorBox.hidden = false;
      } finally {
        button.disabled = false;
        button.textContent = "Sign in";
      }
    });
    byId("sign-out-btn").addEventListener("click", async () => {
      try {
        if (state.user?.role === "admin" && state.capture === "running") {
          const result = await Api.request(`${API_ROOT}/capture/stop`, { method: "POST" });
          updateCaptureStatus(result);
        }
        clearSession();
        toast("Signed out.", "success");
      } catch (error) {
        toast(error.message || "Could not safely finish sign-out.", "error");
      }
    });
    $$("[data-close-dialog]").forEach((button) => button.addEventListener("click", () => closeDialog(button.dataset.closeDialog)));
    byId("refresh-button").addEventListener("click", () => void Dashboard.refresh());
    byId("capture-start").addEventListener("click", () => void handleCapture("start"));
    byId("capture-stop").addEventListener("click", () => void handleCapture("stop"));
    byId("capture-interface").addEventListener("change", updateSessionUI);
    byId("capture-retry").addEventListener("click", async () => {
      try {
        await loadInterfaces();
        await pollCaptureStatus();
        toast("Capture interfaces refreshed.", "success");
      } catch (error) {
        state.captureSetupError = error.message;
        updateCaptureStatus({ status: "error", last_error: error.message });
      }
    });
    byId("timeline-count").addEventListener("click", () => setTimelineMode("count"));
    byId("timeline-rate").addEventListener("click", () => setTimelineMode("rate"));
    byId("timeline-24h").addEventListener("click", () => setTimelineWindow(24));
    byId("timeline-12h").addEventListener("click", () => setTimelineWindow(12));
    byId("detection-prev").addEventListener("click", () => setPage("detections", -1));
    byId("detection-next").addEventListener("click", () => setPage("detections", 1));
    byId("alert-prev").addEventListener("click", () => setPage("alerts", -1));
    byId("alert-next").addEventListener("click", () => setPage("alerts", 1));
    byId("action-prev").addEventListener("click", () => setPage("actions", -1));
    byId("action-next").addEventListener("click", () => setPage("actions", 1));
    byId("detection-search").addEventListener("input", () => Tables.renderDetections());
    byId("alert-search").addEventListener("input", () => Tables.renderAlerts());
    byId("global-search").addEventListener("input", () => {
      Tables.renderDetections();
      Tables.renderAlerts();
    });
    byId("density-toggle").addEventListener("click", () => {
      state.comfortable = !state.comfortable;
      document.body.classList.toggle("density-comfortable", state.comfortable);
      byId("density-toggle").textContent = state.comfortable ? "Compact rows" : "Comfortable rows";
      byId("density-toggle").setAttribute("aria-pressed", String(state.comfortable));
    });
    byId("detection-export").addEventListener("click", exportRows);
    byId("alert-export").addEventListener("click", exportAlerts);
    byId("feed-pause").addEventListener("click", () => setFeedPaused(!state.paused));
    byId("latest-open").addEventListener("click", () => {
      if (state.data.detections[0]) void Drawer.openDetection(state.data.detections[0]);
    });
    byId("drawer-close").addEventListener("click", () => Drawer.close());
    byId("drawer-backdrop").addEventListener("click", () => Drawer.close());
    ["summary", "features", "raw"].forEach((tab) => byId(`drawer-tab-${tab}`).addEventListener("click", () => showDrawerTab(tab)));
    byId("copy-features").addEventListener("click", () => {
      const features = state.activeDrawer?.features;
      if (features) void copyText(JSON.stringify(selectFeatures(features), null, 2));
      else toast("Load an alert feature record first.", "info");
    });
    byId("copy-raw").addEventListener("click", () => {
      const raw = state.activeDrawer?.raw;
      if (raw) void copyText(JSON.stringify(raw, null, 2));
    });
    document.addEventListener("keydown", handleShortcuts);
    window.addEventListener("resize", () => {
      Object.values(chartRegistry).forEach((chart) => chart.resize());
      drawSparkline("spark-detections", state.data.timeline.map((item) => Number(item.count) || 0), "#a98bff");
    });
    $$("#detection-table th button[data-sort]").forEach((button) => button.addEventListener("click", () => {
      const key = button.dataset.sort;
      state.detectionSort = { key, direction: state.detectionSort.key === key && state.detectionSort.direction === "desc" ? "asc" : "desc" };
      Tables.renderDetections();
    }));
  }

  function setTimelineMode(mode) {
    state.timelineMode = mode;
    ["count", "rate"].forEach((name) => {
      byId(`timeline-${name}`).classList.toggle("is-selected", mode === name);
      byId(`timeline-${name}`).setAttribute("aria-pressed", String(mode === name));
    });
    Charts.updateTimeline(state.data.timeline);
  }

  function setTimelineWindow(hours) {
    state.timelineWindow = hours;
    [12, 24].forEach((value) => {
      byId(`timeline-${value}h`).classList.toggle("is-selected", value === hours);
      byId(`timeline-${value}h`).setAttribute("aria-pressed", String(value === hours));
    });
    Charts.updateTimeline(state.data.timeline);
  }

  function handleShortcuts(event) {
    const target = event.target;
    const typing = target instanceof HTMLElement && (target.isContentEditable || ["INPUT", "TEXTAREA", "SELECT"].includes(target.tagName));
    if (event.key === "Escape" && !byId("detail-drawer").hidden) {
      Drawer.close();
      return;
    }
    if (typing) return;
    if (event.key === "/") {
      event.preventDefault();
      byId("global-search").focus();
      return;
    }
    if (event.key === "?") {
      event.preventDefault();
      openDialog("help-dialog");
      return;
    }
    if (event.key.toLowerCase() === "g") {
      window.clearTimeout(handleShortcuts.goTimer);
      handleShortcuts.goTimer = window.setTimeout(() => { handleShortcuts.goPending = false; }, 800);
      handleShortcuts.goPending = true;
      return;
    }
    if (handleShortcuts.goPending && event.key.toLowerCase() === "d") {
      event.preventDefault();
      handleShortcuts.goPending = false;
      window.location.hash = "detections";
      byId("detection-search").focus({ preventScroll: true });
    }
  }

  function init() {
    Charts.init();
    Tables.fillClassFilter();
    bindEvents();
    updateSessionUI();
    void Dashboard.loadSession();
    Api.get("/health").then((health) => {
      updateHealthPill("state-ok", health.status === "ok" ? "API online" : "API warning");
    }).catch(() => updateHealthPill("state-error", "API unavailable"));
    state.refreshTimer = window.setInterval(() => void Dashboard.refresh(), 12000);
    state.captureTimer = window.setInterval(() => void pollCaptureStatus(), 2000);
    const observer = new IntersectionObserver((entries) => {
      entries.forEach((entry) => {
        if (!entry.isIntersecting) return;
        $$(".nav-link").forEach((link) => link.classList.toggle("is-active", link.dataset.nav === entry.target.id));
      });
    }, { rootMargin: "-25% 0px -65% 0px" });
    $$(".page-section[id]").forEach((section) => observer.observe(section));
  }

  init();
})();
