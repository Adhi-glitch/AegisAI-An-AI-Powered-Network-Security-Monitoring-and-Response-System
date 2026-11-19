const tokenKey = "aegisai-capture-token";
const captureStatusLabel = document.getElementById("capture-status");
const captureAuthState = document.getElementById("capture-auth-state");
const captureError = document.getElementById("capture-error");
const captureInterface = document.getElementById("capture-interface");
const captureFilter = document.getElementById("capture-filter");
const captureStartButton = document.getElementById("capture-start");
const captureStopButton = document.getElementById("capture-stop");
const demoReplayButton = document.getElementById("demo-replay");
const demoReplayStatus = document.getElementById("demo-replay-status");
const ruleSourceLabels = {
  port_scan_rule: "TCP scan rule",
  botnet_ioc_rule: "Configured Botnet IOC",
  dos_syn_rate_rule: "SYN-rate DoS rule",
  ddos_syn_rate_rule: "Distributed SYN-rate rule",
  auth_attempt_rule: "Auth-service connection rule",
  http_signature_rule: "HTTP signature rule",
};
const signInLink = document.getElementById("capture-signin");
const sessionSignIn = document.getElementById("session-signin");
const sessionSignOut = document.getElementById("session-signout");
const viewerExport = document.getElementById("viewer-export");
let currentUser = null;
let captureState = "unknown";
let interfacesLoaded = false;
let reconnectTimer = null;
let replayDetections = [];
let persistedDetections = [];
let demoReplayRunning = false;

class CanvasChartFallback {
  constructor(canvas, config) {
    this.canvas = canvas;
    this.data = config.data;
    this.type = config.type;
    this.update();
  }

  update() {
    const canvas = this.canvas;
    const width = Math.max(canvas.clientWidth, 240);
    const height = Math.max(canvas.clientHeight, 180);
    const ratio = Math.min(window.devicePixelRatio || 1, 2);
    canvas.width = Math.round(width * ratio);
    canvas.height = Math.round(height * ratio);
    const context = canvas.getContext("2d");
    context.setTransform(ratio, 0, 0, ratio, 0, 0);
    context.clearRect(0, 0, width, height);
    const values = this.data.datasets[0].data.map((value) => Number(value) || 0);
    const colors = ["#55dda9", "#f0b64c", "#ff8579", "#8db6a3", "#83b5c2", "#a4b995"];
    context.font = "9px DM Mono, Consolas, monospace";

    if (this.type === "doughnut") {
      const centerX = width / 2;
      const centerY = height * 0.42;
      const radius = Math.min(width * 0.25, height * 0.31);
      const total = values.reduce((sum, value) => sum + value, 0) || 1;
      let angle = -Math.PI / 2;
      values.forEach((value, index) => {
        const nextAngle = angle + (value / total) * Math.PI * 2;
        context.beginPath();
        context.arc(centerX, centerY, radius, angle, nextAngle);
        context.strokeStyle = colors[index % colors.length];
        context.lineWidth = 18;
        context.stroke();
        angle = nextAngle;
      });
      const columns = width < 380 ? 1 : 2;
      this.data.labels.forEach((label, index) => {
        const x = (width - (columns * 145)) / 2 + (index % columns) * 145;
        const y = height - 23 + Math.floor(index / columns) * 13;
        context.fillStyle = colors[index % colors.length];
        context.fillRect(x, y - 6, 6, 6);
        context.fillStyle = "#8fa69c";
        context.textAlign = "left";
        context.fillText(String(label).slice(0, 19), x + 11, y);
      });
      return;
    }

    const margin = { top: 12, right: 8, bottom: 43, left: 40 };
    const plotWidth = width - margin.left - margin.right;
    const plotHeight = height - margin.top - margin.bottom;
    const max = Math.max(...values, 1);
    context.textAlign = "right";
    for (let line = 0; line <= 4; line += 1) {
      const y = margin.top + plotHeight * line / 4;
      context.strokeStyle = "rgba(188, 220, 207, .1)";
      context.beginPath();
      context.moveTo(margin.left, y);
      context.lineTo(width - margin.right, y);
      context.stroke();
      context.fillStyle = "#6d837a";
      context.fillText(String(Math.round(max * (1 - line / 4))), margin.left - 7, y + 3);
    }
    const slot = plotWidth / Math.max(values.length, 1);
    values.forEach((value, index) => {
      const barWidth = Math.min(38, slot * .55);
      const barHeight = plotHeight * value / max;
      const x = margin.left + index * slot + (slot - barWidth) / 2;
      context.fillStyle = index === 0 ? "#55dda9" : "#75a892";
      context.fillRect(x, margin.top + plotHeight - barHeight, barWidth, barHeight);
      context.save();
      context.translate(x + barWidth / 2, height - 7);
      context.rotate(-.32);
      context.textAlign = "right";
      context.fillStyle = "#8fa69c";
      context.fillText(String(this.data.labels[index] || "").slice(0, 14), 0, 0);
      context.restore();
    });
  }
}

const ChartEngine = window.Chart || CanvasChartFallback;
const classChart = new ChartEngine(document.getElementById("classChart"), {
  type: "bar",
  data: { labels: [], datasets: [{ label: "Detections", data: [], backgroundColor: "#55dda9", borderRadius: 1, maxBarThickness: 38 }] },
  options: {
    responsive: true,
    maintainAspectRatio: false,
    animation: { duration: 350 },
    plugins: { legend: { display: false } },
    scales: {
      x: { ticks: { color: "#8fa69c", maxRotation: 35, minRotation: 0, font: { family: "DM Mono", size: 8 } }, grid: { display: false } },
      y: { beginAtZero: true, ticks: { color: "#6d837a", precision: 0, font: { family: "DM Mono", size: 8 } }, grid: { color: "rgba(188, 220, 207, .1)" }, border: { display: false } },
    },
  },
});
const actionChart = new ChartEngine(document.getElementById("actionChart"), {
  type: "doughnut",
  data: { labels: [], datasets: [{ data: [], backgroundColor: ["#55dda9", "#f0b64c", "#ff8579", "#8db6a3", "#83b5c2", "#a4b995"], borderColor: "#111d1b", borderWidth: 3, hoverOffset: 3 }] },
  options: {
    responsive: true,
    maintainAspectRatio: false,
    cutout: "68%",
    animation: { duration: 350 },
    plugins: { legend: { position: "bottom", labels: { color: "#8fa69c", boxWidth: 7, boxHeight: 7, padding: 13, font: { family: "DM Mono", size: 8 } } } },
  },
});

function setHealth(ok, text) {
  const element = document.getElementById("health");
  element.className = `model-status ${ok ? "ok" : "bad"}`;
  element.querySelector("span").textContent = text;
}

function updateSessionUI() {
  const isAdmin = currentUser?.role === "admin";
  const loggedIn = Boolean(currentUser);
  const canConfigure = isAdmin && ["stopped", "error"].includes(captureState);
  document.getElementById("session-name").textContent = loggedIn ? `${currentUser.username} / ${currentUser.role}` : "Read-only view";
  sessionSignIn.hidden = loggedIn;
  sessionSignOut.hidden = !loggedIn;
  viewerExport.hidden = currentUser?.role !== "viewer";
  signInLink.hidden = isAdmin;
  captureAuthState.textContent = isAdmin
    ? `Signed in as ${currentUser.username}; capture controls enabled.`
    : loggedIn
      ? "Viewer access: an administrator must sign in to control capture."
      : "Sign in as an administrator to control capture.";
  captureInterface.disabled = !canConfigure;
  captureFilter.disabled = !canConfigure;
  captureStartButton.disabled = !canConfigure;
  captureStopButton.disabled = !isAdmin || captureState !== "running";
  demoReplayButton.hidden = !isAdmin;
  demoReplayButton.disabled = !isAdmin || demoReplayRunning;
}

function setCaptureStatus(status, error = "") {
  const labels = { unknown: "Sign-in required", stopped: "Stopped", starting: "Starting", running: "Running", stopping: "Stopping", error: "Error" };
  captureState = labels[status] ? status : "error";
  captureStatusLabel.className = `capture-state ${captureState}`;
  captureStatusLabel.querySelector("span").textContent = labels[captureState];
  captureError.textContent = error;
  updateSessionUI();
}

function setCounters(status) {
  document.getElementById("capture-packets").textContent = Number(status.packet_count || 0).toLocaleString();
  document.getElementById("capture-flows").textContent = Number(status.flow_count || 0).toLocaleString();
}

async function apiJSON(path) {
  const token = localStorage.getItem(tokenKey);
  const response = await fetch(path, {
    headers: token ? { Authorization: "Bearer " + token } : {},
  });
  if (response.status === 401) {
    localStorage.removeItem(tokenKey);
    window.location.assign("/signin?next=%2Fdashboard");
    throw new Error("Your session expired. Sign in again.");
  }
  if (!response.ok) throw new Error(`Request failed (${response.status})`);
  return response.json();
}

function appendCell(row, value, className = "") {
  const cell = document.createElement("td");
  cell.textContent = value === null || value === undefined ? "—" : String(value);
  if (className) cell.className = className;
  row.append(cell);
}

function showEmptyRow(body, columns, message) {
  const row = document.createElement("tr");
  const cell = document.createElement("td");
  cell.colSpan = columns;
  cell.className = "empty-row";
  cell.textContent = message;
  row.append(cell);
  body.replaceChildren(row);
}

function renderDetections(items) {
  const body = document.getElementById("det-body");
  document.getElementById("detection-count").textContent = String(items.length);
  if (!items.length) return showEmptyRow(body, 6, "No threats above the recording threshold");
  const fragment = document.createDocumentFragment();
  for (const item of items) {
    const row = document.createElement("tr");
    const ruleSourceLabel = ruleSourceLabels[item.detection_source];
    const score = item.confidence === null || item.confidence === undefined
      ? Number.NaN
      : Number(item.confidence);
    appendCell(row, item.id);
    appendCell(row, item.alert_id);
    appendCell(row, item.predicted_class, "class-cell");
    const severity = document.createElement("td");
    const badge = document.createElement("span");
    badge.className = `threat-badge threat-${["low", "medium", "high"].includes(item.severity) ? item.severity : "unknown"}`;
    badge.textContent = item.severity || "Unknown";
    severity.append(badge);
    row.append(severity);
    appendCell(
      row,
      ruleSourceLabel
        ? "Rule-based"
        : Number.isFinite(score) ? score.toFixed(4) : item.confidence ?? "—",
      "score-cell",
    );
    appendCell(
      row,
      ruleSourceLabel
        ? ruleSourceLabel
        : item.detection_source === "dataset_replay"
          ? "Sample replay · simulated"
          : item.model_version || "—",
    );
    if (item.detection_source === "dataset_replay") {
      row.classList.add("simulated-detection-row");
    }
    fragment.append(row);
  }
  body.replaceChildren(fragment);
}

function showReplayDetections(items) {
  for (const item of items) {
    if (item.detection_source !== "dataset_replay" || !item.simulated) continue;
    if (replayDetections.some((existing) => existing.id === item.id)) continue;
    replayDetections.unshift(item);
  }
  replayDetections = replayDetections.slice(0, 12);
  renderDetections([...replayDetections, ...persistedDetections]);
}

function renderAlerts(items) {
  const body = document.getElementById("alert-body");
  document.getElementById("alert-count").textContent = String(items.length);
  if (!items.length) return showEmptyRow(body, 6, "No threat alerts recorded yet");
  const fragment = document.createDocumentFragment();
  for (const item of items) {
    const row = document.createElement("tr");
    const parsed = item.timestamp ? new Date(item.timestamp) : null;
    const time = parsed && !Number.isNaN(parsed.getTime())
      ? parsed.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" })
      : item.timestamp || "—";
    appendCell(row, item.id);
    appendCell(row, time);
    const severity = document.createElement("td");
    const badge = document.createElement("span");
    badge.className = `threat-badge threat-${["low", "medium", "high"].includes(item.severity) ? item.severity : "unknown"}`;
    badge.textContent = item.severity || "Unknown";
    severity.append(badge);
    row.append(severity);
    appendCell(row, item.source_ip || "—");
    appendCell(row, item.dest_ip || "—");
    appendCell(row, item.protocol || "—");
    fragment.append(row);
  }
  body.replaceChildren(fragment);
}

function renderTrafficFlow(flow) {
  const source = String(flow.source_ip || "unknown");
  const destination = String(flow.dest_ip || "unknown");
  const packets = Number(flow.packets) || 0;
  const bytes = Number(flow.bytes) || 0;
  document.getElementById("traffic-origin").textContent = source;
  const siteName = String(flow.site_name || destination);
  document.getElementById("traffic-destination").textContent = siteName;
  document.getElementById("traffic-summary").textContent = `${source} → ${siteName} / ${flow.protocol || "unknown"}`;
  document.getElementById("traffic-volume").textContent =
    `${packets.toLocaleString()} packets · ${bytes.toLocaleString()} bytes · IP ${destination} · Live only; not stored as an alert.`;
  const live = document.getElementById("traffic-live");
  live.className = "traffic-live is-active";
  live.lastChild.textContent = " LIVE FLOW";

  for (const id of ["traffic-packet", "traffic-packet-right"]) {
    const packet = document.getElementById(id);
    packet.classList.remove("is-moving");
    void packet.offsetWidth;
    packet.classList.add("is-moving");
  }

  const event = document.createElement("div");
  event.className = "traffic-event";
  const route = document.createElement("strong");
  route.textContent = `${source} → ${siteName}`;
  const details = document.createElement("span");
  const modelScore = flow.model_score === null || flow.model_score === undefined
    ? Number.NaN
    : Number(flow.model_score);
  const modelVerdict = Number.isFinite(modelScore)
    ? `${flow.model_prediction || "Unknown"} · score ${modelScore.toFixed(3)}`
    : "unavailable";
  details.textContent =
    `${flow.protocol || "IP"} · ${destination} · ${packets} pkt · ${bytes} B · live ML: ${modelVerdict}`;
  event.append(route, details);
  const recent = document.getElementById("traffic-recent");
  recent.prepend(event);
  while (recent.children.length > 5) recent.lastElementChild.remove();
}

async function refresh() {
  if (!localStorage.getItem(tokenKey)) return;
  try {
    const [health, stats, detections, alerts] = await Promise.all([
      apiJSON("/health"), apiJSON("/stats"), apiJSON("/detections?limit=50"), apiJSON("/alerts?limit=50"),
    ]);
    setHealth(Boolean(health.model_loaded), health.model_loaded ? "Model loaded" : "Model missing");
    document.getElementById("m-alerts").textContent = Number(stats.alerts || 0).toLocaleString();
    document.getElementById("m-dets").textContent = Number(stats.detections || 0).toLocaleString();
    document.getElementById("m-acts").textContent = Number(stats.actions || 0).toLocaleString();
    classChart.data.labels = Object.keys(stats.by_class || {});
    classChart.data.datasets[0].data = Object.values(stats.by_class || {});
    classChart.update();
    actionChart.data.labels = Object.keys(stats.by_action || {});
    actionChart.data.datasets[0].data = Object.values(stats.by_action || {});
    actionChart.update();
    persistedDetections = Array.isArray(detections) ? detections : [];
    renderDetections([...replayDetections, ...persistedDetections]);
    renderAlerts(Array.isArray(alerts) ? alerts : []);
    document.getElementById("last-updated").textContent = new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
  } catch (error) {
    setHealth(false, "API unavailable");
    console.error("Dashboard refresh failed", error);
  }
}

async function captureRequest(path, options = {}) {
  const token = localStorage.getItem(tokenKey);
  if (!token) throw new Error("Sign in as an administrator to control capture.");
  const response = await fetch(path, {
    ...options,
    headers: { Authorization: "Bearer " + token, ...(options.headers || {}) },
  });
  const body = await response.json();
  if (response.status === 401) {
    localStorage.removeItem(tokenKey);
    currentUser = null;
    updateSessionUI();
  }
  if (!response.ok) throw new Error(body.detail || `Request failed (${response.status})`);
  return body;
}

demoReplayButton.addEventListener("click", async () => {
  if (currentUser?.role !== "admin" || demoReplayRunning) return;
  demoReplayRunning = true;
  demoReplayStatus.hidden = true;
  demoReplayStatus.classList.remove("error");
  demoReplayButton.textContent = "Replaying samples…";
  updateSessionUI();
  try {
    const result = await captureRequest("/api/v1/demo/replay", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        labels: ["Botnet", "Brute Force", "DDoS", "Web Attack"],
      }),
    });
    showReplayDetections(result.items || []);
    demoReplayStatus.textContent = result.notice;
    demoReplayStatus.hidden = false;
  } catch (error) {
    demoReplayStatus.textContent = error.message || "Safe model replay failed.";
    demoReplayStatus.classList.add("error");
    demoReplayStatus.hidden = false;
  } finally {
    demoReplayRunning = false;
    demoReplayButton.textContent = "Replay four sample detections";
    updateSessionUI();
  }
});

viewerExport.addEventListener("click", async () => {
  viewerExport.disabled = true;
  try {
    const token = localStorage.getItem(tokenKey);
    const response = await fetch("/api/v1/detections/export.csv", {
      headers: { Authorization: "Bearer " + token },
    });
    if (!response.ok) {
      const body = await response.json();
      throw new Error(body.detail || `Export failed (${response.status})`);
    }
    const download = document.createElement("a");
    download.href = URL.createObjectURL(await response.blob());
    download.download = "aegisai-threat-report.csv";
    download.click();
    URL.revokeObjectURL(download.href);
  } catch (error) {
    captureError.textContent = error.message || "Threat report export failed.";
  } finally {
    viewerExport.disabled = false;
  }
});

async function loadInterfaces() {
  const result = await captureRequest("/api/v1/capture/interfaces");
  const previous = captureInterface.value;
  captureInterface.replaceChildren();
  const placeholder = document.createElement("option");
  placeholder.value = "";
  placeholder.textContent = result.interfaces?.length ? "Select an interface" : "No interfaces available";
  captureInterface.append(placeholder);
  for (const name of result.interfaces || []) {
    const option = document.createElement("option");
    option.value = name;
    option.textContent = name;
    captureInterface.append(option);
  }
  if (result.interfaces?.includes(previous)) captureInterface.value = previous;
  interfacesLoaded = true;
  if (!result.interfaces?.length) throw new Error("No interfaces enumerated; check Scapy and Npcap.");
}

async function refreshCaptureStatus() {
  if (!currentUser) return;
  try {
    if (currentUser.role === "admin" && !interfacesLoaded) await loadInterfaces();
    const status = await captureRequest("/api/v1/capture/status");
    setCaptureStatus(status.status, status.last_error || "");
    setCounters(status);
  } catch (error) {
    setCaptureStatus("error", error.message);
  }
}

async function loadSession() {
  if (!localStorage.getItem(tokenKey)) {
    updateSessionUI();
    setHealth(false, "Sign in required");
    return;
  }
  try {
    currentUser = await captureRequest("/api/v1/auth/me");
    updateSessionUI();
    await refreshCaptureStatus();
  } catch (error) {
    localStorage.removeItem(tokenKey);
    currentUser = null;
    updateSessionUI();
    captureError.textContent = error.message;
  }
}

captureStartButton.addEventListener("click", async () => {
  captureError.textContent = "";
  setCaptureStatus("starting");
  try {
    const result = await captureRequest("/api/v1/capture/start", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ interface: captureInterface.value || null, bpf_filter: captureFilter.value.trim() || "ip", idle_timeout: 2.0 }),
    });
    setCaptureStatus(result.status, result.last_error || "");
    setCounters(result);
  } catch (error) {
    setCaptureStatus("error", error.message);
  }
});

captureStopButton.addEventListener("click", async () => {
  captureError.textContent = "";
  setCaptureStatus("stopping");
  try {
    const result = await captureRequest("/api/v1/capture/stop", { method: "POST" });
    setCaptureStatus(result.status, result.last_error || "");
    setCounters(result);
    await refresh();
  } catch (error) {
    setCaptureStatus("error", error.message);
  }
});

sessionSignOut.addEventListener("click", async () => {
  try {
    if (currentUser?.role === "admin" && captureState === "running") {
      setCaptureStatus("stopping");
      const result = await captureRequest("/api/v1/capture/stop", { method: "POST" });
      setCaptureStatus(result.status, result.last_error || "");
      setCounters(result);
    }
  } catch (error) {
    captureError.textContent = error.message;
    return;
  }
  localStorage.removeItem(tokenKey);
  currentUser = null;
  interfacesLoaded = false;
  replayDetections = [];
  persistedDetections = [];
  renderDetections([]);
  setCaptureStatus("stopped");
  updateSessionUI();
});

function connectDetectionFeed() {
  const token = localStorage.getItem(tokenKey);
  if (!token) return;
  const scheme = window.location.protocol === "https:" ? "wss:" : "ws:";
  const socket = new WebSocket(`${scheme}//${window.location.host}/ws/feed?access_token=${encodeURIComponent(token)}`);
  socket.addEventListener("message", (event) => {
    try {
      const message = JSON.parse(event.data);
      if (message.type === "traffic_flow") renderTrafficFlow(message);
      else if (message.detection_source === "dataset_replay") showReplayDetections([message]);
      else if (message.predicted_class) refresh();
    } catch (error) {
      console.error("Invalid live detection event", error);
    }
  });
  socket.addEventListener("close", (event) => {
    if (event.code === 4401) {
      localStorage.removeItem(tokenKey);
      window.location.assign("/signin?next=%2Fdashboard");
      return;
    }
    window.clearTimeout(reconnectTimer);
    reconnectTimer = window.setTimeout(connectDetectionFeed, 2000);
  });
  socket.addEventListener("error", () => socket.close());
}

updateSessionUI();
refresh();
loadSession();
window.setInterval(refresh, 5000);
window.setInterval(refreshCaptureStatus, 3000);
connectDetectionFeed();