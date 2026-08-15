const classChartCtx = document.getElementById("classChart");
const actionChartCtx = document.getElementById("actionChart");

let classChart = new Chart(classChartCtx, {
  type: "bar",
  data: { labels: [], datasets: [{ label: "Count", data: [], backgroundColor: "#3ecf8e" }] },
  options: {
    responsive: true,
    plugins: { legend: { display: false } },
    scales: {
      x: { ticks: { color: "#9bb5ab" }, grid: { color: "rgba(255,255,255,0.05)" } },
      y: { ticks: { color: "#9bb5ab" }, grid: { color: "rgba(255,255,255,0.05)" }, beginAtZero: true },
    },
  },
});

let actionChart = new Chart(actionChartCtx, {
  type: "doughnut",
  data: {
    labels: [],
    datasets: [{ data: [], backgroundColor: ["#3ecf8e", "#f0b429", "#ff6b6b", "#6ea8fe"] }],
  },
  options: {
    plugins: { legend: { labels: { color: "#e8f3ee" } } },
  },
});

function setHealth(ok, text) {
  const el = document.getElementById("health");
  el.textContent = text;
  el.className = "health " + (ok ? "ok" : "bad");
}

async function refresh() {
  try {
    const [health, stats, dets, alerts] = await Promise.all([
      fetch("/health").then((r) => r.json()),
      fetch("/stats").then((r) => r.json()),
      fetch("/detections?limit=50").then((r) => r.json()),
      fetch("/alerts?limit=50").then((r) => r.json()),
    ]);

    setHealth(health.model_loaded, health.model_loaded ? "Model loaded" : "Model missing");

    document.getElementById("m-alerts").textContent = stats.alerts;
    document.getElementById("m-dets").textContent = stats.detections;
    document.getElementById("m-acts").textContent = stats.actions;

    const classLabels = Object.keys(stats.by_class || {});
    const classValues = Object.values(stats.by_class || {});
    classChart.data.labels = classLabels;
    classChart.data.datasets[0].data = classValues;
    classChart.update();

    const actionLabels = Object.keys(stats.by_action || {});
    const actionValues = Object.values(stats.by_action || {});
    actionChart.data.labels = actionLabels;
    actionChart.data.datasets[0].data = actionValues;
    actionChart.update();

    const detBody = document.getElementById("det-body");
    detBody.innerHTML = dets
      .map(
        (d) => `<tr>
        <td>${d.id}</td>
        <td>${d.alert_id}</td>
        <td>${d.predicted_class}</td>
        <td>${Number(d.confidence).toFixed(4)}</td>
        <td>${d.model_version || ""}</td>
      </tr>`
      )
      .join("");

    const alertBody = document.getElementById("alert-body");
    alertBody.innerHTML = alerts
      .map(
        (a) => `<tr>
        <td>${a.id}</td>
        <td>${a.timestamp || ""}</td>
        <td>${a.source_ip || ""}</td>
        <td>${a.dest_ip || ""}</td>
        <td>${a.protocol || ""}</td>
      </tr>`
      )
      .join("");
  } catch (err) {
    setHealth(false, "API unreachable");
    console.error(err);
  }
}

refresh();
setInterval(refresh, 5000);
