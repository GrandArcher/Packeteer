"use strict";
// Overview charts (#349). Loaded after app.js and charts.js. app.js calls
// renderOverviewCharts on every refresh with the provider figures it read;
// the improvements report is read here, at most once a minute.

var OV_REPORT_MS = 60000;
var OV_REPORT_LIMIT = 10000;
var impReport = {at: 0, loading: false, rows: null, error: ""};

function loadImprovementReport() {
  if (impReport.loading || Date.now() - impReport.at < OV_REPORT_MS) return;
  impReport.loading = true;
  getJSON("/api/reports/improvements?days=1&limit=" + OV_REPORT_LIMIT).then(function (data) {
    impReport.rows = (data && data.rows) || [];
    impReport.error = "";
  }, function (err) {
    impReport.rows = null;
    impReport.error = err.status === 404 ? "History is off. Add storage: {type: sqlite} to the config and mount /var/lib/packeteer to chart improvements over time." : err.message;
  }).then(function () {
    impReport.at = Date.now();
    impReport.loading = false;
    drawImprovementChart();
  });
}

function drawImprovementChart() {
  var root = document.getElementById("chart-improvements");
  if (!root) return;
  if (impReport.rows) {
    renderImprovementCounts(root, impReport.rows, impReport.rows.length >= OV_REPORT_LIMIT);
    return;
  }
  clear(root);
  var fig = el("figure", "ts-fig");
  fig.appendChild(el("figcaption", "", "Recommended / active improvements, last 24 h"));
  fig.appendChild(el("p", "empty ts-empty", impReport.error));
  root.appendChild(fig);
}

function renderOverviewCharts(stats, overview) {
  var latency = document.getElementById("chart-latency");
  if (!latency || !overview) return;
  var names = (overview.providers || []).map(function (p) { return p.name; });
  renderProviderLatency(latency, stats, names);
  loadImprovementReport();
}
