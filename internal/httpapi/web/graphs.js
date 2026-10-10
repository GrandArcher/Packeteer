"use strict";
// Graphs page (#129): the timeseries report as before/after charts. Loaded
// after app.js (el, clear, getJSON) and charts.js. Read-only.

var graphData = null;

var BUCKET_NOTES = {
  all: "Every destination Packeteer has an improvement for, on the days it was active.",
  problem: "Destinations moved because the native path broke the loss or latency thresholds (not for commit or cost).",
  better_20: "Days the chosen path's loss or latency was at least 20% lower than the native path's.",
  better_50: "Days the chosen path's loss or latency was at least 50% lower than the native path's."
};

function graphBucket() {
  var sel = document.getElementById("graph-bucket");
  return (sel && sel.value) || "all";
}

function graphURL(format) {
  var days = document.getElementById("graph-days").value || "7";
  var url = "/api/reports/timeseries?days=" + encodeURIComponent(days);
  if (format) url += "&format=" + format;
  return url;
}

function drawGraph() {
  var root = document.getElementById("graph");
  var note = document.getElementById("graph-note");
  if (note) note.textContent = BUCKET_NOTES[graphBucket()] || "";
  if (graphData) renderTimeSeries(root, graphData, graphBucket());
}

function loadGraph() {
  var root = document.getElementById("graph");
  document.getElementById("graph-csv").setAttribute("href", graphURL("csv"));
  getJSON(graphURL("")).then(function (data) {
    graphData = data;
    drawGraph();
  }, function (err) {
    graphData = null;
    clear(root);
    root.appendChild(el("p", "empty", err.message));
  });
}

function initGraphs() {
  var sel = document.getElementById("graph-bucket");
  if (!sel) return;
  TS_BUCKETS.forEach(function (b) {
    var o = el("option", "", b.label);
    o.value = b.id;
    sel.appendChild(o);
  });
  sel.addEventListener("change", drawGraph);
  document.getElementById("graph-days").addEventListener("change", loadGraph);
  document.getElementById("graph-load").addEventListener("click", loadGraph);
  getJSON("/api/reports").then(function (data) {
    if (!data || !data.enabled) {
      var root = document.getElementById("graph");
      clear(root);
      root.appendChild(el("p", "empty", "History is off. Add storage: {type: sqlite} to the config and mount /var/lib/packeteer."));
      return;
    }
    loadGraph();
  }, function (err) {
    var root = document.getElementById("graph");
    clear(root);
    root.appendChild(el("p", "empty", err.message));
  });
}

initGraphs();
