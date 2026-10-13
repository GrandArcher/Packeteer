"use strict";
// The System page (#184): one row per component from GET /api/system.
// Read-only. Rows are built with textContent only. Uses api, el, clear,
// and fmtTime from ui.js. No inline script: the CSP allows scripts from
// this origin only.

var SYSTEM_REFRESH_MS = 5000;

var KIND_TITLES = [
  ["version", "Version"],
  ["ha", "High availability"],
  ["bgp_session", "iBGP sessions"],
  ["rib_source", "RIB sources (BMP)"],
  ["probe_source", "Probe sources"],
  ["prober", "Probers"],
  ["source", "Target sources"],
  ["scorer", "Scorer"],
  ["announcer", "Announcer"],
  ["storage", "Storage"],
  ["notifier", "Notifiers"],
  ["telemetry", "Telemetry"],
  ["federation_peer", "Federation peers"]
];

function systemRow(c) {
  var tr = el("tr");
  tr.setAttribute("data-kind", c.kind);
  tr.setAttribute("data-name", c.name);
  tr.appendChild(el("td", "mono", c.name));
  tr.appendChild(el("td", "mono", c.type || "—"));
  var st = el("td");
  st.appendChild(el("span", "badge sys-" + c.state, c.state));
  tr.appendChild(st);
  tr.appendChild(el("td", "", c.since ? fmtTime(c.since) : "—"));
  tr.appendChild(el("td", c.error ? "bad" : "", c.error || "—"));
  tr.appendChild(el("td", "", c.detail || ""));
  return tr;
}

function renderSystem(data) {
  var root = document.getElementById("system");
  clear(root);
  var by = {};
  (data.components || []).forEach(function (c) {
    (by[c.kind] = by[c.kind] || []).push(c);
  });
  KIND_TITLES.forEach(function (kt) {
    var rows = by[kt[0]];
    if (!rows) return;
    root.appendChild(el("h3", "", kt[1]));
    var table = el("table");
    var head = el("tr");
    ["Name", "Type", "State", "Since", "Last error", "Detail"].forEach(function (h) { head.appendChild(el("th", "", h)); });
    table.appendChild(el("thead")).appendChild(head);
    var body = el("tbody");
    rows.forEach(function (c) { body.appendChild(systemRow(c)); });
    table.appendChild(body);
    root.appendChild(table);
  });
  var s = data.summary || {};
  document.getElementById("system-summary").textContent =
    s.total + " components: " + s.ok + " ok, " + s.degraded + " degraded, " + s.down + " down, " + s.idle + " idle.";
}

function loadSystem() {
  var status = document.getElementById("system-status");
  return api("GET", "/api/system").then(function (data) {
    status.textContent = "";
    status.className = "tag";
    renderSystem(data);
  }, function (err) {
    status.textContent = err.status === 403 ? "Your account may not read this page." : err.message;
    status.className = "bad";
  });
}

document.getElementById("refresh").addEventListener("click", loadSystem);
loadSystem();
setInterval(loadSystem, SYSTEM_REFRESH_MS);
