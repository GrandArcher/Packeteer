"use strict";
// The Events page (#173): recent controller events with a severity
// filter, text search, and range picker over GET /api/events, and for
// admins an Audit tab over GET /api/audit. Both are reads; nothing here
// changes the controller. Rows are built with textContent only. Uses api,
// el, clear, and fmtTime from ui.js, and shellMarkEventsSeen from
// shell.js. No inline script: the CSP allows scripts from this origin only.

var EVENT_ROWS = 500;
var AUDIT_ROWS = 200;
var EVENTS_REFRESH_MS = 5000;
var RANGE_MS = {"1h": 3600e3, "24h": 24 * 3600e3, "7d": 7 * 24 * 3600e3, "30d": 30 * 24 * 3600e3};

var eventsTab = "events";
var searchTimer = null;

function eventsQuery() {
  var p = ["limit=" + EVENT_ROWS];
  var sev = document.getElementById("ev-severity").value;
  if (sev) p.push("severity=" + encodeURIComponent(sev));
  var q = document.getElementById("ev-q").value.trim();
  if (q) p.push("q=" + encodeURIComponent(q));
  var range = document.getElementById("ev-range").value;
  if (RANGE_MS[range]) {
    p.push("from=" + encodeURIComponent(new Date(Date.now() - RANGE_MS[range]).toISOString()));
  } else if (range === "custom") {
    var from = document.getElementById("ev-from").value;
    var to = document.getElementById("ev-to").value;
    if (from) p.push("from=" + encodeURIComponent(new Date(from).toISOString()));
    if (to) p.push("to=" + encodeURIComponent(new Date(to).toISOString()));
  }
  return p.join("&");
}

function eventDetail(e) {
  var td = el("td");
  td.appendChild(document.createTextNode(e.message || ""));
  var keys = Object.keys(e.fields || {}).sort();
  if (keys.length) {
    td.appendChild(el("div", "tag mono", keys.map(function (k) { return k + "=" + e.fields[k]; }).join(" ")));
  }
  return td;
}

function renderEvents(list) {
  var root = document.getElementById("events");
  clear(root);
  if (!list.length) {
    root.appendChild(el("p", "empty", "No events match."));
    return;
  }
  var table = el("table");
  var head = el("tr");
  ["Time", "Source", "Severity", "Event", "Detail"].forEach(function (h) { head.appendChild(el("th", "", h)); });
  table.appendChild(el("thead")).appendChild(head);
  var body = el("tbody");
  list.forEach(function (e) {
    var tr = el("tr");
    tr.appendChild(el("td", "", fmtTime(e.time)));
    tr.appendChild(el("td", "", e.source));
    var sev = el("td");
    sev.appendChild(el("span", "badge sev-" + e.severity, e.severity));
    tr.appendChild(sev);
    tr.appendChild(el("td", "mono", e.kind));
    tr.appendChild(eventDetail(e));
    body.appendChild(tr);
  });
  table.appendChild(body);
  root.appendChild(table);
}

function eventsKept(data) {
  var n = document.getElementById("events-kept");
  if (data.stored) {
    n.textContent = "Events are kept in storage for its retention period and survive a restart.";
  } else {
    n.textContent = "Storage is off: these are the events since " + fmtTime(data.since) +
      " (the newest 1000, in memory). They are lost on restart. Turn on storage to keep them (docs/ui.md).";
  }
}

function loadEvents() {
  var status = document.getElementById("events-status");
  return api("GET", "/api/events?" + eventsQuery()).then(function (data) {
    status.textContent = "";
    status.className = "tag";
    eventsKept(data);
    renderEvents(data.events || []);
    shellMarkEventsSeen(data.now);
  }, function (err) {
    status.textContent = err.message;
    status.className = "bad";
  });
}

function renderAudit(list) {
  var root = document.getElementById("audit");
  clear(root);
  if (!list.length) {
    root.appendChild(el("p", "empty", "No audit records."));
    return;
  }
  var table = el("table");
  var head = el("tr");
  ["Time", "Actor", "Role", "Method", "Action", "Target", "Result", "Status"].forEach(function (h) { head.appendChild(el("th", "", h)); });
  table.appendChild(el("thead")).appendChild(head);
  var body = el("tbody");
  list.forEach(function (r) {
    var tr = el("tr");
    tr.appendChild(el("td", "", fmtTime(r.time)));
    tr.appendChild(el("td", "", r.actor));
    tr.appendChild(el("td", "", r.role || "—"));
    tr.appendChild(el("td", "", r.method));
    tr.appendChild(el("td", "mono", r.action));
    tr.appendChild(el("td", "", r.target || "—"));
    var res = el("td");
    res.appendChild(el("span", r.result === "ok" ? "badge" : "badge warn", r.result));
    tr.appendChild(res);
    tr.appendChild(el("td", "", r.status ? r.status : "—"));
    body.appendChild(tr);
  });
  table.appendChild(body);
  root.appendChild(table);
}

function loadAudit() {
  var status = document.getElementById("audit-status");
  return api("GET", "/api/audit?limit=" + AUDIT_ROWS).then(function (data) {
    status.textContent = "";
    status.className = "tag";
    renderAudit(data.records || []);
  }, function (err) {
    status.textContent = err.status === 403 ? "Your account may not read the audit log." : err.message;
    status.className = "bad";
    clear(document.getElementById("audit"));
  });
}

function loadActive() {
  return eventsTab === "audit" ? loadAudit() : loadEvents();
}

function showTab(name) {
  eventsTab = name;
  ["events", "audit"].forEach(function (t) {
    document.getElementById("tab-" + t).setAttribute("aria-selected", t === name ? "true" : "false");
    document.getElementById("panel-" + t).hidden = t !== name;
  });
  loadActive();
}

function rangeChanged() {
  var custom = document.getElementById("ev-range").value === "custom";
  document.getElementById("ev-from-wrap").hidden = !custom;
  document.getElementById("ev-to-wrap").hidden = !custom;
  loadEvents();
}

document.getElementById("tab-events").addEventListener("click", function () { showTab("events"); });
document.getElementById("tab-audit").addEventListener("click", function () { showTab("audit"); });
document.getElementById("ev-severity").addEventListener("change", loadEvents);
document.getElementById("ev-range").addEventListener("change", rangeChanged);
document.getElementById("ev-from").addEventListener("change", loadEvents);
document.getElementById("ev-to").addEventListener("change", loadEvents);
document.getElementById("ev-q").addEventListener("input", function () {
  clearTimeout(searchTimer);
  searchTimer = setTimeout(loadEvents, 300);
});
document.getElementById("refresh").addEventListener("click", loadActive);

// /events.html#audit opens the Audit tab. A non-admin only gets the
// server's refusal there.
showTab(window.location.hash === "#audit" ? "audit" : "events");
setInterval(loadActive, EVENTS_REFRESH_MS);
