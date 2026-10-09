"use strict";

var catalog = [];
var saved = [];
var current = {title: "", widgets: []};
var dashMode = "";

// improvementsTitle matches the main dashboard: Recommended outside
// inject, Active only while routes are announced (#171).
function improvementsTitle(mode) {
  return mode === "inject" ? "Active improvements" : "Recommended improvements";
}

function apiFor(w) {
  for (var i = 0; i < catalog.length; i++) {
    if (catalog[i].type === w.type) {
      if (w.type === "report") return "/api/reports/" + encodeURIComponent(w.report) + "?days=" + (w.days || 7);
      return catalog[i].api;
    }
  }
  return null;
}

function titleFor(w) {
  if (w.title) return w.title;
  if (w.type === "improvements") return improvementsTitle(dashMode);
  for (var i = 0; i < catalog.length; i++) {
    if (catalog[i].type === w.type) return catalog[i].title + (w.type === "report" ? ": " + w.report : "");
  }
  return w.type;
}

// firstArray is the first array in a response (the rows to show).
function firstArray(data) {
  if (Array.isArray(data)) return data;
  if (!data || typeof data !== "object") return null;
  var keys = ["rows", "providers", "improvements", "prefixes", "decisions", "subscriptions", "rules", "anomalies", "peers", "steers"];
  for (var i = 0; i < keys.length; i++) if (Array.isArray(data[keys[i]])) return data[keys[i]];
  for (var k in data) if (Array.isArray(data[k])) return data[k];
  return null;
}

function renderWidget(w, box) {
  var path = apiFor(w);
  var body = box.querySelector(".widget-body");
  if (!path) { body.textContent = "Unknown widget."; return; }
  fetch(path, {cache: "no-store", headers: {Accept: "application/json"}}).then(function (res) {
    return res.json().then(function (data) { return {ok: res.ok, data: data}; });
  }).then(function (r) {
    clear(body);
    if (w.type === "status") {
      var ready = r.data && r.data.ready;
      body.appendChild(el("span", ready ? "dot up" : "dot down", ready ? "ready" : "not ready"));
      if (r.data && r.data.mode) {
        var known = r.data.mode === "observe" || r.data.mode === "suggest" || r.data.mode === "inject";
        body.appendChild(el("span", known ? "badge mode-" + r.data.mode : "badge mode-unknown", r.data.mode));
      }
      return;
    }
    if (w.type === "improvements" && r.data && r.data.mode) {
      dashMode = r.data.mode;
      if (!w.title) {
        var heading = box.querySelector("h3");
        if (heading) heading.textContent = improvementsTitle(dashMode);
      }
    }
    if (!r.ok) { body.appendChild(el("p", "empty", (r.data && r.data.error) || "unavailable")); return; }
    var rows = firstArray(r.data);
    if (rows) body.appendChild(dataTable(rows));
    else body.appendChild(el("pre", "mono", formatJSON(r.data)));
  }, function (err) { clear(body); body.appendChild(el("p", "empty", err.message)); });
}

function renderGrid() {
  var grid = document.getElementById("db-grid");
  clear(grid);
  document.getElementById("db-heading").textContent = current.title || "Widgets";
  if (!current.widgets.length) {
    grid.appendChild(el("p", "empty", "No widgets. Add some above and save."));
    return;
  }
  current.widgets.forEach(function (w) {
    var box = el("article", w.wide ? "card widget wide" : "card widget");
    box.appendChild(el("h3", "", titleFor(w)));
    box.appendChild(el("div", "widget-body", "Loading…"));
    grid.appendChild(box);
    renderWidget(w, box);
  });
}

function renderList() {
  var ol = document.getElementById("db-widgets");
  clear(ol);
  current.widgets.forEach(function (w, i) {
    var li = el("li", "", titleFor(w) + (w.wide ? " (wide)" : "") + " ");
    var up = el("button", "small", "↑");
    up.type = "button";
    up.addEventListener("click", function () {
      if (i > 0) { current.widgets.splice(i - 1, 0, current.widgets.splice(i, 1)[0]); renderList(); renderGrid(); }
    });
    var rm = el("button", "small", "Remove");
    rm.type = "button";
    rm.addEventListener("click", function () { current.widgets.splice(i, 1); renderList(); renderGrid(); });
    li.appendChild(up);
    li.appendChild(rm);
    ol.appendChild(li);
  });
}

function select(name) {
  current = {title: "", widgets: []};
  saved.forEach(function (d) { if (d.name === name) current = JSON.parse(JSON.stringify(d.spec)); });
  current.widgets = current.widgets || [];
  document.getElementById("db-new-name").value = name || "";
  document.getElementById("db-title").value = current.title || "";
  renderList();
  renderGrid();
}

function status(t) { document.getElementById("db-status").textContent = t; }

function load(pick) {
  api("GET", "/api/providers").then(function (p) {
    dashMode = (p && p.mode) || "observe";
  }, function () {
    if (!dashMode) dashMode = "observe";
  }).then(function () {
    return api("GET", "/api/dashboards");
  }).then(function (data) {
    catalog = data.widget_types || [];
    saved = data.dashboards || [];
    var ws = document.getElementById("db-widget");
    if (!ws.options.length) {
      catalog.forEach(function (c) {
        var label = c.type === "improvements" ? improvementsTitle(dashMode) : c.title;
        var o = el("option", "", label);
        o.value = c.type;
        ws.appendChild(o);
      });
      (data.reports || []).forEach(function (r) {
        var o = el("option", "", r.name); o.value = r.name; document.getElementById("db-report").appendChild(o);
      });
    }
    var sel = document.getElementById("db-name");
    clear(sel);
    var none = el("option", "", "(new)"); none.value = ""; sel.appendChild(none);
    saved.forEach(function (d) { var o = el("option", "", d.name); o.value = d.name; sel.appendChild(o); });
    if (!data.enabled) status("Custom dashboards need a storage plugin that keeps them (sqlite) and auth or basic auth.");
    var name = pick != null ? pick : (saved.length ? saved[0].name : "");
    sel.value = name;
    select(name);
  }, function (err) { status(err.message); });
}

document.getElementById("db-name").addEventListener("change", function (e) { select(e.target.value); });
document.getElementById("db-add").addEventListener("click", function () {
  var w = {type: document.getElementById("db-widget").value, wide: document.getElementById("db-wide").checked};
  if (w.type === "report") {
    w.report = document.getElementById("db-report").value;
    w.days = Number(document.getElementById("db-days").value) || 7;
  }
  current.widgets.push(w);
  renderList();
  renderGrid();
});
document.getElementById("db-save").addEventListener("click", function () {
  var name = document.getElementById("db-new-name").value.trim();
  if (!name) { status("Enter a name."); return; }
  current.title = document.getElementById("db-title").value.trim();
  api("PUT", "/api/dashboards/" + encodeURIComponent(name), current).then(function () {
    status("Saved " + name + ".");
    load(name);
  }, function (err) { status(err.message); });
});
document.getElementById("db-delete").addEventListener("click", function () {
  var name = document.getElementById("db-name").value;
  if (!name) return;
  api("DELETE", "/api/dashboards/" + encodeURIComponent(name)).then(function () {
    status("Deleted " + name + ".");
    load("");
  }, function (err) { status(err.message); });
});
load(null);
setInterval(renderGrid, 15000);
