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

function bucketLabel(id) {
  for (var i = 0; i < TS_BUCKETS.length; i++) if (TS_BUCKETS[i].id === id) return TS_BUCKETS[i].label;
  return id;
}

// reportWidgetAPI is the report URL of a widget: its saved query from the
// Reports page (#178), with days unless the query has its own range.
function reportWidgetAPI(w) {
  var q = new URLSearchParams(w.query || "");
  if (w.days) q.set("days", String(w.days));
  else if (!q.has("from") && !q.has("to")) q.set("days", "7");
  return "/api/reports/" + encodeURIComponent(w.report) + "?" + q.toString();
}

function apiFor(w) {
  for (var i = 0; i < catalog.length; i++) {
    if (catalog[i].type === w.type) {
      if (w.type === "report") return reportWidgetAPI(w);
      if (w.type === "timeseries") return "/api/reports/timeseries?days=" + (w.days || 7);
      if (w.type === "causes") return "/api/reports/causes?days=" + (w.days || 7);
      if (w.type === "commit") return "/api/commit?days=" + (w.days || 7);
      return catalog[i].api;
    }
  }
  return null;
}

function titleFor(w) {
  if (w.title) return w.title;
  if (w.type === "improvements") return improvementsTitle(dashMode);
  for (var i = 0; i < catalog.length; i++) {
    if (catalog[i].type === w.type) {
      if (w.type === "report") return catalog[i].title + ": " + w.report;
      if (w.type === "timeseries") return catalog[i].title + ": " + bucketLabel(w.bucket || "all");
      return catalog[i].title;
    }
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
    if (w.type === "timeseries") { renderTimeSeries(body, r.data, w.bucket || "all"); return; }
    if (w.type === "causes") { renderCauses(body, r.data); return; }
    if (w.type === "commit") { renderCommitGraphs(body, r.data); return; }
    var rows = firstArray(r.data);
    if (rows) body.appendChild(dataTable(rows, w.type === "improvements"));
    else body.appendChild(el("pre", "mono", formatJSON(r.data)));
  }, function (err) { clear(body); body.appendChild(el("p", "empty", err.message)); });
}

// Grid geometry: a row has GRID_COLUMNS columns; a widget with h set is h
// rows of GRID_ROW_PX tall. The CSS classes w-N and h-N must match.
var GRID_COLUMNS = 12;
var MAX_ROWS = 8;
var GRID_ROW_PX = 144;
var DEFAULT_W = 6;
var REFRESHES = [15, 30, 60, 300];
var DAY_CHOICES = {commit: [1, 7, 30], other: [1, 7, 30, 90, 365]};

// cards maps a widget object to its card and refresh timer, so a move or a
// resize updates the page without reading every widget again.
var cards = new Map();
var dragFrom = -1;

function clamp(n, lo, hi) { return Math.max(lo, Math.min(hi, n)); }

function widgetW(w) { return w.w || DEFAULT_W; }

// normalize turns the pre-#182 wide flag into a width.
function normalize(spec) {
  spec.widgets = spec.widgets || [];
  spec.widgets.forEach(function (w) {
    if (w.wide) { w.w = GRID_COLUMNS; delete w.wide; }
  });
  return spec;
}

function sizeClass(w) {
  return "card widget w-" + widgetW(w) + (w.h ? " h-" + w.h : "");
}

function stopTimers() {
  cards.forEach(function (c) { clearInterval(c.timer); });
  cards.clear();
}

function startTimer(w) {
  var c = cards.get(w);
  clearInterval(c.timer);
  c.timer = setInterval(function () { renderWidget(w, c.box); }, (w.refresh || REFRESHES[0]) * 1000);
}

// moveWidget puts the widget at index i at index to (clamped). Moving a
// node in the DOM can drop its focus, so the focused element gets it back.
function moveWidget(i, to) {
  to = clamp(to, 0, current.widgets.length - 1);
  if (to === i) return;
  var active = document.activeElement;
  var w = current.widgets.splice(i, 1)[0];
  current.widgets.splice(to, 0, w);
  layoutGrid();
  renderList();
  if (active && document.contains(active)) active.focus();
  announce("Moved " + titleFor(w) + " to position " + (to + 1) + " of " + current.widgets.length + ".");
}

// resizeWidget sets width (columns) and height (rows, 0 fits the content).
function resizeWidget(w, cols, rows) {
  w.w = clamp(cols, 1, GRID_COLUMNS);
  w.h = clamp(rows, 0, MAX_ROWS);
  if (!w.h) delete w.h;
  cards.get(w).box.className = sizeClass(w);
  renderList();
  announce(titleFor(w) + " is " + w.w + " of " + GRID_COLUMNS + " columns" + (w.h ? " and " + w.h + " rows tall." : " and fits its content."));
}

function announce(text) {
  document.getElementById("db-live").textContent = text;
}

function layoutGrid() {
  var grid = document.getElementById("db-grid");
  current.widgets.forEach(function (w) { grid.appendChild(cards.get(w).box); });
}

// Pointer resize: the pointer's place inside the grid gives the columns and
// rows, snapped to the grid.
function dragResize(w, handle, e) {
  var box = cards.get(w).box;
  var colW = document.getElementById("db-grid").getBoundingClientRect().width / GRID_COLUMNS;
  try { handle.setPointerCapture(e.pointerId); } catch (err) { /* synthetic pointer */ }
  function move(ev) {
    var r = box.getBoundingClientRect();
    var cols = Math.round((ev.clientX - r.left) / colW);
    var rows = Math.round((ev.clientY - r.top) / GRID_ROW_PX);
    if (clamp(cols, 1, GRID_COLUMNS) !== widgetW(w) || clamp(rows, 1, MAX_ROWS) !== (w.h || 0)) resizeWidget(w, cols, rows);
  }
  function done() {
    handle.removeEventListener("pointermove", move);
    handle.removeEventListener("pointerup", done);
    handle.removeEventListener("pointercancel", done);
  }
  handle.addEventListener("pointermove", move);
  handle.addEventListener("pointerup", done);
  handle.addEventListener("pointercancel", done);
}

function grip(kind, text, label) {
  var b = el("button", "grip grip-" + kind, text);
  b.type = "button";
  b.setAttribute("aria-label", label);
  return b;
}

function buildCard(w) {
  var box = el("article", sizeClass(w));
  var head = el("div", "widget-head");
  head.appendChild(el("h3", "", titleFor(w)));
  var tools = el("div", "widget-tools");
  var move = grip("move", "⠿", "Move " + titleFor(w) + ". Arrow keys reorder it; Home and End send it first or last.");
  move.draggable = true;
  var size = grip("size", "◢", "Resize " + titleFor(w) + ". Left and right change the width, up and down the height.");
  tools.appendChild(move);
  tools.appendChild(size);
  head.appendChild(tools);
  box.appendChild(head);
  box.appendChild(el("div", "widget-body", "Loading…"));

  move.addEventListener("keydown", function (e) {
    var i = current.widgets.indexOf(w);
    var to = {ArrowLeft: i - 1, ArrowUp: i - 1, ArrowRight: i + 1, ArrowDown: i + 1, Home: 0, End: current.widgets.length - 1}[e.key];
    if (to == null) return;
    e.preventDefault();
    moveWidget(i, to);
  });
  size.addEventListener("keydown", function (e) {
    var dw = {ArrowLeft: -1, ArrowRight: 1}[e.key] || 0;
    var dh = {ArrowUp: -1, ArrowDown: 1}[e.key] || 0;
    if (!dw && !dh) return;
    e.preventDefault();
    resizeWidget(w, widgetW(w) + dw, (w.h || 0) + dh);
  });
  size.addEventListener("pointerdown", function (e) { e.preventDefault(); dragResize(w, size, e); });
  move.addEventListener("dragstart", function (e) {
    dragFrom = current.widgets.indexOf(w);
    e.dataTransfer.setData("text/plain", String(dragFrom));
    e.dataTransfer.effectAllowed = "move";
    box.classList.add("dragging");
  });
  move.addEventListener("dragend", function () { box.classList.remove("dragging"); dragFrom = -1; });
  box.addEventListener("dragover", function (e) {
    if (dragFrom < 0) return;
    e.preventDefault();
    e.dataTransfer.dropEffect = "move";
  });
  box.addEventListener("drop", function (e) {
    if (dragFrom < 0) return;
    e.preventDefault();
    moveWidget(dragFrom, current.widgets.indexOf(w));
    dragFrom = -1;
  });
  return box;
}

function renderGrid() {
  var grid = document.getElementById("db-grid");
  stopTimers();
  clear(grid);
  document.getElementById("db-heading").textContent = current.title || "Widgets";
  if (!current.widgets.length) {
    grid.appendChild(el("p", "empty", "No widgets. Add some above and save."));
    return;
  }
  current.widgets.forEach(function (w) {
    var box = buildCard(w);
    cards.set(w, {box: box, timer: 0});
    grid.appendChild(box);
    renderWidget(w, box);
    startTimer(w);
  });
}

function hasOwnRange(w) {
  var q = new URLSearchParams(w.query || "");
  return q.has("from") || q.has("to");
}

function takesDays(w) {
  return ["report", "timeseries", "causes", "commit"].indexOf(w.type) >= 0 && !hasOwnRange(w);
}

function choice(label, values, value, onChange, text) {
  var sel = el("select");
  if (values.indexOf(value) < 0) values = values.concat([value]);
  values.forEach(function (v) {
    var o = el("option", "", text(v));
    o.value = String(v);
    sel.appendChild(o);
  });
  sel.value = String(value);
  sel.setAttribute("aria-label", label);
  sel.addEventListener("change", function () { onChange(Number(sel.value)); });
  return sel;
}

function listButton(text, label, fn) {
  var b = el("button", "small", text);
  b.type = "button";
  b.setAttribute("aria-label", label);
  b.addEventListener("click", fn);
  return b;
}

// renderList is the widget list under the form: the same moves and resizes
// as the grips, as plain buttons and menus.
function renderList() {
  var ol = document.getElementById("db-widgets");
  var had = ol.contains(document.activeElement) ? document.activeElement.getAttribute("aria-label") : null;
  clear(ol);
  current.widgets.forEach(function (w, i) {
    var t = titleFor(w);
    var li = el("li", "", t + " ");
    li.appendChild(listButton("↑", "Move " + t + " earlier", function () { moveWidget(i, i - 1); }));
    li.appendChild(listButton("↓", "Move " + t + " later", function () { moveWidget(i, i + 1); }));
    li.appendChild(choice("Width of " + t, [1, 2, 3, 4, 6, 8, 9, 12], widgetW(w), function (n) { resizeWidget(w, n, w.h || 0); },
      function (n) { return "Width " + n + "/" + GRID_COLUMNS; }));
    li.appendChild(choice("Height of " + t, [0, 1, 2, 3, 4, 5, 6, 8], w.h || 0, function (n) { resizeWidget(w, widgetW(w), n); },
      function (n) { return n ? "Height " + n : "Height: fit"; }));
    li.appendChild(choice("Refresh of " + t, REFRESHES, w.refresh || REFRESHES[0], function (n) {
      if (n === REFRESHES[0]) delete w.refresh; else w.refresh = n;
      startTimer(w);
    }, function (n) { return "Every " + n + " s"; }));
    if (takesDays(w)) {
      li.appendChild(choice("Time window of " + t, w.type === "commit" ? DAY_CHOICES.commit : DAY_CHOICES.other, w.days || 7, function (n) {
        w.days = n;
        renderWidget(w, cards.get(w).box);
      }, function (n) { return n + (n === 1 ? " day" : " days"); }));
    }
    li.appendChild(listButton("Remove", "Remove " + t, function () { current.widgets.splice(i, 1); renderList(); renderGrid(); }));
    ol.appendChild(li);
  });
  if (had) {
    var again = Array.prototype.find.call(ol.querySelectorAll("[aria-label]"), function (n) { return n.getAttribute("aria-label") === had; });
    if (again) again.focus();
  }
}

function select(name) {
  current = {title: "", widgets: []};
  saved.forEach(function (d) { if (d.name === name) current = JSON.parse(JSON.stringify(d.spec)); });
  normalize(current);
  document.getElementById("db-new-name").value = name || "";
  document.getElementById("db-title").value = current.title || "";
  document.getElementById("db-favorite").checked = !!current.favorite;
  renderList();
  renderGrid();
}

// firstDashboard is the one the page opens: the favorite (the newest, if
// more than one is marked), else the first by name.
function firstDashboard() {
  var best = null;
  saved.forEach(function (d) {
    if (d.spec.favorite && (!best || d.updated > best.updated)) best = d;
  });
  if (best) return best.name;
  return saved.length ? saved[0].name : "";
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
      TS_BUCKETS.forEach(function (b) {
        var o = el("option", "", b.label); o.value = b.id; document.getElementById("db-bucket").appendChild(o);
      });
      (data.reports || []).forEach(function (r) {
        var o = el("option", "", r.name); o.value = r.name; document.getElementById("db-report").appendChild(o);
      });
    }
    var sel = document.getElementById("db-name");
    clear(sel);
    var none = el("option", "", "(new)"); none.value = ""; sel.appendChild(none);
    saved.forEach(function (d) { var o = el("option", "", (d.spec.favorite ? "★ " : "") + d.name); o.value = d.name; sel.appendChild(o); });
    if (!data.enabled) status("Custom dashboards need a storage plugin that keeps them (sqlite) and auth or basic auth.");
    var name = pick != null ? pick : firstDashboard();
    sel.value = name;
    select(name);
  }, function (err) { status(err.message); });
}

document.getElementById("db-name").addEventListener("change", function (e) { select(e.target.value); });
document.getElementById("db-add").addEventListener("click", function () {
  var w = {type: document.getElementById("db-widget").value, w: Number(document.getElementById("db-width").value)};
  if (w.type === "report") {
    w.report = document.getElementById("db-report").value;
    w.days = Number(document.getElementById("db-days").value) || 7;
  }
  if (w.type === "timeseries") {
    w.bucket = document.getElementById("db-bucket").value;
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
  current.favorite = document.getElementById("db-favorite").checked;
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
