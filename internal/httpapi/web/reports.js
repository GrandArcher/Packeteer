"use strict";
// Reports page (#178): a catalog grouped by category, a range picker in
// local time (sent as UTC), the filters a report supports, sortable columns,
// CSV and XLSX export, and "add to dashboard". The view lives in the URL.
// Sorting and filtering happen on the server, so the table, CSV, and XLSX
// hold the same rows. Loaded after app.js (el, clear, getJSON, fmtTime,
// prefixCell). Read-only apart from saving a dashboard widget.

var REPORT_FILTERS = [
  {name: "provider", input: "rf-provider"},
  {name: "asn", input: "rf-asn"},
  {name: "prefix", input: "rf-prefix"},
  {name: "cause", input: "rf-cause"},
  {name: "ip_version", input: "rf-ip"}
];
var REPORT_PRESETS = ["1", "7", "30", "90", "365"];

var reportDefs = [];
var reportDef = null;
var reportView = null;
var reportData = null;

// reportViewFromURL reads the page URL, which uses the API's own
// parameters: days, or from and to (UTC), then the filters, sort, order,
// and limit. A link from the search page names only the report and a
// prefix or origin AS; it gets the 90 days it always had.
function reportViewFromURL() {
  var q = new URLSearchParams(window.location.search);
  var v = {report: q.get("report") || "", days: q.get("days") || "", from: q.get("from") || "", to: q.get("to") || "",
    sort: q.get("sort") || "", order: q.get("order") || "", limit: q.get("limit") || "", filters: {}};
  REPORT_FILTERS.forEach(function (f) { v.filters[f.name] = q.get(f.name) || ""; });
  if (!v.days && !v.from && !v.to) v.days = v.report === "improvements" ? "90" : "7";
  return v;
}

// reportParams is the API query for the view, without the format.
function reportParams(v) {
  var q = new URLSearchParams();
  if (v.from || v.to) {
    if (v.from) q.set("from", v.from);
    if (v.to) q.set("to", v.to);
  } else {
    q.set("days", v.days || "7");
  }
  REPORT_FILTERS.forEach(function (f) {
    if (v.filters[f.name]) q.set(f.name, v.filters[f.name]);
  });
  if (v.sort) q.set("sort", v.sort);
  if (v.sort && v.order) q.set("order", v.order);
  if (v.limit) q.set("limit", v.limit);
  return q;
}

function reportAPI(v, format) {
  var q = reportParams(v);
  if (format) q.set("format", format);
  return "/api/reports/" + encodeURIComponent(v.report) + "?" + q.toString();
}

function reportSyncURL() {
  var q = reportParams(reportView);
  var qs = "report=" + encodeURIComponent(reportView.report) + "&" + q.toString();
  window.history.replaceState(null, "", window.location.pathname + "?" + qs);
}

// localInput formats a UTC time for a datetime-local input.
function localInput(iso) {
  var d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "";
  var p = function (n) { return (n < 10 ? "0" : "") + n; };
  return d.getFullYear() + "-" + p(d.getMonth() + 1) + "-" + p(d.getDate()) + "T" + p(d.getHours()) + ":" + p(d.getMinutes());
}

// utcFromInput turns a datetime-local value (local time) into RFC 3339 UTC.
// A date-only value from an old link is already UTC and is kept.
function utcFromInput(value) {
  var d = new Date(value);
  if (Number.isNaN(d.getTime())) return "";
  return d.toISOString().replace(/\.\d+Z$/, "Z");
}

function reportFillForm() {
  var v = reportView;
  var range = document.getElementById("report-range");
  var custom = !!(v.from || v.to);
  if (!custom && REPORT_PRESETS.indexOf(v.days) < 0) {
    var o = el("option", "", "Last " + v.days + " days");
    o.value = v.days;
    range.insertBefore(o, range.querySelector("option[value=custom]"));
  }
  range.value = custom ? "custom" : v.days;
  document.getElementById("report-from").value = v.from ? localInput(v.from) : "";
  document.getElementById("report-to").value = v.to ? localInput(v.to) : "";
  reportShowRange();
  REPORT_FILTERS.forEach(function (f) {
    var supported = reportDef.filters.indexOf(f.name) >= 0;
    document.getElementById(f.input + "-label").hidden = !supported;
    document.getElementById(f.input).value = supported ? v.filters[f.name] : "";
  });
  document.getElementById("report-limit-label").hidden = !reportDef.limited;
  var limit = document.getElementById("report-limit");
  if (reportDef.limited && v.limit && !limit.querySelector("option[value='" + v.limit + "']")) {
    var lo = el("option", "", v.limit);
    lo.value = v.limit;
    limit.appendChild(lo);
  }
  limit.value = reportDef.limited ? v.limit : "";
}

function reportShowRange() {
  var custom = document.getElementById("report-range").value === "custom";
  document.getElementById("report-from-label").hidden = !custom;
  document.getElementById("report-to-label").hidden = !custom;
}

function reportError(msg) {
  var p = document.getElementById("report-error");
  p.textContent = msg || "";
  p.hidden = !msg;
}

// reportReadForm copies the form into the view. It returns false, with the
// reason shown, when a custom range cannot be sent.
function reportReadForm() {
  var v = reportView;
  var range = document.getElementById("report-range").value;
  v.days = v.from = v.to = "";
  if (range === "custom") {
    var from = document.getElementById("report-from").value;
    var to = document.getElementById("report-to").value;
    if (!from || !to) { reportError("A custom range needs a From and a To."); return false; }
    v.from = utcFromInput(from);
    v.to = utcFromInput(to);
    if (!v.from || !v.to || v.from >= v.to) { reportError("From must be before To."); return false; }
  } else {
    v.days = range;
  }
  REPORT_FILTERS.forEach(function (f) {
    v.filters[f.name] = reportDef.filters.indexOf(f.name) >= 0 ? document.getElementById(f.input).value.trim() : "";
  });
  v.limit = reportDef.limited ? document.getElementById("report-limit").value : "";
  reportError("");
  return true;
}

function reportCatalog() {
  var root = document.getElementById("report-catalog");
  clear(root);
  var seen = [];
  reportDefs.forEach(function (d) { if (seen.indexOf(d.category) < 0) seen.push(d.category); });
  seen.forEach(function (cat) {
    var group = el("div", "catalog-group");
    group.appendChild(el("h3", "", cat));
    reportDefs.forEach(function (d) {
      if (d.category !== cat) return;
      var a = el("a", "", d.name);
      a.href = "/reports.html?report=" + encodeURIComponent(d.name);
      a.title = d.summary;
      if (reportDef && d.name === reportDef.name) a.setAttribute("aria-current", "page");
      group.appendChild(a);
    });
    root.appendChild(group);
  });
}

function reportCell(col, row) {
  var v = row[col.key];
  var td = el("td", col.type === "number" ? "num" : "");
  if (v == null || v === "") { td.textContent = "—"; return td; }
  if (col.type === "number") {
    td.textContent = String(Math.round(v * 1000) / 1000);
    if (col.key === "origin_asn" || (col.key === "key" && reportDef.name === "asns")) {
      clear(td);
      var as = el("a", "", String(v));
      as.href = "/prefixes.html?asn=" + encodeURIComponent(v);
      td.appendChild(as);
    }
    return td;
  }
  if (col.type === "time") { td.textContent = fmtTime(v); return td; }
  if (col.type === "prefix") {
    var cell = prefixCell(v);
    return cell;
  }
  td.textContent = String(v);
  return td;
}

function reportSort(col) {
  var v = reportView;
  if (v.sort === col.key) {
    v.order = v.order === "desc" ? "asc" : "desc";
  } else {
    v.sort = col.key;
    v.order = col.type === "number" || col.type === "time" ? "desc" : "asc";
  }
  reportLoad();
}

function reportHeader(col) {
  var th = el("th");
  var active = reportView.sort === col.key;
  th.setAttribute("aria-sort", active ? (reportView.order === "desc" ? "descending" : "ascending") : "none");
  var label = col.label + (col.unit ? " (" + col.unit + ")" : "");
  var btn = el("button", "sortbtn", label + (active ? (reportView.order === "desc" ? " ▼" : " ▲") : ""));
  btn.type = "button";
  btn.addEventListener("click", function () { reportSort(col); });
  th.appendChild(btn);
  return th;
}

function reportRender(data) {
  reportData = data;
  var root = document.getElementById("report");
  clear(root);
  var rows = (data && data.rows) || [];
  var cols = (data && data.columns) || [];
  var count = document.getElementById("report-count");
  count.textContent = "Showing " + rows.length + " of " + (data.total != null ? data.total : rows.length) + " rows, " +
    fmtTime(data.from) + " to " + fmtTime(data.to) + ".";
  if (!rows.length) {
    root.appendChild(el("p", "empty", "No rows match this range and these filters."));
    return;
  }
  var table = el("table");
  var hr = el("tr");
  cols.forEach(function (c) { hr.appendChild(reportHeader(c)); });
  var thead = el("thead");
  thead.appendChild(hr);
  table.appendChild(thead);
  var tb = el("tbody");
  rows.forEach(function (r) {
    var tr = el("tr");
    cols.forEach(function (c) { tr.appendChild(reportCell(c, r)); });
    tb.appendChild(tr);
  });
  table.appendChild(tb);
  var wrap = el("div", "table-wrap");
  wrap.appendChild(table);
  root.appendChild(wrap);
}

function reportLoad() {
  reportSyncURL();
  document.getElementById("report-csv").setAttribute("href", reportAPI(reportView, "csv"));
  document.getElementById("report-xlsx").setAttribute("href", reportAPI(reportView, "xlsx"));
  var root = document.getElementById("report");
  getJSON(reportAPI(reportView, "")).then(reportRender, function (err) {
    reportData = null;
    clear(root);
    document.getElementById("report-count").textContent = "";
    root.appendChild(el("p", "empty", err.message.replace(/^\S+ failed: /, "")));
  });
}

function reportSelect(name) {
  reportDef = null;
  reportDefs.forEach(function (d) { if (d.name === name) reportDef = d; });
  if (!reportDef) reportDef = reportDefs[0];
  reportView.report = reportDef.name;
  document.getElementById("report-title").textContent = reportDef.name;
  document.getElementById("report-summary").textContent = reportDef.summary;
  reportCatalog();
  reportFillForm();
}

// reportWidgetTitle names a saved view, or "" when it would not fit.
function reportWidgetTitle(v) {
  var parts = [];
  REPORT_FILTERS.forEach(function (f) { if (v.filters[f.name]) parts.push(f.name + " " + v.filters[f.name]); });
  var t = v.report + (parts.length ? " (" + parts.join(", ") + ")" : "");
  return new TextEncoder().encode(t).length <= 100 ? t : "";
}

// reportWidget is the dashboard widget for the current view: the same
// parameters as the page, so the widget shows the same rows.
function reportWidget(v) {
  var q = reportParams(v);
  var w = {type: "report", report: v.report, wide: true};
  var days = q.get("days");
  if (days) { w.days = Number(days); q.delete("days"); }
  var query = q.toString();
  if (query) w.query = query;
  var title = reportWidgetTitle(v);
  if (title) w.title = title;
  return w;
}

function reportStatus(text) {
  document.getElementById("report-status").textContent = text;
}

function reportSend(method, path, body) {
  return fetch(path, {method: method, cache: "no-store", headers: {Accept: "application/json", "Content-Type": "application/json"},
    body: body === undefined ? undefined : JSON.stringify(body)}).then(function (res) {
    return res.text().then(function (text) {
      var data = null;
      try { data = text ? JSON.parse(text) : null; } catch (e) { data = null; }
      if (!res.ok) throw new Error((data && data.error) || res.statusText);
      return data;
    });
  });
}

function reportOpenAdd() {
  var form = document.getElementById("report-add-form");
  if (!form.hidden) { form.hidden = true; return; }
  reportStatus("");
  getJSON("/api/dashboards").then(function (data) {
    if (!data || !data.enabled) {
      reportStatus("Custom dashboards need a storage plugin that keeps them (sqlite) and auth or basic auth.");
      return;
    }
    var sel = document.getElementById("report-dash");
    clear(sel);
    var fresh = el("option", "", "(new dashboard)");
    fresh.value = "";
    sel.appendChild(fresh);
    (data.dashboards || []).forEach(function (d) {
      var o = el("option", "", d.name);
      o.value = d.name;
      sel.appendChild(o);
    });
    if (data.dashboards && data.dashboards.length) sel.value = data.dashboards[0].name;
    form.hidden = false;
  }, function (err) { reportStatus(err.message); });
}

function reportAddWidget(e) {
  e.preventDefault();
  var chosen = document.getElementById("report-dash").value;
  var name = chosen || document.getElementById("report-dash-new").value.trim();
  if (!name) { reportStatus("Pick a dashboard or name a new one."); return; }
  var widget = reportWidget(reportView);
  getJSON("/api/dashboards").then(function (data) {
    var spec = {title: "", widgets: []};
    (data.dashboards || []).forEach(function (d) { if (d.name === name) spec = d.spec; });
    spec.widgets = (spec.widgets || []).concat([widget]);
    return reportSend("PUT", "/api/dashboards/" + encodeURIComponent(name), spec);
  }).then(function () {
    document.getElementById("report-add-form").hidden = true;
    reportStatus("Added " + reportView.report + " to dashboard " + name + ".");
  }, function (err) { reportStatus(err.message.replace(/^\S+ failed: /, "")); });
}

function reportFillProviders() {
  getJSON("/api/providers").then(function (p) {
    var list = document.getElementById("rf-providers");
    ((p && p.providers) || []).forEach(function (x) {
      var o = el("option");
      o.value = x.name;
      list.appendChild(o);
    });
  }, function () {});
}

function reportInit() {
  reportView = reportViewFromURL();
  document.getElementById("report-range").addEventListener("change", reportShowRange);
  document.getElementById("report-form").addEventListener("submit", function (e) {
    e.preventDefault();
    if (reportReadForm()) reportLoad();
  });
  document.getElementById("report-add").addEventListener("click", reportOpenAdd);
  document.getElementById("report-add-form").addEventListener("submit", reportAddWidget);
  reportFillProviders();
  getJSON("/api/reports").then(function (data) {
    reportDefs = (data && data.reports) || [];
    reportSelect(reportView.report);
    var root = document.getElementById("report");
    document.getElementById("report-view").hidden = false;
    if (!data || !data.enabled) {
      clear(root);
      root.appendChild(el("p", "empty", "History is off. Add storage: {type: sqlite} to the config and mount /var/lib/packeteer."));
      return;
    }
    reportLoad();
  }, function (err) {
    document.getElementById("report-view").hidden = false;
    var root = document.getElementById("report");
    clear(root);
    root.appendChild(el("p", "empty", err.message));
  });
}

reportInit();
