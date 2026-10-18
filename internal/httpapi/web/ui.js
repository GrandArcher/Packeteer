"use strict";
// Shared helpers for the settings and dashboards pages (#34). No inline
// script: the CSP allows scripts from this origin only.

function el(tag, className, text) {
  var n = document.createElement(tag);
  if (className) n.className = className;
  if (text != null && text !== "") n.textContent = String(text);
  return n;
}

function clear(node) {
  while (node.firstChild) node.removeChild(node.firstChild);
}

function api(method, path, body) {
  var opts = {method: method, cache: "no-store", headers: {Accept: "application/json"}};
  if (body !== undefined) {
    opts.headers["Content-Type"] = "application/json";
    opts.body = JSON.stringify(body);
  }
  return fetch(path, opts).then(function (res) {
    return res.text().then(function (text) {
      var data = null;
      try { data = text ? JSON.parse(text) : null; } catch (e) { data = null; }
      if (!res.ok) {
        var err = new Error((data && data.error) || res.statusText);
        err.status = res.status;
        err.data = data;
        throw err;
      }
      return data;
    });
  });
}

// fmtTime is the dashboard's local time. app.js keeps the same function
// for the main page, which does not load this file.
function fmtTime(s) {
  if (!s) return "—";
  var d = new Date(s);
  if (Number.isNaN(d.getTime())) return "—";
  return d.toLocaleString();
}

// Go's time.Time JSON is RFC3339Nano, including a 9-digit fraction.
var isoTime = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$/;

function formatJSON(data) {
  var re = /\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})/g;
  return JSON.stringify(data, null, 2).replace(re, function (s) {
    var formatted = fmtTime(s);
    return formatted === "—" ? s : formatted;
  });
}

function cellText(v) {
  if (v == null) return "—";
  if (typeof v === "number") return Number.isInteger(v) ? String(v) : v.toFixed(2);
  if (typeof v === "object") return JSON.stringify(v);
  var s = String(v);
  if (isoTime.test(s)) {
    var formatted = fmtTime(s);
    if (formatted !== "—") return formatted;
  }
  return s;
}

// dataTable renders an array of objects: scalar columns first, at most 10.
// With prefixLinks, a prefix column links to the prefix page (#179).
function dataTable(rows, prefixLinks) {
  if (!rows || !rows.length) return el("p", "empty", "No rows.");
  var cols = [];
  rows.forEach(function (r) {
    Object.keys(r).forEach(function (k) {
      if (cols.indexOf(k) < 0 && (r[k] == null || typeof r[k] !== "object")) cols.push(k);
    });
  });
  cols = cols.slice(0, 10);
  var t = el("table");
  var thead = el("thead");
  var hr = el("tr");
  cols.forEach(function (c) { hr.appendChild(el("th", "", c.replace(/_/g, " "))); });
  thead.appendChild(hr);
  t.appendChild(thead);
  var tb = el("tbody");
  rows.slice(0, 200).forEach(function (r) {
    var tr = el("tr");
    cols.forEach(function (c) {
      var td = el("td", "", cellText(r[c]));
      if (prefixLinks && c === "prefix" && r[c]) {
        clear(td);
        var a = el("a", "", r[c]);
        a.href = "/prefix/" + encodeURI(r[c]);
        td.appendChild(a);
      }
      tr.appendChild(td);
    });
    tb.appendChild(tr);
  });
  t.appendChild(tb);
  return t;
}

// The IXP pages (#166, #167) share these: a table from header names and rows
// of {text, cls, href} cells, a cell that shows a dash for no value, and a
// number with a unit.
function ixpTable(headers, rows) {
  var t = el("table");
  var hr = el("tr");
  headers.forEach(function (h) { hr.appendChild(el("th", "", h)); });
  t.appendChild(el("thead")).appendChild(hr);
  var body = el("tbody");
  rows.forEach(function (cells) {
    var tr = el("tr");
    cells.forEach(function (c) {
      var td = el("td", c.cls || "", c.text);
      if (c.href) {
        clear(td);
        var a = el("a", "", c.text);
        a.href = c.href;
        td.appendChild(a);
      }
      tr.appendChild(td);
    });
    body.appendChild(tr);
  });
  t.appendChild(body);
  return t;
}

function ixpCell(text, cls) {
  return {text: text == null || text === "" ? "\u2014" : String(text), cls: cls};
}

function ixpNum(v, unit) {
  return typeof v === "number" ? v.toFixed(2) + unit : "\u2014";
}

function ixpSetBox(id, node) {
  var box = document.getElementById(id);
  clear(box);
  box.appendChild(node);
}
