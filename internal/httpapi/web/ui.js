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

function cellText(v) {
  if (v == null) return "—";
  if (typeof v === "number") return Number.isInteger(v) ? String(v) : v.toFixed(2);
  if (typeof v === "object") return JSON.stringify(v);
  return String(v);
}

// dataTable renders an array of objects: scalar columns first, at most 10.
function dataTable(rows) {
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
    cols.forEach(function (c) { tr.appendChild(el("td", "", cellText(r[c]))); });
    tb.appendChild(tr);
  });
  t.appendChild(tb);
  return t;
}
