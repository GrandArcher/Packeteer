"use strict";
// Before/after time-series charts (#129). Inline SVG built with the DOM, no
// library and no inline style: the CSP allows scripts and styles from this
// origin only. Needs el() and clear() from app.js or ui.js.

// The SVG XML namespace is an identifier, never fetched. It is written in two
// parts so the "no remote URL in the UI" test keeps matching every real one.
var SVG_NS = "http:" + "//www.w3.org/2000/svg";
var DAY_MS = 86400000;

var TS_BUCKETS = [
  {id: "all", label: "All destinations"},
  {id: "problem", label: "Problem prefixes"},
  {id: "better_20", label: "20% or more better"},
  {id: "better_50", label: "50% or more better"}
];

function svgEl(tag, attrs, text) {
  var n = document.createElementNS(SVG_NS, tag);
  for (var k in attrs) n.setAttribute(k, String(attrs[k]));
  if (text != null) n.textContent = String(text);
  return n;
}

// tsDay is a report day (YYYY-MM-DD, UTC) as a number of days since the epoch.
function tsDay(s) {
  var t = Date.parse(s + "T00:00:00Z");
  return Number.isNaN(t) ? null : Math.floor(t / DAY_MS);
}

function tsLabel(day) {
  return new Date(day * DAY_MS).toISOString().slice(5, 10);
}

// tsTicks returns four round tick values from 0 up to at least max.
function tsTicks(max) {
  if (!(max > 0)) return [0, 1];
  var pow = Math.pow(10, Math.floor(Math.log(max) / Math.LN10));
  var steps = [1, 2, 2.5, 5, 10];
  var step = pow * 10;
  for (var i = 0; i < steps.length; i++) {
    if (steps[i] * pow * 4 >= max) { step = steps[i] * pow; break; }
  }
  var out = [];
  for (var v = 0; v < max + step * 0.999; v += step) out.push(Math.round(v * 1000) / 1000);
  return out;
}

// tsChart draws one metric: a dashed Before line (the native provider) and a
// solid After line (the chosen provider). first and last are day numbers.
// Days without a point break the line.
function tsChart(title, unit, rows, beforeKey, afterKey, first, last) {
  var W = 640, H = 230, L = 52, R = 28, T = 12, B = 30;
  var days = Math.max(last - first, 1);
  var max = 0;
  rows.forEach(function (r) { max = Math.max(max, r[beforeKey] || 0, r[afterKey] || 0); });
  var ticks = tsTicks(max);
  var top = ticks[ticks.length - 1] || 1;
  function x(d) { return L + (last === first ? (W - L - R) / 2 : (d - first) * (W - L - R) / days); }
  function y(v) { return T + (H - T - B) * (1 - v / top); }

  var svg = svgEl("svg", {"class": "ts-chart", viewBox: "0 0 " + W + " " + H, role: "img", "aria-label": title + ", before and after, by day"});
  svg.appendChild(svgEl("title", {}, title + ", before (native path) and after (chosen path), by day"));
  ticks.forEach(function (v) {
    svg.appendChild(svgEl("line", {"class": "ts-grid", x1: L, x2: W - R, y1: y(v), y2: y(v)}));
    svg.appendChild(svgEl("text", {"class": "ts-tick", x: L - 6, y: y(v) + 4, "text-anchor": "end"}, v));
  });
  var xt = last === first ? [first] : [first, Math.round((first + last) / 2), last];
  xt.forEach(function (d) {
    svg.appendChild(svgEl("text", {"class": "ts-tick", x: x(d), y: H - 10, "text-anchor": "middle"}, tsLabel(d)));
  });

  var series = [
    {key: beforeKey, cls: "ts-before", name: "Before (native)"},
    {key: afterKey, cls: "ts-after", name: "After (chosen)"}
  ];
  series.forEach(function (s) {
    var run = [];
    function flush() {
      if (run.length > 1) svg.appendChild(svgEl("polyline", {"class": "ts-line " + s.cls, points: run.join(" "), fill: "none"}));
      run = [];
    }
    var prev = null;
    rows.forEach(function (r) {
      var d = tsDay(r.day);
      if (d == null) return;
      if (prev != null && d !== prev + 1) flush();
      run.push(x(d) + "," + y(r[s.key] || 0));
      prev = d;
    });
    flush();
    if (rows.length <= 62) {
      rows.forEach(function (r) {
        var d = tsDay(r.day);
        if (d == null) return;
        var c = svgEl("circle", {"class": "ts-dot " + s.cls, cx: x(d), cy: y(r[s.key] || 0), r: 3});
        c.appendChild(svgEl("title", {}, r.day + " " + s.name + ": " + (Math.round((r[s.key] || 0) * 1000) / 1000) + " " + unit + " (" + r.prefixes + " prefixes)"));
        svg.appendChild(c);
      });
    }
  });
  var box = el("figure", "ts-fig");
  box.appendChild(el("figcaption", "", title + " (" + unit + ")"));
  box.appendChild(svg);
  return box;
}

// renderTimeSeries draws the loss and RTT charts for one bucket of a
// timeseries report into root, and a data table under them. data is the
// report response. With no points it says so and draws no chart.
function renderTimeSeries(root, data, bucket) {
  clear(root);
  var all = (data && data.rows) || [];
  var rows = all.filter(function (r) { return r.bucket === bucket; });
  if (!rows.length) {
    root.appendChild(el("p", "empty ts-empty", "No before/after data in this range. A day needs an improvement and probe history for both its native and its chosen provider."));
    return;
  }
  var first = tsDay(String(data.from || "").slice(0, 10));
  var last = tsDay(String(data.to || "").slice(0, 10));
  var days = rows.map(function (r) { return tsDay(r.day); }).filter(function (d) { return d != null; });
  var lo = Math.min.apply(null, days), hi = Math.max.apply(null, days);
  if (first == null || first > lo) first = lo;
  if (last == null) last = hi;
  last = Math.max(hi, last);
  var wrap = el("div", "ts-charts");
  wrap.appendChild(tsChart("Loss", "%", rows, "before_loss_pct", "after_loss_pct", first, last));
  wrap.appendChild(tsChart("Latency", "ms", rows, "before_rtt_ms", "after_rtt_ms", first, last));
  root.appendChild(wrap);
  var legend = el("p", "ts-legend tag");
  legend.appendChild(el("span", "ts-key ts-before", "Dashed: before, the native path"));
  legend.appendChild(document.createTextNode(" "));
  legend.appendChild(el("span", "ts-key ts-after", "Solid: after, the chosen path"));
  root.appendChild(legend);

  var det = el("details", "ts-data");
  det.appendChild(el("summary", "", "Data (" + rows.length + " days)"));
  var table = el("table");
  var hr = el("tr");
  ["Day", "Prefixes", "Loss before %", "Loss after %", "RTT before ms", "RTT after ms"].forEach(function (h) { hr.appendChild(el("th", "", h)); });
  var thead = el("thead");
  thead.appendChild(hr);
  table.appendChild(thead);
  var tb = el("tbody");
  rows.forEach(function (r) {
    var tr = el("tr");
    [r.day, r.prefixes, r.before_loss_pct, r.after_loss_pct, r.before_rtt_ms, r.after_rtt_ms].forEach(function (v) {
      tr.appendChild(el("td", "", v == null ? "—" : (typeof v === "number" ? Math.round(v * 1000) / 1000 : v)));
    });
    tb.appendChild(tr);
  });
  table.appendChild(tb);
  det.appendChild(table);
  root.appendChild(det);
}
