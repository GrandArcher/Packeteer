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

// ---- Provider usage against commit (#174), shared by the Commit & Cost page
// and the commit dashboard widget (#182). Needs fmtTime from app.js or ui.js. ----

var COMMIT_W = 640, COMMIT_H = 250, COMMIT_L = 52, COMMIT_R = 20, COMMIT_T = 12, COMMIT_B = 30;
var COMMIT_TABLE_ROWS = 100;
var COMMIT_MOVE_ROWS = 20;

function mbps(v) {
  return v == null ? "—" : String(Math.round(v * 100) / 100);
}

function plural(n, one, many) {
  return n + " " + (n === 1 ? one : many);
}

function moveText(m, provider) {
  var verb = m.announced ? "Announced" : "Recommended";
  var what = plural(m.prefixes, "prefix", "prefixes");
  if (m.direction === "off") return verb + ": " + what + " off " + provider + " toward " + m.peer;
  return verb + ": " + what + " onto " + provider + " from " + m.peer;
}

function commitTimeLabel(ms, days) {
  var d = new Date(ms);
  return days === 1 ? d.toLocaleTimeString([], {hour: "2-digit", minute: "2-digit"}) : d.toLocaleDateString([], {month: "short", day: "numeric"});
}

// commitLines draws one polyline per run of points. A run ends at a gap
// longer than three steps, and, with breakOnPeriod, where a billing period
// starts, because the 95th starts over there.
function commitLines(svg, pts, key, cls, x, y, gapMs, breakOnPeriod) {
  var run = [], prev = null;
  function flush() {
    if (run.length > 1) svg.appendChild(svgEl("polyline", {"class": "ts-line " + cls, points: run.join(" "), fill: "none"}));
    else if (run.length === 1) svg.appendChild(svgEl("circle", {"class": "usage-dot " + cls, cx: run[0].split(",")[0], cy: run[0].split(",")[1], r: 2.5}));
    run = [];
  }
  pts.forEach(function (p) {
    var t = Date.parse(p.at);
    if (prev != null && (t - prev > gapMs || (breakOnPeriod && p.new_period))) flush();
    run.push(x(t) + "," + y(p[key]));
    prev = t;
  });
  flush();
}

function commitChart(p, data) {
  var from = Date.parse(data.from), to = Date.parse(data.to);
  var pts = p.points || [];
  var max = p.commit_mbps || 0;
  pts.forEach(function (q) { max = Math.max(max, q.mbps || 0, q.p95_mbps || 0); });
  var ticks = tsTicks(max);
  var top = ticks[ticks.length - 1] || 1;
  function x(t) { return COMMIT_L + (t - from) * (COMMIT_W - COMMIT_L - COMMIT_R) / (to - from); }
  function y(v) { return COMMIT_T + (COMMIT_H - COMMIT_T - COMMIT_B) * (1 - v / top); }

  var svg = svgEl("svg", {"class": "ts-chart usage-chart", viewBox: "0 0 " + COMMIT_W + " " + COMMIT_H, role: "img",
    "aria-label": p.provider + ": samples, running 95th, and commit, in Mbps"});
  svg.appendChild(svgEl("title", {}, p.provider + ": samples, running 95th, and commit, in Mbps"));
  ticks.forEach(function (v) {
    svg.appendChild(svgEl("line", {"class": "ts-grid", x1: COMMIT_L, x2: COMMIT_W - COMMIT_R, y1: y(v), y2: y(v)}));
    svg.appendChild(svgEl("text", {"class": "ts-tick", x: COMMIT_L - 6, y: y(v) + 4, "text-anchor": "end"}, v));
  });
  [0, 1 / 3, 2 / 3, 1].forEach(function (f, i) {
    var t = from + (to - from) * f;
    svg.appendChild(svgEl("text", {"class": "ts-tick", x: x(t), y: COMMIT_H - 10, "text-anchor": i === 0 ? "start" : (i === 3 ? "end" : "middle")}, commitTimeLabel(t, data.days)));
  });
  if (p.commit_mbps > 0) {
    svg.appendChild(svgEl("line", {"class": "usage-commit", x1: COMMIT_L, x2: COMMIT_W - COMMIT_R, y1: y(p.commit_mbps), y2: y(p.commit_mbps)}));
  }
  var gap = data.step_seconds * 3000;
  commitLines(svg, pts, "mbps", "usage-sample", x, y, gap, false);
  commitLines(svg, pts, "p95_mbps", "usage-p95", x, y, gap, true);
  (p.moves || []).forEach(function (m) {
    var t = Date.parse(m.at);
    if (t < from || t > to) return;
    var line = svgEl("line", {"class": "usage-move" + (m.announced ? " usage-announced" : ""), x1: x(t), x2: x(t), y1: COMMIT_T, y2: COMMIT_H - COMMIT_B});
    line.appendChild(svgEl("title", {}, moveText(m, p.provider)));
    svg.appendChild(line);
  });
  return svg;
}

function commitDataTable(pts) {
  var det = el("details", "ts-data");
  det.appendChild(el("summary", "", "Data (" + plural(pts.length, "point", "points") + ")"));
  var table = el("table");
  var hr = el("tr");
  ["Time", "Busiest sample (Mbps)", "Running 95th (Mbps)"].forEach(function (h) { hr.appendChild(el("th", "", h)); });
  var thead = el("thead");
  thead.appendChild(hr);
  table.appendChild(thead);
  var tb = el("tbody");
  pts.slice(-COMMIT_TABLE_ROWS).reverse().forEach(function (q) {
    var tr = el("tr");
    [fmtTime(q.at), mbps(q.mbps), mbps(q.p95_mbps)].forEach(function (v) { tr.appendChild(el("td", "", v)); });
    tb.appendChild(tr);
  });
  table.appendChild(tb);
  det.appendChild(table);
  if (pts.length > COMMIT_TABLE_ROWS) det.appendChild(el("p", "tag", "The newest " + COMMIT_TABLE_ROWS + " points."));
  return det;
}

function commitPercent(p) {
  if (p.billable_mbps == null || !(p.commit_mbps > 0)) return null;
  return Math.round(p.billable_mbps * 1000 / p.commit_mbps) / 10;
}

function renderCommitGraphs(root, data) {
  clear(root);
  if (!data.providers.length) {
    var empty = el("p", "empty", "No provider has a telemetry binding, so there is no usage to draw. Commit setup in ");
    var a = el("a", "", "Settings");
    a.href = "/settings.html#commit-setup";
    empty.appendChild(a);
    empty.appendChild(document.createTextNode(" adds the binding and the commit."));
    root.appendChild(empty);
    return;
  }
  if (!data.samples_stored) {
    root.appendChild(el("p", "empty", "Samples are not stored, so there is no history to draw. Add storage: {type: sqlite} to the config and mount /var/lib/packeteer. The figures above are the open billing period."));
  }
  if (data.moves_truncated) {
    root.appendChild(el("p", "empty", "The improvement history is longer than one report can return, so the moves below are incomplete."));
  }
  data.providers.forEach(function (p) {
    var pts = p.points || [];
    var fig = el("figure", "ts-fig usage-fig");
    var pct = commitPercent(p);
    fig.appendChild(el("figcaption", "", p.provider + ": billable 95th " + mbps(p.billable_mbps) + " of " + mbps(p.commit_mbps) + " Mbps commit" + (pct == null ? "" : " (" + pct + "%)")));
    if (!pts.length) {
      fig.appendChild(el("p", "empty usage-empty", data.samples_stored ? "No stored samples for " + p.provider + " in this range." : "No stored samples."));
    } else {
      fig.appendChild(commitChart(p, data));
      var legend = el("p", "ts-legend tag");
      legend.appendChild(el("span", "ts-key usage-sample", "Thin: busiest sample"));
      legend.appendChild(el("span", "ts-key usage-p95", "Thick: running 95th of the billing period"));
      legend.appendChild(el("span", "ts-key usage-commit-key", "Dashed: commit"));
      legend.appendChild(el("span", "ts-key", "Vertical bars: commit moves"));
      fig.appendChild(legend);
      fig.appendChild(commitDataTable(pts));
    }
    var moves = p.moves || [];
    if (moves.length) {
      var ul = el("ul", "usage-moves");
      moves.slice(-COMMIT_MOVE_ROWS).reverse().forEach(function (m) {
        ul.appendChild(el("li", "", fmtTime(m.at) + " · " + moveText(m, p.provider)));
      });
      fig.appendChild(ul);
    } else if (data.moves_recorded) {
      fig.appendChild(el("p", "tag usage-nomoves", "Commit control moved no traffic for " + p.provider + " in this range."));
    } else {
      fig.appendChild(el("p", "tag usage-nomoves", "Moves are not recorded without storage."));
    }
    root.appendChild(fig);
  });
}

// ---- Improvements by cause (#182): stacked bars per UTC day from the
// causes report. ----

var CAUSE_KEYS = [
  {key: "performance", label: "Performance", cls: "cause-performance"},
  {key: "commit", label: "Commit", cls: "cause-commit"},
  {key: "cost", label: "Cost", cls: "cause-cost"}
];

// renderCauses draws one stacked bar per day with improvements, then the
// totals per cause and a data table. data is the causes report response.
function renderCauses(root, data) {
  clear(root);
  var rows = (data && data.rows) || [];
  if (!rows.length) {
    root.appendChild(el("p", "empty cause-empty", "No improvements started in this range."));
    return;
  }
  var W = 640, H = 230, L = 40, R = 12, T = 12, B = 30;
  var max = 0;
  var sums = {};
  CAUSE_KEYS.forEach(function (c) { sums[c.key] = 0; });
  rows.forEach(function (r) {
    max = Math.max(max, r.total || 0);
    CAUSE_KEYS.forEach(function (c) { sums[c.key] += r[c.key] || 0; });
  });
  var ticks = tsTicks(max);
  var top = ticks[ticks.length - 1] || 1;
  var slot = (W - L - R) / rows.length;
  var bar = Math.max(1, Math.min(28, slot - 2));
  function y(v) { return T + (H - T - B) * (1 - v / top); }

  var svg = svgEl("svg", {"class": "ts-chart cause-chart", viewBox: "0 0 " + W + " " + H, role: "img", "aria-label": "Improvements started per day, by cause"});
  svg.appendChild(svgEl("title", {}, "Improvements started per day, by cause"));
  ticks.forEach(function (v) {
    svg.appendChild(svgEl("line", {"class": "ts-grid", x1: L, x2: W - R, y1: y(v), y2: y(v)}));
    svg.appendChild(svgEl("text", {"class": "ts-tick", x: L - 6, y: y(v) + 4, "text-anchor": "end"}, v));
  });
  rows.forEach(function (r, i) {
    var x = L + slot * i + (slot - bar) / 2;
    var base = 0;
    CAUSE_KEYS.forEach(function (c) {
      var n = r[c.key] || 0;
      if (!n) return;
      var rect = svgEl("rect", {"class": "cause-bar " + c.cls, x: x, y: y(base + n), width: bar, height: y(base) - y(base + n)});
      rect.appendChild(svgEl("title", {}, r.day + " " + c.label + ": " + n));
      svg.appendChild(rect);
      base += n;
    });
  });
  [0, rows.length - 1].forEach(function (i, k) {
    if (k === 1 && i === 0) return;
    svg.appendChild(svgEl("text", {"class": "ts-tick", x: L + slot * i + slot / 2, y: H - 10, "text-anchor": i === 0 ? "start" : "end"}, rows[i].day.slice(5)));
  });
  var fig = el("figure", "ts-fig");
  fig.appendChild(el("figcaption", "", "Improvements started per day"));
  fig.appendChild(svg);
  root.appendChild(fig);

  var legend = el("p", "ts-legend tag");
  CAUSE_KEYS.forEach(function (c) {
    legend.appendChild(el("span", "ts-key " + c.cls, c.label + ": " + sums[c.key]));
  });
  root.appendChild(legend);

  var det = el("details", "ts-data");
  det.appendChild(el("summary", "", "Data (" + rows.length + (rows.length === 1 ? " day)" : " days)")));
  var table = el("table");
  var hr = el("tr");
  ["Day", "Performance", "Commit", "Cost", "Total"].forEach(function (h) { hr.appendChild(el("th", "", h)); });
  var thead = el("thead");
  thead.appendChild(hr);
  table.appendChild(thead);
  var tb = el("tbody");
  rows.forEach(function (r) {
    var tr = el("tr");
    [r.day, r.performance, r.commit, r.cost, r.total].forEach(function (v) { tr.appendChild(el("td", "", v)); });
    tb.appendChild(tr);
  });
  table.appendChild(tb);
  det.appendChild(table);
  root.appendChild(det);
}
