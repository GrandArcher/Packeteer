"use strict";
// Commit & Cost page (#174): billable usage against commit per provider,
// from /api/commit. Loaded after app.js (el, clear, getJSON) and charts.js
// (svgEl, tsTicks). Read-only.

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

function renderCommitSummary(root, data) {
  clear(root);
  if (!data.providers.length) return;
  var t = el("table");
  var hr = el("tr");
  ["Provider", "Commit (Mbps)", "Billable 95th (Mbps)", "Of commit", "Samples", "Period (UTC)", "Last sample", "Poll error"].forEach(function (h) { hr.appendChild(el("th", "", h)); });
  var thead = el("thead");
  thead.appendChild(hr);
  t.appendChild(thead);
  var tb = el("tbody");
  data.providers.forEach(function (p) {
    var pct = commitPercent(p);
    var tr = el("tr");
    var cells = [p.provider, mbps(p.commit_mbps), mbps(p.billable_mbps), pct == null ? "—" : pct + "%", p.samples,
      p.period_start.slice(0, 10) + " to " + p.period_end.slice(0, 10), fmtTime(p.updated), p.error || ""];
    cells.forEach(function (v, i) {
      var td = el("td", i === 3 && pct != null && pct >= 100 ? "bad" : "", v);
      tr.appendChild(td);
    });
    tb.appendChild(tr);
  });
  t.appendChild(tb);
  root.appendChild(t);
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

// The range is in the query string (/commit.html?days=30), so a link opens
// the same view.
function loadCommit() {
  var days = document.getElementById("commit-days").value || "7";
  window.history.replaceState(null, "", days === "7" ? window.location.pathname : "?days=" + days);
  var graphs = document.getElementById("commit-graphs");
  getJSON("/api/commit?days=" + encodeURIComponent(days)).then(function (data) {
    renderCommitSummary(document.getElementById("commit-summary"), data);
    renderCommitGraphs(graphs, data);
  }, function (err) {
    clear(document.getElementById("commit-summary"));
    clear(graphs);
    graphs.appendChild(el("p", "empty", err.message));
  });
}

var wantDays = new URLSearchParams(window.location.search).get("days");
if (["1", "7", "30"].indexOf(wantDays) >= 0) document.getElementById("commit-days").value = wantDays;
document.getElementById("commit-days").addEventListener("change", loadCommit);
document.getElementById("commit-load").addEventListener("click", loadCommit);
loadCommit();
