"use strict";
// Runs the Providers table cells, the sparkline, and the two Overview charts
// (#349) against a small DOM stand-in. The functions are cut out of the real
// page sources, so the test runs what ships. Run by TestProviderStatsPage.

var fs = require("fs");
var path = require("path");
var vm = require("vm");

function assert(cond, msg) {
  if (!cond) {
    console.error("FAIL: " + msg);
    process.exit(1);
  }
}

function Node(tag) {
  this.tag = tag;
  this.className = "";
  this.children = [];
  this.attrs = {};
  this.text = "";
}
Node.prototype.appendChild = function (c) { this.children.push(c); return c; };
Node.prototype.removeChild = function (c) { this.children.splice(this.children.indexOf(c), 1); return c; };
Object.defineProperty(Node.prototype, "firstChild", { get: function () { return this.children[0] || null; } });
Object.defineProperty(Node.prototype, "textContent", {
  get: function () { return this.text + this.children.map(function (c) { return c.textContent; }).join(""); },
  set: function (v) { this.text = String(v); this.children = []; }
});
Node.prototype.setAttribute = function (k, v) { this.attrs[k] = v; };

function walk(n, out) {
  out = out || [];
  out.push(n);
  n.children.forEach(function (c) { walk(c, out); });
  return out;
}
function find(root, tag) { return walk(root).filter(function (n) { return n.tag === tag; }); }
// An SVG element keeps its class as an attribute, an HTML one as className.
function classOf(n) { return n.className || n.attrs["class"] || ""; }
function withClass(root, cls) { return walk(root).filter(function (n) { return (" " + classOf(n) + " ").indexOf(" " + cls + " ") >= 0; }); }

var context = {
  document: {
    createElement: function (t) { return new Node(t); },
    createElementNS: function (ns, t) { return new Node(t); },
    createTextNode: function (s) { var n = new Node("#text"); n.text = s; return n; }
  },
  Date: Date, Math: Math, Number: Number, String: String, Infinity: Infinity
};
// An SVG attribute lands in attrs, as in a browser.
vm.createContext(context);

function fn(src, name) {
  var start = src.indexOf("function " + name + "(");
  assert(start >= 0, "function " + name + " not found");
  var depth = 0;
  for (var i = src.indexOf("{", start); i < src.length; i++) {
    if (src[i] === "{") depth++;
    if (src[i] === "}" && --depth === 0) return src.slice(start, i + 1);
  }
  assert(false, "unbalanced " + name);
}
function varLine(src, name) {
  var m = new RegExp("^var " + name + " = [^;]*;$", "m").exec(src);
  assert(m, "var " + name + " not found");
  return m[0];
}

var web = path.join(__dirname, "web");
var app = fs.readFileSync(path.join(web, "app.js"), "utf8");
var charts = fs.readFileSync(path.join(web, "charts.js"), "utf8");
["SVG_NS", "SERIES_N", "HOUR_MS", "OV_W", "OV_GAP_MS"].forEach(function (n) { vm.runInContext(varLine(charts, n), context); });
vm.runInContext(varLine(app, "NO_REPLY"), context);
[[app, "el"], [app, "clear"], [app, "fmtMs"], [app, "fmtPct"], [app, "statCell"], [app, "mbpsText"],
  [charts, "svgEl"], [charts, "tsTicks"], [charts, "clockLabel"], [charts, "lineChart"], [charts, "seriesClass"],
  [charts, "renderProviderLatency"], [charts, "improvementCounts"], [charts, "renderImprovementCounts"], [charts, "sparkline"]
].forEach(function (p) { vm.runInContext(fn(p[0], p[1]), context); });

// ---- table cells ----
var st = {
  provider: "lab-a",
  last_15m: {slots: 3, loss_pct: 8, rtt_ms: 120.04, jitter_ms: 4},
  last_24h: {slots: 288, loss_pct: 7.5, rtt_ms: 118, jitter_ms: 3.5}
};
var lat = context.statCell(st, "rtt_ms", context.fmtMs);
var lines = withClass(lat, "stat-line").map(function (n) { return n.textContent; });
assert(lines.join("|") === "15 min120.0 ms|24 h118.0 ms", "latency cell: " + lines);
var loss = context.statCell(st, "loss_pct", context.fmtPct);
assert(loss.textContent === "15 min8.0%24 h7.5%", "loss cell: " + loss.textContent);

// Silent for 15 minutes: loss but no latency says "no reply", never 0.0 ms.
var silent = {last_15m: {slots: 3, loss_pct: 100}, last_24h: {slots: 288, loss_pct: 40, rtt_ms: 90, jitter_ms: 2}};
var s15 = context.statCell(silent, "rtt_ms", context.fmtMs).textContent;
assert(s15 === "15 minno reply24 h90.0 ms", "no reply: " + s15);
assert(s15.indexOf("15 min0.0 ms") < 0, "a silent path has no 0.0 ms");
assert(context.statCell(silent, "loss_pct", context.fmtPct).textContent === "15 min100.0%24 h40.0%", "loss while silent");
assert(withClass(context.statCell(silent, "rtt_ms", context.fmtMs), "muted").length === 1, "only the silent window is muted");

// No probes at all in a window: no data.
assert(context.statCell(undefined, "rtt_ms", context.fmtMs).textContent === "15 minno data24 hno data", "no stats");
assert(context.statCell({last_15m: {slots: 0}, last_24h: {slots: 0}}, "loss_pct", context.fmtPct).textContent === "15 minno data24 hno data", "empty windows");

// ---- Mbps ----
assert(context.mbpsText(st, {flow: false}) === "no flow data", "no flow source");
assert(context.mbpsText(undefined, null) === "no flow data", "no stats at all");
assert(context.mbpsText({mbps: 12.34}, {flow: true}) === "12.3", "rate with a flow source");
assert(context.mbpsText(undefined, {flow: true}) === "0.0", "flow source, no traffic through this provider");
assert(context.mbpsText({mbps: 0}, {flow: true}) === "0.0", "zero rate");

// ---- sparkline ----
var now = Date.now();
function hourAgo(h) { return new Date(now - h * 3600000).toISOString(); }
var spark = context.sparkline([{t: hourAgo(3), rtt_ms: 100}, {t: hourAgo(2), rtt_ms: 140}, {t: hourAgo(1), rtt_ms: 120}]);
assert(spark.tag === "svg" && classOf(spark) === "spark" && spark.attrs.role === "img", "sparkline is an svg image");
assert(spark.attrs["aria-label"] === "Latency over the last 24 hours, hourly: lowest 100.0 ms, highest 140.0 ms", "label: " + spark.attrs["aria-label"]);
assert(find(spark, "polyline").length === 1 && find(spark, "circle").length === 1, "one line and the latest point");
var empty = context.sparkline([{t: hourAgo(1)}]);
assert(empty.tag === "span" && empty.textContent === "no data", "no latency, no sparkline");
assert(context.sparkline(undefined).textContent === "no data", "no points");

// ---- improvement counts ----
var base = Math.floor(now / 3600000) * 3600000;
var rows = [
  {start: new Date(base - 30 * 3600000).toISOString(), mode: "observe"},
  {start: new Date(base - 5 * 3600000).toISOString(), end: new Date(base - 2 * 3600000).toISOString(), mode: "observe"},
  {start: new Date(base - 3 * 3600000).toISOString(), mode: "inject"}
];
var from = base - 24 * 3600000, to = base;
var counts = context.improvementCounts(rows, from, to);
assert(counts.recommended.length === 25 && counts.active.length === 25, "25 hourly points");
function at(series, hoursAgo) { return series.filter(function (p) { return p.t === base - hoursAgo * 3600000; })[0].v; }
assert(at(counts.recommended, 24) === 1 && at(counts.recommended, 4) === 2, "an open one and a second that started");
assert(at(counts.recommended, 2) === 1, "the second ended at its end time, which is not counted");
assert(at(counts.active, 4) === 0 && at(counts.active, 3) === 1 && at(counts.active, 0) === 1, "inject counts as active from its start");

// ---- the two charts ----
var latency = new Node("div");
var stats = {providers: [
  {provider: "lab-a", last_24h: {slots: 5, rtt_ms: 118}, points: [{t: hourAgo(3), loss_pct: 8, rtt_ms: 120}, {t: hourAgo(2), loss_pct: 8, rtt_ms: 130}]},
  {provider: "lab-b", last_24h: {slots: 5, rtt_ms: 40}, points: [{t: hourAgo(3), loss_pct: 0, rtt_ms: 40}, {t: hourAgo(2), loss_pct: 0, rtt_ms: 41}]},
  {provider: "lab-c", last_24h: {slots: 5, loss_pct: 100}, points: [{t: hourAgo(2), loss_pct: 100}]},
  {provider: "old", last_24h: {slots: 5, rtt_ms: 10}, points: [{t: hourAgo(2), loss_pct: 0, rtt_ms: 10}]}
]};
context.renderProviderLatency(latency, stats, ["lab-a", "lab-b", "lab-c"]);
assert(find(latency, "figcaption")[0].textContent === "Latency by provider, last 24 h", "latency caption");
var svg = find(latency, "svg")[0];
assert(svg && svg.attrs.role === "img" && svg.attrs["aria-label"].indexOf("Latency by provider") === 0, "latency chart is a labelled image");
var texts = find(svg, "text").map(function (n) { return n.textContent; });
assert(texts.indexOf("Round-trip time (ms)") >= 0 && texts.indexOf("Time of day (last 24 hours)") >= 0, "both axes are titled: " + texts);
var polys = find(svg, "polyline");
assert(polys.length === 2 && classOf(polys[0]) === "ts-line series-0" && classOf(polys[1]) === "ts-line series-1", "one line per answering provider, a different class each");
var legend = withClass(latency, "ts-key").map(function (n) { return n.textContent; });
assert(legend.join("|") === "lab-a: median 118.0 ms|lab-b: median 40.0 ms", "legend names each line: " + legend);
assert(withClass(latency, "ts-silent")[0].textContent.indexOf("No reply from lab-c") === 0, "a silent provider is named, not dropped");
assert(latency.textContent.indexOf("old") < 0, "a provider that is not configured is not drawn");

var none = new Node("div");
context.renderProviderLatency(none, {providers: []}, ["lab-a"]);
assert(withClass(none, "ts-empty").length === 1 && find(none, "svg").length === 0, "no stats, no chart, a sentence");

var imp = new Node("div");
context.renderImprovementCounts(imp, [{start: hourAgo(5), mode: "observe"}, {start: hourAgo(5), mode: "observe"}], false);
assert(find(imp, "figcaption")[0].textContent === "Recommended / active improvements, last 24 h", "improvements caption");
var isvg = find(imp, "svg")[0];
var itexts = find(isvg, "text").map(function (n) { return n.textContent; });
assert(itexts.indexOf("Improvements open") >= 0 && itexts.indexOf("Time of day (last 24 hours)") >= 0, "improvement axes are titled");
var ilegend = withClass(imp, "ts-key").map(function (n) { return n.textContent; });
assert(ilegend.join("|") === "Recommended (observe or suggest): 2 now|Active (inject, announced): 0 now", "legend in words: " + ilegend);
var none2 = new Node("div");
context.renderImprovementCounts(none2, [], false);
assert(withClass(none2, "ts-empty").length === 1 && find(none2, "svg").length === 0, "no improvements, a sentence");
assert(withClass(imp, "tag").every(function (n) { return n.textContent.indexOf("floor") < 0; }), "no truncation note when not truncated");
var cut = new Node("div");
context.renderImprovementCounts(cut, [{start: hourAgo(1), mode: "observe"}], true);
assert(cut.textContent.indexOf("a floor") >= 0, "truncation is said");

console.log("ok");
