"use strict";
// Renders the herd page views (#296) from the JSON the API returned for a
// fixture of several members, against a small DOM stand-in. The page
// functions are cut out of the real sources, so the test runs what ships.
// Run by TestHerdPageRendering with the fixture directory as argument.

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
  this.listeners = {};
}
Node.prototype.appendChild = function (c) { this.children.push(c); return c; };
Node.prototype.removeChild = function (c) { this.children.splice(this.children.indexOf(c), 1); return c; };
Node.prototype.addEventListener = function (n, f) { this.listeners[n] = f; };
Object.defineProperty(Node.prototype, "firstChild", { get: function () { return this.children[0] || null; } });
Object.defineProperty(Node.prototype, "textContent", {
  get: function () { return this.text + this.children.map(function (c) { return c.textContent; }).join(""); },
  set: function (v) { this.text = String(v); this.children = []; }
});

function walk(n, out) {
  out = out || [];
  out.push(n);
  n.children.forEach(function (c) { walk(c, out); });
  return out;
}
function find(root, tag) { return walk(root).filter(function (n) { return n.tag === tag; }); }
function texts(root, tag) { return find(root, tag).map(function (n) { return n.textContent; }); }
function rowsOf(root) {
  return find(root, "tr").slice(1).map(function (tr) { return tr.children.map(function (td) { return td.textContent; }); });
}

var context = {
  document: { createElement: function (t) { return new Node(t); } },
  fmtTime: function (s) { return s ? "T(" + s + ")" : "-"; },
  shellAdmin: true,
  charts: [],
  seriesClass: function (i) { return "series-" + i; },
  lineChart: function (label, xTitle, yTitle, unit, series, from, to) {
    context.charts.push({label: label, series: series, from: from, to: to});
    return new Node("svg");
  }
};
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

var web = path.join(__dirname, "web");
var ui = fs.readFileSync(path.join(web, "ui.js"), "utf8");
var herd = fs.readFileSync(path.join(web, "herd.js"), "utf8");
["el", "clear", "ixpTable", "ixpCell"].forEach(function (n) { vm.runInContext(fn(ui, n), context); });
vm.runInContext(fs.readFileSync(path.join(web, "countries.js"), "utf8"), context);
// Every top-level function and var of herd.js except the page glue that
// starts timers and reads the DOM at load.
var glue = {loadHerdOutside: 1, loadHerdMonitor: 1, loadHerdBoard: 1, onHerdTarget: 1, onHerdSearch: 1, startHerdPage: 1, herdBox: 1, herdSetStatus: 1, herdFail: 1};
var names = herd.match(/^function (\w+)\(/gm).map(function (m) { return m.slice(9, -1); });
names.forEach(function (n) { if (!glue[n]) vm.runInContext(fn(herd, n), context); });
["HERD_CHART_SERIES", "HERD_CONDITION_TEXT", "HERD_CONDITION_TILE"].forEach(function (v) {
  var m = new RegExp("^var " + v + " = [^;]*;$", "m").exec(herd);
  assert(m, "var " + v);
  vm.runInContext(m[0], context);
});

var dir = process.argv[2];
function load(name) { return JSON.parse(fs.readFileSync(path.join(dir, name + ".json"), "utf8")); }
function box() { return new Node("div"); }

// Members: this node and three peers, none verified.
var sharing = box(), members = box();
context.renderHerdOverview(sharing, members, load("overview"));
assert(sharing.textContent.indexOf("shares origin_asn records (measurements, paths)") >= 0 && sharing.textContent.indexOf("kept 90 days") >= 0, "sharing: " + sharing.textContent);
assert(find(sharing, "a").some(function (a) { return a.href === "/api/herd/preview"; }), "an admin gets the preview link");
var rows = rowsOf(members);
assert(rows.length === 4 && rows[0][0] === "this node" && rows[0][3] === "no", "member rows: " + JSON.stringify(rows));
assert(rows.every(function (r) { return r[3] === "no"; }), "no member is shown verified");
assert(rows[2][10].indexOf("stale: timeout") === 0 && rows[3][8] === "-" && rows[3][9] === "never", "stale and never-pulled peers: " + JSON.stringify(rows));
assert(members.textContent.indexOf("RPKI identity proof is not implemented") >= 0, "the verified column is explained");
context.shellAdmin = false;
sharing = box();
context.renderHerdOverview(sharing, box(), load("overview"));
assert(find(sharing, "a").length === 0, "a non-admin gets no preview link");

// World view: counts are members; each vantage keeps its numbers.
var events = box();
context.renderHerdEvents(events, load("events"));
var heads = texts(events, "h3");
assert(heads.join(",") === "AS64510,198.51.100.0/24", "event targets: " + heads);
assert(events.textContent.indexOf("3 of 4 members see loss (pooled by origin AS)") >= 0, "agreement count: " + events.textContent);
assert(events.textContent.indexOf("through AS64520: 2 of 3; through AS64521: 1 of 2") >= 0, "provider split");
assert(events.textContent.indexOf("route level, origin AS64512") >= 0, "route level labelled with its origin");
var links = find(events, "a").map(function (a) { return a.href; });
assert(links[0] === "/herd.html?origin_asn=64510#herd-monitor-h", "origin event link: " + links[0]);
assert(links[1] === "/herd.html?origin_asn=64512&prefix=198.51.100.0%2F24#herd-monitor-h", "route event link: " + links[1]);
var vrows = rowsOf(events);
assert(vrows[0][0].indexOf("this node (AS64501), US, via AS64520, icmp") === 0 && vrows[0][1] === "40.0 %" && vrows[0][4] === "loss", "local vantage row: " + JSON.stringify(vrows[0]));
assert(find(events, "td").filter(function (td) { return td.className === "bad"; }).length >= 3, "degraded cells are marked, not only colored: text says loss");
var none = box();
context.renderHerdEvents(none, {events: [], loss_pct: 5, window_seconds: 900, targets: 3});
assert(none.textContent === "No target shows loss at or above 5 % from any member in the last 15 min (3 targets measured).", "quiet: " + none.textContent);

// Mesh: one row per vantage, one column per target, a dash where unmeasured.
var mesh = box();
context.renderHerdMesh(mesh, load("mesh"));
assert(texts(mesh, "th").join("|") === "Vantage|AS64510|AS64511|198.51.100.0/24", "mesh columns: " + texts(mesh, "th"));
rows = rowsOf(mesh);
assert(rows.length === 3 && rows[0][1] === "40.0 %, 90.0 ms" && rows[0][3] === "\u2014", "mesh cells: " + JSON.stringify(rows));
assert(rows[1][3] === "50.0 %, 70.0 ms", "a second vantage keeps its own cell: " + JSON.stringify(rows[1]));

// Map: condition is words, not only color; a silent country is muted.
var map = box();
context.renderHerdMap(map, load("map"));
var tiles = find(map, "div").slice(2);
assert(tiles.length === 3, "tiles: " + tiles.length);
assert(tiles[0].className === "tile bad" && tiles[0].textContent.indexOf("DE") === 0 && tiles[0].textContent.indexOf("Germany") > 0 && tiles[0].textContent.indexOf("loss seen") > 0, "DE tile: " + tiles[0].textContent);
assert(tiles[1].className === "tile good" && tiles[1].textContent.indexOf("no loss") > 0, "JP tile: " + tiles[1].textContent);
assert(tiles[2].className === "tile muted" && tiles[2].textContent.indexOf("no recent data") > 0 && tiles[2].textContent.indexOf("measured targets") < 0, "NZ tile: " + tiles[2].textContent);

// Monitors: one line per vantage, drawn from the vantage's own rounds.
var latency = box();
context.renderHerdLatency(latency, load("monitor"));
assert(context.charts.length === 1, "one chart per target");
var ch = context.charts[0];
assert(ch.series.length === 2 && ch.series[0].name.indexOf("this node") === 0 && ch.series[1].points.length === 3 && ch.series[1].points[2].v === 200 && ch.series[0].points[2].v === 20, "chart series: " + JSON.stringify(ch.series.map(function (s) { return s.name; })));
assert(ch.series[0].cls === "series-0" && ch.series[1].cls === "series-1", "series are told apart by class");
rows = rowsOf(latency);
assert(rows.length === 2 && rows[0][2] === "0.0 %" && rows[1][1] === "3" && rows[1][2] === "30.0 %" && rows[1][3] === "200.0 ms" && rows[1][4] === "30.0 %", "monitor table: " + JSON.stringify(rows));
var paths = box();
context.renderHerdPaths(paths, load("monitor"));
rows = rowsOf(paths);
assert(rows.length === 3 && rows[0][3] === "first seen" && rows[1][3] === "first seen" && rows[2][3] === "changed" && rows[2][4] === "64521 64510", "path changes: " + JSON.stringify(rows));
var emptyPaths = box();
context.renderHerdPaths(emptyPaths, {paths: []});
assert(emptyPaths.textContent.indexOf("paths data class") > 0, "no paths explained");
var vant = box();
context.renderHerdVantages(vant, load("vantages"));
rows = rowsOf(vant);
assert(rows.length === 2 && rows[1][5] !== "this node" && rows[0][5] === "this node", "per-vantage rows carry provenance: " + JSON.stringify(rows));

// Search.
var hits = box();
context.renderHerdHits(hits, load("search"));
rows = rowsOf(hits);
assert(rows.length === 2 && rows[0][0] === "AS64510" && rows[0][2] === "4" && rows[0][5] === "AS64520, AS64521" && rows[1][1] === "route", "hits: " + JSON.stringify(rows));
assert(find(hits, "a")[1].href === "/herd.html?origin_asn=64512&prefix=198.51.100.0%2F24#herd-monitor-h", "hit link");
var nohit = box();
context.renderHerdHits(nohit, {hits: [], days: 90});
assert(nohit.textContent === "Nothing matches within the last 90 days of retention.", "no hits: " + nohit.textContent);

// Outside: each section names its source and age; links open safely; with
// nothing enabled the page says it shows herd data only.
var out = box();
context.renderHerdOutside(out, load("outside"));
var h3 = texts(out, "h3");
assert(h3.length === 4 && h3[0].indexOf("RIPE Atlas") === 0 && h3[1].indexOf("RIPE RIS Live") === 0 && h3[2] === "RPKI validation cache" && h3[3].indexOf("link-outs") === 0, "sections: " + h3);
assert(out.textContent.indexOf("(2 min old)") > 0 && out.textContent.indexOf("Last read failed: /measurements/1001/latest/: 503") > 0, "age and failure shown");
assert(out.textContent.indexOf("no data yet") > 0, "a source with no data says so");
var ext = find(out, "a");
assert(ext.length === 3 && ext.every(function (a) { return a.target === "_blank" && a.rel === "noopener noreferrer"; }), "external links open without a referrer: " + ext.length);
var off = box();
context.renderHerdOutside(off, {sources: [], sections: []});
assert(off.textContent === "No outside source is enabled. The page shows herd data only.", "all off: " + off.textContent);

// The query helper drops empty values and encodes the rest.
assert(context.herdQuery({a: "", b: "x y", c: null, d: "1"}) === "b=x%20y&d=1", "herdQuery");
console.log("ok");
