"use strict";
// Runs the interface capacity columns of the Commit & Cost page (#307)
// against a small DOM stand-in: a provider with no commit, one inside its
// limit, and one past it. The functions are cut out of the real page
// scripts, so the test runs what ships. Run by TestCommitLoadPage.

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
  this.text = "";
}
Node.prototype.appendChild = function (c) { this.children.push(c); return c; };
Node.prototype.removeChild = function (c) { this.children.splice(this.children.indexOf(c), 1); return c; };
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

var context = {
  document: { createElement: function (t) { return new Node(t); } },
  Date: Date, Math: Math, Number: Number, String: String
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
var app = fs.readFileSync(path.join(web, "app.js"), "utf8");
var charts = fs.readFileSync(path.join(web, "charts.js"), "utf8");
var commit = fs.readFileSync(path.join(web, "commit.js"), "utf8");
["el", "clear", "fmtTime"].forEach(function (n) { vm.runInContext(fn(app, n), context); });
["mbps", "plural", "loadText", "commitPercent", "renderCommitGraphs"].forEach(function (n) { vm.runInContext(fn(charts, n), context); });
vm.runInContext(fn(commit, "renderCommitSummary"), context);

function base(extra) {
  var p = {samples: 3, period_start: "2026-10-01T00:00:00Z", period_end: "2026-11-01T00:00:00Z", updated: "2026-10-26T12:00:00Z",
    commit_mbps: 0, error: "", points: [], moves: []};
  Object.keys(extra).forEach(function (k) { p[k] = extra[k]; });
  return p;
}
var data = {samples_stored: false, moves_recorded: false, providers: [
  base({provider: "transit-a", commit_mbps: 1000, billable_mbps: 400, capacity_mbps: 2000, utilization_pct: 20}),
  base({provider: "transit-b", capacity_mbps: 1000, utilization_pct: 91.25, capacity_threshold_pct: 85, overloaded: true}),
  base({provider: "transit-c", capacity_mbps: 1000, utilization_pct: 40, capacity_threshold_pct: 85})
]};

var root = new Node("div");
context.renderCommitSummary(root, data);
var rows = walk(root).filter(function (n) { return n.tag === "tr"; });
assert(rows.length === 4, "rows (header and three providers): " + rows.length);
var header = rows[0].textContent;
assert(header.indexOf("Capacity (Mbps)") >= 0 && header.indexOf("Outbound of capacity") >= 0, "header: " + header);
function cells(i) { return rows[i].children.map(function (c) { return c.textContent; }); }
function bad(i) { return rows[i].children.map(function (c) { return c.className === "bad"; }); }

// With a commit and no limit: the commit figures stay, the load is plain.
assert(cells(1)[0] === "transit-a" && cells(1)[1] === "1000" && cells(1)[4] === "2000" && cells(1)[5] === "20%", "transit-a: " + cells(1));
assert(!bad(1).some(Boolean), "transit-a is flagged");
// No commit: "none", no billable figure, and past its limit the load is flagged.
assert(cells(2)[1] === "none" && cells(2)[2] === "—" && cells(2)[3] === "—" && cells(2)[5] === "91.3% (limit 85%)", "transit-b: " + cells(2));
assert(bad(2)[5] && !bad(2)[3], "transit-b load is not the only flagged cell: " + bad(2));
// Inside the limit: shown with the limit, not flagged.
assert(cells(3)[5] === "40% (limit 85%)" && !bad(3).some(Boolean), "transit-c: " + cells(3) + " " + bad(3));

var graphs = new Node("div");
context.renderCommitGraphs(graphs, data);
var captions = walk(graphs).filter(function (n) { return n.tag === "figcaption"; }).map(function (n) { return n.textContent; });
assert(captions.length === 3, "captions: " + captions);
assert(captions[0] === "transit-a: billable 95th 400 of 1000 Mbps commit (40%); outbound 20% of 2000 Mbps", "caption a: " + captions[0]);
assert(captions[1] === "transit-b: no commit set; outbound 91.3% of 1000 Mbps (limit 85%)", "caption b: " + captions[1]);

// A binding with no capacity says nothing about load.
var plain = new Node("div");
context.renderCommitGraphs(plain, {samples_stored: false, moves_recorded: false, providers: [base({provider: "transit-d", commit_mbps: 100, billable_mbps: 50})]});
var cap = walk(plain).filter(function (n) { return n.tag === "figcaption"; })[0].textContent;
assert(cap === "transit-d: billable 95th 50 of 100 Mbps commit (50%)", "caption without capacity: " + cap);
console.log("ok");
