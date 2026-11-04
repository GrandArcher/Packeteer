"use strict";
// Runs the causes chart (renderCauses in charts.js) against a small DOM
// stand-in. The functions are cut out of the real page sources, so the test
// runs what ships. Run by TestCausesChart.

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
["SVG_NS", "CAUSE_KEYS"].forEach(function (n) { vm.runInContext(varLine(charts, n), context); });
[[app, "el"], [app, "clear"], [charts, "svgEl"], [charts, "tsTicks"], [charts, "renderCauses"]
].forEach(function (p) { vm.runInContext(fn(p[0], p[1]), context); });


// FAB-32: a static pin is drawn and counted as its own cause.
var root = new Node("div");
context.renderCauses(root, {rows: [
  {day: "2026-09-01", performance: 1, commit: 0, cost: 0, static: 2, total: 3},
  {day: "2026-09-02", performance: 0, commit: 1, cost: 1, static: 0, total: 2}
]});
var legend = withClass(root, "ts-key").map(function (n) { return n.textContent; });
assert(legend.join("|") === "Performance: 1|Commit: 1|Cost: 1|Static: 2", "legend: " + legend);
var bars = withClass(root, "cause-bar");
assert(withClass(root, "cause-static").filter(function (n) { return classOf(n).indexOf("cause-bar") >= 0; }).length === 1, "one static bar for the one day with pins");
assert(bars.length === 4, "one bar segment per non-zero cause and day: " + bars.length);
var heads = find(root, "th").map(function (n) { return n.textContent; });
assert(heads.join("|") === "Day|Performance|Commit|Cost|Static|Total", "table head: " + heads);
var cells = find(find(root, "tbody")[0], "td").map(function (n) { return n.textContent; });
assert(cells.slice(0, 6).join("|") === "2026-09-01|1|0|0|2|3", "first row: " + cells.slice(0, 6));
assert(cells.slice(6).join("|") === "2026-09-02|0|1|1|0|2", "second row: " + cells.slice(6));

var empty = new Node("div");
context.renderCauses(empty, {rows: []});
assert(withClass(empty, "cause-empty").length === 1 && find(empty, "svg").length === 0, "no rows, no chart");
console.log("ok");
