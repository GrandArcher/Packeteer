"use strict";
// Runs the steer verification section of the Improvements page (#305)
// against a small DOM stand-in: hidden while verify is off, the empty note,
// and one row per result with its status, moved traffic, and back-out. The
// functions are cut out of the real app.js, so the test runs what ships.
// Run by TestVerificationPage.

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
  this.hidden = true;
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

var section = new Node("section");
var root = new Node("div");
var context = {
  document: {
    createElement: function (t) { return new Node(t); },
    getElementById: function (id) { return id === "verification-section" ? section : id === "verification" ? root : null; }
  },
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

var app = fs.readFileSync(path.join(__dirname, "web", "app.js"), "utf8");
["el", "clear", "fmtTime", "fmtNum", "verifyBadge", "renderVerification"].forEach(function (n) { vm.runInContext(fn(app, n), context); });
var label = app.match(/var VERIFY_LABEL = \{[^}]*\};/);
assert(label, "VERIFY_LABEL not found");
vm.runInContext(label[0], context);

// Verify off, or no answer: the section stays hidden.
section.hidden = false;
context.renderVerification({enabled: false, results: []});
assert(section.hidden === true, "the section is shown with verify off");

// On with nothing checked yet.
context.renderVerification({enabled: true, results: []});
assert(section.hidden === false && root.textContent === "No steer has been checked yet.", "empty note: " + root.textContent);

var data = {enabled: true, results: [
  {kind: "outbound", prefix: "198.51.100.0/24", provider: "transit-b", status: "verified", checked: "2026-10-26T12:05:00Z", expected_mbps: 40, moved_mbps: 38, moved_pct: 95, detail: "38.0 of 40.0 Mbps moved (95%)"},
  {kind: "outbound", prefix: "203.0.113.0/24", provider: "transit-c", status: "partial", checked: "2026-10-26T12:05:00Z", expected_mbps: 40, moved_mbps: 12, moved_pct: 30, detail: "12.0 of 40.0 Mbps moved (30%)"},
  {kind: "inbound", provider: "transit-a", status: "not_moved", backed_out: true, checked: "2026-10-26T12:10:00Z", expected_mbps: 150, moved_mbps: 0, moved_pct: 0, detail: "backed out, held off 30m0s"},
  {kind: "inbound", provider: "transit-b", status: "pending", due: "2026-10-26T12:20:00Z", expected_mbps: 90, moved_mbps: 0, moved_pct: 0, detail: "waiting for the window to pass"},
  {kind: "outbound", prefix: "192.0.2.0/24", provider: "transit-b", status: "unknown", checked: "2026-10-26T12:20:00Z", expected_mbps: 0, moved_mbps: 0, moved_pct: 0, detail: "no flow volume or too little traffic to judge"}
]};
context.renderVerification(data);
var rows = walk(root).filter(function (n) { return n.tag === "tr"; });
assert(rows.length === 6, "rows (header and five results): " + rows.length);
function row(i) { return rows[i].textContent; }
function badge(i, cls) {
  return walk(rows[i]).some(function (n) { return n.tag === "span" && n.className === cls; });
}
assert(row(1).indexOf("outbound") >= 0 && row(1).indexOf("198.51.100.0/24") >= 0 && row(1).indexOf("to transit-b") >= 0 &&
  row(1).indexOf("Verified") >= 0 && row(1).indexOf("38 Mbps (95%)") >= 0 && row(1).indexOf("40 Mbps") >= 0, "verified row: " + row(1));
assert(badge(1, "dot up"), "verified is not green");
assert(row(2).indexOf("Partial") >= 0 && row(2).indexOf("12 Mbps (30%)") >= 0 && badge(2, "dot degraded"), "partial row: " + row(2));
assert(row(3).indexOf("inbound") >= 0 && row(3).indexOf("away from transit-a") >= 0 && row(3).indexOf("Not moved") >= 0 &&
  row(3).indexOf("backed out") >= 0 && badge(3, "dot down"), "not moved row: " + row(3));
assert(row(4).indexOf("Pending") >= 0 && row(4).indexOf("due ") >= 0 && row(4).indexOf("Mbps (") < 0, "pending row: " + row(4));
assert(row(5).indexOf("Unknown") >= 0 && row(5).indexOf("too little traffic") >= 0 && row(5).indexOf("Mbps (") < 0, "unknown row: " + row(5));

// A later render replaces the table, it does not append to it.
context.renderVerification(data);
assert(walk(root).filter(function (n) { return n.tag === "tr"; }).length === 6, "a second render doubled the rows");
console.log("ok");
