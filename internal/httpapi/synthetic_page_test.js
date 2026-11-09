"use strict";
// Runs the Synthetic routes section of the Improvements page (#300) against
// a small DOM stand-in: hidden while the mode is off, the empty note, and one
// labeled row per synthetic prefix with its announced prefix and the link it
// is steered to. It also checks the badge on an improvement row. The
// functions are cut out of the real app.js, so the test runs what ships.
// Run by TestSyntheticPage.

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
  this.attrs = {};
}
Node.prototype.appendChild = function (c) { this.children.push(c); return c; };
Node.prototype.removeChild = function (c) { this.children.splice(this.children.indexOf(c), 1); return c; };
Object.defineProperty(Node.prototype, "lastChild", { get: function () { return this.children[this.children.length - 1] || null; } });
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
var note = new Node("p");
var impRoot = new Node("div");
var impTitle = new Node("h1");
var impTag = new Node("p");
var context = {
  document: {
    createElement: function (t) { return new Node(t); },
    getElementById: function (id) {
      return {"synthetic-section": section, synthetic: root, "synthetic-note": note,
        improvements: impRoot, "improvements-title": impTitle, "improvements-tag": impTag}[id] || null;
    }
  },
  Date: Date, Math: Math, Number: Number, String: String, Boolean: Boolean
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
["el", "clear", "fmtTime", "fmtNum", "fmtDuration", "prefixHref", "prefixCell", "beforeAfter", "gainText", "whyText",
  "renderImprovements", "renderSynthetic"].forEach(function (n) { vm.runInContext(fn(app, n), context); });
vm.runInContext("var lastOverview = null; var lastSynthetic = null;", context);

// Mode off, or no answer: the section stays hidden.
section.hidden = false;
context.renderSynthetic({enabled: false, routes: []});
assert(section.hidden === true, "the section is shown with the mode off");
section.hidden = false;
context.renderSynthetic(null);
assert(section.hidden === true, "the section is shown with no answer");

// On with nothing seen yet.
context.renderSynthetic({enabled: true, default_provider: "isp-a", tracked_blocks: 0, dropped_blocks: 0, routes: []});
assert(section.hidden === false && root.textContent === "No destinations seen in flow data yet.", "empty note: " + root.textContent);
assert(note.textContent.indexOf("not from BGP") >= 0 && note.textContent.indexOf("never exported to a BGP peer") >= 0 && note.textContent.indexOf("isp-a") >= 0, "note: " + note.textContent);

var data = {enabled: true, default_provider: "isp-a", tracked_blocks: 3, dropped_blocks: 2, routes: [
  {source: "synthetic", prefix: "198.51.100.0/24", upper: "198.51.100.0/23", blocks: 1, last_seen: "2026-11-09T12:00:00Z", steered_to: "isp-b", next_hop: "198.51.100.1"},
  {source: "synthetic", prefix: "2001:db8::/46", blocks: 2, last_seen: "2026-11-09T12:00:00Z"}
]};
context.renderSynthetic(data);
assert(note.textContent.indexOf("2 not tracked (max_blocks reached)") >= 0, "dropped blocks are not shown: " + note.textContent);
var rows = walk(root).filter(function (n) { return n.tag === "tr"; });
assert(rows.length === 3, "rows (header and two routes): " + rows.length);
assert(rows[1].textContent.indexOf("198.51.100.0/24") >= 0 && rows[1].textContent.indexOf("synthetic") >= 0 &&
  rows[1].textContent.indexOf("198.51.100.0/23") >= 0 && rows[1].textContent.indexOf("isp-b via 198.51.100.1") >= 0, "steered row: " + rows[1].textContent);
assert(rows[2].textContent.indexOf("2001:db8::/46") >= 0 && rows[2].textContent.indexOf("not looked up") >= 0 &&
  rows[2].textContent.indexOf("default route") >= 0, "default row: " + rows[2].textContent);
assert(walk(rows[1]).some(function (n) { return n.tag === "span" && n.className === "badge muted" && n.textContent === "synthetic"; }), "no synthetic label");

// A later render replaces the table, it does not append to it.
context.renderSynthetic(data);
assert(walk(root).filter(function (n) { return n.tag === "tr"; }).length === 3, "a second render doubled the rows");

// The improvements table labels a synthetic row, and says what inject installs.
vm.runInContext("lastSynthetic = " + JSON.stringify(data) + ";", context);
context.renderImprovements({mode: "inject", improvements: [
  {prefix: "198.51.100.0/24", provider: "isp-b", native: "isp-a", source: "synthetic", cause: "performance", reason: "lower loss"},
  {prefix: "203.0.113.0/24", provider: "isp-b", native: "isp-a", cause: "performance", reason: "lower loss"}
]});
var imps = walk(impRoot).filter(function (n) { return n.tag === "tr"; });
assert(imps.length === 3, "improvement rows: " + imps.length);
assert(walk(imps[1]).some(function (n) { return n.tag === "span" && n.className === "badge muted" && n.textContent === "synthetic"; }), "a synthetic improvement is not labeled");
assert(!walk(imps[2]).some(function (n) { return n.tag === "span" && n.textContent === "synthetic"; }), "a row with no source is labeled synthetic");
assert(impTag.textContent.indexOf("static routes on the router") >= 0 && impTag.textContent.indexOf("NO_EXPORT") < 0, "tag: " + impTag.textContent);
vm.runInContext("lastSynthetic = null;", context);
context.renderImprovements({mode: "inject", improvements: []});
assert(impTag.textContent.indexOf("NO_EXPORT") >= 0, "a BGP site lost its wording: " + impTag.textContent);
console.log("ok");
