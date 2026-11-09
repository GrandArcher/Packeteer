"use strict";
// Runs the prefix page "Why?" panel (#201) against a small DOM stand-in:
// the gate table, the held-back marking, the counterfactual, the 404 text,
// and the stored checks on the timeline. The functions are cut out of the
// real page sources, so the test runs what ships. Run by TestWhyPage.

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
function withClass(root, cls) { return walk(root).filter(function (n) { return (" " + n.className + " ").indexOf(" " + cls + " ") >= 0; }); }

var body = new Node("div");
var context = {
  document: {
    createElement: function (t) { return new Node(t); },
    createTextNode: function (t) { var n = new Node("#text"); n.text = String(t); return n; },
    getElementById: function (id) { return id === "why-body" ? body : null; }
  },
  Date: Date, Math: Math, Number: Number, String: String, Promise: Promise, encodeURIComponent: encodeURIComponent
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
function varBlock(src, name) {
  var m = new RegExp("^var " + name + " = \\{[^;]*\\};$", "m").exec(src);
  assert(m, "var " + name + " not found");
  return m[0];
}

var web = path.join(__dirname, "web");
var app = fs.readFileSync(path.join(web, "app.js"), "utf8");
var page = fs.readFileSync(path.join(web, "prefix.js"), "utf8");
["GATE_LABELS", "GATE_RESULTS", "OUTCOMES"].forEach(function (n) { vm.runInContext(varBlock(page, n), context); });
[[app, "el"], [app, "clear"], [app, "fmtMs"], [app, "fmtPct"], [app, "fmtTime"], [app, "table"], [app, "confidenceCell"],
  [page, "gateLabel"], [page, "whyHeadline"], [page, "gateRow"], [page, "sampleRow"], [page, "renderWhy"], [page, "loadWhy"],
  [page, "whyStored"], [page, "timelineVerb"], [page, "measure"], [page, "improvementEntries"]
].forEach(function (p) { vm.runInContext(fn(p[0], p[1]), context); });
vm.runInContext('var thisPrefix = "198.51.100.0/24";', context);

var held = {
  decided_at: "2026-10-17T12:00:00Z",
  explain: {
    outcome: "held", blocked_by: "thresholds", reason: "native path is best (within thresholds)",
    counterfactual: "would move to lab-b if its RTT delta reached >= 15 ms (now 10 ms) with loss no higher than 0%, or its loss were >= 1 pt lower (now 0 pt)",
    gates: [
      {gate: "rib", status: "pass", value: "native lab-a"},
      {gate: "thresholds", status: "fail", value: "lab-b vs lab-a: loss gain 0 pt, rtt gain 10 ms (20%)", limit: "loss gain >= 1 pt, or rtt gain >= 15 ms with loss no higher, and a lower score", detail: "neither threshold is met"},
      {gate: "evidence", status: "pass", value: "lab-a: icmp, 10/10 replies; lab-b: tcp, 10/10 replies", limit: "display only"},
      {gate: "cap", status: "skip", detail: "not reached: no better path passed the thresholds"},
      {gate: "rpki", status: "skip", detail: "RPKI is off"}
    ],
    samples: [
      {provider: "lab-a", role: "current", loss_pct: 0, rtt_ms: 50, jitter_ms: 1, score: 50, usable: true, confidence: "medium", evidence: "icmp, 10/10 replies"},
      {provider: "lab-b", role: "challenger", loss_pct: 0, rtt_ms: 40, jitter_ms: 1, score: 40, usable: true, confidence: "low", evidence: "tcp, 1/10 replies"},
      {provider: "lab-c", loss_pct: 100, rtt_ms: 0, jitter_ms: 0, score: 0, usable: false, why: "stale", confidence: "none", evidence: "no measurement"}
    ]
  }
};

context.renderWhy(held);
var text = body.textContent;
assert(text.indexOf("Held: native path is best (within thresholds). Held back by: Thresholds.") >= 0, "headline: " + text);
assert(text.indexOf("What would change it: would move to lab-b if its RTT delta reached >= 15 ms (now 10 ms)") >= 0, "counterfactual");
var rows = walk(body).filter(function (n) { return n.tag === "tr"; });
// two header rows, five gates, three samples
assert(rows.length === 2 + 5 + 3, "row count " + rows.length);
assert(withClass(body, "dot down").length === 1 && withClass(body, "dot down")[0].textContent === "Held it back", "one gate held it back");
assert(withClass(body, "dot up").length === 2 && withClass(body, "dot up")[0].textContent === "Passed", "two gates passed");
assert(withClass(body, "badge muted").length === 2, "two skipped gates");
// Confidence (#202): a level pill with the evidence beside it; low is amber; a failed sample shows a dash.
assert(text.indexOf("Measurement evidence") >= 0 && text.indexOf("medium icmp, 10/10 replies") >= 0, "confidence column: " + text);
assert(withClass(body, "badge warn").length === 1 && withClass(body, "badge warn")[0].textContent === "low" && withClass(body, "badge warn")[0].title === "tcp, 1/10 replies", "low confidence is amber");
assert(text.indexOf("no measurement") < 0, "a failed sample shows no evidence text");
assert(text.indexOf("Max simultaneous moves") >= 0 && text.indexOf("Learned RIB") >= 0, "gate labels are plain words");
assert(text.indexOf("not usable: stale") >= 0 && text.indexOf("challenger") >= 0, "samples: " + text);

var moved = JSON.parse(JSON.stringify(held));
moved.explain.outcome = "moved";
moved.explain.blocked_by = "";
moved.explain.counterfactual = "";
context.renderWhy(moved);
assert(body.textContent.indexOf("Moved: native path is best") === 0, "moved headline");
assert(body.textContent.indexOf("Held back by") < 0 && body.textContent.indexOf("What would change it") < 0, "a move names no blocker");

// Stored checks on the timeline: skipped gates are left out.
var entries = context.improvementEntries({start: "2026-10-17T12:00:00Z", mode: "observe", provider: "lab-b", native: "lab-a", cause: "performance",
  reason: "lab-b: loss 0%", explain: held.explain});
var line = entries[0].text;
assert(line.indexOf("Checks at the time: Learned RIB passed (native lab-a); Thresholds held it back (lab-b vs lab-a") >= 0, "timeline: " + line);
assert(line.indexOf("Max simultaneous moves") < 0 && line.indexOf("RPKI") < 0, "skipped gates are not listed");
assert(context.improvementEntries({start: "2026-10-17T12:00:00Z", mode: "observe", provider: "lab-b"})[0].text.indexOf("Checks at the time") < 0, "no stored checks, no line");

// A prefix with no decision gets a sentence, not an error.
var failed = [];
context.getJSON = function (p) {
  failed.push(p);
  var err = new Error("not found");
  err.status = 404;
  return Promise.reject(err);
};
context.loadWhy();
assert(context.gateLabel("med") === "Neighbor MED", "med gate label: " + context.gateLabel("med"));

setTimeout(function () {
  assert(failed[0] === "/api/decisions/198.51.100.0%2F24", "request path " + failed[0]);
  assert(body.textContent.indexOf("Packeteer has no decision for this prefix now") === 0, "404 text: " + body.textContent);
  console.log("ok");
}, 20);
