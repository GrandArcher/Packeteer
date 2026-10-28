"use strict";
// Runs the prefix card (#303) against a small DOM stand-in: a recommended
// exit that overrides the neighbor's MED gets a badge and a line naming
// both exits and their MEDs, a row without one gets neither, and the
// learned paths label says MED breaks ties. The functions are cut out of
// the real app.js, so the test runs what ships. Run by TestPrefixCardMED.

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
  document: {
    createElement: function (t) { return new Node(t); },
    createTextNode: function (t) { var n = new Node("#text"); n.text = String(t); return n; }
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
vm.runInContext('var lastProviders = null, lastOverview = null, NO_REPLY = "no reply";', context);
["el", "exitLabels", "providerState", "healthPill", "fmtPct", "fmtMs", "fmtNum", "confidenceCell", "fmtVia", "fmtAS", "prefixCard"].forEach(function (n) {
  vm.runInContext(fn(app, n), context);
});

var row = {
  prefix: "198.51.100.0/24", native: "link-1", current: "link-1", recommended: "link-2", action: "improve",
  probes: [{provider: "link-1", ok: true, received: 10, loss_pct: 0, rtt_avg_ms: 80}, {provider: "link-2", ok: true, received: 10, loss_pct: 0, rtt_avg_ms: 38}],
  med_override: {asn: 64496, preferred: "link-1", preferred_med: 10, chosen: "link-2", chosen_med: 50, score_gap: 42}
};
var card = context.prefixCard(row);
var badges = walk(card).filter(function (n) { return n.className === "badge warn" && n.text === "overrides MED"; });
assert(badges.length === 1, "one overrides MED badge, got " + badges.length);
assert(badges[0].title.indexOf("thresholds.med_margin") >= 0, "badge title names the margin: " + badges[0].title);
var text = card.textContent;
var want = "Overrides AS64496's MED: link-2 (MED 50) is chosen over link-1 (MED 10), the exit the neighbor prefers, because it scores 42 better.";
assert(text.indexOf(want) >= 0, "override line missing: " + text);

delete row.med_override;
row.paths = [{provider: "link-1", next_hop: "192.0.2.1", as_path: [64496, 64500], selected: true, med: 10}];
// rpkiCell and irrCell are not needed without RPKI or IRR data, but the
// paths table calls them; stand-ins keep the cut small.
vm.runInContext('function rpkiCell() { return el("td", "", "-"); } function irrCell() { return el("td", "", "-"); }', context);
card = context.prefixCard(row);
text = card.textContent;
assert(text.indexOf("overrides MED") < 0 && text.indexOf("Overrides AS") < 0, "override shown without med_override: " + text);
assert(text.indexOf("Learned paths. MED breaks ties between exits to one neighbor AS (thresholds.med_tie_break).") >= 0, "paths label: " + text);
// A synthesized sub-range (#122) carries a badge and the warning line.
delete row.paths;
row.prefix = "198.51.100.0/25";
row.covering = "198.51.100.0/24";
card = context.prefixCard(row);
text = card.textContent;
badges = walk(card).filter(function (n) { return n.className === "badge warn" && n.text === "synthesized"; });
assert(badges.length === 1, "one synthesized badge, got " + badges.length);
assert(text.indexOf("WARNING: synthesized more-specific inside 198.51.100.0/24. It is NOT in the learned RIB and can cause hijack-like effects, RPKI-invalid announcements, and route leaks if misused.") >= 0, "synthesize warning: " + text);
delete row.covering;
text = context.prefixCard(row).textContent;
assert(text.indexOf("synthesized") < 0, "synthesize warning without covering: " + text);
console.log("ok");
