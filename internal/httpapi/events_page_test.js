"use strict";
// Renders the Events rows, the Improvements empty state, and the setup
// checklist (#347) against a small DOM stand-in. The page scripts stay
// outside this file: their functions are cut out of the real sources, so
// the test runs what ships. Run by TestEventsPageRendering.

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

function textNode(s) { var n = new Node("#text"); n.text = s; return n; }
function walk(n, out) {
  out = out || [];
  out.push(n);
  n.children.forEach(function (c) { walk(c, out); });
  return out;
}
function find(root, tag) { return walk(root).filter(function (n) { return n.tag === tag; }); }

var ids = {};
var context = {
  document: {
    createElement: function (t) { return new Node(t); },
    createTextNode: textNode,
    getElementById: function (id) { return ids[id] || (ids[id] = new Node("div")); }
  },
  fmtTime: function (s) { return s; },
  lastOverview: null
};
vm.createContext(context);

// fn returns the source of a top-level function declaration.
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
var shell = fs.readFileSync(path.join(web, "shell.js"), "utf8");
var events = fs.readFileSync(path.join(web, "events.js"), "utf8");
var app = fs.readFileSync(path.join(web, "app.js"), "utf8");
[[shell, "shellEl"], [shell, "docLink"], [app, "el"], [app, "clear"],
  [events, "eventDetail"], [events, "renderEvents"], [app, "renderImprovements"], [app, "renderSetup"], [shell, "bgpState"], [shell, "reportTitle"]
].forEach(function (p) { vm.runInContext(fn(p[0], p[1]), context); });
// varLine returns a top-level var statement that ends on a line of its own.
function varLine(src, name) {
  var m = new RegExp("^var " + name + " = [^;]*;$", "m").exec(src);
  assert(m, "var " + name + " not found");
  return m[0];
}
vm.runInContext(varLine(shell, "BGP_CONNECTING") + varLine(shell, "REPORT_TITLES").replace(/\n/g, " "), context);
context.shellAdmin = true;

var DOC = "https://docs.example.invalid/blob/main/";

// An event row: headline first, the next step as a link, fields behind Details.
var ev = {
  time: "t", source: "provider", severity: "critical", kind: "provider.down",
  message: "Provider lab-b is down: 100% loss on its probes",
  fields: {provider: "lab-b", reason: "100% loss"}, help_url: DOC + "docs/troubleshooting.md#probes-fail"
};
var cell = context.eventDetail(ev);
assert(cell.children[0].className === "event-headline" && cell.children[0].textContent === ev.message, "headline first");
var link = find(cell, "a")[0];
assert(link && link.textContent === "What to do" && link.href === ev.help_url, "What to do link");
assert(link.target === "_blank" && link.rel === "noopener noreferrer", "a doc opens in a new tab without a referrer");
var details = find(cell, "details")[0];
assert(details && find(details, "summary")[0].textContent === "Details", "fields sit under a Details toggle");
assert(details.textContent.indexOf("provider=lab-b reason=100% loss") >= 0, "fields are in the toggle");
assert(cell.children.indexOf(link) >= 0 && cell.children.indexOf(link) < cell.children.indexOf(details), "link before details");
assert(cell.children[0].textContent.indexOf("provider=") < 0, "raw fields are not in the headline");

var sys = context.eventDetail({message: "Edge session down", fields: {}, help_url: "/system.html"});
var sysLink = find(sys, "a")[0];
assert(sysLink.href === "/system.html" && !sysLink.target, "an in-app link stays in the tab");
assert(find(sys, "details").length === 0, "no fields, no toggle");
var bare = context.eventDetail({message: "x", fields: {a: "b"}});
assert(find(bare, "a").length === 0, "no help_url, no link");

context.renderEvents([ev]);
var heads = find(ids["events"], "th").map(function (n) { return n.textContent; });
assert(heads.join(",") === "Time,Source,Severity,Event,What happened", "columns: " + heads);

// Improvements with no BGP session names the session and links to System.
function empty(overview, mode) {
  ids["improvements"] = new Node("div");
  context.lastOverview = overview;
  context.renderImprovements({mode: mode, improvements: []});
  return ids["improvements"];
}
var root = empty({bgp: {configured: true, established: 0}}, "observe");
assert(root.textContent === "No BGP session, so Packeteer can't see current routes and makes no recommendations. Fix the edge session on the System page.",
  "no-session text: " + root.textContent);
var a = find(root, "a")[0];
assert(a && a.textContent === "System page" && a.href === "/system.html", "System link");
root = empty({bgp: {configured: true, established: 1}}, "observe");
assert(root.textContent.indexOf("None. A move is recommended only when") === 0 && find(root, "a").length === 0, "with a session: " + root.textContent);
root = empty(null, "inject");
assert(root.textContent === "No active improvements.", "inject: " + root.textContent);

// The checklist doc is a link.
ids["setup"] = new Node("div");
context.renderSetup({setup: [{id: "providers-down", level: "warn", title: "Every provider is down", detail: "d",
  doc: "docs/policy-routing.md", doc_url: DOC + "docs/policy-routing.md"}]});
var doc = find(ids["setup"], "a")[0];
assert(doc && doc.textContent === "docs/policy-routing.md" && doc.href === DOC + "docs/policy-routing.md" && doc.target === "_blank",
  "checklist doc link");
// A session in Active is connecting (amber), not down; Idle is down; the
// raw state is the tooltip (#351).
[["ACTIVE", false, "Connecting (Active)", "degraded"], ["active", false, "Connecting (Active)", "degraded"],
  ["OPENSENT", false, "Connecting (OpenSent)", "degraded"], ["CONNECT", false, "Connecting (Connect)", "degraded"],
  ["IDLE", false, "Down", "down"], ["idle", false, "Down", "down"], ["", false, "Down", "down"],
  ["ESTABLISHED", true, "Up", "up"], ["Established", false, "Up", "up"]
].forEach(function (c) {
  var v = context.bgpState(c[0], c[1]);
  assert(v.label === c[2] && v.level === c[3], "bgpState(" + c[0] + "): " + JSON.stringify(v));
  assert(v.title === "BGP state: " + (c[0] || "unknown"), "tooltip keeps the raw state: " + v.title);
});

// Report names read as words; an unknown name is shown as it is.
assert(context.reportTitle("asns") === "ASNs" && context.reportTitle("timeseries") === "Time series" &&
  context.reportTitle("probes") === "Probes" && context.reportTitle("future") === "future", "report titles");

// The checklist remedy links to the editor only when it is on and the account is an admin.
function checklist(features, admin) {
  ids["setup"] = new Node("div");
  context.shellAdmin = admin;
  context.renderSetup({features: features, setup: [{id: "bgp-down", level: "warn", title: "t", detail: "d", fix: "/settings.html#form-bgp"},
    {id: "first-round", level: "info", title: "t2", detail: "d2"}]});
  return ids["setup"];
}
var box = checklist([{name: "config_editor", on: true}], true);
var fixes = find(box, "a").filter(function (n) { return n.textContent === "Fix in Settings"; });
assert(fixes.length === 1 && fixes[0].href === "/settings.html#form-bgp", "editor on: one Fix in Settings link");
assert(box.textContent.indexOf("mounted config file") < 0, "editor on: no mounted-file advice: " + box.textContent);
box = checklist([{name: "config_editor", on: false}], true);
assert(find(box, "a").filter(function (n) { return n.textContent === "Fix in Settings"; }).length === 0, "editor off: no link");
assert(box.textContent.indexOf("Edit the mounted config file, then restart the container.") >= 0, "editor off: mounted-file advice");
box = checklist([{name: "config_editor", on: true}], false);
assert(find(box, "a").filter(function (n) { return n.textContent === "Fix in Settings"; }).length === 0, "not an admin: no link");
console.log("ok");
