"use strict";
// Runs the blast-radius section of the settings page script (#227) against
// a small DOM stand-in: the panel lists what would be announced, move, and
// be withdrawn with the warnings; a save the server wants previewed shows
// the preview and saves only with the token it returned. The functions are
// cut out of the real settings.js. Run by TestBlastPage.

var fs = require("fs");
var path = require("path");
var vm = require("vm");

function assert(cond, msg) {
  if (!cond) {
    console.error("FAIL: " + msg);
    process.exit(1);
  }
}

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

function node(tag) {
  var n = {tag: tag, className: "", textContent: "", children: [], dataset: {}, attrs: {}, hidden: false, disabled: false, value: "", checked: false};
  n.appendChild = function (c) { n.children.push(c); return c; };
  n.scrollIntoView = function () { n.scrolled = true; };
  Object.defineProperty(n, "firstChild", {get: function () { return n.children[0] || null; }});
  n.removeChild = function (c) { n.children.splice(n.children.indexOf(c), 1); };
  return n;
}
function text(n) {
  return n.textContent + n.children.map(text).join(" ");
}

var els = {};
["bl-body", "bl-status", "bl-confirm", "blast", "ed-yaml", "ed-inject", "ed-sha"].forEach(function (id) { els[id] = node("x"); });
els["bl-confirm"].hidden = true;
els["ed-yaml"].value = "mode: inject\n";
var calls = [];
var replies = [];
var status = [];
var context = {
  document: {createElement: node, createTextNode: function (t) { var n = node("#text"); n.textContent = t; return n; }, getElementById: function (id) { return els[id]; }},
  byId: function (id) { return els[id]; },
  explain: function (err) { return "explained: " + err.message; },
  describe: function () { return ""; },
  edStatus: function (m) { status.push(m); },
  savedMessage: function () { return "saved"; },
  refreshUnsaved: function () {},
  previewConfig: function () {},
  base: "base1",
  api: function (method, url, body) {
    calls.push({method: method, url: url, body: body});
    return replies.shift();
  }
};
vm.createContext(context);

var ui = fs.readFileSync(path.join(__dirname, "web", "ui.js"), "utf8");
var settings = fs.readFileSync(path.join(__dirname, "web", "settings.js"), "utf8");
["el", "clear"].forEach(function (n) { vm.runInContext(fn(ui, n), context); });
vm.runInContext("var blastToken = '';", context);
["blastRoute", "blastShift", "renderBlast", "loadBlast", "previewCandidate", "putConfig"].forEach(function (n) {
  vm.runInContext(fn(settings, n), context);
});

var report = {
  at: "2026-01-02T03:04:05Z", announces: true, keep: 2, changes: true,
  add: [{prefix: "198.51.100.0/24", from: "transit-a", to: "transit-b", volume_mbps: 12.5}],
  move: [{prefix: "203.0.113.0/24", from: "transit-b", to: "transit-c"}],
  withdraw: [],
  providers: [{provider: "transit-b", in_mbps: 12.5, out_mbps: 0, unknown: 1, current_mbps: 80, projected_mbps: 92.5, capacity_mbps: 100}],
  warnings: [{code: "capacity", message: "transit-b would carry about 92.5 Mbps out, over its limit of 90.0 Mbps"},
    {code: "stale", message: "3 allowlisted prefixes lack a recent successful measurement", prefixes: ["192.0.2.0/24"], count: 3}]
};

context.renderBlast(report);
var body = text(els["bl-body"]);
assert(body.indexOf("Would be announced (1)") >= 0 && body.indexOf("198.51.100.0/24: transit-a -> transit-b (12.5 Mbps)") >= 0, "added route: " + body);
assert(body.indexOf("Would move (1)") >= 0 && body.indexOf("203.0.113.0/24: transit-b -> transit-c (volume unknown)") >= 0, "an unknown volume is said so: " + body);
assert(body.indexOf("Would be withdrawn (0)") >= 0, "empty withdraw list: " + body);
assert(body.indexOf("2 announced routes stay") >= 0, "kept routes counted: " + body);
assert(body.indexOf("transit-b: +12.5 Mbps in, -0.0 Mbps out (at least; 1 without a volume). Now 80.0, after 92.5 of 100.0 Mbps capacity") >= 0, "provider shift: " + body);
assert(body.indexOf("Warnings (2)") >= 0 && body.indexOf("over its limit of 90.0 Mbps") >= 0 && body.indexOf("192.0.2.0/24 and more") >= 0, "warnings: " + body);

// An idle backup taking traffic and a provider that all traffic leaves:
// a zero rate must render, and a missing rate renders as 0.
var idle = JSON.parse(JSON.stringify(report));
idle.providers = [
  {provider: "transit-c", in_mbps: 25, out_mbps: 0, unknown: 0, current_mbps: 0, projected_mbps: 25, capacity_mbps: 1000},
  {provider: "transit-a", in_mbps: 0, out_mbps: 40, unknown: 0, current_mbps: 40, capacity_mbps: 1000}
];
context.renderBlast(idle);
body = text(els["bl-body"]);
assert(body.indexOf("transit-c: +25.0 Mbps in, -0.0 Mbps out. Now 0.0, after 25.0 of 1000.0 Mbps capacity") >= 0, "idle provider: " + body);
assert(body.indexOf("transit-a: +0.0 Mbps in, -40.0 Mbps out. Now 40.0, after 0.0 of 1000.0 Mbps capacity") >= 0, "drained provider: " + body);

var observe = JSON.parse(JSON.stringify(report));
observe.announces = false;
context.renderBlast(observe);
assert(text(els["bl-body"]).indexOf("every route announced now would be withdrawn") >= 0, "a config that does not announce says so");
var calm = JSON.parse(JSON.stringify(report));
calm.warnings = [];
calm.providers = [];
context.renderBlast(calm);
assert(text(els["bl-body"]).indexOf("Warnings (0)") >= 0 && els["bl-body"].children.length > 0, "no warnings is said");

replies.push(Promise.resolve({available: true, report: report}));
context.loadBlast().then(function () {
  assert(calls[0].method === "GET" && calls[0].url === "/api/blast", "load call: " + JSON.stringify(calls[0]));
  assert(els["bl-status"].textContent === "As of 2026-01-02T03:04:05Z.", "status: " + els["bl-status"].textContent);
  replies.push(Promise.resolve({available: false}));
  return context.loadBlast();
}).then(function () {
  assert(els["bl-status"].textContent.indexOf("not available") >= 0, "unavailable: " + els["bl-status"].textContent);
  var err = new Error("no decision round has run yet");
  err.data = {code: "no_round"};
  replies.push(Promise.reject(err));
  return context.loadBlast();
}).then(function () {
  assert(els["bl-status"].textContent === "explained: no decision round has run yet", "no round: " + els["bl-status"].textContent);

  // A save the server wants previewed: the first PUT is refused with
  // preview_required, the page asks for the dry run and shows it with an
  // Apply button, and Apply sends the token with dry_run false.
  calls.length = 0;
  var need = new Error("this change can alter what is announced");
  need.data = {code: "preview_required"};
  replies.push(Promise.reject(need));
  replies.push(Promise.resolve({dry_run: true, required: true, preview_token: "tok1", blast: report}));
  context.putConfig();
  return new Promise(function (r) { setTimeout(r, 20); });
}).then(function () {
  assert(calls.length === 2, "save then dry run: " + JSON.stringify(calls));
  assert(calls[0].method === "PUT" && calls[0].body.dry_run === undefined && calls[0].body.preview_token === undefined, "the first save has no token: " + JSON.stringify(calls[0].body));
  assert(calls[1].method === "PUT" && calls[1].body.dry_run === true && calls[1].body.base === "base1" && calls[1].body.yaml === "mode: inject\n", "dry run body: " + JSON.stringify(calls[1].body));
  assert(els["bl-confirm"].hidden === false, "Apply is offered");
  assert(text(els["bl-body"]).indexOf("Would be announced (1)") >= 0 && els["blast"].scrolled === true, "the preview is shown");
  assert(status.length > 0 && status[status.length - 1].indexOf("Apply this change") >= 0, "the editor status points at Apply: " + status);

  calls.length = 0;
  replies.push(Promise.resolve({file: {sha256: "base2"}, result: {}}));
  context.putConfig();
  return new Promise(function (r) { setTimeout(r, 20); });
}).then(function () {
  var b = calls[0].body;
  assert(b.dry_run === false && b.preview_token === "tok1", "Apply sends the token with dry_run false: " + JSON.stringify(b));
  assert(els["bl-confirm"].hidden === true && context.blastToken === "", "the token is spent and Apply hides");

  // A dry run for a change that needs no confirmation, or one that fails,
  // offers no Apply button.
  replies.push(Promise.resolve({dry_run: true, required: false, blast: report}));
  return context.previewCandidate(true);
}).then(function () {
  assert(els["bl-confirm"].hidden === true, "no token, no Apply button");
  var bad = new Error("the preview failed");
  replies.push(Promise.reject(bad));
  return context.previewCandidate(true);
}).then(function () {
  assert(els["bl-confirm"].hidden === true && els["bl-status"].textContent === "explained: the preview failed", "a failed preview: " + els["bl-status"].textContent);
  console.log("ok");
}).catch(function (e) {
  console.error("FAIL: " + (e && e.stack || e));
  process.exit(1);
});
